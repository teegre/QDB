import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from collections import defaultdict
from random import shuffle

from qdb.lib.exception import QDBParseError, QDBQueryError, QDBQueryNoData
from qdb.lib.functions import (
    expand,
    has_function,
    unwrap,
)
from qdb.lib.ops import OPFUNC, AGGFUNC, BINOP, REVOP
from qdb.lib.parser import QDBParser
from qdb.lib.storage import QDBStore
from qdb.lib.utils import (
    coerce_number,
    is_numeric,
    is_virtual,
    performance_measurement,
)

class QDBQuery:
  def __init__(self, store: QDBStore, parent=None):
    self.store = store
    self._card_cache = {}
    self.parent = parent

  def _dispatch_parse(self, root_index: str, exprs: list) -> list:
    parsed_exprs = []
    current_index = root_index

    for expr in exprs:
      head = expr.split(':', 1)[0]

      if self.store.is_index(head):
        current_index = head
        parsed = self.parser.parse(expr)
      else:
        parsed = self.parser.parse(expr, current_index)

      parsed_exprs.append(parsed)

    return parsed_exprs

  def _get_condition_fields(self, conditions: list):
    for cond in conditions:
      if cond is None:
        continue
      if cond.op in BINOP:
          yield self._get_condition_fields(cond['conditions'])
      else:
        yield cond.field

  def _validate_fields_and_group(self, parsed_exprs: dict, agg_exprs: dict, fields: dict) -> dict:
    def is_grouped(index: str):
      return any(
          v.op in AGGFUNC or (v.op == 'count' and v.field == '*')
          for v in agg_exprs.get(index, [])
      ) or self._query_looks_grouped(index, agg_exprs, parsed_exprs)

    grouped = {}

    condition_fields = {
        (e.index, v)
        for e in parsed_exprs
        for v in self._get_condition_fields(e.conditions)
        if v is not None
    }

    agg_fields = [
        (i, f'{i}:{v.op}{":"+v.field if v.field != "*" else ""}')
        for i, e in agg_exprs.items()
        for v in e
    ]

    explicit_fields = [
        (e.index, f)
        for e in parsed_exprs
        for f in e.fields
        if (e.index, unwrap(f)) not in agg_fields and (e.index, unwrap(f)) not in condition_fields
    ]

    for i, f in explicit_fields:
      if is_grouped(i):
        if i in grouped:
          grouped[i].append(f)
        else:
          grouped[i] = [f]
      if is_grouped(i) and unwrap(f) not in fields.get(i, []):
        continue
      if unwrap(f) not in fields.get(i, []) and f != '*':
        raise QDBQueryError(
            f'Error: field `{i}:{f}` is not used in any condition or aggregation.\n'
            f'Consider removing it from the query or using it as a filter like: `{i}:{f}=value`.'
        )

    return grouped

  def _eval_cond(self, op: str, field_value: str, condition_value: str, field: str) -> bool:
    if op in ('gt', 'ge', 'lt', 'le'):
      if not is_numeric(field_value) or not is_numeric(condition_value):
        return False

      field_num = float(field_value)
      cond_num  = float(condition_value)
      return OPFUNC[op](field_num, cond_num)

    if op not in ('sw', 'ns', 'dw', 'nd', 'ct', 'nc', 'in', 'ni'):
      field_value = coerce_number(field_value) if not is_virtual(field) else field_value
      condition_value = coerce_number(condition_value) if not is_virtual(field) else condition_value
      return OPFUNC[op](field_value, condition_value)

    match op:
      case 'sw':
        return field_value.startswith(condition_value)
      case 'ns':
        return not field_value.startswith(condition_value)
      case 'dw':
        return field_value.endswith(condition_value)
      case 'nd':
        return not field_value.endswith(condition_value)
      case 'ct':
        return condition_value in field_value
      case 'nc':
        return condition_value not in field_value
      case 'in':
        return field_value in condition_value
      case 'ni':
        return field_value not in condition_value
    return False

  def _find_prm_index(self, indexes: list) -> str:
    candidates = reversed(sorted(indexes, key=lambda idx: self.store.index_len(idx)))
    for idx in candidates:
      reachable = all(
          idx == other or self.store.find_index_path(idx, other)
          for other in indexes
      )
      if reachable:
        return idx
    return None

  def _find_prm_index2(self, indexes: list) -> str:
    if len(indexes) == 1:
      return indexes[0]

    candidates = []
    for A in indexes:
      scores = []
      for B in indexes:
        if A != B:
          relation = self.store.cardinality(A, B)
          scores.append(relation)

      oto_c = scores.count(11) # one-to-one
      otm_c = scores.count(12) # one-to-many
      mto_c = scores.count(21) # many-to-one
      mtm_c = scores.count(22) # many-to-many

      candidates.append((oto_c, otm_c, mto_c, mtm_c, A))

    candidates.sort(reverse=True)
    return candidates[0][3]

  def _query_looks_grouped(self, A: str, agg_exprs: list, parsed_exprs: list) -> bool:
    for expr in parsed_exprs:
      B = expr.index
      if B != A and B in agg_exprs:
        return self.store.cardinality(A, B) != 0
    return False

  def _apply_aggregations(
      self,
      tree: dict,
      agg_exprs: list,
      agg_indexes: list,
      group: dict=None,
      unique: bool=False
    ) -> dict:

    def walk(node: dict, idx: str) -> dict:
      if idx in agg_indexes:
        results = {}
        for key, child_node in node.items():
          if key == '@[aggregate]':
            group_fields = group.get(idx, []) if group else []
            grouped = defaultdict(lambda: defaultdict(list))

            for ref in child_node.keys():
              data = self.store.read_hash(ref)
              group_key = tuple(
                  expand(f, data.get(unwrap(f))) for f in group_fields) if group else ('__all__',)

              for agg in agg_exprs[idx]:
                op, f = agg.op, unwrap(agg.field)
                val = data.get(f.replace('*', '$id'))
                val = coerce_number(val) if not is_virtual(f) else val
                grouped[group_key][f'{idx}:{op}:{agg.field}'].append(val)

            for group_key, agg_vals in grouped.items():
              pointer = results
              if group_key == ('__all__',):
                pointer['@[aggregate]'] = self._reduce_aggs(agg_vals)
                continue

              for i, field_value in enumerate(group_key):
                field_name = group_fields[i]
                pointer = pointer.setdefault((field_name,), {}).setdefault(field_value, {})
              pointer['@[aggregate]'] = self._reduce_aggs(agg_vals)

            if unique:
              return results
          else:
            results.setdefault(key, {})
            for child_idx, sub_node in child_node.items():
              results[key][child_idx] = walk(sub_node, child_idx)
        return results
      else:
        results = {}
        for key, child_node in node.items():
          results.setdefault(key, {})
          for child_idx, sub_node in child_node.items():
            results[key][child_idx] = walk(sub_node, child_idx)

        return results

    root_key = list(tree.keys())[0]
    result = {root_key: walk(tree[root_key], root_key)}
    return result

  def _reduce_aggs(self, values: dict) -> dict:
    reduced = {}
    for k, v in values.items():
      clean_values = [x for x in v if x is not None]
      if not clean_values:
        reduced[k] = None
        continue

      idx, op, f = k.split(':')
      try:
        match op:
          case 'avg':
            reduced[f'{idx}:{op}:{f}'] = { expand(f, str(round(sum(clean_values) / len(clean_values), 2))): {} }
          case 'sum':
            reduced[f'{idx}:{op}:{f}'] = { expand(f, str(round(sum(clean_values), 2))): {} }
          case 'min':
            reduced[f'{idx}:{op}:{f}'] = { expand(f, str(min(clean_values))): {} }
          case 'max':
            reduced[f'{idx}:{op}:{f}'] = { expand(f, str(max(clean_values))): {} }
          case 'count':
            count_value = (
                len(set(clean_values)) if f != '*' else len(clean_values)
            )
            reduced[f'{idx}:{op}{':'+f if f != '*' else ''}'] = { str(count_value): {} }
      except TypeError:
        raise QDBQueryError(f'Error: mixed value types in `{unwrap(f)}`.')

    return reduced

  @performance_measurement(message='Fetched')
  def query(self, index_or_key: str, *exprs: str, qq: bool=False) -> tuple[dict, list[dict]] | set:
    limit = None
    random = False

    # Random order, limit results
    if '?!' in index_or_key:
      index_or_key, limit = index_or_key.split('?!')
      random = True
    elif '??' in index_or_key:
      index_or_key = index_or_key.replace('??', '')
      random = True
    elif '!' in index_or_key:
      index_or_key, limit = index_or_key.split('!')

    if limit is not None:
      try:
        limit = int(limit)
        assert limit > 0
      except (ValueError, AssertionError):
        raise QDBQueryError(f'invalid limit: `{limit if limit else ' '}`.')

    # Check index_or_key validity
    root_index = index_or_key if self.store.is_index(index_or_key) else self.store.get_index(index_or_key)
    if not root_index:
      raise QDBQueryError(f'Error: `{index_or_key}`, no such index or hkey.')
    
    def select_best_filter(exprs: list) -> dict:
      return min(exprs, key=lambda e: self.store.index_len(e.index), default={})

    def filter_keys(index: str, expr: dict, base: set=None, limit: int=None) -> set:

      keys = base if base else self.store.get_index_keys(index)
      f, op, val = expr.field, expr.op, expr.value

      is_func = has_function(f)
      field = unwrap(f) if is_func else f

      if not isinstance(val, list) and has_function(val):
        func = unwrap(val, extract_func=True)
        value = unwrap(val)
        val = expand(func, value)

      if is_virtual(field):
        values = val if isinstance(val, list) else [val]
        hkeys = set()

        for v in values:
          match field:
            case '$id':
              hkey = f'{index}:{v}'
            case '$hkey':
              hkey = v
          if not self.store.exists(hkey):
            raise QDBQueryError(f'Error: `{hkey}`, no such hkey.')
          hkeys.add(hkey)

        match op:
          case 'in' | 'eq':
            return hkeys
          case 'ni' | 'ne':
            return keys ^ hkeys
          case _:
            raise QDBQueryError(f'Error: `{REVOP[op]}` not supported for virtual field `{f}` .')

      if op in ('eq', 'in'):
        key_set = self.store.get_indexed(index, field, *val if op == 'in' else (val,))
        if key_set:
          return key_set
      elif op in ('ne', 'ni'):
        key_set = self.store.get_indexed(index, field, *val if op == 'ni' else (val,))
        if key_set:
          return keys ^ key_set

      valid_keys = set()

      for k in keys:
        if limit and len(valid_keys) >= limit:
          break

        value = self.store.read_hash_field(k, field)
        field_value = expand(f, value) if is_func else value

        if self._eval_cond(op, field_value, val, field):
          valid_keys.add(k)

      return valid_keys

    def get_condition_matches(exprs: dict, limit: int=None) -> dict[set]:
      matches = {}
      for expr in exprs:
        index = expr.index
        for cond in expr.conditions:
          if cond is None:
            continue
          base = matches.get(index, None)
          valid_keys = filter_keys(index, cond, base=base, limit=limit if index == root_index else None)
          if index in matches:
            matches[index] &= valid_keys
          else:
            matches[index] = valid_keys
      return matches

    def filter_dataset(dataset: set, index: str, key: str, condition_matches: dict) -> set:
      for i, m in condition_matches.items():
        if self.store.is_index_of(key, i) or i != index:
          continue
        dataset &= m
      return dataset

    def resolve_to_primary(expr: dict) -> set:
      result = set()
      for match_key in cond_matches.get(expr.index, []):
        if self.store.is_index_of(match_key, prm_index):
          result.add(match_key)
        else:
          result.update(self.store.get_refs(match_key, prm_index))
      return result

    def remove_agg_filters():
      for entry in condition_exprs:
        index = entry.index
        if index in agg_indexes:
          for cond in entry.conditions:
            if cond is not None:
              f = cond.field
              if f in group_fields:
                continue
              try:
                selected_fields[index]['fields'].remove(f)
              except ValueError:
                pass

    def build_ref_tree(node: dict, rmap: dict|set, unique: bool=False, flat: bool=False):
      ''' Build a hierarchical references tree from a references map. '''
      if isinstance(rmap, set):
        for ref in rmap:
          node.setdefault(ref, {})
        return
      if unique:
        agg_node = node.setdefault('@[aggregate]', {})
        for key in rmap.keys():
          agg_node[key] = {}
        return
      if flat:
        for key in node.keys():
          node[key] = {}
        return
      for idx, refs in rmap.items():
        if idx in agg_indexes: # It's an aggregation index
          agg_node = node.setdefault(idx, {}).setdefault("@[aggregate]", {})
          build_ref_tree(agg_node, refs)
        else:
          node.setdefault(idx, {})
          if isinstance(refs, set):
            for ref in refs:
              node[idx].setdefault(ref, {})
            if idx not in agg_exprs:
              continue
            return
          for k, submap in refs.items():
            node[idx].setdefault(k, {})
            build_ref_tree(node[idx][k], submap)

    # Parse expressions
    self.parser = QDBParser(self.store, root_index)
    parsed_exprs = self._dispatch_parse(root_index, exprs)
    condition_exprs = [e for e in parsed_exprs for c in e.conditions if c]
    cond_matches = {}
    cond_indexes = set()
    agg_exprs = { e.index: e.aggregations for e in parsed_exprs if e.aggregations }
    agg_indexes = list(agg_exprs.keys()) if agg_exprs else []

    data_tree = {root_index: {}}
    all_keys = None

    # Gather used indexes
    selected_indexes = list(dict.fromkeys(e.index for e in parsed_exprs))

    # Fields
    selected_fields = {}

    # Assuming '$hkey' when no fields are selected for the main index,
    if root_index not in selected_indexes:
      selected_fields = {root_index: {'fields': ['$hkey'], 'sort': None }}
      selected_indexes.append(root_index)

    for d in parsed_exprs:
      i = d.index
      if i not in selected_fields:
        selected_fields[i] = {'fields': [], 'sort': d.sort}
      for f in d.fields:
        if f not in selected_fields[i]['fields']:
          selected_fields[i]['fields'].append(f)

    # Check for any unused fields and get grouped fields
    group_fields = self._validate_fields_and_group(
        parsed_exprs,
        agg_exprs,
        {
          i: self.store.get_fields_from_index(i)
          for i in selected_indexes
        }
    )

    # Determining query's primary index
    if exprs and agg_exprs:
      if root_index in agg_exprs or self._query_looks_grouped(root_index, agg_exprs, parsed_exprs):
        prm_index = root_index
      else:
        prm_index = self._find_prm_index2(selected_indexes) or root_index
    elif exprs:
      prm_index = self._find_prm_index(selected_indexes) or root_index
    else:
      prm_index = root_index

    # Query is based on a particular hkey...
    if self.store.has_index(index_or_key):
      if root_index != prm_index:
        all_keys = set(self.store.get_refs(index_or_key, prm_index))
      else:
        all_keys = { index_or_key }
    # ... or an index
    else:
      all_keys = set(self.store.get_index_keys(prm_index))

    if condition_exprs:
      cond_matches = get_condition_matches(condition_exprs)

      best_expr = select_best_filter(condition_exprs)

      # Primary condition
      # Query may be based on a specific key, hence'&='
      all_keys &= resolve_to_primary(best_expr)

      # Secondary conditions
      for expr in condition_exprs:
        if expr is best_expr:
          continue
        keys = resolve_to_primary(expr)
        all_keys &= keys

    # Stop here if nothing was found
    if not all_keys:
      raise QDBQueryNoData('No data.')

    if root_index != prm_index:
      root_keys = (
          {index_or_key} if self.store.has_index(index_or_key)
          else self.store.get_index_keys(root_index)
      )

      if agg_exprs:
        # Get all root keys from store
        if root_index in cond_matches:
          root_keys &= cond_matches[root_index]

        if random:
          root_keys = list(root_keys)
          shuffle(root_keys)
        if limit:
          root_keys = root_keys[:limit] if random else sorted(root_keys)[:limit]

        derived_keys = set()
        for rkey in root_keys:
          refs = self.store.get_refs(rkey, prm_index)
          if not refs:
            continue
          derived_keys.update(refs)

        # Restrict all_keys
        all_keys &= derived_keys
    else:
      root_keys = None

    # Apply random/limit modifiers
    if not agg_exprs or root_index == prm_index:
      if random:
        all_keys = list(all_keys)
        shuffle(all_keys)

      # Apply limit
      if limit:
        all_keys = all_keys[:limit] if random else sorted(all_keys)[:limit]

    if qq and agg_exprs:
      raise QDBQueryError(f'Error: aggregation not supported.')

    # Unique index query, no expressions: build tree and return it
    if not parsed_exprs and len(selected_indexes) == 1:
      if qq:
        return all_keys
      for key in sorted(all_keys) if not random else all_keys:
        data_tree[root_index][key] = {}
      return data_tree, {}, False

    # Unique index query + aggregations
    if agg_exprs and len(selected_indexes) == 1:
      # remove filter fields
      remove_agg_filters()
      refs_map = {}
      for key in all_keys:
        refs_map[key] = {}
      node = data_tree[root_index] = {}
      build_ref_tree(node, refs_map, unique=True)
      data_tree = self._apply_aggregations(data_tree, agg_exprs, agg_indexes, group=group_fields, unique=True)
      return data_tree, selected_fields, False

    # Build references map
    refs_map = defaultdict(lambda: defaultdict(set))

    cond_indexes = set(cond_matches.keys()) if cond_matches else set()

    if agg_exprs:
      for key in all_keys.copy():
        refs_map.setdefault(key, defaultdict(dict))
        for agg_index in agg_indexes:
          base_dataset = filter_dataset(
              set(self.store.get_refs(key, agg_index)),
              agg_index,
              key,
              cond_matches
          )

          if agg_index in cond_indexes:
            base_dataset &= cond_matches.get(agg_index)

          if root_index != prm_index:
            base_dataset &= {
                r for r in base_dataset
                if any(set(self.store.get_refs(r, root_index)) & set(root_keys))
            }
          if not base_dataset:
            if len(all_keys) == 1:
              if self.store.find_index_path(self.store.get_index(key), agg_index):
                raise QDBQueryNoData(f'No `{agg_index}` data found.')
              if prm_index == root_index:
                aggs = ', '.join([o+':'+f for o, f in [tuple(a.values()) for a in agg_exprs[agg_index]]])
                candidates = [i for i in selected_indexes if i not in (root_index, agg_exprs)]
                msg = (
                    f'Error: `{agg_index}:@[{aggs}]` '
                    f'cannot be resolved from root index `{root_index}`.'
                )
                if candidates:
                  msg += f'\nTry using one of the following as the root index: {", ".join(candidates)}.'
                else:
                  msg += '\nNo alternative root index could resolve the aggregate target. '
                  if 'count' in aggs:
                    msg += '\nHint: aggregations like `@[count:*]` require traversing a valid path from the root index.'
                raise QDBQueryError(msg)

            # NO agg_index for key
            del refs_map[key]
            all_keys.remove(key)
            break

          other_indexes = [i for i in selected_indexes if i not in (prm_index, agg_index)]
          if not other_indexes:
            # Simple case: only aggregate index
            for ref in base_dataset:
              refs_map.setdefault(key, defaultdict(dict))
              refs_map[key][agg_index].setdefault(ref, {})
            continue

          # Complex case: aggregate + other indexes
          for index in other_indexes:
            refs_for_index = cond_matches.get(index, set(self.store.get_refs(key, index)))
            for ref in refs_for_index:
              ref_data = set(self.store.get_refs(ref, agg_index))
              dataset = base_dataset & ref_data
              if dataset:
                node = refs_map.setdefault(key, defaultdict(dict))
                node.setdefault(index, defaultdict(dict))
                node[index][ref][agg_index] = dataset

    elif set(selected_indexes) - cond_indexes - {root_index} or not refs_map:
      if qq:
        root_keys = set()
      for key in all_keys:
        for idx in selected_indexes:
          if idx == prm_index:
            continue
          # In get_refs we trust!
          refs = self.store.get_refs(key, idx)
          if not refs:
            raise QDBQueryError(f'Error: no references: `{prm_index}` → `{idx}`.')
          if qq:
            root_keys.update(refs)
            continue
          refs_map[key][idx].update(refs)

    if qq:
      if prm_index == root_index:
        return all_keys
      return root_keys if root_keys else all_keys


    if not refs_map and not agg_exprs:
      for k in all_keys:
        refs_map.setdefault(k, defaultdict(set))
        refs_map[k][root_index].add(k)

    if not refs_map:
      raise QDBQueryNoData('No data.')

    flat = (
        not condition_exprs and
        not agg_exprs and
        len(selected_indexes) == 1
    )

    # Build tree
    data_tree = { prm_index: {} }
    for key in sorted(all_keys):
      node = data_tree[prm_index][key] = {}
      build_ref_tree(node, refs_map[key], flat=flat)

    if agg_exprs:
      # remove filter fields
      remove_agg_filters()
      data_tree = self._apply_aggregations(data_tree, agg_exprs, agg_indexes, group=group_fields, unique=len(selected_indexes) == 1)

    return data_tree, selected_fields, flat
