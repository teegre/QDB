import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from collections import defaultdict
from random import shuffle

from src.datacache import Cache
from src.exception import QDBParseError, QDBQueryError, QDBQueryNoData
from src.ops import OPFUNC, BINOP
from src.parser import Parser
from src.storage import Store
from src.utils import is_numeric, coerce_number, is_virtual, performance_measurement

from src.utils import performance_measurement

class Query:
  def __init__(self, store: Store, cache: Cache, parent=None):
    self.store = store
    self.cache = cache
    self.parser = Parser(self.store)
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

  def _eval_binop_cond(self, key: str, record: dict, expr: dict) -> bool:
    op = expr['op']
    conditions = expr['conditions']

    if op == 'AND':
      return all(
          self._eval_cond(cond['op'], record.get(cond['field']), cond['value'], field=cond['field'])
          for cond in conditions
      )

    if op == 'OR':
      return any(
          self._eval_cond(cond['op'], record.get(cond['field']), cond['value'], field=cond['field'])
          for cond in conditions
      )

  def _eval_cond(self, op: str, field_value: str, condition_value: str, field: str) -> bool:
    if op in ('gt', 'ge', 'lt', 'le'):
      if not is_numeric(field_value) or not is_numeric(condition_value):
        return False

      field_num = float(field_value)
      cond_num  = float(condition_value)
      return OPFUNC[op](field_num, cond_num)

    field_value = coerce_number(field_value) if not is_virtual(field) else field_value
    condition_value = coerce_number(condition_value) if not is_virtual(field) else condition_value

    if op not in ('sw', 'ns', 'dw', 'nd', 'ct', 'nc', 'in', 'ni'):
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

  def _cardinality(self, A: str, B: str, sample_size: int=100) -> int:
    ''' Estimate cardinality between index A and B. '''
    if (A, B) in self._card_cache:
      return self._card_cache[(A, B)]

    Ak = sorted(self.store.get_index_keys(A))
    Bk = sorted(self.store.get_index_keys(B))
    ss = min(sample_size, len(Ak), len(Bk))

    Ac = [len(self.store.get_refs(k, B)) for k in Ak[:ss]]
    Bc = [len(self.store.get_refs(k, A)) for k in Bk[:ss]]

    Aac = round(sum(Ac) / len(Ac)) if Ac else 0 # A → B
    Bac = round(sum(Bc) / len(Bc)) if Bc else 0 # B → A

    tolerance = 0.1
    is_one_AtoB = (1 - tolerance) <= Aac <= (1 + tolerance)
    is_one_BtoA = (1 - tolerance) <= Bac <= (1 + tolerance)

    if is_one_AtoB and Bac > (1 + tolerance):
      self._card_cache[(A, B)] = 21
      self._card_cache[(B, A)] = 12
      return 21 # many-to-one
    if Aac > (1 + tolerance) and is_one_BtoA:
      self._card_cache[(A, B)] = 12
      self._card_cache[(B, A)] = 21
      return 12 # one-to-many
    if Aac > (1 + tolerance) and Bac > (1 + tolerance):
      self._card_cache[(A, B)] = 22
      self._card_cache[(B, A)] = 22
      return 22 # many-to-many
    if is_one_AtoB and is_one_BtoA:
      self._card_cache[(A, B)] = 11
      self._card_cache[(B, A)] = 11
      return 11 # one-to-one
    return 0 # ???

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
          relation = self._cardinality(A, B)
          scores.append(relation)

      otm_c = scores.count(12) # one-to-many
      mto_c = scores.count(21) # many-to-one
      mtm_c = scores.count(22) # many-to-many

      candidates.append((otm_c, mto_c, mtm_c, A))

    candidates.sort(reverse=True)
    return candidates[0][3]

  def _query_looks_grouped(self, A: str, agg_exprs: list, parsed_exprs: list) -> bool:
    for expr in parsed_exprs:
      B = expr['index']
      if B != A and B in agg_exprs:
        return self._cardinality(A, B) != 0
    return False

  def _apply_aggregations(self, tree: dict, agg_exprs: list, agg_indexes: list, unique:bool=False) -> dict:
    def walk(node: dict, idx: str) -> dict:
      if idx in agg_indexes:
        results = {}
        for key, child_node in node.items():
          if key == '@[aggregate]':
            collected = defaultdict(list)
            for ref in child_node.keys():
              data = self.cache.read(ref)
              for agg in agg_exprs[idx]:
                op, f = agg['op'], agg['field']
                val = data.get(f.replace('*', '@id'))
                val = coerce_number(val) if not is_virtual(agg['field']) else val
                collected[f'{idx}:{op}:{f}'].append(val)
            results = { '@[aggregate]': self._reduce_aggs(collected) }
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
      match op:
        case 'avg':
          reduced[f'{idx}:{op}:{f}'] = { str(round(sum(clean_values) / len(clean_values), 2)): {} }
        case 'sum':
          reduced[f'{idx}:{op}:{f}'] = { str(sum(clean_values)): {} }
        case 'min':
          reduced[f'{idx}:{op}:{f}'] = { str(min(clean_values)): {} }
        case 'max':
          reduced[f'{idx}:{op}:{f}'] = { str(max(clean_values)): {} }
        case 'count':
          reduced[f'{idx}:{op}{':'+f if f != '*' else ''}'] = { str(len(clean_values)): {} }

    return reduced

  @performance_measurement(message='Fetched')
  def query(self, index_or_key: str, *exprs: str) -> (dict, list[dict]):
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
      return min(exprs, key=lambda e: self.store.index_len(e['index']), default={})

    def filter_keys(expr: dict) -> set:
      index = expr.get('index') or root_index
      valid_keys = set()
      for k in self.store.get_index_keys(index):
        kv = self.store.read_hash(k)
        for op in expr['conditions']:
          if op is None:
            continue
          if op['op'] in BINOP:
            if self._eval_binop_cond(k, kv, op):
              valid_keys.add(k)
            continue
          if self._eval_cond(op['op'], kv.get(op['field']), op['value'], field=op['field']):
            valid_keys.add(k)
      return valid_keys

    def resolve_to_primary(expr: dict) -> set:
      result = set()
      for match_key in cond_matches.get(expr.get('index'), []):
        if self.store.is_index_of(match_key, prm_index):
          result.add(match_key)
        else:
          result.update(self.store.get_refs(match_key, prm_index))
      return result

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
    self.parser = Parser(self.store, root_index)
    parsed_exprs = self._dispatch_parse(root_index, exprs)
    condition_exprs = [e for e in parsed_exprs for c in e['conditions'] if c]
    agg_exprs = { e['index']: e['aggregations'] for e in parsed_exprs if e['aggregations'] }
    agg_indexes = list(agg_exprs.keys()) if agg_exprs else []
    data_tree = {root_index: {}}
    all_keys = None

    # Gather used indexes
    used_indexes = [e['index'] for e in parsed_exprs]

    # Fields
    fields = {}

    # Assuming '@hkey' when no fields are selected for the main index,
    if root_index not in used_indexes:
      fields = {root_index: {'fields': ['@hkey'], 'sort': None }}
      used_indexes.append(root_index)

    for d in parsed_exprs:
      fields[d['index']] = {'fields': d['fields'], 'sort': d['sort']}

    # Determining query's primary index
    if exprs and agg_exprs:
      if root_index in agg_exprs or self._query_looks_grouped(root_index, agg_exprs, parsed_exprs):
        prm_index = root_index
      else:
        prm_index = self._find_prm_index2(used_indexes)
    elif exprs:
      prm_index = self._find_prm_index(used_indexes)
    else:
      prm_index = root_index

    # Precompute matched keys
    cond_matches = {
        expr['index']: filter_keys(expr)
        for expr in condition_exprs
    }

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
      raise QDBQueryNoData(f'No data.')

    root_keys = (
        {index_or_key} if self.store.has_index(index_or_key)
        else self.store.get_index_keys(root_index)
    )

    if root_index != prm_index and agg_exprs:
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
        for ref in refs:
          if not self.cache.exists(ref):
            self.cache.write(ref, self.store.read_hash(ref))
        derived_keys.update(refs)

      # Restrict all_keys
      all_keys &= derived_keys

    # Apply random/limit modifiers
    if not agg_exprs or root_index == prm_index:
      if random:
        all_keys = list(all_keys)
        shuffle(all_keys)

      # Apply limit
      if limit:
        all_keys = all_keys[:limit] if random else sorted(all_keys)[:limit]

    # Unique index query, no expressions: build tree an return it
    if not parsed_exprs and len(used_indexes) == 1:
      for key in sorted(all_keys) if not random else all_keys:
        if not self.cache.exists(key):
          self.cache.write(key, self.store.read_hash(key))
        data_tree[root_index][key] = {}
      return data_tree, {}, False

    # Unique index query + aggregations
    if agg_exprs and len(used_indexes) == 1:
      refs_map = {}
      for key in all_keys:
        refs_map[key] = {}
        if not self.cache.exists(key):
          self.cache.write(key, self.store.read_hash(key))
      node = data_tree[root_index] = {}
      build_ref_tree(node, refs_map, unique=True)
      data_tree = self._apply_aggregations(data_tree, agg_exprs, agg_indexes, unique=True)
      return data_tree, fields, False

    # Build references map
    refs_map = defaultdict(lambda: defaultdict(set))

    # Populate based on condition matches
    if cond_matches and not agg_exprs:
      for idx, candidates in cond_matches.items():
        refs = candidates & set(all_keys)
        for ref in refs:
          for key in self.store.get_transitive_backrefs(ref, root_index):
            if not self.cache.exists(key):
              self.cache.write(ref, self.store.read_hash(ref))
            refs_map[key][idx].add(ref)

    cond_indexes = set(cond_matches.keys())

    if agg_exprs:
      empty_keys = set()
      for key in all_keys.copy():
        if not self.cache.exists(key):
          self.cache.write(key, self.store.read_hash(key))
        refs_map.setdefault(key, defaultdict(dict))
        for agg_index in agg_indexes:
          base_dataset = set(self.store.get_refs(key, agg_index))
          base_dataset &= {
              r for r in base_dataset
              if any(set(self.store.get_refs(r, root_index)) & set(root_keys))
          }
          if not base_dataset:
            if len(all_keys) == 1:
              if len(root_keys) == 1:
                raise QDBQueryNoData(f'No data: `{self.store.get_index(key)} → {agg_index}`.')
              else:
                aggs = ', '.join([o+':'+f for o, f in [tuple(a.values()) for a in agg_exprs[agg_index]]])
                aggl = len(agg_exprs[agg_index])
                candidates = [i for i in used_indexes if i not in (root_index, agg_exprs)]
                msg = (
                    f'Error: aggregate function{"s" if aggl > 1 else ""}: `{agg_index}:@[{aggs}]` '
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

          other_indexes = [i for i in used_indexes if i not in (prm_index, agg_index)]
          if not other_indexes:
            # Simple case: only aggregate index
            for ref in base_dataset:
              refs_map.setdefault(key, defaultdict(dict))
              refs_map[key][agg_index].setdefault(ref, {})
              if not self.cache.exists(ref):
                self.cache.write(ref, self.store.read_hash(ref))
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
                for r in dataset:
                  if not self.cache.exists(r):
                    self.cache.write(r, self.store.read_hash(r))
      all_keys = list(set(all_keys).difference(empty_keys))

    elif set(used_indexes) - cond_indexes - {root_index} or not refs_map:
      flat_refs = self.store.build_hkeys_flat_refs(all_keys)
      for key in all_keys:
        for idx in used_indexes:
          if idx == prm_index:
            continue
          refs = flat_refs[key][idx] or self.store.get_refs(key, idx)
          if idx in cond_indexes:
            refs = sorted(cond_matches[idx] & set(refs))
          if refs:
            refs_map[key][idx].update(refs)
          for ref in refs:
            if not self.cache.exists(ref):
              self.cache.write(ref, self.store.read_hash(ref))

    if not refs_map and not agg_exprs:
      for k in all_keys:
        if not self.cache.exists(k):
          self.cache.write(k, self.store.read_hash(k))
        refs_map.setdefault(k, defaultdict(set))
        refs_map[k][root_index].add(k)

    if not refs_map:
      raise QDBQueryNoData('No data.')

    flat = (
        not condition_exprs and
        not agg_exprs and
        len(used_indexes) == 1
    )

    # Build tree
    data_tree = { prm_index: {} }
    for key in sorted(all_keys):
      node = data_tree[prm_index][key] = {}
      build_ref_tree(node, refs_map[key], flat)

    if agg_exprs:
      data_tree = self._apply_aggregations(data_tree, agg_exprs, agg_indexes)

    return data_tree, fields, flat
