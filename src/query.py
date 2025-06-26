import math
import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from collections import defaultdict
from random import shuffle

from src.datacache import Cache
from src.exception import MDBParseError, MDBQueryError, MDBQueryNoData
from src.ops import OPFUNC, BINOP
from src.parser import Parser
from src.storage import Store
from src.utils import is_numeric, performance_measurement

from src.utils import performance_measurement

class Query:
  def __init__(self, store: Store, cache: Cache):
    self.store = store
    self.cache = cache
    self.parser = Parser(self.store)

  def _dispatch_parse(self, main_index: str, exprs: list) -> list:
    parsed_exprs = []
    current_index = main_index

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
          self._eval_cond(cond['op'], record.get(cond['field']), cond['value'])
          for cond in conditions
      )

    return any(
        self._eval_cond(cond['op'], record.get(cond['field']), cond['value'])
        for cond in conditions
    )

  def _eval_cond(self, op: str, field_value: str, condition_value: str) -> bool:
    if op in ('gt', 'ge', 'lt', 'le'):
      if not is_numeric(field_value) or not is_numeric(condition_value):
        return False

      field_num = float(field_value)
      cond_num  = float(condition_value)
      return OPFUNC[op](field_num, cond_num)

    if op not in ('sw', 'ns', 'dw', 'nd', 'ct', 'nc'):
      if is_numeric(field_value) and is_numeric(condition_value):
        field_value = float(field_value)
        condition_value = float(condition_value)
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
    return False

  def _cardinality(self, A: str, B: str, sample_size: int=100) -> int:
    ''' Estimate _cardinality between index A and B. '''
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
      return 21 # many-to-one
    if Aac > (1 + tolerance) and is_one_BtoA:
      return 12 # one-to-many
    if Aac > (1 + tolerance) and Bac > (1 + tolerance):
      return 22 # many-to-many
    if is_one_AtoB and is_one_BtoA:
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
                if is_numeric(val):
                  val = float(val) if not val.isdigit() else int(val)
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
        raise MDBQueryError(f'invalid limit: `{limit if limit else ' '}`.')

    # Check index_or_key validity
    main_index = index_or_key if self.store.is_index(index_or_key) else self.store.get_index(index_or_key)
    if not main_index:
      raise MDBQueryError(f'Error: `{index_or_key}`, no such index or hkey.')
    
    def select_best_filter(exprs: list) -> dict:
      return min(exprs, key=lambda e: self.store.index_len(e['index']), default={})

    def filter_keys(expr: dict) -> set:
      index = expr.get('index') or main_index
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
          if self._eval_cond(op['op'], kv.get(op['field']), op['value']):
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

    def build_ref_tree(node: dict, rmap: dict|set):
      ''' Build a hierarchical references tree from a references map. '''
      if isinstance(rmap, set):
        for ref in rmap:
          node.setdefault(ref, {})
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
    self.parser = Parser(self.store, main_index)
    parsed_exprs = self._dispatch_parse(main_index, exprs)
    condition_exprs = [e for e in parsed_exprs for c in e['conditions'] if c]
    agg_exprs = { e['index']: e['aggregations'] for e in parsed_exprs if e['aggregations'] }
    agg_indexes = list(agg_exprs.keys()) if agg_exprs else []
    all_keys = None

    # Fields
    selected_indexes = {e['index'] for e in parsed_exprs}
    fields = {}

    # Assuming '@hkey' when no fields are selected for the main index,
    if main_index not in selected_indexes and parsed_exprs:
      fields = {main_index: {'fields': ['@hkey'], 'sort': None }}

    for d in parsed_exprs:
      fields[d['index']] = {'fields': d['fields'], 'sort': d['sort']}

    # Gather used indexes
    used_indexes = [e['index'] for e in parsed_exprs]
    if main_index not in used_indexes:
      used_indexes.insert(0, main_index)

    # Determining query's primary index
    if exprs and agg_exprs:
      prm_index = self._find_prm_index2(used_indexes)
    elif exprs:
      prm_index = self._find_prm_index(used_indexes)
    else:
      prm_index = main_index

    # Precompute matched keys
    cond_matches = {
        expr['index']: filter_keys(expr)
        for expr in condition_exprs
    }

    if condition_exprs:
      best_expr = select_best_filter(condition_exprs)

      # Primary condition
      all_keys = resolve_to_primary(best_expr)

      # Secondary conditions
      for expr in condition_exprs:
        if expr is best_expr:
          continue
        keys = resolve_to_primary(expr)
        all_keys &= keys

    else:
      # Query is based on a particular hkey...
      if self.store.has_index(index_or_key):
        all_keys = { index_or_key }
      # ... or an index
      else:
        all_keys = set(self.store.get_index_keys(prm_index))

    # Stop here if nothing was found
    if not all_keys:
      raise MDBQueryNoData(f'No data.')

    # Apply random FIXME: useless here
    if random:
      all_keys = list(all_keys)
      shuffle(all_keys)

    # Apply limit
    if limit and random:
      all_keys = all_keys[:limit]
    elif limit:
      all_keys = sorted(all_keys)[:limit]

    # Unique index quey, build tree an return it
    if not parsed_exprs and not fields:
      data_tree = {main_index: {}}
      for key in sorted(all_keys):
        self.cache.write(key, self.store.read_hash(key))
        data_tree[main_index][key] = {}
      return data_tree, {}

    # Build references map
    refs_map = defaultdict(lambda: defaultdict(set))
    root_index = main_index

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
      for key in sorted(all_keys):
        self.cache.write(key, self.store.read_hash(key))
        refs_map.setdefault(key, defaultdict(dict))
        for agg_index in agg_indexes:
          base_dataset = set(self.store.get_refs(key, agg_index))

          # Get out if no data and 1 key:
          if not base_dataset:
            if len(all_keys) == 1:
              raise MDBQueryNoData(f'No data: `{self.store.get_index(key)} → {agg_index}`.')
            continue

          other_indexes = [i for i in used_indexes if i not in (agg_index, prm_index)]
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
            refs_for_index = cond_matches.get(index, set(self.store.get_index_keys(index)))
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

    elif set(used_indexes) - cond_indexes - {root_index} or not refs_map:
      flat_refs = self.store.build_hkeys_flat_refs(all_keys)
      for key in all_keys:
        for idx in used_indexes:
          if idx == prm_index:
            continue
          refs = flat_refs[key][idx] or self.store.get_refs(key, idx)
          if idx in cond_indexes:
            refs = sorted(cond_matches[idx] & set(refs))
          refs_map[key][idx].update(refs)
          for ref in refs:
            if not self.cache.exists(ref):
              self.cache.write(ref, self.store.read_hash(ref))

    if not refs_map:
      for k in sorted(all_keys):
        self.cache.write(k, self.store.read_hash(k))
        refs_map.setdefault(k, defaultdict(set))
        refs_map[k][prm_index].add(k)

    if not refs_map:
      raise MDBQueryNoData('No data.')

    # Build tree
    data_tree = { prm_index: {} }
    for key in sorted(all_keys):
      node = data_tree[prm_index][key] = {}
      build_ref_tree(node, refs_map[key])

    if agg_exprs:
      data_tree = self._apply_aggregations(data_tree, agg_exprs, agg_indexes, unique=(len(used_indexes) == 1))

    return data_tree, fields
