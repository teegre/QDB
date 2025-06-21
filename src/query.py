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
      cond_num = float(condition_value)
      return OPFUNC[op](field_num, cond_num)

    if op not in ('sw', 'ns', 'dw', 'nd', 'ct', 'nc'):
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

  def _apply_aggregations(self, tree: dict, agg_exprs: list, agg_indexes: list) -> dict:
    leaf_index = [list(a.keys())[0] for a in agg_exprs][0]

    def walk(node: dict, idx: str) -> dict:
      results = defaultdict(list)
      is_leaf_level = idx == leaf_index
      if is_leaf_level:
        collected = defaultdict(list)

        for key, data_node in node.items():
          data = self.cache.read(key)
          for entries in agg_exprs:
            if idx in entries:
              for entry in entries[idx]:
                op, f = entry['op'], entry['field']
                val = data.get(f)
                if is_numeric(val):
                  val = float(val) if not val.isdigit() else int(val)
                collected[f'{op}:{f}'].append(val)
        results = self._reduce_aggs(collected)
      else:
        for key, child in node.items():
          results.setdefault(key, {})
          for child_idx, sub_node in child.items():
            if child_idx in agg_indexes:
              r = {'aggregated': walk(sub_node, child_idx)}
            else:
              r = walk(sub_node, child_idx)
            results[key][child_idx] = r
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

      op, field = k.split(':', 1)
      match op:
        case 'avg':
          reduced[f'[{op}:{field}]'] = { str(round(sum(clean_values) / len(clean_values), 2)): {} }
        case 'sum':
          reduced[f'[{op}:{field}]'] = { str(sum(clean_values)): {} }
        case 'min':
          reduced[f'[{op}:{field}]'] = { str(min(clean_values)): {} }
        case 'max':
          reduced[f'[{op}:{field}]'] = { str(max(clean_values)): {} }
        case 'count':
          reduced[f'[{op}:{field}]'] = { str(len(clean_values)): {} }

    return reduced

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

    def build_ref_tree(node: dict, key: str, is_next_level_leaf: bool=False):
      for idx, refs in refs_map.get(key, {}).items():
        node[idx] = {}
        for ref in refs:
          edge = (key, idx, ref)
          if edge in visited:
            continue
          visited.add(edge)
          node[idx][ref] = {}
          if not is_next_level_leaf:
            build_ref_tree(node[idx][ref], ref, is_next_level_leaf=(idx == leaf_index))

    # Parse expressions
    self.parser = Parser(self.store, main_index)
    parsed_exprs = self._dispatch_parse(main_index, exprs)
    condition_exprs = [e for e in parsed_exprs for c in e['conditions'] if c]
    agg_exprs = [{e['index']: e['aggregations']} for e in parsed_exprs if e['aggregations']]
    agg_indexes = [list(a.keys())[0] for a in agg_exprs] if agg_exprs else None
    all_keys = None

    # Fields
    selected_indexes = {e['index'] for e in parsed_exprs}
    fields = {}

    # Assuming '*' when no fields are selected for the main index,
    if main_index not in selected_indexes and parsed_exprs:
      fields = {main_index: {'fields': ['*'], 'sort': None }}

    for d in parsed_exprs:
      fields[d['index']] = {'fields': d['fields'], 'sort': d['sort']}

    # Gather used indexes
    used_indexes = [e['index'] for e in parsed_exprs]
    if main_index not in used_indexes:
      used_indexes.insert(0, main_index)

    # Determining query's primary index

    if exprs and not agg_exprs:
      prm_index = self._find_prm_index(used_indexes) or main_index
      leaf_index = None
    else:
      prm_index = main_index
      if agg_exprs:
        leaf_index = [list(a.keys())[0] for a in agg_exprs][0] # nul à chier!

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

    # Applu random
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
      tree = {main_index: {}}
      for key in all_keys:
        tree[main_index][key] = {}
      return tree, {}

    # Build references map
    refs_map = defaultdict(lambda: defaultdict(set))
    root_index = main_index
    if cond_matches:
      for idx, candidates in cond_matches.items():
        refs = candidates & set(all_keys)
        for ref in refs:
          for key in self.store.get_transitive_backrefs(ref, root_index):
            if not self.cache.exists(key):
              self.cache.write(ref, self.store.read_hash(ref))
            refs_map[key][idx].add(ref)

    cond_indexes = set(cond_matches.keys())

    if agg_exprs:
      for key in all_keys:
        for index in used_indexes:
          if index == main_index:
            continue
          refs = self.store.get_refs(key, index)
          for ref in refs:
            if not self.cache.exists(ref):
              self.cache.write(ref, self.store.read_hash(ref))
            refs_map[key][index].add(ref)
    elif set(used_indexes) - cond_indexes - {root_index} or not refs_map:
      flat_refs = self.store.build_hkeys_flat_refs(all_keys)
      for key in sorted(all_keys):
        for idx in used_indexes:
          if idx == prm_index:
            continue
          refs = flat_refs[key][idx]
          if not refs: # try get_refs:
            refs = self.store.get_refs(key, idx)
          for ref in refs:
            if not self.cache.exists(ref):
              self.cache.write(ref, self.store.read_hash(ref))
            refs_map[key][idx].add(ref)

    # Build tree
    tree = { prm_index: {} }
    if not refs_map:
      for k in all_keys:
        refs_map[k][prm_index].add(k)

    if not refs_map:
      raise MDBQueryNoData('No data.')

    visited = set()

    for key in refs_map.keys():
      if not self.cache.exists(key):
        self.cache.write(key, self.store.read_hash(key))
      node = tree[prm_index][key] = {}
      build_ref_tree(node, key)

    if agg_exprs:
      agg_results = self._apply_aggregations(tree, agg_exprs, agg_indexes)
      return agg_results, fields

    return tree, fields
