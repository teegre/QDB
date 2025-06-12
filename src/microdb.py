import json
import operator
import os
import sys

from collections import deque
from random import shuffle
from time import time
from typing import Any

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.datacache import Cache
from src.exception import MDBQueryError, MDBParseError
from src.parser import Parser
from src.storage import Store

def performance_measurement(func, *args):
  def wrap_func(*args, **kwargs):
    t1 = time()
    result = func(*args, **kwargs)
    t2 = time()
    print(f'Executed in {(t2-t1):.4f}s.', file=sys.stderr)
    return result
  return wrap_func

class MicroDB:
  def __init__(self, name: str):
    self.store = Store(name)
    self.cache = Cache()

    self.commands = {
        'DEL' : self.delete,
        'GET' : self.get,
        'HDEL': self.hdel,
        'HGET': self.hget,
        'HGETV': self.hget_field,
        'HKEY': self.hkey,
        'HLEN': self.hlen,
        'HSET': self.hset,
        'IDX' : self.idx,
        'KEY': self.keys,
        'MDEL': self.mdel,
        'MGET': self.mget,
        'MSET': self.mset,
        'SET' : self.set,
    }

    self.__ops = {
        '=': 'eq',  # equal
        '!=': 'ne', # not equal
        '>': 'gt',  # greater than
        '>=': 'ge', # greater or equal
        '<': 'lt',  # less than
        '<=': 'le', # less than or equal
        '^': 'sw',  # starts with
        '!^': 'ns', # not starts with
        '$': 'dw',  # ends with
        '!$': 'nd', # not ends with
        '**': 'ct', # contains
        '!*': 'nc', # not contains
    }

    self.__opfunc = {
        'eq': operator.eq,
        'ne': operator.ne,
        'gt': operator.gt,
        'ge': operator.ge,
        'lt': operator.lt,
        'le': operator.le,
  }

    self.__sort_prefix = {
        '++': 'asc',
        '--': 'desc',
        '??': 'rand',
    }

    self.__special_fields = {
        '@id': None,
        '@hkey': None,
    }

    self.autoid = { '@autoid': self.store.autoid }

  def error(self, cmd: str=None, *args: str) -> int:
    if cmd not in self.commands:
      print('Error: invalid command.', file=sys.stderr)
    else:
      print(f'{cmd}: arguments missing.', file=sys.stderr)
    return 1

  def set(self, key: str, val: str) -> int:
    ''' Set a single value '''
    data, vsz, ts = self.store.serialize(key, val)
    return self.store.write(data, key, vsz, ts)

  def get(self, key: str) -> int:
    ''' Get a value '''
    val = self.store.read(key)
    if val is not None:
      print(f'{val}')
      return 0
    return 1

  def keys(self) -> int:
    ''' Print existing keys '''
    found = 0
    for k in self.store.keystore.keys():
      if not self.store.has_index(k):
        found += 1
        print(k)
    if found == 0:
      print(f'KEYS: No key found.', file=sys.stderr)
      return 1
    return 0

  def delete(self, key: str) -> int:
    ''' delete a single key '''
    return self.store.delete(key)
    
  def mset(self, *items: str) -> int:
    '''
    set multiple values
    items are key/value pairs
    '''
    if len(items) % 2 != 0:
      print('MSET: invalid number of arguments.', file=sys.stderr)
      return 1
    err = 0
    for key, val in zip(items[::2], items[1::2]):
      err += self.set(key, val)
    return err

  def mget(self, *keys: str) -> int:
    ''' get multiple values '''
    err = 0
    for key in keys:
      err += self.get(key)
    return err

  def mdel(self, *keys: str) -> int:
    ''' delete multiple keys '''
    err = 0
    for key in keys:
      err += self.delete(key)
      if err:
        print(f'MDEL: key `{key}` not found.', file=sys.stderr)
    return err

  def hset(self, hkey_or_index: str, *members: str) -> int:
    ''' 
    Create/update multiple members to a hash
    (a member is a field/value pair)
    '''
    if len(members) % 2 != 0:
      print(f'HSET: members mismatch. (missing field or value)', file=sys.stderr)
      return 1

    if self.store.is_index(hkey_or_index):
      keys = sorted(self.store.get_index_keys(hkey_or_index))
    else:
      keys = [hkey_or_index]

    if not keys:
      print(f'HSET: `{hkey_or_index}` no such key or index.', file=sys.stderr)
      return 1

    err = 0

    for key in keys:
      # Original hash
      kv = self.store.read_hash(key)
      subkv = {k: v for k, v in zip(members[::2], members[1::2])}
      if kv is None: # New hash
        kv = subkv.copy()
      refs: list(str) = []

      # Get fields for index or new fields
      if self.store.has_index(key):
        fields = self.store.get_fields_from_index(key.split(':')[0])
      else:
        fields = list(subkv.keys())

      # Update fields
      for field in fields:
        v = subkv.get(field)
        if field in subkv:
          if self.store.has_index(v): # ref
            # delete former key in reference.
            self.store.delete_ref_of_key(key, kv.get(field))
            refs.append(v)
          kv[field] = v
          subkv.pop(field, None)

      for k, v in subkv.items():
        kv[k] = v
        # Reference?
        if self.store.exists(v):
          refs.append(v)

      # Serialize and write on disk
      data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
      if self.store.write(data, key, vsz, ts, refs) != 0:
        print(f'HSET: Error: failed to update `{key}` hkey.', file=sys.stderr)
        err += 1

    return err

  def is_special_field(self, field: str) -> bool:
    return field in self.__special_fields

  def is_numeric(self, value: str) -> bool:
    try:
      float(value)
      return True
    except (ValueError, TypeError):
      return False

  def get_sort_key(self, value: Any) -> tuple:
    if '?NOFIELD?' in value:
      return (2, value)
    if self.is_numeric(value):
      return (0, float(value))
    return (1, str(value))

  def evaluate_condition(self, op: str, field_value: str, condition_value: str) -> bool:
    if '?NOFIELD?' in field_value:
      return False
    if op in ('gt', 'ge', 'lt', 'le'):
      if not self.is_numeric(field_value) or not self.is_numeric(condition_value):
        return False
      field_num = float(field_value)
      cond_num = float(condition_value)
      return self.__opfunc[op](field_num, cond_num)
    if op not in ('sw', 'ns', 'dw', 'nd', 'ct', 'nc'):
      return self.__opfunc[op](field_value, condition_value)
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

  def key_map_tree(self, primary_index: str, keys: dict[str: list[str]]) -> dict:
    ''' Return a tree of indexes/hkeys '''

    def process_sub_elems(refs: set, cur_idx, cur_map, last=False) -> tuple[dict, dict]:
      for ref in refs:
        keys = self.store.get_refs(ref, cur_idx)
        if last:
          cur_map[ref][cur_idx] = keys
        else:
          cur_map[ref][cur_idx] = {}
          for key in keys:
            cur_map[ref][cur_idx][key] = {}
      if last:
        return cur_map
      return cur_map, keys

    root = primary_index
    key_map = { root: {} }
    hutch = keys.get(root, [])
    processed = set()

    for start_key in hutch: # start_key & hutch
      key_map[root][start_key] = {}
      queue = deque([(start_key, root, key_map[root][start_key])])
      used_indexes = [x for x in keys if x != root]
      while queue:
        cur_key, cur_idx, cur_map = queue.popleft()
        if not used_indexes:
          break
        if (cur_key, cur_idx) in processed:
          continue
        processed.add((cur_key, cur_idx))
        next_idx = used_indexes.pop(0)
        refs = self.store.get_refs(cur_key, next_idx)
        if refs:
          cur_map[next_idx] = {}
          for ref in refs:
            cur_map[next_idx][ref] = {}

          cur_map[next_idx], hkeys = process_sub_elems(
              refs,
              used_indexes.pop(0) if used_indexes else next_id,
              cur_map[next_idx],
              last=len(used_indexes) == 0
          )

          if len(used_indexes) > 0:          
            queue.append((refs, used_indexes.pop(0), cur_map[next_idx]))
    return key_map

  def query(self, index_or_key: str, *exprs: str) -> tuple[list[dict], dict, list, dict] | None:
    prm_index = index_or_key if self.store.is_index(index_or_key) else self.store.get_index(index_or_key)
    if not prm_index:
      raise MDBQueryError(f'Error: `{index_or_key}`, no such key or index.')

    start_keys = self.store.get_index_keys(prm_index) if self.store.is_index(index_or_key) else [index_or_key]
  
    parser = Parser(store=self.store, primary_index=prm_index)
    parsed_exprs = []
    used_indexes = []
    filt_indexes = set()

    index_fields = self.store.get_fields_from_index(prm_index)

    sort_info = {}

    for expr in exprs:
      try:
        parsed = parser.parse(expr=expr)
      except MDBParseError as e:
        print(e, file=sys.stderr)
        return None, None, None, None

      # Sorting prefixes
      if parsed['sort']:
          p = parsed['sort']
          sort_info['index'] = parsed['index']
          sort_info.update(p[0]) # TODO: handle multiple fields sorting

      parsed_exprs.append(parsed)

    used_indexes = [prm_index] + [kv['index'] for kv in parsed_exprs if kv['index']]

    # Validate fields
    for pf in parsed_exprs:
      index, fields = pf['index'], pf['fields']
      if index is None:
        for field in fields:
          if field not in index_fields:
            raise MDBQueryError(f'Error: `{field}`, no such field in `{index_or_key}`.')
      elif index != prm_index and fields != ['*']:
        ref_fields = self.store.get_fields_from_index(index)
        for field in fields:
          if field not in ref_fields:
            raise MDBQueryError(f'Error: `{field}`, no such field in `{index}`.')

    prm_filt_keys = None
    sec_filt_keys = {}
    filtered = False

    # Pre-filter
    for pf in parsed_exprs:
      index, conditions = pf['index'], pf['conditions']
      if conditions:
        filtered = True
        target_index = index if index else prm_index
        filt_indexes.add(target_index)
        keys = self.store.get_index_keys(target_index)
        matching_keys = []
        discarded_keys = []
        for key in keys:
          data = self.store.read_hash(key)
          for condition in conditions:
            op, field, value = condition['op'], condition['field'], condition['value']
            if self.evaluate_condition(op, data.get(field), value):
              if key not in discarded_keys:
                matching_keys.append(key)
                self.cache.write(key, data)
            else:
              discarded_keys.append(key)
              if key in matching_keys:
                matching_keys.remove(key)
                self.cache.delete(key)
        if not self.store.refs:
          continue
        if target_index == prm_index:
          if prm_filt_keys is None:
            prm_filt_keys = set(matching_keys)
          else:
            prm_filt_keys &= set(matching_keys)
        else:
          sec_filt_keys[target_index] = set(matching_keys)

    if not prm_filt_keys and not sec_filt_keys and filtered:
      start_keys = []

    elif not prm_filt_keys and filtered:
      prm_filt_keys = set(start_keys)
    
    # Filter secondary keys for primary index keys
    if prm_filt_keys and sec_filt_keys:
      for sec_idx, sec_keys in sec_filt_keys.copy().items():
        filt_keys = set()
        sec_is_bigger = len(sec_keys) > len(prm_filt_keys)
        for p_key in prm_filt_keys.copy():
          if sec_keys & set(refs := self.store.get_refs(p_key, sec_idx)):
            if sec_is_bigger:
              filt_keys.update(sec_filt_keys[sec_idx] & set(refs))
            else:
              filt_keys.add(p_key)
        if not sec_is_bigger:
          prm_filt_keys &= filt_keys
          break
        else:
          sec_filt_keys[sec_idx] = filt_keys

    elif prm_filt_keys and not sec_filt_keys: # No secondary keys
      for pf in parsed_exprs:
        for p_key in prm_filt_keys:
          idx = pf['index'] if pf['index'] else prm_index
          sec_filt_keys[idx] = self.store.get_refs(p_key, idx)
          for k in sec_filt_keys[idx]:
            self.cache.write(k, self.store.read_hash(k))

    # Update start keys
    if filtered:
      prm_keys = set(self.store.get_index_keys(prm_index))
      if prm_filt_keys is not None and prm_filt_keys & prm_keys:
        start_keys = [k for k in prm_filt_keys]
      else:
        start_keys = []
        for sec_keys in sec_filt_keys.values():
          for sec_key in sec_keys:
            refs = self.store.get_refs(sec_key, prm_index)
            start_keys.extend(refs)

    if filtered and not start_keys:
      return None, None, None, None

    filt_keys = {prm_index: prm_filt_keys if prm_filt_keys else start_keys}
    filt_keys.update({idx: set() for idx in used_indexes if idx != prm_index})
    if sec_filt_keys:
      filt_keys.update({idx: set(keys) for idx, keys in sec_filt_keys.items()})

    left_indexes = set(used_indexes) - filt_indexes & set(k for k,v in filt_keys.items() if not v)
    if left_indexes:
      for idx in left_indexes:
        for key in filt_keys.copy()[prm_index]:
          filt_keys[idx].update(self.store.get_refs(key, idx))
          for k in filt_keys[idx]:
            self.cache.write(k, self.store.read_hash(k))

    return parsed_exprs, sort_info, used_indexes, filt_keys


  @performance_measurement
  def hget(self, index_or_key: str, *fields: str) -> int:
    '''
    Query
    '''

    # Special syntax for limiting row count:
    # HGET index:id!10
    try:
      index_or_key, limit = index_or_key.split('!')
    except ValueError:
      limit = None

    if limit is not None:
      try:
        limit = int(limit)
        assert limit > 0
      except (ValueError, AssertionError):
        print(f'HGET: Error: invalid limit: `{limit}`.', file=sys.stderr)
        return 1

    if not (self.store.is_index(index_or_key) or self.store.has_index(index_or_key)):
      print(f'HGET: Error: `{index_or_key}`, no such index or hkey.', file=sys.stderr)
      return 1

    if self.store.is_index(index_or_key):
      start_keys: list = self.store.get_index_keys(index_or_key)
      prm_index = index_or_key
    elif self.store.exists(index_or_key):
      start_keys: list = [index_or_key]
      prm_index: str = self.store.get_index(index_or_key)

    index_fields: list = self.store.get_fields_from_index(index_or_key)

    rows: list = []

    if not fields:
      for key in start_keys:
        row = [key]
        data = self.store.read_hash(key)
        for field in index_fields:
          if self.is_special_field(field):
            continue
          row.append(f'{field}=' + str(data.get(field, '?NOFIELD?')))
        if any(row[1:]):
          rows.append(row)
        if limit and len(rows) == limit:
          break
      if rows:
        for row in rows:
          print(' | '.join(row))
        rows_found = len(rows)
        print(f'{rows_found}', 'rows' if rows_found > 1 else 'row', 'found.', file=sys.stderr)
        return 0

      print(f'HGET: No data for `{index_or_key}`.', file=sys.stderr)
      return 1


    try:
      pe, si, ui, fk = self.query(index_or_key, *fields)
    except (MDBParseError, MDBQueryError):
      return 1

    limit_reached = False
    if si and si['order'] == 'rand':
      keys_to_process = fk.get(prm_index)
      shuffle(keys_to_process)
    else:
      keys_to_process = sorted(fk.get(prm_index))

    for start_key in keys_to_process:
      if limit_reached:
        break

      key_map = {
          idx: sorted(fk.get(idx, set()))
          for idx in ui if self.store.is_index(idx)
      }

      print(key_map)

      # Check query validity
      for idx, keys in key_map.items():
        if idx != prm_index and not keys:
          print('PRIMARY INDEX', prm_index)
          print('START KEY:', start_key)
          print('FILTER:', fk)
          print('KEY MAP:', key_map)
          print('DATA CACHE:', self.cache)
          print(f'HGET: Error: trying to query unrelated data: `{idx}`.', file=sys.stderr)
          return 1

      max_depth = max(
          (len(pf['fields']) if pf['index'] else 0 for pf in pe), default=0
      )

      deepest_index = next(
          (pf['index'] for pf in reversed(pe)
           if pf['index'] and len(pf['fields']) == max_depth),
          None
      )

      deep_keys = key_map.get(deepest_index, []) if deepest_index else [start_key]

      for deep_key in deep_keys:
        row = {'row': [], 'sort_value': None}
        valid_row = True

        for pf in pe:
          index, fields, conditions = pf['index'], pf['fields'], pf['conditions']
          data_key = start_key if index is None or index == prm_index else (
              deep_key if self.store.is_index_of(deep_key, index) else (
                key_map.get(index, [None])[0] if key_map.get(index) else None
              )
          )

          if data_key is None:
            print('{deep_key} skipped?', file=sys.stderr)
            continue

          data = self.cache.read(data_key)
          if fields == ['*']:
            for field, value in data.items():
              if si and si['index'] == index and si['field'] == field:
                row['sort_value'] = value
              row['row'].append(f'{field}={value}')
          else:
            for field in fields:
              value = data.get(field, '?NOFIELD?')
              if index and conditions:
                for condition in conditions:
                  if condition['field'] == field:
                    if not self.evaluate_condition(condition['op'], value, condition['value']):
                      valid_row = False
                      break
              if si and si['index'] == index and si['field'] == field:
                row['sort_value'] = value
              row['row'].append(value)
            if not valid_row:
              break

        if valid_row and row['row']:
          rows.append(row)
          if limit and len(rows) == limit:
            limit_reached = True
            break

    if not valid_row and not rows:
      print('HGET: No data.', file=sys.stderr)
      return 1

    if valid_row and not rows:
      print('HGET: An unexpected error occurred.', file=sys.stderr)
      return 1

    # Apply sorting
    if si:
      if si['order'] == 'rand':
        shuffle(rows)
      else:
        # TODO: Sort on multiple keys...
        reverse = si['order'] == 'desc'
        rows.sort(key=lambda x: self.get_sort_key(x['sort_value']), reverse=reverse)

    for row in rows:
      print(' | '.join(v for v in row['row']))
    rows_found = len(rows)

    print(f'{rows_found}', 'rows' if rows_found > 1 else 'row', 'found.', file=sys.stderr)
    return 0

  def hdel(self, index_or_key: str, *fields: str) -> int:
    ''' Delete a hash or an index or fields in a hash or in an index '''
    is_index = self.store.is_index(index_or_key)
    if is_index:
      keys = self.store.get_index_keys(index_or_key)
    else:
      keys = [index_or_key]

    err = 0

    for key in keys:
      # Delete the whole key
      if not fields:
         err += self.store.delete(key)
         if err > 0:
           return 1
         continue
      # Delete fields
      kv = self.store.read_hash(key)
      for field in fields:
        try:
          v = kv.pop(field)
          if self.store.is_refd_by(key, v):
            print(f'HDEL: deleting {v} referenced by {key}...')
            self.store.delete_ref_of_key(ref=v, hkey=key)
        except KeyError:
          print(f'HDEL: Warning: `{field}`, no such field in `{key}`.', file=sys.stderr)
          continue
      if fields:
        data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
        err += self.store.write(data, key, vsz, ts)
    return 1 if err > 0 else 0

  def hget_field(self, hkey: str, field: str) -> int:
    ''' Return the value of a field in a hash. '''
    if self.store.exists(hkey):
      value = self.store.read_hash_field(hkey, field)
      if value == '?NOFIELD?':
        print(f'HGETV: Error: `{field}`, no such field in `{hkey}`.', file=sys.stderr)
        return 1
      if value:
        print(value)
        return 0
      print(f'HGETV: {hkey}: no data.', file=sys.stderr)
      return 0
    print(f'HGETV: Error: `{hkey}`, no such hkey.', file=sys.stderr)
    return 1

  def hkey(self, key: str=None) -> int:
    ''' 
    Get all fields for the given key/index
    or for all indexes if none is provided.
    '''
    if key:
      if self.store.is_index(key):
        keys = sorted([k for k in self.store.keystore if k.startswith(key + ':')])
      else:
        keys = [key]
      if not keys:
        if key in self.store.keystore:
          print(f'HKEYS: Error: `{key}` is not a hash.', file=sys.stderr)
        else:
          print(f'HKEYS: Error: `{key}` key not found.', file=sys.stderr)
        return 1
      for k in keys:
        kv = self.store.read_hash(k)
        if not kv:
          print(f'HKEY: `{k}` no such key or index.', file=sys.stderr)
          return 1
        print(f'{k}: {" | ".join([f for f in kv.keys() if not self.is_special_field(f)])}')
      return 0
    err = 0
    for k in sorted(self.store.keystore.keys()):
      if not self.store.has_index(k):
        continue
        err += self.hkey(k)
      kv = self.store.read_hash(k)
      print(f'{k}: {" | ".join([f for f in kv.keys() if not self.is_special_field(field)])}')
    return 0 if err == 0 else 1

  def idx(self) -> None:
    for i, index in enumerate(sorted(self.store.indexes), 1):
      print(f'{i}. {index}')

  def hlen(self, index: str=None) -> int:
    '''
    Print hkeys count for the given index.
    Return 0 on success, 1 if index does not exist.
    '''
    if not index:
      for idx in sorted(self.store.indexes):
        print(f'{idx}: {self.store.index_len(idx)}')
      return 0
    if not self.store.is_index(index):
      print(f'HLEN: Error: `{index}` no such index.', file=sys.stderr)
      return 1
    print(f'{index}: {self.store.index_len(index)}')
    return 0

  def flush(self):
    return self.store.flush()
