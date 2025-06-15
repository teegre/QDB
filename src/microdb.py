import json
import os
import sys

from random import shuffle
from time import time
from typing import Any

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.datacache import Cache
from src.exception import MDBQueryError, MDBParseError
from src.ops import OPFUNC, SPECIAL
from src.query import Query
from src.storage import Store
from src.utils import performance_measurement, is_numeric

class MicroDB:
  def __init__(self, name: str):
    self.store = Store(name)
    self.cache = Cache()
    self.query = Query(self.store, self.cache)

    self.commands = {
        'COMPACT': self.compact,
        'DEL' :    self.delete,
        'GET' :    self.get,
        'HDEL':    self.hdel,
        'HGET':    self.hget,
        'HGETV':   self.hget_field,
        'HKEY':    self.hkey,
        'HLEN':    self.hlen,
        'HSET':    self.hset,
        'IDX' :    self.idx,
        'KEY':     self.keys,
        'MDEL':    self.mdel,
        'MGET':    self.mget,
        'MSET':    self.mset,
        'SCHEMA':  self.schema,
        'SET' :    self.set,
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
    return field in SPECIAL

  def get_sort_key(self, value: Any) -> tuple:
    if '?NOFIELD?' in value:
      return (2, value)
    if self.is_numeric(value):
      return (0, float(value))
    return (1, str(value))

  @performance_measurement
  def hget(self, index_or_key: str, *exprs: str) -> int:
    try:
      tree, fields = self.query.query(index_or_key, *exprs)
    except (MDBParseError, MDBQueryError) as e:
      print(f'HGET: {e}', file=sys.stderr)
      return 1


    prm_index = list(tree.keys())[0]
    index_fields: list = self.store.get_fields_from_index(prm_index)

    rows: list = []

    if not fields:
      for key in tree[prm_index].keys():
        row = [key]
        data = self.store.read_hash(key)
        for field in index_fields:
          if self.is_special_field(field):
            continue
          row.append(f'{field}=' + str(data.get(field, '?NOFIELD?')))
        if any(row[1:]):
          rows.append(row)
      if rows:
        for row in rows:
          print(' | '.join(row))
        rows_found = len(rows)
        print(f'{rows_found}', 'rows' if rows_found > 1 else 'row', 'found.', file=sys.stderr)
        return 0

      print(f'HGET: No data for `{index_or_key}`.', file=sys.stderr)
      return 1


    # keys_to_process = sorted(fk.get(prm_index))

    # for start_key in keys_to_process:
    #   if limit_reached:
    #     break

    #   key_map = {
    #       idx: sorted(fk.get(idx, set()))
    #       for idx in ui if self.store.is_index(idx)
    #   }

    #   # Check query validity
    #   for idx, keys in key_map.items():
    #     if idx != prm_index and not keys:
    #       print('PRIMARY INDEX', prm_index)
    #       print('START KEY:', start_key)
    #       print('FILTER:', fk)
    #       print('KEY MAP:', key_map)
    #       print('DATA CACHE:', self.cache)
    #       print(f'HGET: Error: trying to query unrelated data: `{idx}`.', file=sys.stderr)
    #       return 1

    #   max_depth = max(
    #       (len(pf['fields']) if pf['index'] else 0 for pf in pe), default=0
    #   )

    #   deepest_index = next(
    #       (pf['index'] for pf in reversed(pe)
    #        if pf['index'] and len(pf['fields']) == max_depth),
    #       None
    #   )

    #   deep_keys = key_map.get(deepest_index, []) if deepest_index else [start_key]

    #   for deep_key in deep_keys:
    #     row = {'row': [], 'sort_value': None}
    #     valid_row = True

    #     for pf in pe:
    #       index, fields, conditions = pf['index'], pf['fields'], pf['conditions']
    #       data_key = start_key if index is None or index == prm_index else (
    #           deep_key if self.store.is_index_of(deep_key, index) else (
    #             key_map.get(index, [None])[0] if key_map.get(index) else None
    #           )
    #       )

    #       if data_key is None:
    #         print('{deep_key} skipped?', file=sys.stderr)
    #         continue

    #       data = self.cache.read(data_key, self.store.read_hash(data_key))

    #       if fields == ['*']:
    #         for field, value in data.items():
    #           if si and si['index'] == index and si['field'] == field:
    #             row['sort_value'] = value
    #           row['row'].append(f'{field}={value}')
    #       else:
    #         for field in fields:
    #           value = data.get(field, '?NOFIELD?')
    #           if index and conditions:
    #             for condition in conditions:
    #               if condition['field'] == field:
    #                 if not self.evaluate_condition(condition['op'], value, condition['value']):
    #                   valid_row = False
    #                   break
    #           if si and si['index'] == index and si['field'] == field:
    #             row['sort_value'] = value
    #           row['row'].append(value)
    #         if not valid_row:
    #           break

    #     if valid_row and row['row']:
    #       rows.append(row)
    #       if limit and len(rows) == limit:
    #         limit_reached = True
    #         break

    # if not valid_row and not rows:
    #   print('HGET: No data.', file=sys.stderr)
    #   return 1

    # if valid_row and not rows:
    #   print('HGET: An unexpected error occurred.', file=sys.stderr)
    #   return 1

    # # Apply sorting
    # if si:
    #   if si['order'] == 'rand':
    #     shuffle(rows)
    #   else:
    #     # TODO: Sort on multiple keys...
    #     reverse = si['order'] == 'desc'
    #     rows.sort(key=lambda x: self.get_sort_key(x['sort_value']), reverse=reverse)

    # for row in rows:
    #   print(' | '.join(v for v in row['row']))
    # rows_found = len(rows)

    # print(f'{rows_found}', 'rows' if rows_found > 1 else 'row', 'found.', file=sys.stderr)
    # return 0

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
      print(f'{k}: {" | ".join([f for f in kv.keys() if not self.is_special_field(f)])}')
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

  def compact(self):
    return self.store.compact()

  def schema(self):
    self.store.database_schema()

  def flush(self):
    return self.store.flush()
