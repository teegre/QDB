import json
import os
import sys
import traceback

from random import shuffle
from time import time
from typing import Any

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.datacache import Cache
from src.exception import MDBError, MDBMissingFieldError
from src.ops import OPFUNC, VIRTUAL
from src.query import Query
from src.storage import Store
from src.utils import performance_measurement, is_numeric

class MicroDB:
  def __init__(self, name: str):
    self.store = Store(name)
    self.cache = Cache()
    self.Q = Query(self.store, self.cache)

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
        'IDXF':    self.idxf,
        'KEY':     self.keys,
        'MDEL':    self.mdel,
        'MGET':    self.mget,
        'MSET':    self.mset,
        'SCHEMA':  self.schema,
        'SET' :    self.set,
    }

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

  @performance_measurement(message='Written')
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
          self.cache.write(k, v)
          subkv.pop(field, None)

      for k, v in subkv.items():
        kv[k] = v
        self.cache.write(k, v)
        # Reference?
        if self.store.exists(v):
          refs.append(v)

      # Serialize and write on disk
      data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
      if self.store.write(data, key, vsz, ts, refs) != 0:
        print(f'HSET: Error: failed to update `{key}` hkey.', file=sys.stderr)
        err += 1

    return err

  def _is_virtual_field(self, field: str) -> bool:
    return field in VIRTUAL

  @performance_measurement(message='Processed')
  def hget(self, index_or_key: str, *exprs: str) -> int:
    if not index_or_key:
      print(f'HGET: missing index or hkey.', file=sys.stderr)
      return 1

    try:
      tree, fields_data = self.Q.query(index_or_key, *exprs)
    except MDBError as e:
      print(f'HGET: {e}', file=sys.stderr)
      raise

    main_index = list(tree.keys())[0]
    index_fields: list = self.store.get_fields_from_index(main_index)

    rows: list = []

    # No field case
    if not fields_data:
      for key in tree[main_index].keys():
        row = [key]
        data = self.cache.read(key, self.store.read_hash)
        for field in index_fields:
          if self._is_virtual_field(field):
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

      print(f'HGET: An unexpected error occured.', file=sys.stderr)
      return 1

    pos = 0
    field_positions = {}
    for idx, fields in fields_data.items():
      if fields['fields'] == ['*']:
        all_fields = self.store.get_fields_from_index(idx)
        star = True
      else:
        all_fields = fields['fields']
        star = False
      for f in all_fields:
        if star and self._is_virtual_field(f):
          continue
        field_positions[f'{idx}:{f}'] = pos
        pos += 1

    def walk(index: str, key: str, node: dict, values: dict, row_meta: dict):
      data = self.cache.read(key, self.store.read_hash)

      is_aggregation = False

      fields = fields_data[index]['fields']
      sort_data = fields_data[index]['sort']

      if key == '@[aggregated]':
        data = {af: f'{af}={list(v.keys())[0]}' for af, v in node.items()}
        is_aggregation = True

      if fields == ['*']:
        for f, v in data.items():
          if self._is_virtual_field(f):
            continue
          values[(index, f)] = v
      else:
        for field in fields:
          try:
            value = data[field]
          except KeyError:
            raise MDBError(f'HGET: an unexpected error involving `{field}` occured.')
          values[(index, field)] = value
        if row_meta.get('sort_value') is None:
          if sort_data:
            for rule in sort_data:
              for field in fields:
                if rule['field'] == field:
                  row_meta['sort_value'] = value
                  break
      for child_idx, children in node.items():
        if is_aggregation:
          break
        for child_key, child_node in children.items():
          walk(child_idx, child_key, child_node, values, row_meta)

    def _descending_value(val):
      if is_numeric(val):
        val = float(val)
      if isinstance(val, float):
        return -val
      return ''.join(chr(255 - ord(c)) for c in val)

    def sort_key(row: list, fields_info: dict) -> tuple:
      key = []
      for index, info in fields_info.items():
        sort_list = info.get('sort')
        if not sort_list:
          continue
        for sort_entry in sort_list:
          field = sort_entry['field']
          order = sort_entry['order']
          full_field = f'{index}:{field}'
          pos = field_positions.get(full_field)
          if pos is None:
            value = row.get('sort_value')
          else:
            value = row['row'][pos]
            if '=' in value:
              value = value.split('=', 1)[1]
          if is_numeric(value):
            value = float(value)
          elif value is None:
            value = ''

          key.append(_descending_value(value) if order == 'desc' else value)
      return tuple(key)

    # Tree
    elements = tree.get(main_index, {})

    # Build rows
    rows = []
    for key, children in elements.items():
      values = {}
      row_meta = { 'sort_value': None }
      try:
        walk(main_index, key, children, values, row_meta)
      except MDBError as e:
        print(e, file=sys.stderr)
        return 1

      row = []
      for index, spec in fields_data.items():
        for field in spec['fields']:
          if field == '*':
            star_fields = [k[1] for k in values.keys() if k[0] == index]
            for star_field in star_fields:
              row.append(f'{star_field}={values[(index, star_field)]}')
          else:
            row.append(values[(index, field)])
      rows.append({'row': row, 'sort_value': row_meta['sort_value']})

    if not rows:
      print(f'HGET: an unexpected error occured.', file=sys.stderr)
      return 1

    # Sorting and output
    rows.sort(key=lambda row: sort_key(row, fields_data))

    for row in rows:
      print(' | '.join(row['row']))

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
        print(f'{k}: {" | ".join([f for f in kv.keys() if not self._is_virtual_field(f)])}')
      return 0
    err = 0
    for k in sorted(self.store.keystore.keys()):
      if not self.store.has_index(k):
        continue
        err += self.hkey(k)
      kv = self.store.read_hash(k)
      print(f'{k}: {" | ".join([f for f in kv.keys() if not self._is_virtual_field(f)])}')
    return 0 if err == 0 else 1

  def idx(self) -> None:
    for i, index in enumerate(sorted(self.store.indexes), 1):
      print(f'{i}. {index}')

  def idxf(self, index: str) -> None:
    if self.store.is_index(index):
      fields = self.store.get_fields_from_index(index)
      print(f'{index}: {' | '.join([f for f in fields if not self._is_virtual_field(f)])}')
      return 0
    print(f'Error: `{index}`, no such index.', file=sys.stderr)

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
