import json

from random import shuffle
from typing import Any
from sys import stderr

from storage import Store

class MicroDB:
  def __init__(self, name: str):
    self.store = Store(name)

    self.commands = {
        'DEL' : self.delete,
        'GET' : self.get,
        'HDEL': self.hdel,
        'HGET': self.hget,
        'HGETV': self.hget_field,
        'HKEY': self.hkey,
        'HSET': self.hset,
        'IDX' : self.idx,
        'KEY': self.keys,
        'MDEL': self.mdel,
        'MGET': self.mget,
        'MSET': self.mset,
        'SET' : self.set,
    }

    self.__op = {
        '=': 'equal',
        '!=': 'not_equal',
        '>': 'greater_than',
        '>=': 'greater_than_or_equal',
        '<': 'less_than',
        '<=': 'less_than_or_equal',
        '^': 'starts_with',
        '!^': 'not_starts_with',
        '$': 'ends_with',
        '!$': 'not_ends_with',
        '**': 'contains',
    }

    self.__sort_prefix = {
        '++': 'asc',
        '--': 'desc',
        '??': 'rand',
    }

  def error(self, cmd: str=None, *args: str) -> int:
    if cmd not in self.commands:
      print('Error: invalid command.', file=stderr)
    else:
      print(f'{cmd}: arguments missing.', file=stderr)
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
      print(f'KEYS: No key found.', file=stderr)
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
      print('MSET: invalid number of arguments.', file=stderr)
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
        print(f'MDEL: key `{key}` not found.', file=stderr)
    return err

  def hset(self, hkey_or_index: str, *members: str) -> int:
    ''' 
    Create/update multiple members to a hash
    (a member is a field/value pair)
    '''
    if len(members) % 2 != 0:
      print(f'HSET: members mismatch. (missing field or value)', file=stderr)
      return 1

    if self.store.is_index(hkey_or_index):
      keys = sorted(self.store.get_index_keys(hkey_or_index))
    else:
      keys = [hkey_or_index]

    if not keys:
      print(f'HSET: `{hkey_or_index}` no such key or index.', file=stderr)
      return 1

    err = 0

    for key in keys:
      # Original hash
      kv = self.store.read_hash(key)
      subkv = {k: v for k, v in zip(members[::2], members[1::2])}
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
            self.store.delete_key_of_ref(key, kv.get(field))
            refs.append(v)
          kv[field] = v
          subkv.pop(field, None)

      for k, v in subkv.items():
        kv[k] = v
        if self.store.exists(v):
          refs.append(v)

      # Serialize and write on disk
      data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
      if self.store.write(data, key, vsz, ts, refs) != 0:
        print(f'HSET: Error: failed to update `{key}` hkey.', file=stderr)
        err += 1

    return err

  def parse_expr(self, expr: str) -> list[dict]:
    parts = expr.split(':')
    if parts[-1] == '*' and len(parts) != 2:
      print(f'Error: invalid syntax in `{expr}`.', file=stderr)
      return None
    if parts[-1] == '*' and len(parts) == 2:
      return [{'index': parts[0], 'fields': ['*']}]

    result = []
    current_index = None
    current_fields = []
    sort = None
    sort_field = None

    for i, part in enumerate(parts):
      temp_field = part
      temp_sort = self.__sort_prefix.get(part[:2])
      if temp_sort:
        temp_field = part[2:]
      if i == 0 and self.store.is_index(part):
        current_index = part
      elif i == 0 and temp_sort:
        if sort:
          print(f'Error: multiple sort modifiers in `{expr}`.', file=stderr)
          return None
        sort = temp_sort
        sort_field = temp_field
        current_fields.append(temp_field)
      elif i == 0:
        current_fields.append(temp_field)
      else:
        if temp_sort:
          if sort:
            print(f'Error: multiple sort modifiers in `{expr}`.', file=stderr)
            return None
          sort = temp_sort
          sort_field = temp_field
        current_fields.append(temp_field)
    if current_fields:
      res = {'index': current_index, 'fields': current_fields}
      if sort:
        res['sort'] = sort
        res['sort_field'] = sort_field
      result.append(res)

    if not result:
      print(f'Error: invalid expression `{expr}`.', file=stderr)
      return None

    return result

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

  def hget(self, index_or_key: str, *fields: str) -> int:
    '''
    Retrieve and print fields from keys or an index.
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
        print(f'HGET: Error: invalid limit: `{limit}`.', file=stderr)
        return 1


    if not (self.store.is_index(index_or_key) or self.store.has_index(index_or_key)):
      print(f'HGET: Error: `{index_or_key}`, no such index or hkey.', file=stderr)
      return 1

    if self.store.is_index(index_or_key):
      start_keys: list = self.store.get_index_keys(index_or_key)
      index_fields: list = self.store.get_fields_from_index(index_or_key)
    elif self.store.exists(index_or_key):
      start_keys: list = [index_or_key]
      index: str = self.store.get_index(index_or_key)
      index_fields: list = self.store.get_fields_from_index(index)

    rows: list = []

    if not fields:
      for key in start_keys:
        row = [key]
        data = self.store.read_hash(key)
        for field in index_fields:
          row.append(f'{field}=' + str(data.get(field, '?NOFIELD?')))
        if any(row[1:]):
          rows.append(row)
        if limit and len(rows) == limit:
          break
      if rows:
        for row in rows:
          print(' | '.join(row))
        return 0
      print(f'HGET: No data for `{index_or_key}`.', file=stderr)
      return 1

    parsed_fields: list = []
    sort_info = None
    random_rows = False

    for field in fields:
      parsed = self.parse_expr(field)
      if parsed is None:
        return 1
      for p in parsed:
        if 'sort' in p:
          if sort_info:
            print(f'HGET: Error: multiple sort modifiers in query.', file=stderr)
            return 1
          sort_info = {
              'sort': p['sort'],
              'field': p['sort_field'],
              'index': p['index']
          }
          if p['sort'] == 'rand':
            random_rows = True
      parsed_fields.extend(parsed)

    used_indexes = {index_or_key} | { pf['index'] for pf in parsed_fields if pf['index'] }

    limit_reached = False
    if random_rows:
      shuffle(start_keys)

    for start_key in start_keys if random_rows else sorted(start_keys):
      if limit_reached:
        break
      key_map: dict[str: list[str]] = {
          idx: sorted(set(self.store.get_refs(start_key, idx))) for idx in used_indexes
          if self.store.is_index(idx)
      }

      # Check query validity
      for index, keys in key_map.copy().items():
        # Ignore main index
        if index == index_or_key:
          continue
        if not keys:
          # No relation found, error...
          print(f'HGET: Error: trying to query unrelated data: `{index}`.', file=stderr)
          return 1

      max_depth: int = max(
          (len(f['fields']) if f['index'] else 0 for f in parsed_fields),
           default=0
      )

      deepest_index: str = None
      for pf in reversed(parsed_fields):
        if pf['index'] and len(pf['fields']) == max_depth:
          deepest_index = pf['index']
          break

      if deepest_index:
        deep_keys = key_map.get(deepest_index, [])

        for deep_key in deep_keys:
          row = {'row': [], 'sort_value': None}
          for pf in parsed_fields:
            index, fields = (pf['index'], pf['fields'])
            if index is None or index == index_or_key:
              data = self.store.read_hash(start_key)
              for field in fields:
                value = data.get(field)
                if value is None: # non existing unique field
                  print(f'HGET: Error: `{field}`, no such field in `{start_key}`', file=stderr)
                  return 1
                if sort_info and sort_info['index'] is None and sort_info['field'] == field:
                  row['sort_value'] = value
                row['row'].append(value)
            else:
              if self.store.is_index_of(deep_key, index):
                data = self.store.read_hash(deep_key)
              else:
                try:
                  assert len(key_map.get(index)) == 1
                  key = key_map.get(index)[0]
                  data = self.store.read_hash(key)
                except AssertionError:
                  print(f'HGET: Error: {index} -> {", ".join(key_map.get(index, []))}', file=stderr)
                  return 1
              if fields == ['*']:
                for field, value in data.items():
                  if sort_info and sort_info['index'] == index and sort_info['field'] == field:
                    row['sort_value'] = value
                  row['row'].append(f'{field}={value}')
              else:
                for field in fields:
                  if field not in data:
                    print(f'HGET: Error: `{field}` no such field in `{index}`.', file=stderr)
                    return 1
                  value = data.get(field, f'{field}=?NOFIELD?')
                  if sort_info and sort_info['index'] == index and sort_info['field'] == field:
                    row['sort_value'] = value
                  row['row'].append(value)
          if row:
            rows.append(row)
          if limit and limit == len(rows):
            limit_reached = True
      else:
        # Simple list of field as in
        # `HGET index field1 field2` or `HGET hkey field1:field2`
        # Must return an error if field is not in index_fields since
        # fields are explicitly given.
        row = {'row': [], 'sort_value': None}
        data = self.store.read_hash(start_key)
        for pf in parsed_fields:
          for field in pf['fields']:
            if field not in index_fields:
              print(f'HGET: Error: `{field}`, no such field in `{index_or_key}`.', file=stderr)
              return 1
            value = data.get(field, f'{field}=?NOFIELD?')
            if sort_info and sort_info['index'] is None and sort_info['field'] == field:
              row['sort_value'] = value
            row['row'].append(value)
        rows.append(row)
        if limit and limit == len(rows):
          limit_reached = True

    if not rows:
      print('HGET: An unexpected error occurred.', file=stderr)
      return 1

    if sort_info:
      if sort_info['sort'] == 'rand':
        shuffle(rows)
      else:
        reverse = sort_info['sort'] == 'desc'
        rows.sort(key=lambda x: self.get_sort_key(x['sort_value']), reverse=reverse)

    for row in rows:
      print(' | '.join(v for v in row['row']))
    return 0

  def hdel(self, hkey_or_index: str, *fields: str) -> int:
    ''' Delete a hash or an index or fields in a hash or in an index '''

    if self.store.is_index(hkey_or_index):
      keys = self.store.get_index_keys(hkey_or_index)
      is_index = True
    else:
      keys = [hkey_or_index]
      is_index = False

    err = 0

    if not fields and not keys and is_index:
      return self.store.delete_index(hkey_or_index)

    for key  in keys:
      if self.store.is_refd(key) and not fields:
        print(f'HDEL: Error: `{key}` is referenced (skipped).', file=stderr)
        err += 1
        continue
      if not fields and is_index: # delete the whole key:
        # Delete references here
        index_keys = self.store.get_index_keys(hkey_or_index)
        for k in index_keys:
          if self.store.has_ref(k):
            refs = self.store.get_refs_of(k)
            for ref in refs:
              self.store.delete_ref_of_key(k, ref)
        err += self.store.delete(key)
        continue
      kv = self.store.read_hash(key)
      if not kv and not key in self.store.keystore:
        print(f'HDEL: `{key}`, no such key.', file=stderr)
        err += 1
        continue

      if not fields: # Delete the key:
        err += self.store.delete(key)
        continue

      for field in fields:
        try:
          v = kv.pop(field)
          if self.store.is_refd_by(key=key, ref=v):
            self.store.delete_key_of_ref(key=key, ref=v)
        except KeyError:
          print(f'HDEL: `{key}`: unknown field: {field}', file=stderr)
          err += 1

      if fields:
        data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
        err += self.store.write(data, key, vsz, ts)
      else:
        err += 1
    return err

  def hget_field(self, hkey: str, field: str) -> str:
    ''' Return the value of a field in a hash. '''
    return self.store.read_hash_field(hkey, field)

  def hkey(self, key: str=None) -> int:
    ''' Get all fields for the given key/index or all indexes if none is provided '''
    if key:
      if self.store.is_index(key):
        keys = sorted([k for k in self.store.keystore if k.startswith(key + ':')])
      else:
        keys = [key]
      if not keys:
        if key in self.store.keystore:
          print(f'HKEYS: Error: `{key}` is not a hash.', file=stderr)
        else:
          print(f'HKEYS: Error: `{key}` key not found.', file=stderr)
        return 1
      for k in keys:
        kv = self.store.read_hash(k)
        if not kv:
          print(f'HKEY: `{k}` no such key or index.', file=stderr)
          return 1
        print(f'{k}: {" | ".join(kv.keys())}')
      return 0
    err = 0
    for k in sorted(self.store.keystore.keys()):
      if not self.store.has_index(k):
        continue
        err += self.hkey(k)
      kv = self.store.read_hash(k)
      print(f'{k}: {" | ".join(kv.keys())}')
    return 0 if err == 0 else 1

  def idx(self) -> None:
    for i, index in enumerate(sorted(self.store.indexes), 1):
      print(f'{i}. {index}')

  def flush(self):
    return self.store.flush()
