import json
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

    self.__prefix = {
        '++': 'asc_order',
        '--': 'desc_order',
        '??': 'random_order',
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
      print(f'HSET: members mismatch. (missing field or value?)', file=stderr)
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
            self.store.delete_key_of_ref(kv.get(field), key)
            refs.append(v)
          kv[field] = v
          subkv.pop(field, None)

      for k, v in subkv.items():
        kv[k] = v
        if v in self.store.keystore:
          refs.append(v)

      # Serialize and write on disk
      data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
      if self.store.write(data, key, vsz, ts, refs) != 0:
        print(f'HSET: Error: failed to update `{key}` hkey.', file=stderr)
        err += 1

    return err

  def parse_expr(self, expr: str) -> list[dict[str, list[list[str]]]]:
    parts = expr.split(':')
    if parts[-1] == '*' and len(parts) != 2:
      print(f'Error: invalid `*` syntax in `{expr}`.')
      return None
    if parts[-1] == '*' and len(parts) == 2:
      return [{'index': parts[0], 'fields': ['*']}]
    if len(parts) == 1:
      return [{'index': None, 'fields': [parts[0]]}]
    result = []
    current_index = None
    current_fields = []
    for part in parts:
      if self.store.is_index(part):
        if current_fields:
          result.append({'index': current_index, 'fields': current_fields})
          current_fields = []
        current_index = part
      else:
        current_fields.append(part)
    if current_fields:
      result.append({'index': current_index, 'fields': current_fields})
    return result

  def hget(self, index_or_key: str, *fields: str) -> int:
    if not (self.store.is_index(index_or_key) or self.store.has_index(index_or_key)):
      print(f'HGET: Error: `{index_or_key}`, no such index or key.')
      return 1

    # no fields case
    if not fields:
      if self.store.is_index(index_or_key):
        start_keys = sorted(self.store.get_index_keys(index_or_key))
        if not start_keys:
          print(f'HGET: No keys found for index `{index_or_key}`.', file=stderr)
          return 1
        index_fields = self.store.get_fields_from_index(index_or_key)
      elif index_or_key in self.store.keystore:
        start_keys = [index_or_key]
        index = self.store.get_index(index_or_key)
        index_fields = self.store.get_fields_from_index(index)
      else:
        print(f'HGET: Error: `{index_or_key}`, no such key or index.', file=stderr)
        return 1

      rows = []
      for key in start_keys:
        row = [key]
        data = self.store.read_hash(key)
        for field in index_fields:
          row.append(f'{field}=' + str(data.get(field, '?NOFIELD?')))
        if any(row[1:]):
          rows.append(row)
      if rows:
        for row in rows:
          print(' | '.join(row))
        return 0
      print(f'HGET: No data for `{index_or_key}`.', file=stderr)
      return 1

    parsed_fields = []
    for field in fields:
      parsed = self.parse_expr(field)
      if None is parsed:
        return 1
      parsed_fields.extend(parsed)

    # what indexes are involved in the query?
    used_indexes = {index_or_key} | {pf['index'] for pf in parsed_fields if pf['index']}

    if self.store.is_index(index_or_key):
      start_keys = self.store.get_index_keys(index_or_key)
    elif index_or_key and index_or_key in self.store.keystore:
      start_keys = [index_or_key]
    else:
      start_keys = []

    if not start_keys:
      print(f'HGET: `{index_or_key}`, no such index or hkey.', file=stderr)
      return 1

    rows = []
    for start_key in sorted(start_keys):
      # collect related keys for each index
      key_map = {
          idx: sorted(set(self.store.get_refs(start_key, idx))) for idx in used_indexes
          if self.store.is_index(idx)
      }

      # are there missing references?
      missing_indexes = [idx for idx, keys in key_map.items() if not keys ]
      # I do not like this!
      for missing_index in missing_indexes:
        for idx, keys in key_map.copy().items():
          if idx == missing_index:
            continue
          if not keys:
            hkeys = self.store.get_refs_of(start_key)
            for hkey in hkeys:
              href = self.store.get_ref(hkey)
              if href:
                key_map[idx].append(href)
          for k in keys:
            hkeys = db.store.get_refs(k, missing_index)
            if hkeys:
              key_map[missing_index].extend(hkeys)
      # ... But it seems to do the trick... or not...

      # check relational integrity
      for pf in parsed_fields:
        if pf['index'] and not key_map.get(pf['index']) and len(parsed_fields) == 1:
          # ignore when 'index_or_key' is used in field expressions...
          # i.e. `HGET artist artist:name`
          # if not start_key.startswith(pf['index'] + ':'):
          print(f'HGET: Error: no `{pf["index"]}` key found for `{start_key}`.',
                file=stderr
          )
          return 1

      # find the deepest index for row iteration
      max_depth = max(
          (len(f['fields']) if f['index'] else 0 for f in parsed_fields),
          default=0
      )

      deepest_index = None
      for pf in reversed(parsed_fields):
        if pf['index'] and len(pf['fields']) == max_depth:
          deepest_index = pf['index']
          break

      if deepest_index:
        deep_keys = key_map.get(deepest_index, [])
        for deep_key in deep_keys:
          if not deep_key in self.store.keystore:
            print(f'HGET: Error: {deep_key}, no such key (referenced by {start_key}).')
            continue
          row = []
          # Reconstruct the path to deep_key
          path = [start_key] + self.store.find_path(start_key, deep_key) + [deep_key]

          if not self.store.is_refd_by(deep_key, start_key) and not deep_key in path:
            print(f'HGET: Warning: {deep_key} is not referenced by {start_key}.')
            # Skip bad references.
            continue

          # Build row using the path
          for pf in parsed_fields:
            index, fields = (pf['index'], pf['fields'])
            if index is None:
              # Simple field from start_key
              data = self.store.read_hash(start_key)
              for field in fields:
                if field not in data:
                  print(f'HGET: ERROR: `{field}`,  no such field in `{start_key}`.', file=stderr)
                  return 1
                row.append(str(data.get(field)))
            else:
              # find the related key for this index in the path
              related_key = None
              for k in path:
                if k.startswith(index + ':'):
                  related_key = k
                  break
              if not related_key:
                # not found in the current path, try from deep_key:
                for target_key in key_map.get(index, []) or self.store.get_index_keys(index) or []:
                  if self.store.are_related(deep_key, target_key) or self.store.find_path(deep_key, target_key):
                    related_key = target_key
                    break
              # still not found...
              if not related_key:
                print(f'HGET: Skipped {deep_key}')
                row.append(f'{index}:{deep_key}=?UNRELATED?')
                continue
              
              data = self.store.read_hash(related_key)
              if fields == ['*']:
                index_fields = self.store.get_fields_from_index(pf['index'])
                for field in index_fields:
                  row.append(f'{field}=' + str(data.get(field, '?NOFIELD?')))
              else:
                for field in fields:
                  if field not in data:
                    print(f'HGET: Error: `{field}` no such field in `{pf['index']}`.', file=stderr)
                    # return 1
                  row.append(str(data.get(field, f'{field}=?NOFIELD?')))

          if row and any(v for v in row):
            rows.append(row)
      else:
        row = []
        for pf in parsed_fields:
          data = self.store.read_hash(start_key)
          for field in pf['fields']:
            if not field in data:
              print(f'HGET: Error: `{field}` no such field in `{index_or_key}`', file=stderr)
              return 1
            row.append(str(data.get(field, f'{field}=?MISS?')))
        if row and any(v for v in row):
          rows.append(row)

    if not rows:
      print(f'HGET: No data for `{index_or_key}.`', file=stderr)
      return 1

    for row in rows:
      print(' | '.join(str(v) for v in row if row))

    return 0

  def hdel(self, hkey_or_index: str, *fields: str) -> int:
    ''' Delete a hash or an index or fields in a hash or an index '''

    if self.store.is_index(hkey_or_index):
      keys = self.store.get_index_keys(hkey_or_index)
      is_index = True
    else:
      keys = [hkey_or_index]
      is_index = False

    err = 0

    for key  in keys:
      if key in self.store.refs and not fields:
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
              self.store.delete_refd_key(ref=ref, key=k)
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
          if self.store.is_refd_by(ref=v, key=key):
            self.store.delete_refd_key(key=key, ref=v)
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
