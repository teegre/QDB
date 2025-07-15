import atexit
import json
import os
import re
import sys
import traceback

from random import shuffle
from time import time
from typing import Any

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb.lib.exception import QDBError, QDBNoDatabaseError
from qdb.lib.query import QDBQuery
from qdb.lib.storage import QDBStore
from qdb.lib.utils import performance_measurement, is_numeric, is_virtual, validate_hkey

class QDB:
  def __init__(self, name: str):
    self.store = QDBStore(name)
    atexit.register(self.store.deinitialize)
    self.Q = QDBQuery(self.store, parent=self)
    self._perf_info = {}

    self.commands = {
        'COMMIT':  self.store.commit,
        'COMPACT': self.compact,
        'DEL' :    self.delete,
        'GET' :    self.get,
        'HDEL':    self.hdel,
        'Q':       self.q,
        'QF':      self.get_field,
        'HLEN':    self.hlen,
        'W':       self.w,
        'IDX' :    self.idx,
        'IDXF':    self.idxf,
        'KEYS':    self.keys,
        'LIST':    self.store.list_files,
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

  def set(self, key: str, value: str) -> int:
    ''' Set a single value '''
    self.store.write(key, value)

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

  def _autoid(self, expr: str) -> str:
    '''
    Return @autoid or 'expr' otherwise.
    '''
    AUTOID_RE = re.compile(r'^@autoid\((?P<index>[a-zA-Z_]+)\)$')
    m = AUTOID_RE.match(expr.lower())

    if not m:
      if expr.lower().startswith('@autoid'):
        raise QDBError(
            f'Error: invalid @autoid expression: `{expr}`.\n'
            f'Syntax: @autoid(index)'
        )
      else:
        return expr

    index = m.groupdict()['index']
    return f'{index}:{self.store.autoid(index)}'

  # @performance_measurement(message='Written')
  def w(self, hkey_or_index: str, *members: str) -> int:
    ''' 
    Create/update multiple members of a hash
    '''
    if len(members) % 2 != 0:
      print(f'W: arguments mismatch. (missing field or value)', file=sys.stderr)
      return 1

    hkey_or_index = self._autoid(hkey_or_index)

    if self.store.is_index(hkey_or_index):
      keys = sorted(self.store.get_index_keys(hkey_or_index))
    else:
      try:
        validate_hkey(hkey_or_index)
      except QDBError as e:
        print(f'W: {e}', file=sys.stderr)
        return 1
      keys = [hkey_or_index]

    if not keys:
      print(f'W: `{hkey_or_index}` no such key or index.', file=sys.stderr)
      return 1

    err = 0

    for key in keys:
      # Original hash
      try:
        kv = self.store.read_hash(key) or {}
      except QDBNoDatabaseError:
        kv = {}
      subkv = {k: v for k, v in zip(members[::2], members[1::2])}
      refs: list[str] = []

      for field, new_value in subkv.items():
        old_value = kv.get(field)
        if new_value == old_value: # and not is_new:
          continue

        if self.store.is_refd_by(key, old_value):
          # delete old referenced key.
          self.store.delete_ref_of_key(key, old_value)

        kv[field] = new_value

        # NOTE: if it looks like a valid hkey then create a reference
        if validate_hkey(new_value, confirm=True):
          refs.append(new_value)

      # Write on disk
      self.store.write(key, kv, refs)

    return 1 if err > 0 else 0

  def _sort_key(self, row: list, fields_info: dict, field_positions: dict, force_t_type: bool=False) -> tuple:
    def _descending_value(val: str) -> float | str:
      if not force_t_type:
        if is_numeric(val):
          val = float(val)
        if isinstance(val, float):
          return -val
      return ''.join(chr(255 - ord(c)) for c in val)

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
          value = ''
        else:
          value = row['row'][pos]
          if '=' in value:
            value = value.split('=', 1)[1]
        if not force_t_type:
          if is_numeric(value):
            value = float(value)
        if value is None:
          value = ''

        key.append(_descending_value(value) if order == 'desc' else value)
    return tuple(key)

  def _q_flat(self, tree: dict, fields_data: dict, field_positions: dict, root_index: str) -> int:
    rows = []
    elements = tree[root_index]
    index_fields = self.store.get_fields_from_index(root_index) if not fields_data else None
    for key in elements:
      row = []
      data = self.store.read_hash(key)
      if index_fields:
        row.append(key)
        for f in index_fields:
          if not is_virtual(f):
            v = data.get(f, '?NOFIELD?')
            row.append(f'{f}={v}')
        rows.append({'row': row, 'sort_value': None})
      else:
        for index, spec in fields_data.items():
          fields = spec['fields']
          if fields == ['*']:
            for f, v in data.items():
              if not is_virtual(f):
                row.append(f'{f}={v}')
          else:
            for field in fields:
              val = data.get(field, '?NOFIELD?')
              row.append(val)
              sort_data = fields_data[root_index]['sort']
        rows.append({'row': row, 'sort_value': sort_data})

    if not rows:
      print(f'Q: an unexpected error occured.', file=sys.stderr)
      return 1

    # Sorting and output
    if index_fields is None:
      try:
        rows.sort(key=lambda row: self._sort_key(row, fields_data, field_positions))
      except TypeError:
        rows.sort(key=lambda row: self._sort_key(row, fields_data, field_positions, force_t_type=True))

    for row in rows:
      print(' | '.join(row['row']), flush=True)

    if not os.getenv('__QDB_QUIET__'):
      print(file=sys.stderr)
      print(len(rows), 'rows' if len(rows) > 1 else 'row', 'found.', file=sys.stderr)

    return 0

  def _format_row(self, result_value: dict, fields_data: dict) -> list[str]:
    row = []
    for index, spec in fields_data.items():
      for field in spec['fields']:
        if field == '*':
          star_fields = [k[1] for k in result_value.keys() if k[0] == index]
          for star_field in star_fields:
            row.append(f'{star_field}={result_value[(index, star_field)]}')
        else:
          row.append(result_value[(index, field)])
    return row

  def _walk_tree(self, tree: dict, root_index: str, fields_data: dict) -> list[dict]:
    def _combine_results(node: dict, values: dict, row_meta: dict):
      combined = []
      current_index = root_index

      for i, ch in node.items():
        r = []

        if isinstance(i, tuple): # Grouped field
          g_field = i[0]
          for v, cn in ch.items():
            temp_values = dict(values)
            temp_values[(root_index, g_field)] = v
            for k, n in cn.items():
              r.extend(walk(
                root_index,
                k,
                n,
                temp_values,
                dict(row_meta),
                group=True
              ))
        else:
          r = []
          for k, n in ch.items():
            r.extend(walk(i, k, n, dict(values), dict(row_meta)))
 
        if combined:
          combined = [
            {**a, **b}
            for a in combined
            for b in r
          ]
        else:
          combined = r

      return combined

    def walk(index: str, key, node: dict, values: dict, row_meta: dict, group: bool=False):
      results = []
      is_aggregation = False
      current_values = dict(values)

      if group:
        fields = [f for f in fields_data[index]['fields'] if (index, f) not in current_values]
      else:
        fields = fields_data[index]['fields']
      sort_data = fields_data[index]['sort']

      if key == '@[aggregate]':
        data = {af: f'{af}={list(v.keys())[0]}' for af, v in node.items()}
        is_aggregation = True
      else:
        data = self.store.read_hash(key)

      if fields == ['*']:
        for f, v in data.items():
          if not is_virtual(f):
            current_values[(index, f)] = v
      else:
        for f in fields:
          try:
            current_values[(index, f)] = data[f]
          except (KeyError, TypeError):
            raise QDBError(f'an unexpected error involving `{index}:{f}` occured.')
        if row_meta.get('sort_value') is None and sort_data:
          for rule in sort_data:
            for f in fields:
              if rule['field'] == f:
                row_meta['sort_value'] = data[f]
                break

      if node and not is_aggregation:
        results.extend(_combine_results(node, dict(current_values), dict(row_meta)))
      else:
        results.append(current_values)

      return results

    rows = []
    elements = tree.get(root_index, {})

    for key, children in elements.items():
      row_meta = { 'sort_value': None }

      if isinstance(key, tuple): # Group
        f = key[0]
        for g_val, g_node in children.items():
          results = []
          temp = {}
          temp[(root_index, f)] = g_val
          if '@[aggregate]' in g_node:
            k = '@[aggregate]'
            results.extend(walk(root_index, k, g_node[k], dict(temp), dict(row_meta), group=True))
          else:
            combined_results = _combine_results(g_node, temp, dict(row_meta))
            if combined_results:
              results.extend(combined_results)

          for r in results:
            rows.append({
              'row': self._format_row(r, fields_data),
              'sort_value': row_meta['sort_value']
            })
      else:
        try:
          results_values = walk(root_index, key, children, {}, row_meta)
          for result_value in results_values:
            rows.append({
              'row': self._format_row(result_value, fields_data),
              'sort_value': row_meta['sort_value']
            })
        except QDBError as e:
          raise(e)

    return rows

  def _build_fields_positions(self, fields_data: dict) -> dict:
    pos = 0
    fields_positions = {}
    for idx, fields in fields_data.items():
      if fields['fields'] == ['*']:
        all_fields = self.store.get_fields_from_index(idx)
        star = True
      else:
        all_fields = fields['fields']
        star = False
      for f in all_fields:
        if star and is_virtual(f):
          continue
        fields_positions[f'{idx}:{f}'] = pos
        pos += 1
    return fields_positions

  @performance_measurement(message='Processed')
  def q(self, index_or_key: str, *exprs: str) -> int:
    if not index_or_key:
      print(f'Q: missing index or hkey.', file=sys.stderr)
      return 1

    try:
      tree, fields_data, flat = self.Q.query(index_or_key, *exprs)
    except QDBError as e:
      print(f'Q: {e}', file=sys.stderr)
      if os.getenv('__QDB_DEBUG__'):
        raise
      return 1

    root_index = next(iter(tree))
    index_fields: list = self.store.get_fields_from_index(root_index)
    fields_positions = self._build_fields_positions(fields_data)

    rows: list = []

    if flat or not fields_data:
      res = self._q_flat(tree, fields_data if fields_data else None, fields_positions, root_index)
      if res == 0:
        exec_dur = 0
      return res

    try:
      all_rows = self._walk_tree(tree, root_index, fields_data)
    except QDBError as e:
      print(e, file=sys.stderr)
      if os.getenv('__QDB_DEBUG__'):
        raise
      return 1

    if not all_rows:
      print(f'Q: an unexpected error occured.', file=sys.stderr)
      return 1

    # Sorting and output
    try:
      all_rows.sort(key=lambda row: self._sort_key(row, fields_data, fields_positions))
    except TypeError:
      all_rows.sort(key=lambda row: self._sort_key(row, fields_data, fields_positions, force_t_type=True))


    for row in all_rows:
      print(' | '.join(row['row']), flush=True)

    if not os.getenv('__QDB_QUIET__'):
      print(' ', file=sys.stderr)
      print(len(all_rows), 'rows' if len(all_rows) > 1 else 'row', 'found.', file=sys.stderr)

    return 0

  def hdel(self, index_or_key: str, *fields: str) -> int:
    ''' Delete a hash or an index or fields in a hash or in an index '''
    is_index = self.store.is_index(index_or_key)
    if is_index:
      keys = self.store.get_index_keys(index_or_key).copy()
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
            # print(f'HDEL: deleting {v} referenced by {key}...')
            self.store.delete_ref_of_key(ref=v, hkey=key)
        except KeyError:
          print(f'HDEL: Warning: `{field}`, no such field in `{key}`.', file=sys.stderr)
          continue
      if fields:
        self.store.write(key, kv)
    return 1 if err > 0 else 0

  def get_field(self, hkey: str, field: str) -> int:
    ''' Return the value of a field in a hash. '''
    if self.store.exists(hkey):
      value = self.store.read_hash_field(hkey, field)
      if value == '?NOFIELD?':
        print(f'GETF: Error: `{field}`, no such field in `{hkey}`.', file=sys.stderr)
        return 1
      if value:
        print(value)
        return 0
      print(f'GETF: {hkey}: no data.', file=sys.stderr)
      return 0
    print(f'GETF: Error: `{hkey}`, no such hkey.', file=sys.stderr)
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
        print(f'{k}: {" | ".join([f for f in kv.keys() if not is_virtual(f)])}')
      return 0
    err = 0
    for k in sorted(self.store.keystore.keys()):
      if not self.store.has_index(k):
        continue
        err += self.hkey(k)
      kv = self.store.read_hash(k)
      print(f'{k}: {" | ".join([f for f in kv.keys() if not is_virtual(f)])}')
    return 0 if err == 0 else 1

  def idx(self) -> None:
    for i, index in enumerate(sorted(self.store.indexes), 1):
      print(f'{i}. {index}')

  def idxf(self, index: str) -> None:
    if self.store.is_index(index):
      fields = self.store.get_fields_from_index(index)
      print(f'{index}: {' | '.join([f for f in fields if not is_virtual(f)])}')
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

  def schema(self) -> int:
    self.store.database_schema()
    return 0

  def compact(self):
    try:
      self.store.compact(force=True)
    except QDBError as e:
      print(e, file=sys.stderr)
      return 1
    return 0

  def is_db_empty(self) -> bool:
    return self.store.is_db_empty
