import os
import json
import struct

from collections import deque
from dataclasses import dataclass
from glob import glob
from shutil import move
from sys import stdin, stdout, stderr
from time import time, strftime
from zlib import crc32

# Record format on disk:
# CRC TS VT KSZ VSZ K V
#     <----- CRC ----->
#
# Keystore:
# K → ID VSZ VPOS TS
#
# Record format in hint file on disk;
# TS KSZ VSZ VPOS K
#
# Legend:
# K = KEY, V = VALUE
# TS = TIMESTAMP,
# VT = VALUE TYPE (1 byte: either - or +)
# KSZ = KEY SIZE
# VSZ = VALUE SIZE
# VPOS = VALUE POSITION

#             CRC TS  VT  KSZ VSZ
HEADER_SIZE = 4 + 8 + 1 + 4 + 4
HINT_HEADER_SIZE = HEADER_SIZE - 1

@dataclass
class KeyStoreEntry:
  filename: str
  value_size: int
  position: int
  timestamp: int

class Store:
  def __init__(self, name: str) :
    self.database: str = name
    self.keystore: Dict[str, KeyStoreEntry] = {}
    self.indexes = set()
    self.refs: Dict[str, set[str]] = {}
    self.file = None
    self._file_id: int = self._max_id
    self._file_pos: int = 0
    self.reconstruct()
  
  def open(self) -> int:
    if not os.path.exists(self.database):
      os.mkdir(self.database)
    self._file_id = self._max_id
    try:
      self.file = open(self.active_file, 'ab+')
      return 0
    except:
      return 1

  def close(self) -> int:
    try:
      self.file.close()
      self._file_id = self._max_id
      self.file = None
      self._file_pos = 0
      return 0
    except:
      return 1

  def flush(self) -> int:
    if self.file is None:
      return 1
    try:
      self.file.flush()
      return self.close()
    except (IOError, OSError) as e:
      print(f'Error: flush did not work: {e}.', file=stderr)
      return 1

  def serialize(self, key: str, val: str, string: bool = True) -> (int, int, int):
    ts = int(time())
    ksz = len(key)
    vsz = len(val)
    rec = struct.pack(
        f'<Q1sII{ksz}s{vsz}s',
        ts,
        '-'.encode() if string else '+'.encode(),
        ksz, vsz, key.encode(),
        val.encode()
    )
    crc = crc32(rec)
    return struct.pack('<L', crc) + rec, vsz, ts

  def deserialize_header(self, header: bytes) -> (int, int, str, int, int):
    crc, ts, vt, ksz, vsz = struct.unpack('<LQ1sII', header)
    return crc, ts, vt, ksz, vsz

  def check_crc(self, crc, ts, vt, ksz, vsz, key, val: bytes) -> bool:
    xcrc = crc32(struct.pack(f'<Q1sII{ksz}s{vsz}s', ts, vt, ksz, vsz, key, val))
    return crc == xcrc

  def write(self, data: bytes, key: str, vsz: int, ts: int, refs: list[str]=[]) -> int:
    ''' Write data to file, update keystore, indexes and refs '''
    if not self.file:
      self.open()
    try:
      self._file_pos = self.file.tell()
      bytes_written = self.file.write(data)
      if bytes_written > 0:
        self.keystore[key] = KeyStoreEntry(
            self.active_file,
            vsz,
            self._file_pos,
            ts
        )
        # TODO: Check hkey syntax → KEYNAME:ID
        if ':' in key:
          if self.create_index(key) != 0:
            return 1
        for ref in refs :
          self.create_ref(ref, key)

      return 0 if bytes_written > 0 else 1
    except:
      print(f'Error writing key: `{key}`.', file=stderr)
      return 1

  def read(self, key: str) -> str:
    ''' Read data for the given key '''
    entry = self.keystore.get(key)
    if entry is None:
      return None
    fn = entry.filename
    vsz = entry.value_size
    pos = entry.position
    ts = entry.timestamp

    ksz = len(key)

    if fn == self.active_file and self.file is not None:
      f = self.file
    else:
      f = open(fn, 'rb')

    f.seek(pos)
    header = f.read(HEADER_SIZE)

    vt = self.deserialize_header(header)[2]

    f.seek(pos + HEADER_SIZE + ksz)
    val = f.read(vsz)

    if fn != self.active_file:
      f.close()

    if vt.decode() != '-':
      print(f'Error: {key} is a hash.')
      return None

    return val.decode()

  def read_hash(self, key: str) -> dict:
    ''' Return hash for the given key as a dict '''
    if key in self.keystore:
      entry: KeyStoreEntry = self.keystore.get(key)

      fn = entry.filename
      vsz = entry.value_size
      pos = entry.position
      ts = entry.timestamp

      ksz = len(key)

      if fn == self.active_file and self.file is not None:
        f = self.file
      else:
        f = open(fn, 'rb')

      f.seek(pos)
      header = f.read(HEADER_SIZE)
      vt = self.deserialize_header(header)[2]

      if vt.decode() != '+':
        if fn != self.active_file:
          f.close()
        print(f'Error: {key} is not a hash.', file=stderr)
        return {}

      f.seek(pos + HEADER_SIZE + ksz)
      val = f.read(vsz)

      if fn != self.active_file:
        f.close()

      data = json.loads(val.decode())
      return data

    return {}

  def read_hash_field(self, key: str, field: str) -> str:
    data = self.read_hash(key)
    if data:
      return data.get(field)
    return None

  def delete(self, key: str) -> int:
    '''
    Delete a key from the keystore
    and mark it for deletion
    '''
    if key in self.keystore:
      if self.has_refs(key):
        print(f'DEL: Error: key `{key}` has references.', file=stderr)
        return 1
      ts = int(time())
      ksz = len(key)
      vsz = 0
      rec = struct.pack(
          f'<Q1sII{ksz}s',
          ts,
          '+'.encode() if self.has_index(key) else '-'.encode(),
          ksz,
          vsz,
          key.encode()
      )
      crc = crc32(rec)
      data = struct.pack('<L', crc) + rec
      self.write(data, key, vsz, ts)
      self.keystore.pop(key, None)
      if self.is_ref(key):
        ref = key
        refkey = self.get_ref_key(ref)
        self.delete_ref(refkey, ref)
      return 0
    return 1

  def dump(self) -> str:
    ''' Dump current database in json format '''
    for key in self.keystore.keys():
      if self.has_index(key): # hash
        data = {key: self.read_hash(key)}
      else:
        data = {key: self.read(key) }
      print(json.dumps(data))

  def reconstruct(self) -> int:
    ''' Reconstruct keystore from data files '''
    files = sorted(glob(os.path.join(self.database, "*.log")))
    err = 0
    for file in files:
      hint_file = file.replace('.log', '.hint')
      # remove empty files...
      if os.path.getsize(file) == 0:
        os.remove(file)
        if os.path.exists(hint_file):
          os.remove(hint_file)
        continue
      if os.path.exists(hint_file):
        err += self.reconstruct_from_hint(hint_file)
        continue
      err += self.reconstruct_keystore(file)
    return err

  def reconstruct_keystore(self, file: str) -> int:
    ''' Populate keystore  '''
    with open(file, 'rb') as f:
      pos = 0
      while True:
        try:
          header = f.read(HEADER_SIZE)
          if not header:
            break
          if len(header) != HEADER_SIZE:
            print(f'Warning: incomplete header at {file}:{pos}', file=stderr)
            return 1
          crc, ts, vt, ksz, vsz = self.deserialize_header(header)

          key = f.read(ksz)
          val = f.read(vsz)

          # check CRC validity
          if not self.check_crc(crc, ts, vt, ksz, vsz, key, val):
            print(f'Warning: bad CRC at {file}:{pos}', file=stderr)
            return 1

          key = key.decode()

          if len(key) != ksz:
            print(f'Warning: incomplete key at {file}:{pos}', file=stderr)
            return 1
          if vsz == 0:
            self.keystore.pop(key, None)
          else:
            entry = self.keystore.get(key)
            if entry is None or ts > entry.timestamp:
              self.keystore[key] = KeyStoreEntry(file, vsz, pos, ts)

            if ':' in key:
              self.create_index(key)

            if vt.decode() == '+': # hash
              kv = json.loads(val.decode())
              values = [v for v in kv.values() if ':' in v]
              for value in values:
                self.create_ref(value, key)
          pos = f.tell()
        except Exception as e:
          print(f'Error processing record at {file}:{pos}: {e}', file=stderr)
          return 1
    return 0

  def reconstruct_from_hint(self, hint_file: str) -> int:
    ''' Reconstruct keystore from a hint file '''
    with open(hint_file, 'rb') as h:
      fpos = 0
      while True:
        header = h.read(HINT_HEADER_SIZE)
        if not header:
          break
        if len(header) != HINT_HEADER_SIZE:
          print(f'Warning: incomplete header at {hint_file}:{pos}', file=stderr)
          break
        ts, ksz, vsz, pos = struct.unpack('<QIII', header)
        key = h.read(ksz)
        if len(key) != ksz:
          print(f'Warning: incomplete header at {hint_file}:{fpos}', file=stderr)
          return 1
        if vsz == 0:
          self.keystore.pop(key.decode(), None)
        else:
          filename = hint_file.replace('.hint', '.log')
          if self.reconstruct_keystore(filename) != 0:
            return 1
        fpos = h.tell()
    return 0
        
  def compact(self) -> int:
    ''' Compact files and clean database directory '''
    if self.file is not None:
      if self.flush() != 0:
        return
      print('Flushed and closed active file', file=stderr)

    files = [f for f in sorted(glob(os.path.join(self.database, '*.log')))
             if f != self.active_file]
    if not files or len(files) == 1:
      print('Nothing to do.', file=stderr)
      return 0

    name = strftime('%Y%m%d_%H%M%S')
    newfile = os.path.join(self.database, f'{name}.log')
    newhint = newfile.replace('.log', '.hint')
    tmpfile = newfile + '.tmp'
    tmphint = newhint + '.tmp'

    warnings = 0

    latest_records: Dict[str, tuple] = {}

    for file in files:
      with open(file, 'rb') as f:
        pos = 0
        while True:
          try:
            header= f.read(HEADER_SIZE)
            if not header:
              break
            if len(header) != HEADER_SIZE:
              print(f'Error: incomplete header at {file}:{pos}', file=stderr)
              break
            crc, ts, vt, ksz, vsz = self.deserialize_header(header)

            key = f.read(ksz)
            val = f.read(vsz)
            
            # check CRC validity
            if not self.check_crc(crc, ts, vt, ksz, vsz, key, val):
              print('Error: bad CRC at {file}:{pos}', file=stderr)
              warnings += 1
              break

            key = key.decode()
            if key not in latest_records or ts > latest_records[key][2]:
              latest_records[key] = (file, pos, ts, vt, ksz, vsz)

            pos = f.tell()
          except Exception as e:
            print(f'Error processing record at {file}:{pos}: {e}', file=stderr)
            warnings += 1
            break

    with open(tmpfile, 'wb') as d, open(tmphint, 'wb') as h:
      pos = 0
      keystore: Dict[str, KeyStoreEntry] = {}

      for key, (oldfile, oldpos, ts, vt, ksz, vsz) in sorted(latest_records.items()):
        # skipping marked for deletion
        if vsz == 0:
          continue

        with open(oldfile, 'rb') as f:
          f.seek(oldpos + HEADER_SIZE + ksz)
          val = f.read(vsz)

        rec = struct.pack(f'<Q1sII{ksz}s{vsz}s', ts, vt, ksz, vsz, key.encode(), val)
        crc = struct.pack('<L', crc32(rec))
        d.write(crc + rec)
        hint = struct.pack(f'<QIII{ksz}s', ts, ksz, vsz, pos, key.encode())
        h.write(hint)

        keystore[key] = KeyStoreEntry(newfile, vsz, pos, ts)
        pos += HEADER_SIZE + ksz + vsz

    move(tmpfile, newfile)
    move(tmphint, newhint)

    self.keystore = keystore

    for file in files:
      try:
        os.remove(file)
        hint_file = file.replace('.log', '.hint')
        if os.path.exists(hint_file):
          os.remove(hint_file)
      except Exception as e:
        print(f'Error removing file {file}: {e}', file=stderr)
        return 1

    print('Success!.', file=stderr)
    return warnings

  def create_index(self, key: str) -> int:
    ''' Create an index. '''
    try:
      index, _ = key.split(':')
    except ValueError:
      index = None
    if not index or index.isdigit():
      print(f'Error: invalid key name: `{index}`', file=stderr)
      return 1
    self.indexes.add(index)
    return 0

  def delete_index(self, key: str) -> int:
    if self.has_index(key):
      if self.has_index_refs(key):
        print(f'Error: `{key}` has references.', file=stderr)
        return 1
      try:
        index = key.split(':')[0]
        del self.indexes[index]
      except KeyError:
        print(f'Error: {key.split()}index not found.', file=stderr)

  def get_index_keys(self, index: str) -> list:
    ''' Get all keys for a given index '''
    if self.is_index(index):
      return [k for k in self.keystore.keys() if k.startswith(index + ':')]
    return []

  def create_ref(self, key: str, ref: str) -> int:
    ''' Add a reference for a given key '''
    refs = self.refs.get(key)
    if refs is None and self.has_index(key):
      self.refs[key] = set([ref])
      return 0
    if self.has_index(key):
      self.refs[key].add(ref)
      return 0
    return 1


  def get_refs(self, key: str, index: str) -> list[str]:
    '''
    Return a list of keys of type `index` that are reachable
    from `key` through any number of references
    '''
    # Validate inputs
    if not self.has_index(key) or not self.is_index(index):
      return []

    # Initialize BFS
    queue = deque([key])  # Keys to explore
    visited = {key}  # Track visited keys to avoid cycles
    refs = []  # Collect keys of type `index`

    while queue:
      current_key = queue.popleft()

      # Get neighbors (keys referenced by current_key)
      neighbors = self.refs.get(current_key, set())

      for neighbor in neighbors:
        # Collect neighbor if it matches the desired type
        if neighbor.startswith(index + ':'):
          refs.append(neighbor)

            # Explore unvisited neighbors
        if neighbor not in visited:
          visited.add(neighbor)
          queue.append(neighbor)

    # Remove duplicates while preserving order
    forward_refs = list(dict.fromkeys(refs))
    reverse_refs = [
        k for k, refs in self.refs.items()
        if key in refs and k.startswith(index + ':')
    ]
    return sorted(set(forward_refs + reverse_refs))

  def get_ref_key(self, ref: str) -> str:
    ''' Get the key that ref references to... '''
    for key, values in self.refs.items():
      if ref in values:
        return key
    return None

  def are_related(self, k1: str, k2: str) -> bool:
    ''' Return True if k1 and k2 are direcly related '''
    return k1 in self.refs.get(k2, []) or k2 in self.refs.get(k1, [])


  def find_path(self, k1: str, k2: str) -> list[str]:
    '''
    Returns the keys that form a path from k1 to k2 (or k2 to k1), if any.
    Considers forward references from self.refs and reverse references.
    '''
    # If at least one key does not exist, no path exists
    if not self.has_index(k1) or not self.has_index(k2):
      return []

    # If keys are the same, no intermediate path exists
    if k1 == k2:
      return []

    # Build reverse references (keys that reference the current key)
    reverse_refs = {}
    for key, refs in self.refs.items():
      for ref in refs:
        if ref not in reverse_refs:
          reverse_refs[ref] = set()
        reverse_refs[ref].add(key)

    # Initialize BFS
    queue = deque([(k1, [k1])])  # (current_key, path_so_far)
    visited = {k1}  # Track visited keys to avoid cycles

    while queue:
      current_key, path = queue.popleft()

        # Get neighbors: forward refs from self.refs, reverse refs from reverse_refs
      forward_neighbors = self.refs.get(current_key, set())
      reverse_neighbors = reverse_refs.get(current_key, set())
      neighbors = forward_neighbors | reverse_neighbors

      for neighbor in neighbors:
        if neighbor not in visited:
          visited.add(neighbor)
          new_path = path + [neighbor]
          queue.append((neighbor, new_path))

          if neighbor == k2:
            # Return the path, excluding start and end keys
            return new_path[1:-1]

    # No path found
    return []

  def delete_ref(self, key: str, ref: str) -> int:
    refs = self.refs.get(key)
    if refs is None:
      return 1
    self.refs[key].discard(ref)
    if len(self.refs[key]) == 0:
      del self.refs[key]

  def has_index(self, key: str) -> bool:
    index = key.split(':')[0]
    return index in self.indexes

  def is_index(self, key: str) -> bool:
    return key in self.indexes

  def has_refs(self, key: str) -> bool:
    return key in self.refs

  def has_index_refs(self, key: str) -> bool:
    for ref in self.refs.keys():
      if ref in key:
        return True
    return False

  def is_ref(self, ref: str, key: str=None) -> bool:
    if key:
      refs = self.refs.get(key)
      return ref in refs if refs else False
    else:
      for refs in self.refs.values():
        if ref in refs:
          return True
    return False

  @property
  def _max_id(self) -> int:
    try:
      return sum([1 for _ in glob(os.path.join(self.database, 'data*.log'))])
    except:
      return 0

  @property
  def active_file(self) -> str:
    name = f'data{str(self._file_id).zfill(4)}.log'
    return os.path.join(self.database, name)

class MicroDB:
  def __init__(self, name: str):
    self.store = Store(name)

    self.__commands = {
        'DEL' : self.delete,
        'FLUSH': self.flush,
        'GET' : self.get,
        'HDEL': self.hdel,
        'HGET': self.hget,
        'HKEY': self.hkey,
        'HSET': self.hset,
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
        '~': 'like',
    }

    self.__prefix = {
        '++': 'asc_order',
        '--': 'desc_order',
        '??': 'random_order',
    }

  def set(self, key: str, val: str) -> int:
    ''' Set a single value '''
    data, vsz, ts = self.store.serialize(key, val)
    return self.store.write(data, key, vsz, ts)

  def get(self, key: str) -> int:
    ''' Get a value '''
    val = self.store.read(key)
    if val is not None:
      stdout.write(f'{val}\n')
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

  def hset(self, key_or_index: str, *members: str) -> int:
    ''' 
    set multiple members to a hash
    (a member is a key/value pair)
    '''
    if len(members) % 2 != 0:
      print(f'HSET: members mismatch. (missing key or value?)', file=stderr)
      return 1

    if self.store.is_index(key_or_index):
      keys = self.store.get_index_keys(key_or_index)
    else:
      keys = [key_or_index]

    if not keys:
      print(f'HSET: `{key_or_index}` no such key or index.', file=stderr)
      return 1

    for key in keys:
      kv = self.store.read_hash(key)
      refs: list(str) = []
      # process fields and values
      for k, v in zip(members[::2], members[1::2]):
        if v in self.store.keystore: # ref
          refs.append(v)
        kv[k] = v

      data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
      if self.store.write(data, key, vsz, ts, refs) != 0:
        return 1
    return 0

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
      print(f'HGET: Error: invalid index or key `{index_or_key}`.')
      return 1

    # no fields case
    if not fields:
      if self.store.is_index(index_or_key):
        start_keys = sorted(self.store.get_index_keys(index_or_key))
        if not start_keys:
          print(f'HGET: No keys found for index `{index_or_key}`.', file=stderr)
          return 1
      elif index_or_key in self.store.keystore:
        start_keys = [index_or_key]
      else:
        print(f'HGET: Error: `{index_or_key}`, no such key or index.', file=stderr)
        return 1

      all_fields = set()
      for key in start_keys:
        data = self.store.read_hash(key)
        all_fields.update(data.keys())
      all_fields = sorted(all_fields)

      rows = []
      for key in start_keys:
        data = self.store.read_hash(key)
        row = [key] + [str(f) + '=' + str(data.get(f, '???')) for f in all_fields]
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
    else:
      start_keys = [index_or_key]

    if not start_keys:
      print(f'HGET: No keys found for index `{index_or_key}`.', file=stderr)
      return 1

    rows = []
    for start_key in sorted(start_keys):
      # collect related keys for each index
      key_map = {
          idx: sorted(self.store.get_refs(start_key, idx)) for idx in used_indexes
          if self.store.is_index(idx)
      }

      # check relational integrity
      for pf in parsed_fields:
        if pf['index'] and not key_map.get(pf['index']):
          # ignore when index is used in field expressions...
          # i.e. `HGET artist artist:name`
          if not start_key.startswith(pf['index'] + ':'):
            print(f'HGET: Warning: no `{pf["index"]}` key found for `{start_key}`.',
                  file=stderr
            )

      # find the deepest index for row iteration
      max_depth = max(
          (len(f['fields']) if f['index'] else 0 for f in parsed_fields), default=0
      )

      deepest_index = None
      for pf in reversed(parsed_fields):
        if pf['index'] and len(pf['fields']) == max_depth:
          deepest_index = pf['index']
          break

      if deepest_index:
        deep_keys = key_map.get(deepest_index, [])
        for deep_key in deep_keys:
          row = []
          # reconstruct the path to deep_key using parent_map
          path = [start_key] + self.store.find_path(start_key, deep_key) + [deep_key]

          # buld row using the path
          for pf in parsed_fields:
            index, fields = (pf['index'], pf['fields'])
            if index is None:
              # simple field from start_key
              data = self.store.read_hash(start_key)
              for field in fields:
                row.append(str(data.get(field, '???')))
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
                  if self.store.are_related(deep_key, target_key):
                    related_key = target_key
                    break
              # still not found...
              if not related_key:
                row.append('???')
                continue
              
              data = self.store.read_hash(related_key)
              if fields == ['*']:
                values = [str(data.get(k, '???')) for k in sorted(data.keys())]
                row.extend(values)
              else:
                for field in fields:
                  row.append(str(data.get(field, '???')))

          if row and any(v for v in row):
            rows.append(row)
      else:
        row = []
        for pf in parsed_fields:
          data = self.store.read_hash(start_key)
          for field in pf['fields']:
            row.append(str(data.get(field, '???')))
        if row and any(v for v in row):
          rows.append(row)

    if not rows:
      print(f'HGET: No data for `{index_or_key}.`', file=stderr)
      return 1

    for row in rows:
      print(' | '.join(str(v) for v in row if row))

    return 0

  def hdel(self, key: str, *fields: str) -> int:
    ''' Delete a hash or fields in a hash '''
    if not fields:
      # delete hash
      return self.delete(key)

    kv = self.store.read_hash(key)
    if not kv:
      print(f'HDEL: `{key}`, no such key.', file=stderr)
      return 1

    err = 0
    for field in fields:
      try:
        v = kv.pop(field)
        if self.store.is_ref(v, key):
          self.store.delete_ref(key, v)
      except KeyError:
        print(f'HDEL: `{key}`: unknown field: {field}', file=stderr)
        err += 1

    data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
    err += 0 if self.store.write(data, key, vsz, ts) > 0 else 1
    return err

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
        print(f'{k}: {" | ".join(sorted(kv.keys()))}')
      return 0
    err = 0
    for k in sorted(self.store.keystore.keys()):
      if not self.store.has_index(k):
        continue
        err += self.hkey(k)
      kv = self.store.read_hash(k)
      print(f'{k}: {" | ".join(sorted(kv.keys()))}')
    return 0 if err == 0 else 1

  def flush(self):
    return self.store.flush()
