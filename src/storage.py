import fcntl
import os
import json
import struct
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from collections import defaultdict, deque
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

# Terminology:
# key: a key in simple key/value pair
# hash: a multiple field/value pair
# hkey : a key in a key/hash pair
# field : a key in a hash
# index: kind of like a table
# reference: a hkey used as a value in a field

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
    self.indexes_map: Dict[str: set[str]] = {}
    self.refs: Dict[str: set[str]] = {}
    self._refs_cache: Dict[tuple[str, str]: set[str]] = {}
    self.reverse_refs: Dict[str: set[str]] = {}
    self.transitive_reverse_refs = defaultdict(lambda: defaultdict(set))
    self.file = None
    self._file_id: int = self._max_id
    self._file_pos: int = 0
    self.initialize()

  def initialize(self):
    self.reconstruct()
    self.build_indexes_map()
    self.update_reverse_refs()

  def open(self) -> int:
    if not os.path.exists(self.database):
      os.mkdir(self.database)
    self._file_id = self._max_id
    try:
      self.file = open(self.active_file, 'ab+')
      return 0
    except (IOError, OSError):
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
      fcntl.flock(self.file, fcntl.LOCK_EX)
      self.file.seek(self._file_pos)
      bytes_written = self.file.write(data)
      if bytes_written != len(data):
        print(f'Error writing `{key}`: imcomplete write: {bytes_written}/{len(data)} bytes.', file=stderr)
        return 1

      self.file.flush()

      self.keystore[key] = KeyStoreEntry(
          self.active_file,
          vsz,
          self._file_pos,
          ts
      )
      self._file_pos = self.file.tell()
      # TODO: Check hkey syntax → INDEX:ID
      if ':' in key:
        if self.create_index(key) != 0:
          return 1
      for ref in refs :
        self.create_ref(key, ref)

      self.write_references()

      return 0
    except Exception as e:
      print(f'Error writing key: `{key}`.', file=stderr)
      return 1
    finally:
      fcntl.flock(self.file, fcntl.LOCK_UN)
      self.update_reverse_refs()

  def write_references(self, ref_file: str=None) -> int:
    if ref_file is not None:
      rf = ref_file
    else:
      rf = self.active_refs
    if self.refs:
      refs = {ref: sorted(list(keys)) for ref, keys in self.refs.items()}
      data = json.dumps(refs)
      rsz = len(data)
      with open(rf,'wb') as f:
        rec = struct.pack(f'<4sI{rsz}s', 'REFS'.encode(), rsz, data.encode())
        bytes_written = f.write(rec)
        if bytes_written != len(rec):
          print('Error writing references: incomplete write {bytes_written}/{len(rec)} bytes.', file=stderr)
          return 1
    return 0

  def load_references(self, ref_file: str=None) -> int:
    if ref_file is not None:
      rf = ref_file
    else:
      rf = self.active_refs

    if os.path.exists(rf):
      with open(rf, 'rb') as f:
        header = f.read(8)
        tag, rsz = struct.unpack('<4sI', header)
        if tag.decode() != 'REFS':
          print(f'Error: invalid reference file.', file=stderr)
          return 1
        data = f.read(rsz)
        refs = json.loads(data.decode())
        for ref, keys in refs.items():
          self.refs[ref] = set(keys)
    return 0

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

  def read_hash(self, key: str, dump: bool=False) -> dict:
    ''' Return the hash associated to the given key '''
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
        try:
          f = open(fn, 'rb')
        except FileNotFoundError:
          print(f'Error: data file not found for `{key}` key.', file=stderr)
          return None

      f.seek(pos)
      header = f.read(HEADER_SIZE)
      vt = self.deserialize_header(header)[2]

      if vt.decode() != '+':
        if fn != self.active_file:
          f.close()
        print(f'Error: {key} is not a hash.', file=stderr)
        return None

      f.seek(pos + HEADER_SIZE + ksz)
      val = f.read(vsz)

      if fn != self.active_file:
        f.close()

      data = json.loads(val.decode())

      if not dump:
        ID = key.split(':')[1]
        data['@id'] = ID
        data['@hkey'] = key

      return data

    return None

  def read_hash_field(self, key: str, field: str) -> int:
    data = self.read_hash(key)
    if data:
      return(data.get(field, '?NOFIELD?'))
    return None

  def delete(self, key: str) -> int:
    '''
    Delete a key from the keystore
    and mark it for deletion
    '''
    if key in self.keystore:
      if self.has_ref(key):
        print(f'Error: key `{key}` is referenced.', file=stderr)
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
      if self.is_ref(key):
        self.delete_ref(key)
      index = self.get_index(key)
      self.keystore.pop(key, None)
      if self.is_index_empty(index):
        self.delete_index(index)
      self.write_references()
      return 0
    return 1

  def dump(self) -> None:
    ''' Dump current database in json format '''
    for key in sorted(self.keystore.keys()):
      if self.has_index(key): # hash
        data = {key: self.read_hash(key, dump=True)}
      else:
        data = {key: self.read(key) }
      print(json.dumps(data))

  def keystore_dump(self) -> None:
    ''' Dump keystore content '''
    for k, v in self.keystore.items():
      print(f'{k}: {v}')

  def reconstruct(self) -> int:
    ''' Reconstruct keystore from data files '''
    files = sorted(glob(os.path.join(self.database, "*.log")))
    err = 0
    for file in files:
      hint_file = file.replace('.log', '.hint')
      ref_file = file.replace('.log', '.ref')
      # remove empty files...
      if os.path.getsize(file) == 0:
        os.remove(file)
        if os.path.exists(hint_file):
          os.remove(hint_file)
        if os.path.exists(ref_file):
          os.remove(ref_file)
        continue
      if os.path.exists(hint_file):
        err += self.reconstruct_from_hint(hint_file)
        err += self.load_references(ref_file)
        continue
      err += self.reconstruct_keystore(file)
      err += self.load_references(ref_file)
    # delete empty indexes if any:
    for index in self.indexes.copy():
      if self.is_index_empty(index):
        self.delete_index(index)
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
          vt = vt.decode()

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

          pos = f.tell()
        except Exception as e:
          print(f'Error processing record at {file}:{pos}: {e}', file=stderr)
          return 1

    return self.load_references()

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

        key = key.decode()

        if vsz == 0:
          self.keystore.pop(key, None)
        else:
          entry = self.keystore.get(key)
          if entry is None or ts > entry.timestamp:
            self.keystore[key] = KeyStoreEntry(hint_file.replace('.hint', '.log'), vsz, pos, ts)

            if ':' in key:
              self.create_index(key)

        fpos = h.tell()
    return self.load_references()
        
  def compact(self) -> int:
    ''' Compact files and clean database directory '''
    if self.file is not None:
      if self.flush() != 0:
        return
      print('Flushed and closed active file', file=stderr)

    files = [f for f in sorted(glob(os.path.join(self.database, '*.log')))
             if f != self.active_file]
    if not files:
      print('Nothing to do.', file=stderr)
      return 0

    name = strftime('%Y%m%d_%H%M%S')
    newfile = os.path.join(self.database, f'{name}.log')
    newhint = newfile.replace('.log', '.hint')
    newrefs = newfile.replace('.log', '.ref')
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

    if warnings > 0:
      return 1

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
        ref_file = file.replace('.log', '.ref')
        if os.path.exists(hint_file):
          os.remove(hint_file)
        if os.path.exists(ref_file):
          os.remove(ref_file)
      except Exception as e:
        print(f'Error removing file {file}: {e}', file=stderr)
        return 1

      self.write_references(newrefs)

    print('Success!', file=stderr)
    return warnings

  def create_index(self, hkey: str) -> int:
    ''' Create an index from the given key. '''
    try:
      index, _ = hkey.split(':')
    except ValueError:
      index = None
    if not index or index.isdigit():
      print(f'Error: invalid hkey name: `{index}`', file=stderr)
      return 1
    self.indexes.add(index)
    return 0

  def delete_index(self, index: str) -> int:
    ''' Delete the given empty index. '''
    if self.is_index(index) and self.is_index_empty(index):
      self.indexes.discard(index)
      return 0
    if not self.is_index(index):
      print(f'Error: `{index}`, no such index.', file=stderr)
      return 1
    keycount = len(self.get_index_keys(index))
    print(
        f'Error: `{index}` still contains {keycount}',
        'hkeys' if keycount > 1 else 'hkey',
        file=stderr
    )
    return 1

  def get_index(self, key: str) -> str | None:
    ''' Return the index of a given key if key and index exist. '''
    if not key in self.keystore:
      return None
    try:
      index = key.split(':')[0]
    except ValueError:
      return None
    if self.is_index(index):
      return index
    return None

  def get_index_keys(self, index: str) -> list:
    ''' Get all the keys for a given index. '''
    if self.is_index(index):
      keys = self.indexes_map.get(index)
      if keys:
        return keys
      return [k for k in self.keystore.keys() if k.startswith(index + ':')]
    return []

  def create_ref(self, hkey: str, ref: str) -> int:
    ''' Add a reference for a given key '''
    if hkey == ref:
      print(f'Error: `{hkey}` references itself! (ignored).', file=stderr)
      return 1
    if not self.exists(hkey):
      return 1
    refs = self.refs.get(hkey)
    rev_refs = self.refs.get(ref)
    if refs is None and self.has_index(hkey):
      self.refs[hkey] = set([ref])
      if rev_refs is None:
        self.reverse_refs[ref] = set([hkey])
      else:
        self.reverse_refs[ref].add(hkey)
      return 0
    if self.has_index(hkey):
      self.refs[hkey].add(ref)
      if rev_refs is None:
        self.reverse_refs[ref] = set([hkey])
      else:
        self.reverse_refs[ref].add(hkey)
      return 0
    return 1

  def build_indexes_map(self):
    for index in self.indexes:
      self.indexes_map.setdefault(index, set())
      for key in self.get_index_keys(index):
        self.indexes_map[index].add(key)

  def get_all_ref_hkeys(self, index: str) -> list[str]:
    ''' Return all referenced hkeys'''
    refs = []
    for hkey, hrefs in self.refs.items():
      if hkey.startswith(index + ':'):
        refs.extend(list(hrefs))
    return sorted(set(str(r) for r in refs))

  def get_ref(self, key: str) -> str:
    ''' Return the ref referenced by key if any. '''
    for ref, keys in self.refs.items():
      if key in keys:
        return ref
    return None

  def build_hkeys_flat_refs(self, hkeys: set) -> dict:
    flat_refs = defaultdict(lambda: defaultdict(set))

    visited = set()

    def dfs(cur_key):
      if (root_key, cur_key) in visited:
        return
      visited.add((root_key, cur_key))

      refs = self.refs.get(cur_key, set())
      # if not refs:
      #   refs = self.reverse_refs.get(cur_key, set())
      for ref in refs:
        idx = self.get_index(ref)
        flat_refs[root_key][idx].add(ref)
        dfs(ref)

    for root_key in hkeys:
      dfs(root_key)

    return flat_refs

  def update_reverse_refs(self):
    reverse_refs = {}
    for k, refs in self.refs.items():
      for ref in refs:
        reverse_refs.setdefault(ref, set()).add(k)
    self.reverse_refs = reverse_refs

  def get_refs_with_index(self, key: str, index: str) -> set:
    '''
    Return the direct references or reverse references of 'key'
    if they are related to 'index'
    '''
    results = set()

    if not self.exists(key) or not self.is_index(index):
      return results

    for ref in self.refs.get(key, []):
      if self.is_index_of(ref, index):
        results.add(ref)

    if not results:
      for ref in self.reverse_refs.get(key, []):
        if self.is_index_of(ref, index):
          results.add(ref)

    return results

  def get_refs(self, key: str, index: str) -> list:
    '''
    Return all forward or reverse refs related to index
    '''
    if not self.has_index(key) or not self.is_index(index):
      return []

    if self.get_index(key) == index:
      return []

    if (key, index) in self._refs_cache:
      return self._refs_cache[(key, index)]

    path = self.find_index_path(self.get_index(key), index)
    if not path:
      return []

    results = {key}
    for i in range(len(path) - 1):
      next_idx = path[i + 1]
      refs = set()
      for ref in results:
        refs |= set(self.get_refs_with_index(ref, next_idx))
      results = refs

    if results:
      self._refs_cache[(key, index)] = sorted(results)

    return sorted(results)

  def get_ref_key(self, key: str) -> str:
    ''' Get the key that key references to... '''
    return self.reverse_refs.get(key, [])

  def get_refs_of(self, hkey: str) -> list[str]:
    ''' Get references of key. '''
    return self.refs.get(hkey, [])

  def are_related(self, k1: str, k2: str) -> bool:
    ''' Return True if k1 and k2 are directly related '''
    return k1 in self.refs.get(k2, []) or k2 in self.refs.get(k1, [])

  def get_transitive_backrefs(self, ref: str, index: str) -> set:
    if ref in self.transitive_reverse_refs[index]:
      return self.transitive_reverse_refs[index][ref]

    visited = set()
    result = set()

    def dfs(ref):
      if ref in visited:
        return
      visited.add(ref)

      for backref in self.reverse_refs.get(ref, set()):
        if self.is_index_of(backref, index):
          result.add(backref)
        else:
          dfs(backref)

    dfs(ref)

    self.transitive_reverse_refs[index][ref] = result
    return result

  def find_path(self, k1: str, k2: str, use_index: bool=False) -> list[str]:
    '''
    Returns the keys that form a path from k1 to k2 (or k2 to k1), if any.
    Considers forward references from self.refs and reverse references.
    Also works with indexes.
    '''
    if not use_index and (not self.has_index(k1) or not self.has_index(k2)):
      return []

    if use_index and (not self.is_index(k1) or not self.is_index(k2)):
      return []

    if k1 == k2:
      return []

    if use_index:
      k1 = next(iter(self.get_index_keys(k1)), None)
      k2 = next(iter(self.get_index_keys(k2)), None)

    queue = deque([(k1, [k1])])
    visited = {k1}

    while queue:
      current_key, path = queue.popleft()

      forward_neighbors = self.refs.get(current_key, set())
      reverse_neighbors = self.reverse_refs.get(current_key, set())
      neighbors = forward_neighbors | reverse_neighbors

      for neighbor in neighbors:
        if neighbor not in visited:
          visited.add(neighbor)
          new_path = path + [neighbor]
          queue.append((neighbor, new_path))

          if not use_index and neighbor == k2:
            return new_path
          if use_index and self.get_index(neighbor) == self.get_index(k2):
              index_path = [self.get_index(k) for k in new_path]
              return index_path

    # No path found
    return []

  def find_index_path(self, idx1: str, idx2: str) -> list:
    return self.find_path(idx1, idx2, use_index=True)

  def delete_ref_of_key(self, hkey: str, ref: str) -> int:
    '''
    Delete the `ref` referenced by `hkey` and
    delete `hkey` if it's no longer referenced.
    Return 0 on success, 1 on fail.
    '''
    refs = self.refs.get(hkey)
    if refs is None:
      return 1
    self.refs[hkey].discard(ref)
    if len(self.refs[hkey]) == 0:
      del self.refs[hkey]
    self.update_reverse_refs()
    return 0

  def delete_ref(self, ref: str) -> None:
    '''
    Delete ref in all keys.
    Delete key if not used by any ref.
    '''
    update = False
    for key, refs in self.refs.copy().items():
      if ref in refs:
        self.refs[key].discard(ref)
        update = True
        if len(refs) == 0:
          del self.refs[key]
    if update:
      self.update_reverse_refs()

  def _get_most_recent_hkey_from_index(self, index: str) -> str:
    '''
    Get the most recent hkey containing the most data
    from a given index
    '''
    hkeys = self.get_index_keys(index)
    if not hkeys:
      return None
    ts = 0
    vsz = 0
    hkey = None
    for hk in hkeys:
       ks_entry: KeyStoreEntry = self.keystore.get(hk)
       if ks_entry.timestamp > ts and ks_entry.value_size > vsz:
         ts = ks_entry.timestamp
         vsz = ks_entry.value_size
         hkey = hk
    return hkey

  def get_fields_from_index(self, index: str) -> list[str]:
    ''' Get fields of a given index. '''
    hkey = self._get_most_recent_hkey_from_index(index)
    if not hkey:
      return []
    return list(self.read_hash(hkey).keys())

  def has_index(self, key: str) -> bool:
    ''' Return True if a given key exists and has an index, False otherwise. '''
    index = key.split(':')[0]
    return index in self.indexes and key in self.keystore

  def is_index(self, index: str) -> bool:
    ''' Return True if index exists. '''
    return index in self.indexes

  def is_index_of(self, hkey: str, index: str) -> bool:
    ''' Return true if hkey exists and belongs to index. '''
    if hkey is None or index is None:
      return False
    return self.get_index(hkey) == index

  def is_index_empty(self, index_or_key: str) -> bool:
    ''' Return True if index or key of index is empty. '''
    index = index_or_key.split(':')[0]
    if self.is_index(index):
      return len(self.get_index_keys(index)) == 0
    return False

  def is_ref(self, hkey: str) -> bool:
    ''' Return True is hkey is a reference '''
    return hkey in self.keystore and hkey in self.reverse_refs

  def is_refd_by(self, key: str, ref: str) -> bool:
    ''' Return True if `key` references `ref`. '''
    return ref in self.refs.get(key, set())

  def is_refd_by_index(self, key: str, index: str) -> bool:
    ''' Return True if key exists and at least one reference of key belongs to index. '''
    refs = self.refs.get(key, [])
    for ref in refs:
      if self.is_index_of(key, index):
        return True and key in self.keystore
    return False

  def is_ref_of(self, ref: str, key: str) -> bool:
    ''' Return True if ref is a reference of key '''
    return ref in self.refs.get(key, set())

  def has_ref(self, key: str) -> bool:
    ''' Return True if key has references '''
    return key in self.keystore and key in self.refs

  def exists(self, key: str) -> bool:
    ''' Return True if `key` exists in the keystore. '''
    return key in self.keystore

  def index_len(self, index: str) ->  int:
    ''' Return the number of hkeys in the given index.'''
    if self.is_index(index):
      return sum(1 for k in self.keystore.keys() if k.startswith(index + ':'))
    return 0

  def database_schema(self):
    graph = defaultdict(set)
    all_children = set()
    unrelated = set()

    indexes = sorted(self.indexes)
    for i1 in indexes:
      for i2 in indexes:
        if i1 == i2:
          continue
        path = self.find_index_path(i1, i2)
        if path:
          for a, b in zip(path, path[1:]):
            graph[a].add(b)
            all_children.add(b)
        else:
          unrelated.update((i1, i2))

    unrelated -= all_children
    roots = sorted(self.indexes - unrelated)
    starting_points = roots or sorted(self.indexes)

    visited = set()

    def print_tree(node, prefix='', is_last=True, not_related=False):
      connector = '└─ ' if is_last else '├─ '
      line = prefix + connector + node
      if node in visited:
        line += ' (↻)'
        print(line)
        return

      if not_related:
        print(line + ' (x)')
      else:
        print(line)

      visited.add(node)

      children = sorted(graph.get(node, []))
      for i, child in enumerate(children):
        next_is_last = i == len(children) - 1
        next_prefix = prefix + ('   ' if is_last else '│  ')
        print_tree(child, next_prefix, next_is_last)

    for i, root in enumerate(starting_points):
      if root not in visited:
        print_tree(root, '', i == len(starting_points) - 1)
    if unrelated:
      print('x')
      for i, root in enumerate(sorted(unrelated)):
        print_tree(root, '', is_last=i == len(unrelated) - 1, not_related=True)

  def autoid(self, index: str) -> str:
    ''' Return current greatest ID + 1 in index '''
    return str(self.index_len(index) + 1)

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

  @property
  def active_refs(self) -> str:
    name = f'data{str(self._file_id).zfill(4)}.ref'
    return os.path.join(self.database, name)
