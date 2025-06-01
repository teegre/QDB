import fcntl
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

# key: a key in simple key/value pair
# hash: a multiple field/value pair
# hkey : a key in a key/hash pair
# field : a key in a hash
# index: kind of like a table
# reference: a key used as a value in a field

class MuDBError(Exception):
  pass

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
    self._refs_file: str = os.path.join(self.database, '.references')
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

  def write_references(self) -> int:
    if self.refs:
      refs = {ref: sorted(list(keys)) for ref, keys in self.refs.items()}
      data = json.dumps(refs)
      rsz = len(data)
      with open(self._refs_file,'wb') as f:
        rec = struct.pack(f'<4sI{rsz}s', 'REFS'.encode(), rsz, data.encode())
        bytes_written = f.write(rec)
        if bytes_written != len(rec):
          print('Error writing references: incomplete write {bytes_written}/{len(rec)} bytes.', file=stderr)
          return 1
    return 0

  def load_references(self) -> int:
    if os.path.exists(self._refs_file):
      with open(self._refs_file, 'rb') as f:
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

  def read_hash(self, key: str) -> dict:
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
          return {}

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

  def read_hash_field(self, key: str, field: str) -> int:
    data = self.read_hash(key)
    if data:
      print(data.get(field, '?NOFIELD?'))
      return 0
    print('?NOHKEY?')
    return 1

  def delete(self, key: str) -> int:
    '''
    Delete a key from the keystore
    and mark it for deletion
    '''
    if key in self.keystore:
      if self.is_refd(key):
        print(f'DEL: Error: key `{key}` is referenced.', file=stderr)
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
      if self.is_refd(key):
        self.delete_ref(key)
      if self.has_index(key) and self.is_index_empty(key):
        self.delete_index(key)
      self.write_references()
      return 0
    return 1

  def dump(self) -> None:
    ''' Dump current database in json format '''
    for key in self.keystore.keys():
      if self.has_index(key): # hash
        data = {key: self.read_hash(key)}
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

  def delete_index(self, key: str) -> int:
    if self.is_index(key) and self.is_index_empty(key):
      self.indexes.discard(key)
      return 0
    if self.has_index(key):
      if self.is_refd(key):
        print(f'Error: `{key}` is referenced.', file=stderr)
        return 1
      try:
        index = key.split(':')[0]
        self.indexes.discard(index)
      except KeyError:
        print(f'Error: {index} index not found.', file=stderr)
        return 1
      return 0
    return 1

  def get_index(self, key: str) -> str | None:
    ''' Return the index of a given key. '''
    if not key in self.keystore:
      return None
    index = key.split(':')[0]
    if self.is_index(index):
      return index
    return None

  def get_index_keys(self, index: str) -> list:
    ''' Get all the keys for a given index. '''
    if self.is_index(index):
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
    if refs is None and self.has_index(hkey):
      self.refs[hkey] = set([ref])
      return 0
    if self.has_index(hkey):
      self.refs[hkey].add(ref)
      return 0
    return 1

  def get_all_ref_hkeys(self, index: str) -> list[str]:
    ''' Return all referenced hkeys'''
    refs = []
    for hkey, hrefs in self.refs.items():
      if hkey.startswith(index + ':'):
        refs.extend(list(hrefs))
    return sorted([str(r) for r in refs])

  def get_ref(self, key: str) -> str:
    ''' Return the ref referenced by key if any. '''
    for ref, keys in self.refs.items():
      if key in keys:
        return ref
    return None

  def get_refs(self, key: str, index: str) -> list[str]:
    '''
    Return a list of keys of type `index` that are reachable
    from `key` through any number of references!
    '''
    if not self.has_index(key) or not self.is_index(index):
      return []

    reverse_refs = {}
    for k, refs in self.refs.items():
      for ref in refs:
        reverse_refs.setdefault(ref, set()).add(k)

    forward_refs = set()
    queue = deque([key])
    visited = {key}

    while queue:
      current_key = queue.popleft()
      for neighbor in self.refs.get(current_key, set()):
        if neighbor.startswith(index + ':'):
          forward_refs.add(neighbor)
        if neighbor not in visited:
          visited.add(neighbor)
          queue.append(neighbor)

    # Reverse lookup
    reverse_refs_set = set()
    queue = deque([key])
    visited = {key}

    while queue:
      current_key = queue.popleft()
      for neighbor in reverse_refs.get(current_key, set()):
        if neighbor.startswith(index + ':'):
          reverse_refs_set.add(neighbor)
        if neighbor not in visited:
          visited.add(neighbor)
          queue.append(neighbor)

    return sorted(forward_refs | reverse_refs_set)

  def get_ref_key(self, key: str) -> str:
    ''' Get the key that key references to... '''
    for ref, keys in self.refs.items():
      if ref in keys:
        return ref
    return None

  def get_refs_of(self, hkey: str) -> list[str]:
    ''' Get references of key. '''
    found_refs = []
    for key, refs in self.refs.items():
      if hkey in refs:
        found_refs.append(key)
    return found_refs

  def are_related(self, k1: str, k2: str) -> bool:
    ''' Return True if k1 and k2 are directly related '''
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

  def delete_key_of_ref(self, hkey: str, ref: str) -> int:
    '''
    Delete the `ref` referenced by `hkey` and
    delete `hkey` if it's no longer referenced.
    Return 0 on success, 1 on fail.
    '''
    refs = self.refs.get(hkey)
    if refs is None:
      return 1
    self.refs[key].discard(ref)
    if len(self.refs[hkey]) == 0:
      del self.refs[hkey]
    return 0

  def delete_ref(self, ref: str) -> None:
    '''
    Delete ref in all keys.
    Delete key if not used by any ref.
    '''
    empty_refs = []
    for key, refs in self.refs.items():
      if ref in refs:
        self.refs[key].discard(ref)
        if len(refs) == 0:
          empty_refs.append(key)
    for key in empty_refs:
      del self.refs[key]

  def get_most_recent_hkey_from_index(self, index: str) -> str:
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
    hkey = self.get_most_recent_hkey_from_index(index)
    if not hkey:
      return []
    return list(self.read_hash(hkey).keys())

  def has_index(self, key: str) -> bool:
    ''' Return True if a given key has an index, False otherwise. '''
    index = key.split(':')[0]
    return index in self.indexes and key in self.keystore

  def is_index(self, index: str) -> bool:
    return index in self.indexes

  def is_index_of(self, hkey: str, index: str) -> bool:
    ''' Return true if hkey belongs to index. '''
    try:
      key, _ = hkey.split(':')
    except ValueError:
      return False
    return self.is_index(index) and key == index

  def is_index_empty(self, index_or_key: str) -> bool:
    ''' Return True if index or key of index is empty. '''
    index = index_or_key.split(':')[0]
    if self.is_index(index):
      return len(self.get_index_keys(index)) == 0
    return False

  def is_refd(self, hkey: str) -> bool:
    ''' Return True is hkey is referenced '''
    for refs in self.refs.values():
      if hkey in refs:
        return True
    return False

  def is_refd_by(self, key: str, ref: str) -> bool:
    ''' Return True if `key` references `ref`. '''
    return ref in self.refs.get(key, {})

  def has_ref(self, key: str) -> bool:
    return key in self.refs

  def exists(self, key: str) -> bool:
    ''' Return True if `key` exists in the keystore. '''
    return key in self.keystore

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

