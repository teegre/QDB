import os
import json
import struct

from dataclasses import dataclass
from glob import glob
from shutil import move
from sys import stdin, stdout, stderr
from time import time, strftime
from zlib import crc32

# Record format on disk:
# CRC TS VTYPE KSZ VSZ K V
#     <------- CRC ------>
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
# VTYPE = VALUE TYPE (1 byte: either - or +)
# KSZ = KEY SIZE
# VSZ = VALUE SIZE
# VPOS = VALUE POSITION

#             CRC TS  VTYPE KSZ VSZ
HEADER_SIZE = 4 + 8 + 1 + 4 + 4
HINT_HEADER_SIZE = HEADER_SIZE - 1

class MicroDBError(Exception):
  pass

@dataclass
class KeyStoreEntry:
  filename: str
  value_size: int
  position: int
  timestamp: int

class ReferenceEntry:
  def __init__(self, key: str, count:int=0):
    self.key: str = key
    self.count: int = count

  def __repr__(self):
    return f'Ref(key={self.key}, count={self.count})'

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
      stderr.write(f'Error: flushing did not work: {e}.\n')
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
    ''' write data to file, update keystore '''
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
        if ':' in key:
          self.create_index(key)
        for ref in refs :
          self.create_ref(ref, key)

      return 0 if bytes_written > 0 else 1
    except:
      stderr.write(f'Error writing key: `{key}`.\n')
      return 1

  def read(self, key: str) -> str:
    ''' read data for the given key '''
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
      return None

    return val.decode()

  def read_hash(self, key: str) -> dict:
    ''' return hash for the given key as a dict '''
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
        return None

      f.seek(pos + HEADER_SIZE + ksz)
      val = f.read(vsz)

      if fn != self.active_file:
        f.close()

      data = json.loads(val.decode())
      return data

    return None

  def delete(self, key: str) -> int:
    '''
    delete a key from the keystore
    and mark it for deletion
    '''
    if key in self.keystore:
      if self.has_refs(key):
        stderr.write(f'DEL: Error: key `{key}` has references.\n')
        return 1
      ts = int(time())
      ksz = len(key)
      vsz = 0
      rec = struct.pack(f'<Q1sII{ksz}s', ts, '-'.encode(), ksz, vsz, key.encode())
      crc = crc32(rec)
      data = struct.pack('<L', crc) + rec
      self.write(data, key, vsz, ts)
      self.keystore.pop(key, None)
      return 0
    return 1

  def reconstruct(self) -> int:
    ''' reconstruct keystore from data files '''
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
    ''' populate keystore  '''
    with open(file, 'rb') as f:
      pos = 0
      while True:
        try:
          header = f.read(HEADER_SIZE)
          if not header:
            break
          if len(header) != HEADER_SIZE:
            stderr.write(f'Warning: incomplete header at {file}:{pos}\n')
            return 1
          crc, ts, vt, ksz, vsz = self.deserialize_header(header)

          key = f.read(ksz)
          val = f.read(vsz)

          # check CRC validity
          if not self.check_crc(crc, ts, vt, ksz, vsz, key, val):
            stderr.write(f'Warning: bad CRC at {file}:{pos}\n')
            return 1

          key = key.decode()

          if len(key) != ksz:
            stderr.write(f'Warning: incomplete key at {file}:{pos}\n')
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
          stderr.write(f'Error processing record at {file}:{pos}: {e}\n')
          return 1
    return 0

  def reconstruct_from_hint(self, hint_file: str) -> int:
    ''' reconstruct keystore from a hint file '''
    with open(hint_file, 'rb') as h:
      fpos = 0
      while True:
        header = h.read(HINT_HEADER_SIZE)
        if not header:
          break
        if len(header) != HINT_HEADER_SIZE:
          stderr.write(f'Warning: incomplete header at {hint_file}:{pos}\n')
          break
        ts, ksz, vsz, pos = struct.unpack('<QIII', header)
        key = h.read(ksz)
        if len(key) != ksz:
          stderr.write(f'Warning: incomplete header at {hint_file}:{fpos}\n')
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
    ''' compact files and clean database directory '''
    if self.file is not None:
      if self.flush() != 0:
        return
      stderr.write('Flushed and closed active file\n')

    files = [f for f in sorted(glob(os.path.join(self.database, '*.log')))
             if f != self.active_file]
    if not files or len(files) == 1:
      stderr.write('Nothing to do.\n')
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
              stderr.write(f'Error: incomplete header at {file}:{pos}\n')
              break
            crc, ts, vt, ksz, vsz = self.deserialize_header(header)

            key = f.read(ksz)
            val = f.read(vsz)
            
            # check CRC validity
            if not self.check_crc(crc, ts, vt, ksz, vsz, key, val):
              stderr.write('Error: bad CRC at {file}:{pos}\n')
              warnings += 1
              break

            key = key.decode()
            if key not in latest_records or ts > latest_records[key][2]:
              latest_records[key] = (file, pos, ts, vt, ksz, vsz)

            pos = f.tell()
          except Exception as e:
            stderr.write(f'Error processing record at {file}:{pos}: {e}\n')
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
        stderr.write(f'Error removing file {file}: {e}\n')
        return 1

    stderr.write('Success!.\n')
    return warnings

  def create_index(self, key: str) -> int:
    index = key.split(':')[0]
    if not index or index.isdigit():
      stderr.write(f'Error: bad key name: `{index}`\n')
      return 1
    self.indexes.add(index)
    return 0

  def delete_index(self, key: str) -> int:
    if self.has_index(key):
      if self.has_index_refs(key):
        stderr.write(f'Error: `{key}` has references.\n')
        return 1
      try:
        index = key.split(':')[0]
        del self.indexes[index]
      except KeyError:
        stderr.write(f'Error: {key.split()}index not found.\n')

  def create_ref(self, key: str, ref: str) -> int:
    refs = self.refs.get(key)
    if refs is None and self.has_index(key):
      self.refs[key] = set([ref])
      return 0
    if self.has_index(key):
      self.refs[key].add(ref)
      return 0
    return 1

  def get_refs(self, key: str, ref: str) -> list:
    refs = self.refs.get(key)
    if refs:
      return [r for r in refs if ref in r]
    return []

  def delete_ref(self, key: str, ref: str) -> int:
    refs = self.refs.get(key)
    if refs is None:
      return 1
    self.refs[key].discard(ref)
    if len(self.refs[key]) == 0:
      del self.refs[src]

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

  def is_ref(self, key: str, ref: str) -> bool:
    refs = self.refs.get(key)
    return False if refs is None else ref in refs

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
        'HKEYS': self.hkeys,
        'HSET': self.hset,
        'KEYS': self.keys,
        'MDEL': self.mdel,
        'MGET': self.mget,
        'MSET': self.mset,
        'SET' : self.set,
    }

  def set(self, key: str, val: str) -> int:
    ''' set a single value '''
    data, vsz, ts = self.store.serialize(key, val)
    return self.store.write(data, key, vsz, ts)

  def get(self, key: str) -> int:
    ''' get a value '''
    val = self.store.read(key)
    if val is not None:
      stdout.write(f'{val}\n')
      return 0
    return 1

  def keys(self) -> int:
    for k in self.store.keystore.keys():
      print(k)
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
      stderr.write('MSET: invalid number of arguments.\n')
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
        stderr.write(f'MDEL: key `{key}` not found.\n')
    return err

  def hset(self, key: str, *members: str) -> int:
    ''' 
    set multiple members to a hash
    (a member is a key/value pair)
    '''
    if len(members) % 2 != 0:
      stderr.write(f'HSET: members mismatch. (missing key?)\n')
      return 1

    kv = self.store.read_hash(key)
    refs: list(str) = []
    if kv is None:
      kv = {}
    for k, v in zip(members[::2], members[1::2]):
      if ':' in v: #ref
        refs.append(v)
      kv[k] = v

    data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
    return self.store.write(data, key, vsz, ts, refs)

  def hquery(self, key: str, kv: dict[str,str], expr: str) -> list:
    q = expr.split(':')
    if not q or len(q) < 1:
      stderr.write(f'HGET: invalid expression `{expr}`')
      return
    if len(q) == 1 or (q[1] != '*' and not q[1:]):
      stderr.write(f'HGET: expression `{expr}` requires at least one column or `*`.')
      return
    refs = self.store.get_refs(key, q[0])
    rows = []

    for r in sorted(refs):
      subkv = self.store.read_hash(r)
      if q[1] == '*':
        row = [v for v in subkv.values()]
        rows.append(row)
      else:
        row = []
        for col in q[1:]:
          v = subkv.get(col)
          if v is None:
            stderr.write(f'HGET: invalid key `{col}` in expression: `{expr}`\n')
            return
          row.append(v)
        rows.append(row)
    if not rows:
      v = kv.get(q[0])
      row = []
      if v is None:
        stderr.write(f'HGET: invalid key `{q[0]}` in expression: `{expr}` (missing ref?)\n')
        return
      subkv = self.store.read_hash(v)
      if q[1] == '*':
        row = [v for v in subkv.values()]
        rows.append(row)
      else:
        for col in q[1:]:
          v = subkv.get(col)
          if v is None:
            stderr.write(f'HGET: invalid key `{col}` in expression: `{expr}`\n')
            return
          row.append(v)
        rows.append(row)
    return rows

  def hget(self, key: str, *fields: str) -> int:
    ''' get fields from a hash '''
    kv = self.store.read_hash(key)

    if kv is None:
      stderr.write(f'HGET: key `{key}` not found.\n')
      return 1
    if not fields:
      for k, v in kv.items():
        print(f'{k}: {v}')
      return 0

    err = 0
    rows = []

    for field in fields:
      if ':' in field:
        data = self.hquery(key, kv, field)
        if not data:
          stderr.write(f'HGET: error querying `{field}` for `{key}`.\n')
          return 1
        if len(data) == 1:
          if rows:
            for row in rows:
              row += data[0]
          else:
            rows = data
        elif len(data) > len(rows) and rows:
          for i, row in enumerate(data):
            data[i] = rows[0] + row
          rows = data
        else:
          rows += data
      else:
        v = kv.get(field)
        if v is None:
          stderr.write(f'HGET: field `{field}` not found.\n')
          return 1
        if rows:
          for row in rows:
            row += [v]
        else:
          rows = [[v]]

    if rows:
      for row in rows:
        print('|'.join(row))
    else:
      return 1

    return 0

  def hkeys(self, key: str) -> int:
    ''' get all fields for the given key '''
    kv = self.store.read_hash(key)
    if kv is None:
      return 1
    for k in kv.keys():
      print(k)
    return 0

  def hdel(self, key: str, *fields: str) -> int:
    ''' delete a hash or fields in a hash '''
    if not fields:
      # delete hash
      return self.delete(key)

    kv = self.store.read_hash(key)
    if kv is None:
      return 1

    err = 0
    for field in fields:
      try:
        v = kv.pop(key)
        if self.store.is_ref(v):
          self.store.delete_ref(key, v)
      except KeyError:
        stderr.write(f'HDEL: {key}: unknown field: {field}\n')
        err += 1

    data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
    err += 0 if self.store.write(data, key, vsz, ts) > 0 else 1
    return err

  def flush(self):
    return self.store.flush()
