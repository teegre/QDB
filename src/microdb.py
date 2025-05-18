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

@dataclass
class KeyStoreEntry:
  filename: str
  value_size: int
  position: int
  timestamp: int

class Store:
  def __init__(self, name: str) :
    self.database = name
    self.keystore: Dict[str, KeyStoreEntry] = {}
    self.file = None
    self._file_id = self._max_id
    self._file_pos = 0
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
      stderr.write(f'error: flushing did not work: {e}\n')
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

  def write(self, data: bytes, key: str, vsz: int, ts: int) -> int:
    ''' write data to file '''
    if not self.file:
      self.open()
    try:
      self._file_pos = self.file.tell()
      bytes_written = self.file.write(data)
      self.keystore[key] = KeyStoreEntry(
          self.active_file,
          vsz,
          self._file_pos,
          ts
      )
      return bytes_written
    except:
      return 0

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
            stderr.write(f'warning: incomplete header at {file}:{pos}\n')
            return 1
          crc, ts, vt, ksz, vsz = self.deserialize_header(header)

          key = f.read(ksz)
          val = f.read(vsz)

          # check CRC validity
          if not self.check_crc(crc, ts, vt, ksz, vsz, key, val):
            stderr.write(f'warning: bad CRC at {file}:{pos}\n')
            return 1

          key = key.decode()

          if len(key) != ksz:
            stderr.write(f'warning: incomplete key at {file}:{pos}\n')
            return 1
          if vsz == 0:
            self.keystore.pop(key, None)
          else:
            entry = self.keystore.get(key)
            if entry is None or ts > entry.timestamp:
              self.keystore[key] = KeyStoreEntry(file, vsz, pos, ts)
          pos = f.tell()
        except Exception as e:
          stderr.write(f'error processing record at {file}:{pos}: {e}\n')
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
          stderr.write(f'warning: incomplete header at {hint_file}:{pos}\n')
          break
        ts, ksz, vsz, pos = struct.unpack('<QIII', header)
        key = h.read(ksz)
        if len(key) != ksz:
          stderr.write(f'reconstruct: warning: incomplete header at {hint_file}:{fpos}\n')
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
      stderr.write('compact: flushed and closed active file\n')

    files = [f for f in sorted(glob(os.path.join(self.database, '*.log')))
             if f != self.active_file]
    if not files or len(files) == 1:
      stderr.write('compact: nothing to do.\n')
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
              stderr.write(f'compact: incomplete header at {file}:{pos}\n')
              break
            crc, ts, vt, ksz, vsz = self.deserialize_header(header)

            key = f.read(ksz)
            val = f.read(vsz)
            
            # check CRC validity
            if not self.check_crc(crc, ts, vt, ksz, vsz, key, val):
              stderr.write('compact: bad CRC at {file}:{pos}\n')
              warnings += 1
              break

            key = key.decode()
            if key not in latest_records or ts > latest_records[key][2]:
              latest_records[key] = (file, pos, ts, vt, ksz, vsz)

            pos = f.tell()
          except Exception as e:
            stderr.write(f'compact: error processing record at {file}:{pos}: {e}\n')
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
        stderr.write(f'compact: error removing file {file}: {e}\n')

    stderr.write('compact: operation complete.\n')
    return warnings

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
        'SET' : self.set,
        'GET' : self.get,
        'DEL' : self.delete,
        'MSET': self.mset,
        'MGET': self.mget,
        'MDEL': self.mdel,
        'HSET': self.hset,
        'HGET': self.hget,
        'HDEL': self.hdel,
        'FLUSH': self.flush,
    }

    self.__types = {
        int: 'integer',
        float: 'float',
        str: 'string',
    }

  def set(self, key: str, val: str) -> int:
    ''' set a single value '''
    if type(val) in self.__types:
      data, vsz, ts = self.store.serialize(key, val)
      return self.store.write(data, key, vsz, ts)
    else:
      stderr.write(f'unknow type {type(value)}\n')
      return 0

  def get(self, key: str) -> str:
    ''' get a value '''
    val = self.store.read(key)
    if val is not None:
      stdout.write(f'{val}\n')
      return 0
    return 1

  def delete(self, key: str) -> int:
    ''' delete a single key '''
    return self.store.delete(key)
    
  def mset(self, *items: str) -> int:
    ''' set multiple values '''
    if len(items) % 2 != 0:
      stderr.write('mset: invalid number of arguments.\n')
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
        stderr.write(f'delete: key not found [{key}]\n')
    return err

  def hset(self, key: str, *members: str) -> int:
    ''' 
    set multiple members to a hash
    (a member is a key/value pair)
    '''
    if len(members) % 2 != 0:
      stderr.write(f'sset: members mismatch.\n')
      return 1

    kv = self.store.read_hash(key)
    if kv is None:
      kv = {}
    for k, v in zip(members[::2], members[1::2]):
      kv[k] = v
    data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
    return self.store.write(data, key, vsz, ts)

  def hget(self, key: str, *fields: str) -> int:
    ''' get members of a set '''
    kv = self.store.read_hash(key)
    if kv is None:
      return 1
    if not fields:
      for k, v in kv.items():
        print(f'{k}: {v}')
      return 0

    err = 0
    for field in fields:
      v = kv.get(field)
      if v is None:
        err += 1
        continue
      print(v)

    return err

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
        del kv[field]
      except KeyError:
        stderr.write(f'hdel: {key}: unknown field: {field}\n')
        err += 1

    data, vsz, ts = self.store.serialize(key, json.dumps(kv), string=False)
    err += 0 if self.store.write(data, key, vsz, ts) > 0 else 1
    return err


  def flush(self):
    return self.store.flush()
