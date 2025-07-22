import json
import os
import struct
import sys
import tarfile
import tempfile
import time

from dataclasses import dataclass
from io import BytesIO
from operator import itemgetter
from tarfile import TarInfo
from tempfile import TemporaryFile
from zlib import crc32

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb.lib.users import QDBUsers
from qdb.lib.utils import validate_hkey

from qdb.lib.exception import (
    QDBIOReadError, 
    QDBIOWriteError,
    QDBIOMissingLogError,
    QDBIODataIntegrityError,
    QDBIOCompactionError,
)

@dataclass
class QDBInfo:
  filename: str
  value_size: int
  position: int
  timestamp: int

@dataclass
class QDBHint:
  timestamp: int
  key_size: int
  value_size: int
  position: int
  key: bytes

@dataclass
class QDBHintHeader:
  timestamp: int
  key_size: int
  value_size: int
  position: int

@dataclass
class QDBIOHeader:
  crc: int
  timestamp: int
  value_type: bytes
  key_size: int
  value_size: int

@dataclass
class QDBData:
  header: QDBIOHeader
  data: bytes

class QDBIO:
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

  #                 CRC TS  VT  KSZ VSZ
  LOG_HEADER_SIZE = 4 + 8 + 1 + 4 + 4
  HINT_HEADER_SIZE = LOG_HEADER_SIZE - 1
  REFS_HEADER_SIZE = LOG_HEADER_SIZE - 5

  def __init__(self, database_path: str):
    self._database_path = database_path
    self._archive = None
    self._active_file = None
    self._active_file_size = 0
    self._position = 0
    self._active_refs = None
    self._active_refs_size = 0
    self.users = None
    self.isdatabase = False
    self.haschanged = False
    self._load()

  def _load(self):
    if os.path.exists(self._database_path):
      self._archive = tarfile.open(self._database_path, 'r:')
      self.isdatabase = True
    if self.users is None:
      self.users = QDBUsers(self._database_path)


  def _get(self, name):
    if self._archive:
      try:
        return self._archive.extractfile(name)
      except KeyError:
        return None
    return None

  def _new_tmp_file(self, origin: str=None, hint: bool=False, user: bool=False):
    tmp = tempfile.NamedTemporaryFile(prefix='qdb')

    if origin and hint:
      tmp.name = origin.replace('.log', '.hint')
    elif origin:
      tmp.name = origin.replace('.log', '.ref')
    elif user:
      tmp.name += '.user'
    else:
      tmp.name += '.log'

    return tmp
    
  def _serialize(self, key: str, value: str|dict, delete: bool=False) -> QDBData:
    data_value = value if isinstance(value, str) else json.dumps(value)
    timestamp =  int(time.time())
    value_type = b'-' if isinstance(value, str) else b'+'
    key_size = len(key)
    value_size = len(data_value) if not delete else 0

    crc_data = struct.pack(
        f'<Q1sII{key_size}s{value_size}s',
        timestamp,
        value_type,
        key_size,
        value_size,
        key.encode(),
        data_value.encode()
    )

    crc = crc32(crc_data)
    data = struct.pack('<L', crc) + crc_data
    header = QDBIOHeader(crc, timestamp, value_type, key_size, value_size)
    return QDBData(header, data)

  def _deserialize_header(self, header: bytes) -> QDBIOHeader:
    return QDBIOHeader(*struct.unpack('<LQ1sII', header))

  def _serialize_hint(self, qdbhint: QDBHint):
    return struct.pack(
        f'<QIII{qdbhint.key_size}s',
        qdbhint.timestamp,
        qdbhint.key_size,
        qdbhint.value_size,
        qdbhint.position,
        qdbhint.key
    )

  def _deserialize_hint_header(self, header: bytes) -> QDBHintHeader:
    return QDBHintHeader(*struct.unpack('<QIII', header))

  def _validate_crc(self, key: str, qdbdata: QDBData) -> bool:
    xcrc = crc32(struct.pack(
      f'<Q1sII{qdbdata.header.key_size}s{qdbdata.header.value_size}s',
      qdbdata.header.timestamp,
      qdbdata.header.value_type,
      qdbdata.header.key_size,
      qdbdata.header.value_size,
      key,
      qdbdata.data
    ))
    return xcrc == qdbdata.header.crc

  def read(self, qdbinfo: QDBInfo, key: str):
    name = qdbinfo.filename
    value_size = qdbinfo.value_size
    position = qdbinfo.position
    key_size = len(key)

    if self._active_file and self._active_file.name == qdbinfo.filename:
      logfile = self._active_file
    else:
      logfile = self._get(name)
    
    if logfile is None:
      raise QDBIOMissingLogError(f'IO Error: missing log entry: `{name}`.')

    logfile.seek(position)
    header = logfile.read(QDBIO.LOG_HEADER_SIZE)
    value_type = self._deserialize_header(header).value_type
    logfile.seek(position + QDBIO.LOG_HEADER_SIZE + key_size)
    value = logfile.read(value_size)

    if value_type == b'+': # Hash
      return json.loads(value.decode())
    if value_type == b'-':
      return value.decode()

    raise QDBIOReadError(f'IO Error: most likely due to a corrupted hint file: {name.replace('.log', '.hint')}')

  def write(self, key: str, value: str|dict, delete: bool=False) -> QDBInfo:
    if not self._active_file:
      self._active_file = self._new_tmp_file()
         
    qdbdata = self._serialize(key, value, delete=delete)
    self._active_file.seek(self._position)
    bytes_written = self._active_file.write(qdbdata.data)
    if bytes_written != len(qdbdata.data):
      raise QDBIOWriteError(f'IO Error: could not write data for `{key}`.')
    self._active_file_size += bytes_written

    qdbinfo = QDBInfo(
        self._active_file.name,
        qdbdata.header.value_size if not delete else 0,
        self._position,
        qdbdata.header.timestamp
    )

    self._position = self._active_file.tell()

    self.isdatabase = True

    return qdbinfo if not delete else None

  def _remove(self, *files: str):
    if not files:
      return
    temp = self._database_path + '.tmp'
    with tarfile.open(temp, 'w') as new:
      for tarinfo in self._archive.getmembers():
        if tarinfo.name not in files:
          new.addfile(tarinfo, self._archive.extractfile(tarinfo))

    os.replace(temp, self._database_path)

  def load_refs(self) -> dict:
    refs = {}
    empty = []
    reflist = [f for f in self._archive.getnames() if f.endswith('.ref')]

    for entry in reflist:
      ref_file = self._get(entry)
      header = ref_file.read(QDBIO.REFS_HEADER_SIZE)
      tag, size = struct.unpack('<12sI', header)

      if tag != b'__QDB_REFS__':
        raise QDBIOWriteError(f'IO Error: invalid references: {ref_file.name}.')
      data = json.loads(ref_file.read(size).decode())

      if not data:
        empty.add(ref_file)
        continue

      for hkey, ops in data.items():
        if isinstance(ops, list): # Compacted version
          refs.setdefault(hkey, set()).update(ops)
          continue
        if 'add' in ops:
          refs.setdefault(hkey, set()).update(ops['add'])
        if 'del' in ops:
          if ops['del'] == '__all__':
            refs.pop(hkey, None)
          else:
            for r in ops['del']:
              refs[hkey].discard(r)

    self._remove(*empty)

    return refs

  def save_refs(self, refs: dict, ref_file: TemporaryFile=None):
    if not refs:
      return

    if ref_file:
      self._active_refs = ref_file
    if not self._active_refs:
      self._active_refs = self._new_tmp_file(origin=self._active_file.name)

    if ref_file:
      refs_data = json.dumps({k: sorted(r) for k, r in refs.items()}).encode()
    else:
      refs_data = json.dumps(refs, sort_keys=True).encode()
    
    data = struct.pack(
        f'<12sI{len(refs_data)}s',
        b'__QDB_REFS__',
        len(refs_data),
        refs_data
    )

    bytes_written = self._active_refs.write(data)

    if bytes_written != len(data):
      raise QDBIOWriteError('IO Error: could not write references.')

    self._active_refs.flush()
    self._active_refs.seek(0, os.SEEK_END)
    self._active_refs_size = self._active_refs.tell()

  def save_cache(self, cache_data: BytesIO):
    if not self._archive:
      return
    if '.cache' in self._archive.getnames():
      self._remove('.cache')
    with tarfile.open(self._database_path, 'a') as tar:
      cacheinfo = tarfile.TarInfo('.cache')
      QDBUsers.set_user_info(cacheinfo)
      cacheinfo.size = cache_data.seek(0, os.SEEK_END)
      cache_data.seek(0)
      cacheinfo.mtime = time.time()
      tar.addfile(cacheinfo, cache_data)

  def load_cache(self) -> bytes:
    if not self._archive:
      return
    try:
      cache_data = self._archive.extractfile('.cache')
    except KeyError:
      cache_data = None
    return cache_data.read() if cache_data else b'{}'

  def flush(self, refs: dict=None, quiet: bool=False) -> str:
    if self._active_file:
      self._active_file.flush()

      if self._archive:
        self._archive.close()

      if not os.getenv('__QDB_QUIET__') and not quiet:
        print(f'QDB: Committing changes...', file=sys.stderr)

      self._archive = tarfile.open(self._database_path, 'a')

      info = tarfile.TarInfo(name=os.path.basename(self._active_file.name))
      QDBUsers.set_user_info(info)
      info.size = self._active_file_size
      info.mtime = time.time()
      self._active_file.seek(0)

      if refs:
        self.save_refs(refs)
        inforefs = tarfile.TarInfo(name=os.path.basename(self._active_refs.name))
        QDBUsers.set_user_info(inforefs)
        inforefs.size = self._active_refs_size
        inforefs.mtime = info.mtime
        self._active_refs.seek(0)

      try:
        self._archive.addfile(info, self._active_file)
        if refs:
          self._archive.addfile(inforefs, self._active_refs)
          self._active_file_size = 0
          self._active_refs = None
          refs.clear()
      except IOError:
        raise QDBIOWriteError('IO Error: new data could not be saved.')

      new_file = info.name

      self._active_file.close()
      self._active_file = None
      self._active_file_size = 0
      self._position = 0

      self._archive.close()

      if self.users:
        self.users._save()

      self._load()

      self.haschanged = True

      if not os.getenv('__QDB_QUIET__') and not quiet:
        print(f'QDB: Done.', file=sys.stderr)

      return new_file

  def compact(self, force: bool=False) -> dict:
    if not self.isdatabase and not self.users.haschanged:
      return

    if not force and not self.haschanged and not self.users.haschanged:
      return

    if not self.isdatabase and self.users.users:
      self._archive = tarfile.open(self._database_path, 'w')
      self.users._save()

    files = [f for f in sorted(self._archive.getnames()) if f.endswith('.log')]

    user_files = [u for u in sorted(self._archive.getnames()) if u.startswith('.users')]

    if self.users.haschanged or force:
      self._compact_users(user_files)

    if (not files or not self.haschanged) and not force:
      return

    if not os.getenv('__QDB_QUIET__'):
      print('QDB: Compacting database...', file=sys.stderr)

    latest = {}

    for file in files:
      position = 0
      warnings = 0

      log = self._get(file)

      while True:
        header = log.read(QDBIO.LOG_HEADER_SIZE)

        if not header:
          break

        header = self._deserialize_header(header)

        key = log.read(header.key_size)
        data = log.read(header.value_size)

        qdbdata = QDBData(header, data)

        if not self._validate_crc(key, qdbdata):
          print(f'IO Error: bad CRC: `{log.name}:{position}`', file=sys.stderr)
          warnings += 1
          break

        key = key.decode()
        if key not in latest or header.timestamp > latest[key][2]:
          latest[key] = (
              file,
              position,
              header.timestamp,
              header.value_type,
              header.key_size,
              header.value_size
          )

        position = log.tell()

    if warnings > 0:
      raise QDBIODataIntegrityError('IO Error: database compaction failed.')

    keystore = {}
        
    tmplog = self._new_tmp_file()
    tmphint = self._new_tmp_file(origin=tmplog.name, hint=True)

    logname = os.path.basename(tmplog.name)
    hintname = os.path.basename(tmphint.name)

    refs = {}
    position = 0
    logsize = 0
    hintsize = 0

    for key, (oldfile, oldpos, ts, vt, ksz, vsz) in sorted(latest.items(), key=itemgetter(0)):
      if vsz == 0: # Marked for deletion
        continue

      oldlog = self._get(oldfile)
      oldlog.seek(oldpos + QDBIO.LOG_HEADER_SIZE + ksz)
      val = oldlog.read(vsz)
      oldlog.close()

      qdbdata = self._serialize(
          key, 
          val.decode() if vt == b'-' else json.loads(val.decode())
      )
      tmplog.write(qdbdata.data)
      hint = self._serialize_hint(QDBHint(ts, ksz, vsz, position, key.encode()))
      tmphint.write(hint)
      tmplog.flush()
      tmphint.flush()
      tmplog.seek(0, os.SEEK_END)
      tmphint.seek(0, os.SEEK_END)
      logsize = tmplog.tell()
      hintsize = tmphint.tell()

      keystore[key] = QDBInfo(logname, vsz, position, ts)
      position += QDBIO.LOG_HEADER_SIZE + ksz + vsz

      oldref = oldlog.name.replace('.log', '.ref')
      if oldref in self._archive.getnames():
        ref = self._get(oldref)

    new = tarfile.open(self._database_path + '.tmp', 'w')

    references = [r for r in self._archive.getnames() if r.endswith('.ref')]

    tmplog.seek(0)
    tmphint.seek(0)

    infolog = tarfile.TarInfo(name=logname)
    infohint = tarfile.TarInfo(name=hintname)
    QDBUsers.set_user_info(infolog)
    QDBUsers.set_user_info(infohint)
    infolog.size = logsize
    infohint.size = hintsize
    infolog.mtime = infohint.mtime = time.time()

    if references:
      tmprefs = self._new_tmp_file(origin=logname)
      refs = self.load_refs()
      self.save_refs(refs, ref_file=tmprefs)
      tmprefs.seek(0)
      inforefs = tarfile.TarInfo(name=tmprefs.name)
      QDBUsers.set_user_info(inforefs)
      inforefs.size = self._active_refs_size
      inforefs.mtime = infolog.mtime

    try:
      new.addfile(infolog, tmplog)
      new.addfile(infohint, tmphint)
      if references:
        new.addfile(inforefs, tmprefs)
      if self.users.filename in self._archive.getnames():
        usersinfo = self._archive.getmember(self.users.filename)
        new.addfile(usersinfo, self._archive.extractfile(self.users.filename))
      if '.cache' in self._archive.getnames():
        cacheinfo = self._archive.getmember('.cache')
        new.addfile(cacheinfo, self._archive.extractfile('.cache'))
    except IOError as e:
      new.close()
      os.remove(new.name)
      raise QDBIOCompactionError('IO Error: compaction failed during last stage.')
    finally:
      tmplog.close()
      tmphint.close()
      if references:
        tmprefs.close()
      new.close()

    os.replace(new.name, self._database_path)
    self._load()

    if not os.getenv('__QDB_QUIET__'):
      print('QDB: Done.', file=sys.stderr)

    if self._archive and not os.getenv('__QDB_REPL__'):
      self._archive.close()

    self.haschanged = False

    return keystore

  def _compact_users(self, user_files: list):
    other_files = [o for o in self._archive.getmembers() if o.name not in user_files]
    users = {}

    for filename in sorted(user_files):
      user_file = self._archive.extractfile(filename)
      users_ops = json.loads(user_file.read())
      for user, op in users_ops.items():
        if 'add' in op:
          users[user] = op['add']
        elif 'del' in op:
          users.pop(user, None)
        else:
          users[user] = op

    users_data = json.dumps(users, indent=2).encode()
    tmpuser = self._new_tmp_file(user=True)
    tmpuser.write(users_data)
    tmpuser.flush()
    tmpuser.seek(0, os.SEEK_END)
    usersize = tmpuser.tell()
    tmpuser.seek(0)

    infouser = tarfile.TarInfo(name=self.users.filename)
    QDBUsers.set_user_info(infouser)
    infouser.size = usersize
    infouser.mtime = time.time()

    new = tarfile.open(self._database_path + '.tmp', 'w')
    try:
      for tarinfo in other_files:
        new.addfile(tarinfo, self._archive.extractfile(tarinfo))
    except IOError:
      new.close()
      os.remove(new.name)
      raise QDBIOCompactionError('IO Error: compaction failed.')
    try:
      new.addfile(infouser, tmpuser)
    except IOError:
      new.close()
      os.remove(new.name)
      raise QDBIOCompactionError('IO Error: compaction failed')

    tmpuser.close()
    os.replace(new.name, self._database_path)
    new.close()
    if not self._archive:
      self._archive = tarfile.open(self._database_path, 'r:')

    self.haschanged = False

  def rebuild(self, partial: bool=False):
    keystore = {}
    indexes = set()
    refs = {}

    empty = []

    if not self._archive:
      return keystore, indexes, refs

    files = [f for f in self._archive.getnames() if f.endswith('.log')]

    if not files and self._archive.getnames():
      raise QDBIODataIntegrityError('IO Error: No data could be found.')

    for log in files:
      hint = log.replace('.log', '.hint')
      ref = log.replace('.log', '.ref')
      m = self._archive.getmember(log)
      if m.size == 0:
        empty.append(log)
        if hint in self._archive.getnames():
          empty.append(hint)
        if ref in self._archive.getnames():
          empty.append(ref)
        continue
      if hint in self._archive.getnames():
        self._rebuild_from_hint(hint, keystore, indexes)
        continue
      self._rebuild_keystore(log, keystore, indexes, partial)
    refs = self.load_refs()

    self._remove(*empty)

    return keystore, indexes, refs

  def _rebuild_keystore(self, name: str, keystore: dict, indexes: set, partial: bool=False):
    position = 0

    log = self._get(name)
    while True:
      header = log.read(QDBIO.LOG_HEADER_SIZE)
      
      if not header:
        break
      
      header = self._deserialize_header(header)
      key = log.read(header.key_size)
      value = log.read(header.value_size)
      qdbdata = QDBData(header, value)
      
      if not self._validate_crc(key, qdbdata):
        raise QDBIODataIntegrityError(f'IO Error: bad CRC: `{log.name}:{position}`')

      key = key.decode()

      if partial and not key.startswith('@'):
        break
      
      if header.value_size == 0:
        keystore.pop(key, None)
      else:
        info = keystore.get(key, None)
        if info is None or header.timestamp > info.timestamp:
          keystore[key] = QDBInfo(log.name, header.value_size, position, header.timestamp)
        if header.value_type == b'+' and validate_hkey(key, confirm=True):
          indexes.add(key.split(':')[0])
      position = log.tell()

  def _rebuild_from_hint(self, name: str, keystore: dict, indexes: set, partial: bool=False):
    hint = self._get(name)

    while True:
      header = hint.read(QDBIO.HINT_HEADER_SIZE)

      if not header:
        break

      header = self._deserialize_hint_header(header)
      key = hint.read(header.key_size)
      key = key.decode()

      if partial and not key.startswith('@'):
        break

      if header.value_size == 0:
        keystore.pop(key, None)
      else:
        info = keystore.get(key, None)
        if info is None or header.timestamp > info.timestamp:
          keystore[key] = QDBInfo(
              hint.name.replace('.hint', '.log'),
              header.value_size,
              header.position,
              header.timestamp
          )

          if validate_hkey(key, confirm=True):
            indexes.add(key.split(':')[0])

    return keystore, indexes

  def list(self):
    if not self._archive:
      self._archive.open(self._database_path, 'r:')
    if self._archive:
      self._archive.list(verbose=True)
      return
    if self.isdatabase:
      print('QDB: Empty database.', file=sys.stderr)
