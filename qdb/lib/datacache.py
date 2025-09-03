import json
import os
import struct
import sys

from dataclasses import dataclass
from io import BytesIO
from time import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))


@dataclass
class QDBCacheEntry:
  data: dict|str
  timestamp: int

class QDBCache:

  #                  ikssz   kssz
  IDXD_HEADER_SIZE = 8     + 8

  HEADER_STRUCT = struct.Struct('<QQ')

  __cache: dict = {}
  __indexed_fields = {}

  def __init__(self):
    self.haschanged = False

  def write(self, key: str, data: dict[str], old_data: dict={}):
    entry = self.__cache.get(key)
    if entry and entry.data == data:
      return
    self.__cache[key] = QDBCacheEntry(data, int(time()))

    if isinstance(data, dict):
      index = key.partition(':')[0]
      if old_data: # update
        for old, new in zip(old_data.items(), data.items()):
          if new[1] == old[1]:
            continue
          field = new[0]
          self.drop(index, field, old[1], key)
          value = new[1]
          index_entry = f'{index}:{field}={value}'
          if index_entry in self.__indexed_fields:
            self.__indexed_fields[index_entry].add(key)
          else:
            self.__indexed_fields.setdefault(index_entry, {key})
      else:
        for field, value in data.items():
          index_entry = f'{index}:{field}={value}'
          if index_entry in self.__indexed_fields:
            self.__indexed_fields[index_entry].add(key)
          else:
            self.__indexed_fields.setdefault(index_entry, {key})

    self.haschanged = True

  def read(self, key: str, field: str=None) -> dict[str] | str | None:
    entry: QDBCacheEntry = self.__cache.get(key)
    if entry:
      if field:
        return entry.data.get(field)
      return entry.data.copy() if isinstance(entry.data, dict) else entry.data
    return None

  def get_key(self, index: str, field: str, *values: str) -> set:
    hkeys = set()
    for value in values:
      index_entry = f'{index}:{field}={value}'
      hkeys.update(self.__indexed_fields.get(index_entry, set()))
    return hkeys

  def get_id(self, index: str, field: str, value: str) -> str:
    index_entry = f'{index}:{field}={value}'
    ID: list = list(self.__indexed_fields.get(index_entry, set()))
    if len(ID) > 1:
      return None
    return ID[0].partition(':')[2] if ID else None

  def get_key_timestamp(self, key: str) -> int:
    entry = self.__cache.get(key)
    return entry.timestamp if entry else 0

  def delete(self, key: str) -> None:
    if key in self.__cache:
      del self.__cache[key]

  def purge(self) -> int:
    self.__cache.clear()
    self.haschanged = True
    return 0

  def _serialize(self) -> BytesIO:
    # iksz kssz ik ks
    data = bytearray()
    for ik, keys in self.__indexed_fields.items():
      ikbytes = ik.encode()
      iksz = len(ikbytes)
      ks = ','.join(sorted(keys)).encode()
      kssz = len(ks)
      data.extend(struct.pack(
          f'<QQ{iksz}s{kssz}s',
          iksz,
          kssz,
          ikbytes,
          ks
      ))
    return BytesIO(data)

  def _deserialize(self, data: BytesIO):
    self.__indexed_fields.clear()
    raw = data.read()
    position = 0
    while position < len(raw):
      iksz, kssz = self.HEADER_STRUCT.unpack_from(raw, position)
      position += self.IDXD_HEADER_SIZE
      ik = raw[position:position+iksz].decode()
      position += iksz
      ks = raw[position:position+kssz].decode().split(',')
      position += kssz
      self.__indexed_fields[ik] = set(ks)

  def dump(self) -> tuple[BytesIO, BytesIO]:
    return BytesIO(json.dumps(
      {k: [ce.data, ce.timestamp] for k, ce in self.__cache.items()}
      ).encode()), self._serialize()

  def drop(self, index: str, field: str, value: str, key: str):
    index_entry = f'{index}:{field}={value}'
    self.__indexed_fields[index_entry].discard(key)
    if not self.__indexed_fields[index_entry]:
      self.__indexed_fields.pop(index_entry, None)

  def load(self, cache_data: bytes, indexed_data: bytes):
    if cache_data:
      self.__cache = {
          k: QDBCacheEntry(v[0], v[1])
          for k, v in json.loads(cache_data.decode()).items()
      }
    if indexed_data:
      self._deserialize(indexed_data)
    self.haschanged = False

  def set_indexed_fields(self, indexed_fields: dict):
    self.__indexed_fields = indexed_fields
    self.haschanged = True

  @property
  def isindexed(self):
    return len(self.__indexed_fields) > 0

  @property
  def size(self):
    return len(self.__cache)

  @property
  def indexed(self):
    return self.__indexed_fields

  def __repr__(self):
    return f'Cached: {len(self.__cache)}' if self.__cache else 'Cache: empty.'
