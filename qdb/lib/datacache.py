import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from dataclasses import dataclass
from io import BytesIO
from time import time

@dataclass
class QDBCacheEntry:
  data: dict|str
  timestamp: int

class QDBCache:
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
      for old, new in zip(old_data.items(), data.items()):
        if new[1] == old[1]:
          continue
        index = key.split(':')[0]
        field = new[0]
        self.drop(index, field, old[1], key)
        value = new[1]
        index_entry = f'{index}:{field}={value}'
        if index_entry in self.__indexed_fields:
          self.__indexed_fields[index_entry].add(key)
        else:
          self.__indexed_fields.setdefault(index_entry, {key})

    self.haschanged = True

  def read(self, key: str) -> dict[str] | str | None:
    entry = self.__cache.get(key)
    if entry:
      return entry.data
    return None

  def get_key(self, index: str, field: str, *values: str) -> set:
    hkeys = set()
    for value in values:
      index_entry = f'{index}:{field}={value}'
      hkeys.update(self.__indexed_fields.get(index_entry, set()))
    return hkeys

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

  def dump(self) -> tuple[BytesIO, BytesIO]:
    return BytesIO(json.dumps(
      {k: [ce.data, ce.timestamp] for k, ce in self.__cache.items()}
      ).encode()), BytesIO(json.dumps(
        { ie: list(k) for ie, k in self.__indexed_fields.items() }
        ).encode())

  def drop(self, index: str, field: str, value: str, key: str):
    index_entry = f'{index}:{field}={value}'
    self.__indexed_fields[index_entry].discard(key)
    if not self.__indexed_fields[index_entry]:
      self.__indexed_fields.pop(index_entry, None)

  def load(self, cache_data: BytesIO, indexed_data: BytesIO):
    if cache_data:
      self.__cache = {
          k: QDBCacheEntry(v[0], v[1])
          for k, v in json.loads(cache_data.decode()).items()
      }
    if indexed_data:
      self.__indexed_fields = {
          ie: set(k) for ie, k in json.loads(indexed_data.decode()).items()
      }
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

  def __repr__(self):
    idxs = [ k.split(':')[0] for k in sorted(self.__cache.keys()) ]
    rpr = sorted(set(f'{idx} ({idxs.count(idx)})' for idx in idxs))
    return f'Cache: {", ".join(rpr)}' if rpr else 'Cache: empty.'
