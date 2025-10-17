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
          if new[0] == old[0] and new[1] == old[1]:
            continue
          self.drop(index, old[0], old[1], key)
          field = new[0]
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

  def recache(self) -> int:
    self.__cache.clear()
    self.haschanged = True
    return 0

  def drop(self, index: str, field: str, value: str, key: str):
    index_entry = f'{index}:{field}={value}'
    if self.__indexed_fields.get(key, None):
      self.__indexed_fields[index_entry].discard(key)
      if not self.__indexed_fields[index_entry]:
        self.__indexed_fields.pop(index_entry, None)

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
    return f'* cached: {len(self.__cache)}' if self.__cache else '* cache: empty.'
