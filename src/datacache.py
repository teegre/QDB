import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from dataclasses import dataclass
from time import time

@dataclass
class CacheEntry:
  data: dict|str
  timestamp: int

class Cache:
  __cache: dict = {}
  def write(self, key: str, data: dict[str]):
    entry = self.__cache.get(key)
    if entry and entry.data == data:
      return
    self.__cache[key] = CacheEntry(data, int(time()))

  def read(self, key: str) -> dict[str] | str | None:
    entry = self.__cache.get(key)
    if entry:
      return entry.data
    return None

  def get_key_timestamp(self, key: str) -> int:
    entry = self.__cache.get(key)
    return entry.timestamp if entry else 0

  def delete(self, key: str) -> int:
    try:
      del self.__cache[key]
      return 0
    except KeyError:
      return 1

  def purge(self) -> int:
    self.__cache.clear()
    return 0

  def exists(self, key: str) -> bool:
    return key in self.__cache

  def __repr__(self):
    idxs = [ k.split(':')[0] for k in sorted(self.__cache.keys()) ]
    rpr = sorted(set(f'{idx} ({idxs.count(idx)})' for idx in idxs))
    return f'Cache: {", ".join(rpr)}' if rpr else 'Cache: empty.'
