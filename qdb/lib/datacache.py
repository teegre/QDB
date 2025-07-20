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
  def __init__(self):
    self.haschanged = False

  def write(self, key: str, data: dict[str]):
    entry = self.__cache.get(key)
    if entry and entry.data == data:
      return
    self.__cache[key] = QDBCacheEntry(data, int(time()))
    self.haschanged = True

  def read(self, key: str) -> dict[str] | str | None:
    entry = self.__cache.get(key)
    if entry:
      return entry.data
    return None

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

  def dump(self) -> BytesIO:
    return BytesIO(json.dumps(
      {k: [ce.data, ce.timestamp] for k, ce in self.__cache.items()}
    ).encode())

  def load(self, cache_data: bytes):
    self.__cache = {
        k: QDBCacheEntry(v[0], v[1])
        for k, v in json.loads(cache_data.decode()).items()
    }


  @property
  def size(self):
    return len(self.__cache)

  def __repr__(self):
    idxs = [ k.split(':')[0] for k in sorted(self.__cache.keys()) ]
    rpr = sorted(set(f'{idx} ({idxs.count(idx)})' for idx in idxs))
    return f'Cache: {", ".join(rpr)}' if rpr else 'Cache: empty.'
