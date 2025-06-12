import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class Cache:
  __cache: dict = {}
  def write(self, key: str, data: dict[str]):
    self.__cache[key] = data

  def read(self, key: str, default: dict[str]=None) -> dict[str] | str:
    data = self.__cache.get(key, default)
    return data

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

  
