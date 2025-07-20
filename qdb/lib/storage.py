import fcntl
import os
import json
import struct
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from collections import defaultdict, deque
from glob import glob
from shutil import move
from sys import stdin, stdout, stderr
from time import time, strftime
from zlib import crc32

from qdb.lib.datacache import QDBCache
from qdb.lib.exception import QDBNoDatabaseError, QDBNoAdminError
from qdb.lib.io import QDBIO, QDBInfo

# Terminology:
# key: a key in simple key/value pair
# hkey : a key in a key/hash pair
# hash: a multiple field/value pair
# field : a key in a hash
# index: entity
# reference: a hkey used as a value in a field

class QDBStore:
  def __init__(self, db_path: str, load: bool=True) :
    self.io = QDBIO(db_path)
    self.users = self.io.users
    self.database_name = os.path.splitext(os.path.basename(db_path))[0]
    self.haschanged = False
    self.datacache = QDBCache()
    if load:
      self.keystore: Dict[str, QDBInfo] = {}
      self._pending_keys = set()
      self.indexes = set()
      self.indexes_map: Dict[str: set[str]] = {}
      self.refs: Dict[str: set[str]] = {}
      self._refs_cache: Dict[tuple[str, str]: set[str]] = {}
      self._refs_ops: Dict[str, Dict[str, list[str]|str]] = {}
      self.reverse_refs: Dict[str: set[str]] = {}
      self.__paths__: Dict[tuple: list] = {}
      self.initialize()

  def initialize(self):
    self.keystore, self.indexes, self.refs = self.io.rebuild()
    if not self.users.hasusers and '@QDB_USERS' in self.keystore:
      raise QDBNoAdminError('Access denied.')
    self.build_indexes_map()
    self.update_reverse_refs()
    self.precompute_paths()
    cache = self.io.load_cache()
    self.datacache.load(cache)

  def deinitialize(self):
    if self.io.haschanged or (self.haschanged and not os.getenv('__QDB_REPL__')):
      self.io.flush(self._refs_ops)
    if self.users.unsaved:
      self.users._save()
      self.io._archive.close()
      self.io._load()
    if self.datacache.haschanged:
      self.io.save_cache(self.datacache.dump())
    self.io.compact()

  def commit(self):
    new_file = self.io.flush(self._refs_ops)
    for key in self._pending_keys:
      self.keystore[key].filename = new_file
    self._pending_keys.clear()
    self.haschanged = False

  def compact(self, force: bool=False):
    self.keystore = self.io.compact(force=force)

  def list_files(self):
    if not self.io.isdatabase:
      raise QDBNoDatabaseError(f'QDB: Error: `{self.io._database_path}` no such database.')
    self.io.list()

  def write(self, key: str, value: str|dict, refs: list=[])  -> int:
    ''' Write data to file, update keystore, indexes and refs '''
    entry = self.io.write(key, value)
    self.keystore[key] = self.io.write(key, value)

    self._pending_keys.add(key)

    self.haschanged = True

    if isinstance(value, dict):
      if not self.has_index(key):
        if self.create_index(key) != 0:
          return 1
      for ref in refs :
        self.create_ref(key, ref)
      # add new hkey to the indexes map
      self.indexes_map.setdefault(self.get_index(key), set()).add(key)
      if entry.timestamp > self.datacache.get_key_timestamp(key):
        self.datacache.write(key, value)

    return 0

  def read(self, key: str, read_hash: bool=False) -> str | dict:
    ''' Read data for the given key '''
    if not self.io.isdatabase:
      raise QDBNoDatabaseError(f'QDB: Error: `{self.io._database_path}` no such database.')
    entry = self.keystore.get(key)
    if entry is None:
      return None
    if not read_hash:
      return self.io.read(entry, key)
    if entry.timestamp < self.datacache.get_key_timestamp(key):
      return self.datacache.read(key)
    value = self.io.read(entry, key)
    self.datacache.write(key, value)
    return value

  def read_hash(self, hkey: str, dump: bool=False) -> dict:
    ''' Return the hash associated to the given hkey '''
    if not self.io.isdatabase:
      raise QDBNoDatabaseError(f'QDB: Error: `{self.io._database_path}` no such database.')
    value = self.read(hkey, read_hash=True)

    if value and not dump:
      ID = hkey.split(':')[1]
      value['@hkey'] = hkey
      value['@id'] = ID

    return value

  def read_hash_field(self, key: str, field: str) -> int:
    data = self.read_hash(key)
    if data:
      return(data.get(field, '?NOFIELD?'))
    return None

  def delete(self, key: str) -> int:
    '''
    Delete a key from the keystore
    and mark it for deletion
    '''
    if not self.io.isdatabase:
      raise QDBNoDatabaseError(f'QDB: Error: `{self.io._database_path}` no such database.')

    if key in self.keystore:
      if self.has_ref(key):
        print(f'Error: key `{key}` is referenced.', file=stderr)
        return 1
      self.io.write(key, None, delete=True)
      if self.has_index(key):
        if self.is_refd(key):
          self.delete_refd_key(key)
        index = self.get_index(key)
        self.keystore.pop(key, None)
        self.indexes_map[index].discard(key)
        if self.is_index_empty(index):
          self._delete_index(index)
          self.indexes_map.pop(index, None)
      else:
        self.keystore.pop(key, None)

      self.datacache.delete(key)
      self.haschanged = True
      return 0
    return 1

  def get_hkey_timestamp(self, hkey: str) -> int:
    entry = self.keystore.get(hkey)
    if entry:
      return entry.timestamp
    return 0

  def dump(self) -> None:
    ''' Dump current database in json format '''
    if not self.io.isdatabase:
      raise QDBNoDatabaseError(f'QDB: Error: `{self.io._database_path}` no such database.')

    data = {
        index: {
          hkey: self.read_hash(hkey, dump=True)
          for hkey in self.get_index_keys(index)
        }
        for index in self.indexes
    }
    print(json.dumps(data, sort_keys=True))
    keys = set(self.keystore.keys())
    hkeys = set()
    for index in self.indexes:
      hkeys.update(self.get_index_keys(index))
    keys ^= hkeys
    data = {k: self.read(k) for k in sorted(keys)}
    if data:
      print(json.dumps(data,sort_keys=True))

  def keystore_dump(self) -> None:
    ''' Dump keystore content '''
    for k, v in self.keystore.items():
      print(f'{k}: {v}')

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

  def _delete_index(self, index: str) -> int:
    ''' Delete the given empty index. '''
    self.indexes.discard(index)
    for idx1, idx2 in self.__paths__.copy():
      if idx1 == index or idx2 == index:
        self.__paths__.pop((idx1, idx2), None)
        self.__paths__.pop((idx1, idx2), None)
    return 0

  def get_index(self, hkey: str) -> str | None:
    ''' Return the index of a given key if key and index exist. '''
    if not hkey in self.keystore:
      return None
    try:
      index = hkey.split(':')[0]
    except ValueError:
      return None
    if self.is_index(index):
      return index
    return None

  def get_index_keys(self, index: str) -> list:
    ''' Get all the keys for a given index. '''
    keys = self.indexes_map.get(index)
    if keys:
      return keys
    return [k for k in self.keystore.keys() if k.startswith(index + ':')]

  def create_ref(self, hkey: str, ref: str) -> int:
    '''
    Add a reference for a given hkey and
    add a hkey for a given reference.
    '''
    if self.is_refd_by(hkey, ref):
      return 0

    if hkey == ref:
      print(f'Error: `{hkey}` references itself! (ignored).', file=stderr)
      return 1

    self.refs.setdefault(hkey, set()).add(ref)
    self.reverse_refs.setdefault(ref, set()).add(hkey)
    self._refs_ops.setdefault(hkey, {}).setdefault('add', []).append(ref)

    return 0

  def build_indexes_map(self):
    for index in self.indexes:
      self.indexes_map.setdefault(index, set())
      for key in self.get_index_keys(index):
        self.indexes_map[index].add(key)

  def precompute_paths(self):
    for x1 in self.indexes:
      for x2 in self.indexes:
        if x1 == x2:
          continue
        self.__paths__[(x1, x2)] = self.find_index_path(x1, x2)

  def get_all_ref_hkeys(self, index: str) -> list[str]:
    ''' Return all referenced hkeys'''
    refs = []
    for hkey, hrefs in self.refs.items():
      if hkey.startswith(index + ':'):
        refs.extend(list(hrefs))
    return sorted(set(str(r) for r in refs))

  def get_ref(self, key: str) -> str:
    ''' Return the ref referenced by key if any. '''
    for ref, keys in self.refs.items():
      if key in keys:
        return ref
    return None

  def update_reverse_refs(self):
    reverse_refs = {}
    for k, refs in self.refs.items():
      for ref in refs:
        reverse_refs.setdefault(ref, set()).add(k)
    self.reverse_refs = reverse_refs

  def get_refs_with_index(self, key: str, index: str) -> set:
    '''
    Return the direct references or reverse references of 'key'
    if they are related to 'index'
    '''
    results = set()

    if not self.exists(key) or not self.is_index(index):
      return results

    for ref in sorted(self.refs.get(key, [])):
      if self.is_index_of(ref, index):
        results.add(ref)

    if not results:
      for ref in sorted(self.reverse_refs.get(key, [])):
        if self.is_index_of(ref, index):
          results.add(ref)

    return results

  def get_refs(self, key: str, index: str) -> list:
    '''
    Return all forward or reverse refs related to index
    '''
    if not self.has_index(key) or not self.is_index(index):
      self._refs_cache.pop((key, index), None)
      return []

    if self.get_index(key) == index:
      return []

    if (key, index) in self._refs_cache:
      return self._refs_cache[(key, index)]

    path = self.find_index_path(self.get_index(key), index)
    if not path:
      return []

    results = {key}
    for i in range(len(path) - 1):
      next_idx = path[i + 1]
      refs = set()
      for ref in results:
        refs |= set(self.get_refs_with_index(ref, next_idx))
      results = refs

    if results:
      self._refs_cache[(key, index)] = sorted(results)

    return sorted(results)

  def get_ref_key(self, key: str) -> str:
    ''' Get the key that key references to... '''
    return self.reverse_refs.get(key, [])

  def get_refs_of(self, hkey: str) -> list[str]:
    ''' Get references of key. '''
    return self.refs.get(hkey, [])

  def are_related(self, k1: str, k2: str) -> bool:
    ''' Return True if k1 and k2 are directly related '''
    return k1 in self.refs.get(k2, []) or k2 in self.refs.get(k1, [])

  def find_index_path(self, idx1: str, idx2: str) -> list:
    '''
    Returns the indexes that form a path from idx1 to idx2,
    including idx1 and idx2, if any.
    A, C → [A, B, C]
    D, E → [D, E]
    '''

    if idx1 == idx2:
      return []

    if not self.is_index(idx1) or not self.is_index(idx2):
      # Remove from cache
      self.__paths__.pop((idx1, idx2), None)
      self.__paths__.pop((idx2, idx1), None)
      return []

    if (idx1, idx2) in self.__paths__:
      return self.__paths__[(idx1, idx2)]

    max_depth = len(self.indexes)

    def is_valid_path(path: list[str]) -> bool:
      return len(set(path)) == len(path)

    valid_paths = []

    def dfs(hkey: str, path: list):
      nonlocal result, valid_paths
      if len(path) > max_depth:
        return
      if self.is_index_of(hkey, idx2):
        new_path = [self.get_index(k) for k in path]
        if is_valid_path(new_path):
          valid_paths.append(new_path)
        return

      ngbs = self.refs.get(hkey, set()) | self.reverse_refs.get(hkey, set())
      for ngb in ngbs:
        if ngb not in path:
          dfs(ngb, path + [ngb])

    hk1 = sorted(self.get_index_keys(idx1))[0]
    dfs(hk1, [hk1])

    result = min(valid_paths, key=len, default=[])

    if result:
      # Add to cache
      self.__paths__[(idx1, idx2)] = result
      self.__paths__[(idx2, idx1)] = list(reversed(result))

    return result

  def delete_ref_of_key(self, hkey: str, ref: str) -> int:
    '''
    Delete the `ref` referenced by `hkey` and
    delete `hkey` if it's no longer referenced.
    Return 0 on success, 1 on fail.
    '''
    refs = self.refs.get(hkey)
    if refs is None:
      return 1

    self.refs[hkey].discard(ref)
    self.reverse_refs[ref].discard(hkey)

    # Remove from cache
    pair1 = (hkey, self.get_index(ref))
    pair2 = (ref, self.get_index(hkey))
    if pair1 in self._refs_cache:
      self._refs_cache[pair1].remove(ref)
      if not self._refs_cache[pair1]:
        self._refs_cache.pop(pair1)
    if pair2 in self._refs_cache:
      self._refs_cache[pair2].remove(hkey)
      if not self._refs_cache[pair2]:
        self._refs_cache.pop(pair2)

    if not self.refs[hkey]:
      del self.refs[hkey]
    if not self.reverse_refs[ref]:
      del self.reverse_refs[ref]

    try:
      self._refs_ops.setdefault(hkey, {}).setdefault('del', []).append(ref)
    except AttributeError:
      self._refs_ops.setdefault(hkey, {})
      self._refs_ops[hkey].update({ 'del', [ref] })

    if not self._refs_ops.get(hkey).get('del'):
      self._refs_ops[hkey] = {'del': '__all__'}

    return 0

  def delete_refd_key(self, hkey: str) -> int:
    err = 0
    for ref in self.refs.copy().get(hkey, []).copy():
      err += self.delete_ref_of_key(hkey, ref)
    return 1 if err else 0

  def delete_ref(self, ref: str) -> None:
    '''
    Delete ref in all keys.
    Delete key if not used by any ref.
    '''
    update = False
    for key, refs in self.refs.copy().items():
      if ref in refs:
        self.refs[key].discard(ref)
        update = True
        if len(refs) == 0:
          del self.refs[key]
    if update:
      self.update_reverse_refs()

  def _get_most_recent_hkey_from_index(self, index: str) -> str:
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
    hkey = self._get_most_recent_hkey_from_index(index)
    if not hkey:
      return []
    return list(self.read_hash(hkey).keys())

  def has_index(self, key: str) -> bool:
    ''' Return True if a given key exists and has an index, False otherwise. '''
    return self.get_index(key) and key in self.keystore

  def is_index(self, index: str) -> bool:
    ''' Return True if index exists. '''
    return index in self.indexes

  def is_index_of(self, hkey: str, index: str) -> bool:
    ''' Return true if hkey exists and belongs to index. '''
    return self.get_index(hkey) == index

  def is_index_empty(self, index_or_key: str) -> bool:
    ''' Return True if index or key of index is empty. '''
    index = index_or_key.split(':')[0]
    if self.is_index(index):
      return len(self.get_index_keys(index)) == 0
    return False

  def is_refd_by(self, hkey: str, ref: str) -> bool:
    ''' Return True if `key` references `ref`. '''
    return ref in self.refs.get(hkey, set())

  def is_refd_by_index(self, key: str, index: str) -> bool:
    ''' Return True if key exists and at least one reference of key belongs to index. '''
    refs = self.refs.get(key, [])
    for ref in refs:
      if self.is_index_of(key, index):
        return True and key in self.keystore
    return False

  def is_refd(self, hkey: str) -> bool:
    ''' Return True is hkey is a reference '''
    return hkey in self.keystore and hkey in self.refs

  def has_ref(self, key: str) -> bool:
    ''' Return True if key has references '''
    return key in self.keystore and key in self.reverse_refs

  def exists(self, key: str) -> bool:
    ''' Return True if `key` exists in the keystore. '''
    return key in self.keystore

  def index_len(self, index: str) ->  int:
    ''' Return the number of hkeys in the given index.'''
    if self.is_index(index):
      return sum(1 for k in self.keystore.keys() if k.startswith(index + ':'))
    return 0

  def database_schema(self):
    graph = defaultdict(set)
    all_children = set()
    unrelated = set()

    for indexes, path in self.__paths__.items():
      if not path:
        unrelated.update(indexes)
        continue
      for a, b in zip(path, path[1:]):
        graph[a].add(b)
        all_children.add(b)

    unrelated -= all_children
    roots = sorted(self.indexes - unrelated, key=lambda idx: len(self.get_index_keys(idx)), reverse=True)
    starting_points = roots or indexes

    visited = set()

    def print_tree(node, prefix='', is_last=True, not_related=False):
      connector = '└─ ' if is_last else '├─ '
      line = prefix + connector + node
      if node in visited:
        line += ' (↻)'
        print(line)
        return

      if not_related:
        print(line + ' (x)')
      else:
        print(line)

      visited.add(node)

      children = graph.get(node, [])
      for i, child in enumerate(children):
        next_is_last = i == len(children) - 1
        next_prefix = prefix + ('   ' if is_last else '│  ')
        print_tree(child, next_prefix, next_is_last)

    for i, root in enumerate(starting_points):
      if root not in visited:
        print_tree(root, '', i == len(starting_points) - 1)
    if unrelated:
      print('x')
      for i, root in enumerate(sorted(unrelated)):
        print_tree(root, '', is_last=i == len(unrelated) - 1, not_related=True)

  def autoid(self, index: str) -> str:
    ''' Return current greatest ID + 1 in index '''
    # TODO: MAKE IT SMARTER
    return str(self.index_len(index) + 1)

  @property
  def is_db_empty(self) -> bool:
    return len(self.keystore) == 0

  @property
  def isdatabase(self) -> bool:
    return self.io.isdatabase
