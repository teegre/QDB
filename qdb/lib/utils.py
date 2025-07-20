import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from functools import wraps
from getpass import getpass
from time import perf_counter
from typing import Any

from qdb.lib.exception import (
    QDBAuthenticationCancelledError,
    QDBNoAdminError,
    QDBHkeyError,
    QDBUnauthorizedError,
)
from qdb.lib.ops import VIRTUAL
from qdb.lib.users import QDBUsers, QDBAuthType

def performance_measurement(_func=None, *, message: str='Executed'):
  def decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      t1 = perf_counter()
      if os.getenv('__QDB_QUIET__'):
        return func(*args, **kwargs)
      result = func(*args, **kwargs)
      if not os.getenv('__QDB_DEBUG__'):
        if result == 1:
          return result
      t2 = perf_counter()
      d = t2 - t1
      if hasattr(args[0], 'parent') and hasattr(args[0].parent, '_perf_info'):
        args[0].parent._perf_info[message] = d
      else:
        p = d - args[0]._perf_info['Fetched']
        t = d
        print(f'Fetched:   {args[0]._perf_info["Fetched"]:.4f}s.', file=sys.stderr)
        print(f'{message}: {p:.4f}s.', file=sys.stderr)
        print(f'Total:     {d:.4f}s.', file=sys.stderr)
      
      return result
    return wrapper
  return decorator

def authorization(auth_types: list[QDBAuthType]):
  def decorator(func):
    @wraps(func)
    def wrap(self, *args, **kwargs):
      if self.users is None or not self.users.users:
        return func(self, *args, **kwargs)
      user = os.getenv('__QDB_USER__')
      if not user:
        authorize(self.users)
        user = os.getenv('__QDB_USER__')
      auth = self.users.get_auth(user)
      if QDBAuthType(auth) in auth_types:
        return func(self, *args, **kwargs)
      raise QDBUnauthorizedError('QDB: Unauthorized action.')
    return wrap
  return decorator

def authorize(qdbusers: QDBUsers, username: str=None, password: str=None):
  try:
    if not username:
      print('QDB: This database requires authentication.', file=sys.stderr)
      username = input('Username: ')
    if not password:
      password = getpass('Password: ')
  except (KeyboardInterrupt, EOFError):
    print()
    raise QDBAuthenticationCancelledError('Authentication cancelled.')
  qdbusers.authenticate(username, password) 
  del password

def user_add(qdbusers: QDBUsers, username: str=None, password: str=None, auth_type: str=None):
  try:
    if not username:
      username = input('Username: ')
      if not username:
        raise QDBAuthenticationCancelledError('QDB: user creation cancelled.')

    if not password:
      password1 = getpass('Password: ')
      if not password1:
        raise QDBAuthenticationCancelledError('QDB: password is mandatory.')
      password2 = getpass('Again: ')
      if password1 != password2:
        raise QDBAuthenticationCancelledError('QDB: passwords do not match.')
      password = password2
      del password1, password2
    if not auth_type:
      auth_type = input('Authorization type (admin,[readonly]): ')
    if not auth_type:
      auth = QDBAuthType.QDB_READONLY
    else:
      match auth_type:
        case 'admin':
          auth = QDBAuthType.QDB_ADMIN
        case 'readonly':
          auth = QDBAuthType.QDB_READONLY
        case _:
          raise QDBAuthenticationCancelledError(
              f'QDB: `{auth_type}`, invalid authorization type.'
              '\nQDB: should be `admin` or `readonly`.'
          )
  except (KeyboardInterrupt, EOFError):
    print()
    raise QDBAuthenticationCancelledError('QDB: user creation cancelled.')

  if auth != QDBAuthType.QDB_ADMIN and not qdbusers.hasadmin:
    del password
    raise QDBNoAdminError(
        'QDB: You MUST create an administrator before adding any other user.'
    )

  qdbusers.add_user(username, password, auth)
  del password

def is_numeric(value: str) -> bool:
  try:
    float(value)
    return True
  except (ValueError, TypeError):
    return False

def coerce_number(x: Any) -> Any:
  '''
  Convert 'x' to an int or float if possible.
  Return 'x' as is otherwise.
  '''
  if is_numeric(x):
    return float(x) if not x.isdigit() else int(x)
  return x

def is_virtual(field: str) -> bool:
  return field in VIRTUAL

def validate_key(key: str, confirm: bool=False) -> bool | None:
  KEY_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*')
  if not KEY_RE.match(key):
    if confirm:
      return False
    raise QDBKeyError(f'Error: malformad KEY: `{key}`.')
  if confirm:
    return True

def validate_hkey(hkey: str, confirm: bool=False) -> bool | None:
  HKEY_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*:[a-zA-Z0-9-_]+$')
  if not HKEY_RE.match(hkey):
    if confirm:
      return False
    raise QDBHkeyError(f'Error: malformed HKEY: `{hkey}`.')
  if confirm:
    return True

def validate_field_name(field: str) -> None:
  FIELD_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9]*$')
  if not FIELD_RE.match(field):
    raise QDBError('Error: malformed field name: `{field}`.')
