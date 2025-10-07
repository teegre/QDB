import glob
import os
import re
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from functools import wraps
from getpass import getpass
from typing import Any

from qdb.lib.exception import (
    QDBAuthenticationCancelledError,
    QDBError,
    QDBHkeyError,
    QDBKeyError,
    QDBNoAdminError,
    QDBUnauthorizedError,
)
from qdb.lib.ops import VIRTUAL
from qdb.lib.users import QDBUsers, QDBAuthType

__ENV__ = {
    'debug'  : '__QDB_DEBUG__',
    'hushf'  : '__QDB_HUSHF__',
    'log'    : '__QDB_LOG__',
    'pwd'    : '__QDB_PWD__',
    'pipe'   : '__QDB_PIPE__',
    'quiet'  : '__QDB_QUIET__',
    'repl'   : '__QDB_REPL__',
    'session': '__QDB_SESSION__',
    'user'   : '__QDB_USER__',
}

def setenv(var: str, value: str='1'):
  if (envvar := __ENV__.get(var, None)) is None:
    return
  os.environ[envvar] = value

def unsetenv(var: str):
  if var == 'user':
    return
  if (envvar := __ENV__.get(var)) is not None:
    os.environ.pop(envvar, None)

def isset(var: str) -> bool:
  envvar = __ENV__.get(var, None)
  return os.getenv(envvar) is not None if envvar else False

def getuser():
  return os.environ.get('__QDB_USER__', 'anyone')

def getsessionenv() -> str:
  return os.environ.get('__QDB_SESSION__', '__null__')

def session_id(db_path) -> str:
  name, ext = os.path.splitext(os.path.basename(db_path))
  if not ext:
    name += '.qdb'

def performance_measurement(_func=None, *, message: str='executed'):
  def decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      t1 = time.perf_counter()
      if isset('quiet'):
        return func(*args, **kwargs)
      result = func(*args, **kwargs)
      if result == 1:
        return result
      t2 = time.perf_counter()
      d = t2 - t1
      if hasattr(args[0], 'parent') and hasattr(args[0].parent, '_perf_info'):
        args[0].parent._perf_info[message] = d
      else:
        p = d - args[0]._perf_info['Fetched']
        t = d
        print(f'* fetched:   {args[0]._perf_info["Fetched"]:.4f}s.', file=sys.stderr)
        print(f'* {message.lower()}: {p:.4f}s.', file=sys.stderr)
        print(f'* total:     {d:.4f}s.', file=sys.stderr)
      
      return result
    return wrapper
  return decorator

def authorization(auth_types: list[QDBAuthType]):
  def decorator(func):
    @wraps(func)
    def wrap(self, *args, **kwargs):
      if self.users is None or not self.users.users:
        return func(self, *args, **kwargs)
      user = self.users.getuser()
      if not user:
        authorize(self.users)
        user = self.users.getuser()
      auth = self.users.get_auth(user)
      if QDBAuthType(auth) in auth_types:
        return func(self, *args, **kwargs)
      raise QDBUnauthorizedError('unauthorized action.')
    return wrap
  return decorator

def authorize(qdbusers: QDBUsers, username: str=None, password: str=None, change: bool=False):
  try:
    with open('/dev/tty', 'r') as stdin, open('/dev/tty', 'w') as stdout:
      if not username:
        print('* \x1b[1mthis database requires authentication\x1b[0m.', file=sys.stderr)
        stdout.write('* username: ')
        stdout.flush()
        username = stdin.readline().strip()
      if not password:
        password = getpass('* password: ' if not change else '* current password: ', stream=stdout)
  except (KeyboardInterrupt, EOFError):
      print()
      raise QDBAuthenticationCancelledError('authentication cancelled.')
  except OSError:
    raise QDBError(
        'cannot prompt for credentials in pipe mode.'
        '\n * use `--username` and `--password` options.'
    )

  qdbusers.authenticate(username, password) 
  del password

def user_add(qdbusers: QDBUsers, username: str=None, password: str=None, auth_type: str=None, change: bool=False):
  try:
    if not username:
      print('* \x1b[1m[new user]\x1b[0m')
      username = input('* username: ')
      if not username:
        raise QDBAuthenticationCancelledError('user creation cancelled.')

    if not password:
      password1 = getpass('* password: ' if not change else '* new password: ')
      if not password1:
        raise QDBAuthenticationCancelledError('password is mandatory.')
      password2 = getpass('* again: ')
      if password1 != password2:
        raise QDBAuthenticationCancelledError('* passwords do not match.')
      password = password2
      del password1, password2
    if not auth_type:
      auth_type = input('* authorization type (admin,[readonly]): ')
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
              f'`{auth_type}`, invalid authorization type.'
              '\n* should be `admin` or `readonly`.'
          )
  except (KeyboardInterrupt, EOFError):
    print()
    raise QDBAuthenticationCancelledError('user creation cancelled.')

  if auth != QDBAuthType.QDB_ADMIN and not qdbusers.hasadmin:
    del password
    raise QDBNoAdminError(
        '* you \x1b[1mMUST\x1b[0m create an \x1b[1madministrator\x1b[0m before adding any other user.'
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
    if str(x)[0] in '-+':
      s = str(x)[0]
      d = str(x)[1:]
      return float(s+d) if not d.isdigit() else int(s+d)
    return float(x) if not x.isdigit() else int(x)
  return x

def is_virtual(field: str) -> bool:
  return field in VIRTUAL

def validate_key(key: str, confirm: bool=False) -> bool | None:
  KEY_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*')
  if not KEY_RE.match(key):
    if confirm:
      return False
    raise QDBKeyError(f'malformed key: `{key}`.')
  if confirm:
    return True

def validate_hkey(hkey: str, confirm: bool=False) -> bool | None:
  HKEY_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*:[a-zA-Z0-9-_]+$')
  if not HKEY_RE.match(hkey):
    if confirm:
      return False
    raise QDBHkeyError(f'malformed hkey: `{hkey}`.')
  if confirm:
    return True

def validate_field_name(field: str) -> None:
  FIELD_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9]*$')
  if not FIELD_RE.match(field):
    raise QDBError('malformed field name: `{field}`.')


def spinner():
  # │╱─╲
  chars = 20 * '|' + 20 * '/' + 20 * '-' + 20 * '\\'
  while True:
    for c in chars:
      yield c

def loader():
  frames = [
      '*     ',
      '**    ',
      '***   ',
      ' ***  ',
      '  *** ',
      '   ***',
      '    **',
      '     *'
  ]
  while True:
    for f in frames:
      yield f

def splitcmd(cmd: str) -> list[str]:
  token = ''
  tokens = []
  quoted = False
  quote_char = ''
  pos = 0
  while pos < len(cmd):
    c = cmd[pos]

    if c in '"\'' and not cmd[pos - 1] == '\\':
      if not quoted:
        quoted = True
        quote_char = c
      elif c == quote_char:
        quoted = False
        quote_char = ''
      token += c
    elif c == ' ' and not quoted:
      tokens.append(token)
      token = ''
    else:
      token += c
    pos += 1
  if token:
    tokens.append(token)

  if quoted:
    raise QDBError(f'unbalanced \x1b[1m{quote_char}\x1b[0m in expression.')

  return tokens

def unquote(expr: str) -> str:
  quoted = re.sub(r'''(?<!\\)"(.*?)(?<!\\)"''', r'\1', expr)
  unescaped = bytes(quoted, 'utf-8').decode('unicode_escape').encode('latin-1').decode()
  return unescaped

def quote(value: str) -> str:
  quoted = value.replace('"', '\\"').replace("'", "\\'")
  return f'"{quoted}"'
