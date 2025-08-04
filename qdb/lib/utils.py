import os
import re
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timedelta
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
    'debug': '__QDB_DEBUG__',
    'quiet': '__QDB_QUIET__',
    'user' : '__QDB_USER__',
    'repl' : '__QDB_REPL__',
    'pipe' : '__QDB_PIPE__',
}

def isset(var: str) -> bool:
  envvar = __ENV__.get(var, None)
  return os.getenv(envvar) is not None if envvar else False

def performance_measurement(_func=None, *, message: str='Executed'):
  def decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      t1 = time.perf_counter()
      if isset('quiet'):
        return func(*args, **kwargs)
      result = func(*args, **kwargs)
      if isset('debug'):
        if result == 1:
          return result
      t2 = time.perf_counter()
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
      user = self.users.getuser()
      if not user:
        authorize(self.users)
        user = self.users.getuser()
      auth = self.users.get_auth(user)
      if QDBAuthType(auth) in auth_types:
        return func(self, *args, **kwargs)
      raise QDBUnauthorizedError('QDB: Unauthorized action.')
    return wrap
  return decorator

def authorize(qdbusers: QDBUsers, username: str=None, password: str=None, change: bool=False):
  try:
    with open('/dev/tty', 'r') as stdin, open('/dev/tty', 'w') as stdout:
      if not username:
        print('QDB: This database requires authentication.', file=sys.stderr)
        stdout.write('Username: ')
        stdout.flush()
        username = stdin.readline().strip()
      if not password:
        password = getpass('Password: ' if not change else 'Current password: ', stream=stdout)
  except (KeyboardInterrupt, EOFError):
      print()
      raise QDBAuthenticationCancelledError('Authentication cancelled.')
  except OSError:
    raise QDBError(
        'Cannot prompt for credentials in pipe mode.'
        '\nUse `--username` and `--password` options.'
    )

  qdbusers.authenticate(username, password) 
  del password

def user_add(qdbusers: QDBUsers, username: str=None, password: str=None, auth_type: str=None, change: bool=False):
  try:
    if not username:
      print('[New user]')
      username = input('Username: ')
      if not username:
        raise QDBAuthenticationCancelledError('QDB: user creation cancelled.')

    if not password:
      password1 = getpass('Password: ' if not change else 'New password: ')
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


def spinner():
  # │╱─╲
  chars = 20 * '|' + 20 * '/' + 20 * '-' + 20 * '\\'
  while True:
    for c in chars:
      yield c

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

  return tokens

def abs_(value: str) -> str:
  value = coerce_number(value)
  if isinstance(value, (int, float)):
    return str(abs(value))
  raise QDBError(f'@abs: Type error: `{value}`.')

def epoch(value: str=None, real: bool=False) -> str:
  if value is None:
    return str(time.time()) if real else str(int(time.time()))
  try:
    dt = datetime.fromisoformat(value)
  except ValueError:
    raise QDBError(
        f'QDB: {"@epochreal" if real else "@epoch"} error: invalid value `{value}`.'
        '\nISO date/time string expected.'
    )
  return str(int(dt.timestamp())) if not real else str(dt.timestamp())

def epochreal(value: str=None) -> str:
  return epoch(value=value, real=True)

def now(dummy: str=None) -> str:
  return epochreal(value=None)

def nowiso(dummy: str=None) -> str:
  return datetime.now().isoformat()

def todate(value: str) -> str:
  try:
    return datetime.fromtimestamp(coerce_number(value)).date().isoformat()
  except (ValueError, TypeError):
    raise QDBError(f'QDB: @date error: `{value}`, invalid value.')

def todatetime(value: str) -> str:
  try:
    return datetime.fromtimestamp(coerce_number(value)).isoformat()
  except (ValueError, TypeError):
    raise QDBError(f'QDB: @datetime error: `{value}`, invalid timestamp.')

def totime(value: str):
  return value

  # except (ValueError, TypeError):
  #   raise QDBError(f'QDB: @time error: `{value}`, invalid value.')

def inc(value: str) -> str:
  value = coerce_number(value)
  if isinstance(value, (int, float)):
    return str(value + 1)
  return str(value)

def dec(value: str) -> str:
  value = coerce_number(value)
  if isinstance(value, (int, float)):
    return str(value - 1)
  return str(value)

FUNCTIONS = {
    '@abs':       abs_,
    '@date':      todate,
    '@datetime':  todatetime,
    '@dec':       dec,
    '@epoch':     epoch,
    '@epochreal': epochreal,
    '@inc':       inc,
    '@now':       now,
    '@nowiso':    nowiso,
    '@time':      totime,
}

def unquote(expr: str):
  quoted = re.sub(r'''(?<!\\)"(.*?)(?<!\\)"''', r'\1', expr)
  unescaped = bytes(quoted, 'utf-8').decode('unicode_escape').encode('latin-1').decode()
  return unescaped

def expand(expr: str, value: str=None, write: bool=False) -> str:
  expanded = expr = unquote(expr)
  value = unquote(value) if value is not None else value
  func = unwrap_function(expr, extract_func=True)
  if func in FUNCTIONS:
    expanded = FUNCTIONS[func](value)
    return expanded
  return expr if write else value

def unwrap_function(expr: str, extract_func: bool=False) -> str:
  '''
  Return base field from function or function if 'extract_func' is True.
  '''
  while match := re.match(r'(?P<sort>\+\+|--)?(@?\w+)\(([^()]+)\)', expr):
    if extract_func:
      func = match.group(2)
      if func in FUNCTIONS:
        expr = func
        break
      if func[0] == '@':
        raise QDBError(f'Error: `{func}`, no such function.')
      else:
        break
    else:
      expr = match.group(3)
  return expr.strip()

def has_function(expr: str) -> bool:
  if match := re.match(r'(?P<sort>\+\+|--)?(@?\w+)\(([^()]+\))', expr):
    return match.group(2) in FUNCTIONS
  return False
