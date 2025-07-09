import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from functools import wraps
from time import perf_counter
from typing import Any

from src.exception import QDBHkeyError
from src.ops import VIRTUAL

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
