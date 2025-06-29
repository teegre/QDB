import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from functools import wraps
from time import perf_counter
from typing import Any

from src.exception import MDBError

def performance_measurement(_func=None, *, message: str='Executed'):
  def decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      t1 = perf_counter()
      result = func(*args, **kwargs)
      if not os.getenv('__MUDB_DEBUG__'):
        if result == 1:
          return result
      t2 = perf_counter()
      d = t2 - t1
      if hasattr(args[0], 'parent') and hasattr(args[0].parent, '_perf_info'):
          args[0].parent._perf_info[message] = d
      else:
        print(f'{message} in {d:.4f}s.', file=sys.stderr)
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


