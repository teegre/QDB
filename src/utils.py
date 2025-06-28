import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from functools import wraps
from time import time

from src.exception import MDBError

def performance_measurement(_func=None, *, message: str='Executed'):
  def decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      t1 = time()
      if os.getenv('__MUDB_DEBUG__'):
          result = func(*args, **kwargs)
      else:
        try:
          result = func(*args, **kwargs)
        except Exception as e:
          if not isinstance(e, MDBError):
            print(e)
          return 1
      t2 = time()
      print(f'{message} in {(t2-t1):.4f}s.', file=sys.stderr)
      return result
    return wrapper

  if _func is not None and callable(_func):
    return decorator(_func)
  return decorator

def is_numeric(value: str) -> bool:
  try:
    float(value)
    return True
  except (ValueError, TypeError):
    return False

