import os
import sys

from functools import wraps
from time import time

def performance_measurement(_func=None, *, message: str='Executed'):
  def decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      t1 = time()
      result = func(*args, **kwargs)
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

