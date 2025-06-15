import os
import sys

from time import time

def performance_measurement(func, *args):
  def wrap_func(*args, **kwargs):
    t1 = time()
    result = func(*args, **kwargs)
    t2 = time()
    print(f'Executed in {(t2-t1):.4f}s.', file=sys.stderr)
    return result
  return wrap_func

def is_numeric(value: str) -> bool:
  try:
    float(value)
    return True
  except (ValueError, TypeError):
    return False

