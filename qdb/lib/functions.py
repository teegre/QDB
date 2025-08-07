import os
import re
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timedelta

from qdb.lib.exception import QDBError
from qdb.lib.utils import coerce_number, unquote

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

def now(dummy: str=None, real: bool=False) -> str:
  return epochreal() if real else epoch()

def nowiso(dummy: str=None) -> str:
  return datetime.now().isoformat()

def nowreal(dummy: str=None) -> str:
  return now(real=True)

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

def year(value: str) -> str:
  try:
    return str(datetime.fromtimestamp(coerce_number(value)).year)
  except(ValueError, TypeError):
    raise QDBError(f'QDB: @year error: `{value}`, invalid timestamp.')

def month(value: str) -> str:
  try:
    return str(datetime.fromtimestamp(coerce_number(value)).month)
  except(ValueError, TypeError):
    raise QDBError(f'QDB: @month error: `{value}`, invalid timestamp.')

def totime(value: str):
  try:
    dt = timedelta(seconds=int(float(value)))
    return str(dt)
  except (ValueError, TypeError):
    raise QDBError(f'QDB: @time error: `{value}`, invalid value.')

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

def neg(value: str) -> str:
  value = coerce_number(value)
  if isinstance(value, (int, float)):
    return str(-value)
  return str(value)

FUNCTIONS = {
    '@abs':       abs_,
    '@date':      todate,
    '@datetime':  todatetime,
    '@dec':       dec,
    '@epoch':     epoch,
    '@epochreal': epochreal,
    '@inc':       inc,
    '@month':     month,
    '@neg':       neg,
    '@now':       now,
    '@nowiso':    nowiso,
    '@nowreal':   nowreal,
    '@time':      totime,
    '@year':      year,
}


def expand(expr: str, value: str=None, write: bool=False) -> str:
  if not has_function(expr) and expr[0] == '@':
    raise QDBError(f'QDB: Error: `{unwrap(expr, True)}`, no such function.')
  expanded = expr = unquote(expr)
  value = unquote(value) if value is not None else value
  func = unwrap(expr, extract_func=True)

  if write:
    if (arg := unwrap(expr)) != expr:
      value = unquote(arg)

  if func in FUNCTIONS:
    expanded = FUNCTIONS[func](value)
    return expanded
    raise QDBError(f'QDB: Error: `{unwrap(expr, True)}`, no such function.')
  return expr if write else value

def unwrap(expr: str, extract_func: bool=False) -> str:
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
    return True
  return False
