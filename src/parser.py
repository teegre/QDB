import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.exception import MDBParseError
from src.storage import Store

class Parser:
  def __init__(self, store: Store, primary_index: str=None, expr: str=None):
    self.store = store
    self._index = primary_index
    self._expr = expr
    self._idx = 0

    self.__ops = {
        '=': 'eq',  # equal
        '!=': 'ne', # not equal
        '>': 'gt',  # greater than
        '>=': 'ge', # greater or equal
        '<': 'lt',  # less than
        '<=': 'le', # less than or equal
        '^': 'sw',  # starts with
        '!^': 'ns', # not starts with
        '$': 'dw',  # ends with
        '!$': 'nd', # not ends with
        '**': 'ct', # contains
        '!*': 'nc', # not contains
    }

    self.__sort_prefix = {
        '++': 'asc',
        '--': 'desc',
        '??': 'rand',
        }

  def parse(self, expr: str) -> dict:
    q_p = r'''(["'])(?:(?=(\\?))\2.)*?\1'''
    q_r = re.compile(q_p)
    q_v = {}

    def store_quoted(m):
      key = f'__Q{len(q_v)}__'
      quoted = m.group(0)[1:-1]
      unescaped = bytes(quoted, 'utf-8').decode('unicode_escape')
      q_v[key] = unescaped
      return key

    expr_safe = q_r.sub(store_quoted, expr)

    parts = expr_safe.split(':')
    index = None
    if self.store.is_index(parts[0]):
      index = parts[0]
      parts = parts[1:]
    if parts == ['*']:
      return {
          'index': index,
          'fields': ['*'],
          'conditions': None,
          'sort': None
      }

    if '*' in parts:
      raise MDBParseError('Error: `*` only allowed after an index.')


    fields = []
    sort = []
    conditions = []

    for part in parts:
      for k, v in q_v.items():
        part = part.replace(k, v)

      match = re.match(
          r'^(?P<sort>\+\+|--|\?\?)?(?P<field>[^=><!*^$]+)'
          r'(?P<op>\*\*|!\*|!=|<=|>=|=|<|>|!?\^|!?\$)?'
          r'(?P<value>.+)?$', part
      )

      if not match:
        raise MDBParseError(f'Error: Invalid expression: `{part}`')

      groups = match.groupdict()
      field = groups['field'].strip()

      if groups['sort']:
        sort.append({'order': self.__sort_prefix[groups['sort']], 'field': field})

      if groups['op']:
        op = self.__ops[groups['op']]
        value = groups['value']
        for k, v in q_v.items():
          value = value.replace(k, v)
        conditions.append({'field': field, 'op': op, 'value': value.strip()})

      fields.append(field)

    return {
        'index': index,
        'fields': fields,
        'conditions': conditions if conditions else None,
        'sort': sort if sort else None
    }
