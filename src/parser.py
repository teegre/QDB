import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.exception import MDBParseError
from src.ops import OP, SORTPREFIX
from src.storage import Store

class Parser:
  def __init__(self, store: Store, main_index: str=None):
    self.store = store
    self.main_index = main_index

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

    if self.store.is_index(parts[0]):
      index = parts[0]
      parts = parts[1:]
    else:
      index = self.main_index

    if parts == ['*']:
      return {
          'index': index,
          'fields': ['*'],
          'conditions': None,
          'sort': None,
          'aggregations': None
      }

    if '*' in parts:
      raise MDBParseError('Error: `*` only allowed after an index.')

    fields = []
    sort = []
    conditions = []
    aggregations = {}

    for part in parts:
      for k, v in q_v.items():
        part = part.replace(k, v)

      agg_match = re.match(r'^(P<field>\w+):@\[([^\]]+)\]$', part)
      if agg_match:
        field = agg_match.group('field')
        aggs = agg_match.group(2).split(',')
        for agg in aggs:
          if ':' not in agg:
            raise MDBParseError(f'Invalid aggregation: `{agg}`.')
          agg_op, agg_field = agg.split(':', 1)
          aggregations.setdefault(field, []).append({
            'op': agg_op.strip(),
            'field': agg_field.strip()
          })
        fields.append(field)
        continue

      match = re.match(
          r'^(?P<sort>\+\+|--)?(?P<field>[^=><!*^$]+)'
          r'(?P<op>\*\*|!\*|!=|<=|>=|=|<|>|!?\^|!?\$)?'
          r'(?P<value>.+)?$', part
      )

      if not match:
        raise MDBParseError(f'Error: Invalid expression: `{part}`')

      groups = match.groupdict()
      field = groups['field'].strip()

      if groups['sort']:
        sort.append({'order': SORTPREFIX[groups['sort']], 'field': field})

      if groups['op']:
        op = OP[groups['op']]
        value = groups['value']
        for k, v in q_v.items():
          value = value.replace(k, v)
        conditions.append({'field': field, 'op': op, 'value': value.strip()})

      fields.append(field)

    return {
        'index': index,
        'fields': fields,
        'conditions': conditions if conditions else None,
        'sort': sort if sort else None,
        'aggregations': aggregations if aggregations else None
    }
