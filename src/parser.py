import difflib
import os
import re
import sys

from typing import Optional

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.exception import MDBParseError, MDBMissingFieldError
from src.ops import OP, SORTPREFIX, AGGFUNC
from src.storage import Store

class Parser:
  def __init__(self, store: Store, main_index: str=None):
    self.store = store
    self.main_index = main_index

  def validate_field(self, index: str, field: str, excepted: list=[], context: str=None) -> None:
    valid_fields = self.store.get_fields_from_index(index)
    if field not in valid_fields + excepted:
      suggestions = difflib.get_close_matches(field, valid_fields, n=3, cutoff=0.5)

      msg = f'Error: `{field}` is not a valid field for `{index}`'
      msg += '.' if not context else f' in `{context}`.'

      if suggestions:
        raise MDBParseError(
            msg +
            f'\nDid you mean: {', '.join(suggestions)}?'
        )
      else:
        raise MDBParseError(
            msg +
            f'\nAvailable fields: {', '.join(valid_fields)}'
        )

  def validate_aggregation_func(self, index, func: str, field: str) -> None:
    if func not in AGGFUNC:
      suggestions = difflib.get_close_matches(func, AGGFUNC, n=3, cutoff=0.5)
      msg = f'Error: `{func}` no such aggregation function in `{index}:@[{func}:{field}]`.'

      if suggestions:
        raise MDBParseError(
            msg +
            f'\nDid you mean {', '.join(suggestions)}?'
        )
      else:
        raise MDBParseError(
            msg +
            f'\nAvailable aggregation functions: {', '.join(sorted(AGGFUNC))}'
        )

  def _parse_condition(self, part: str, fields: list, sort: list) -> Optional[dict]:
      match = re.match(
          r'^(?P<sort>\+\+|--)?(?P<field>[^=><!*^$]+)'
          r'(?P<op>\*\*|!\*|!=|<=|>=|=|<|>|!?\^|!?\$)?'
          r'(?P<value>.+)?$', part
      )

      if not match:
        raise MDBParseError(f'Error: invalid expression: `{part}`')

      groups = match.groupdict()
      field = groups['field'].strip()
      if field not in fields and not field.startswith('@['):
        fields.append(field)

      if groups['sort']:
        sort.append({'order': SORTPREFIX[groups['sort']], 'field': field})

      if groups['op']:
        return {
            'field': field,
            'op': OP[groups['op']],
            'value': groups['value'].strip() if groups['value'] else ''
        }

      return None

  def parse(self, expr: str, index_hint: str=None) -> dict:
    q_p = r'''(["'])(?:(?=(\\?))\2.)*?\1'''
    q_r = re.compile(q_p)
    q_v = {}

    def store_quoted(m):
      key = f'__Q{len(q_v)}__'
      quoted = m.group(0)[1:-1]
      unescaped = bytes(quoted, 'utf-8').decode('unicode_escape')
      q_v[key] = unescaped
      return key

    def safe_split_colon(s: str) -> list:
      parts = []
      cur = ''
      br_depth = 0
      for c in s:
        if c == '[':
          br_depth += 1
        elif c == ']':
          br_depth -= 1
        if c == ':' and br_depth == 0:
          parts.append(cur)
          cur = ''
        else:
          cur += c

      if cur:
        parts.append(cur)
      return parts

    expr_safe = q_r.sub(store_quoted, expr)

    # How come?
    if not expr_safe.strip():
      raise MDBParseError('Error: empty expression.')

    parts = safe_split_colon(expr_safe)

    if self.store.is_index(parts[0]):
      index = parts[0]
      parts = parts[1:]
    else:
      index = index_hint or self.main_index

    if expr == '*':
      raise MDBParseError('Error: `*` only allowed after an index.')

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
    sort_info = []
    conditions = []
    aggregations = []
    agg_fields = []
    fields_to_check = []
    index_fields = self.store.get_fields_from_index(index)

    for part in parts:
      for k, v in q_v.items():
        part = part.replace(k, v)

      # Logical operators
      if '&&' in part or '||' in part:
        binop = '&&' if '&&' in part else '||'
        sub_parts = part.split(binop)
        cond_group = {'op': 'AND' if binop == '&&' else 'OR', 'conditions': []}
        last_field = None
        for sub_part in sub_parts:
          sub_part = sub_part.strip()
          if not re.match(r'^[^=><!*^$]+', sub_part):
            if last_field is None:
              raise MDBParseError(f'Error: missing field in `{sub_part}`.')
            sub_part = f'{last_field}{sub_part}'
          else:
            m = re.match(r'^(?P<field>[^=><!*^$]+)', sub_part)
            if m:
              last_field = m.group('field').strip()
          cond_group['conditions'].append(
              self._parse_condition(sub_part, fields, sort_info)
          )
        conditions.append(cond_group)
        continue

      conditions.append(self._parse_condition(part, fields, sort_info))

      agg_match = re.match(r'^@\[(?P<aggs>[^\]]+)\]$', part)
      if agg_match:
        aggs = agg_match.group('aggs')

        if not aggs:
          raise MDBParseError(f'Error: invalid syntax: `@[{aggs}]`')

        item_r = r'(?P<sort>\+\+|--)?(?P<op>\w+):(?P<field>[\w@]+)'

        items = aggs.split(',')

        for item in items:
          item = item.strip()
          m = re.match(item_r, item)
          if m:
            agg_sort = m.group('sort') or None
            op = m.group('op')
            f = m.group('field')

            self.validate_aggregation_func(index, op, f)
            self.validate_field(index, f, context=f'{index}:@[{item}]')

            aggregations.append({
              'op': op,
              'field': f
            })

            composite_field = f'[{op}:{f}]'
            if composite_field not in agg_fields:
              agg_fields.append(composite_field)
              if agg_sort:
                sort_info.append({'order': SORTPREFIX[agg_sort], 'field': composite_field})

    # Field validity check
    for field in fields:
      self.validate_field(index, field, excepted=agg_fields)

    return {
        'index': index,
        'fields': fields + agg_fields,
        'conditions': conditions,
        'sort': sort_info if sort_info else None,
        'aggregations': aggregations if aggregations else None
    }

