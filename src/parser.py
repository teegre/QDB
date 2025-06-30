import difflib
import os
import re
import sys

from typing import Optional

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.exception import QDBParseError
from src.ops import OP, SORTPREFIX, AGGFUNC
from src.storage import Store
from src.utils import coerce_number, is_virtual

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
        raise QDBParseError(
            msg +
            f'\nDid you mean: {', '.join(suggestions)}?'
        )
      else:
        raise QDBParseError(
            msg +
            f'\nAvailable fields: {', '.join(valid_fields)}'
        )

  def validate_aggregate(self, index, func: str, field: str) -> None:
    if func not in AGGFUNC:
      suggestions = difflib.get_close_matches(func, AGGFUNC, n=3, cutoff=0.5)
      msg = f'Error: `{func}` no such aggregate function in `{index}:@[{func}:{field}]`.'

      if suggestions:
        raise QDBParseError(
            msg +
            f'\nDid you mean {', '.join(suggestions)}?'
        )
      else:
        raise QDBParseError(
            msg +
            f'\nAvailable aggregate functions: {', '.join(sorted(AGGFUNC))}'
        )

  def _parse_condition(self, part: str, fields: list, sort: list) -> Optional[dict]:
    # IN-style syntax: optional sort, field(value1[, ..., valueN])
    in_match = re.match(
        r'^(?P<sort>\+\+|--)?(?P<field>[^\s:!()]+)'
        r'(?P<neg>!)?\((?P<values>[^\)]*)\)$', part
    )

    if in_match:
      field = in_match.group('field').strip()

      values_raw = in_match.group('values')
      if not values_raw or not values_raw.strip():
        raise QDBParseError(f'Error: missing values in: `{part}`')

      values = [
          coerce_number(v.strip()) if not is_virtual(field)
          else v.strip()
          for v in in_match.group('values').split(',')
      ]

      if not values:
        raise QDBParseError(f'Error: missing values in: `{part}`')

      if field not in fields:
        fields.append(field)
      if in_match.group('sort'):
        sort.append({'order': SORTPREFIX[in_match.group('sort')], 'field': field})

      return {
          'field': field,
          'op': 'ni' if in_match.group('neg') else 'in',
          'value': values
      }

    match = re.match(
        r'^(?P<sort>\+\+|--)?(?P<field>[^=><!*^$]+)'
        r'(?P<op>\*\*|!\*|!=|<=|>=|=|<|>|!?\^|!?\$)?'
        r'(?P<value>.+)?$', part
    )

    if not match:
      raise QDBParseError(f'Error: invalid expression: `{part}`')

    groups = match.groupdict()
    field = groups['field'].strip()
    if field not in fields and not field.startswith('@['):
      fields.append(field)

    if groups['sort']:
      sort.append({'order': SORTPREFIX[groups['sort']], 'field': field})

    if not groups['value'] and groups['op']:
      raise QDBParseError(f'Error: missing value in condition: `{part}`')

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

    def validate_quoted_expr(expr: str):
      stack = []
      for i, c in enumerate(expr):
        if c in ('"', "'"):
          if stack and stack[-1] == c:
            stack.pop()
          else:
            stack.append(c)
      if stack:
        raise QDBParseError(f'Error: unbalanced quotes in expression: `{expr}`.')

    def store_quoted(m):
      key = f'__Q{len(q_v)}__'
      quoted = m.group(0)[1:-1]
      unescaped = bytes(quoted, 'utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')
      q_v[key] = unescaped
      return key

    def safe_split_colon(s: str) -> list:
      parts = []
      cur = ''
      br_depth = 0
      pr_depth = 0
      for c in s:
        if c == '(':
          pr_depth += 1
        if c == '[':
          br_depth += 1
        elif c == ')':
          pr_depth -= 1
        elif c == ']':
          br_depth -= 1
        if c == ':' and br_depth == pr_depth == 0:
          parts.append(cur)
          cur = ''
        else:
          cur += c
      if br_depth != 0:
        raise QDBParseError(f'Error: mismatched brackets in expression: `{expr}`.')
      if pr_depth != 0:
        raise QDBParseError(f'Error: mismatched parentheses in expression; `{expr}`')

      if cur:
        parts.append(cur)

      return parts

    validate_quoted_expr(expr)
    expr_safe = q_r.sub(store_quoted, expr)

    # How come?
    if not expr_safe.strip():
      raise QDBParseError('Error: empty expression.')

    parts = safe_split_colon(expr_safe)

    if self.store.is_index(parts[0]):
      index = parts[0]
      parts = parts[1:]
    else:
      index = index_hint or self.main_index

    if expr == '*':
      raise QDBParseError('Error: `*` only allowed after an index.')

    if parts == ['*']:
      return {
          'index': index,
          'fields': ['*'],
          'conditions': [],
          'sort': None,
          'aggregations': None
      }

    if '*' in parts:
      raise QDBParseError('Error: `*` only allowed after an index.')

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
              raise QDBParseError(f'Error: missing field in `{sub_part}`.')
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
          raise QDBParseError(f'Error: invalid syntax: `@[{aggs}]`')

        item_r = r'(?P<sort>\+\+|--)?(?P<op>\w+):(?P<field>[\w|\*@]+)'

        items = aggs.split(',')

        for item in items:
          item = item.strip()
          m = re.match(item_r, item)
          if m:
            agg_sort = m.group('sort') or None
            op = m.group('op')
            f = m.group('field')

            self.validate_aggregate(index, op, f)
            self.validate_field(index, f, context=f'{index}:@[{item}]', excepted=['*'] if op == 'count' else [])

            aggregations.append({
              'op': op,
              'field': f
            })

            composite_field = f'{index}:{op}{':'+f if f != '*' else ''}'
            if composite_field not in agg_fields:
              agg_fields.append(composite_field)
              if agg_sort:
                sort_info.append({'order': SORTPREFIX[agg_sort], 'field': composite_field})
          else:
            raise QDBParseError(f'syntax error in: `@[{item}]`')

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

