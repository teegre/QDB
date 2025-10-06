import difflib
import os
import re
import sys

from dataclasses import dataclass
from typing import Optional

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb.lib.exception import QDBParseError
from qdb.lib.functions import  unwrap
from qdb.lib.ops import OP, SORTPREFIX, AGGFUNC
from qdb.lib.storage import QDBStore
from qdb.lib.utils import coerce_number, is_virtual, unquote

@dataclass
class QDBParserField:
  name: str
  visible: bool

@dataclass
class QDBParserCond:
  field: str
  op: str
  value: str|list

@dataclass
class QDBParserAgg:
  op: str
  field: str

@dataclass
class QDBParserExpr:
  index: str
  fields: list[QDBParserField]
  conditions: list[QDBParserCond]
  sort: str
  aggregations: list[QDBParserAgg]

class QDBParser:
  def __init__(self, store: QDBStore, main_index: str=None):
    self.store = store
    self.main_index = main_index

  def validate_field(self, index: str, field: QDBParserField, excepted: list=[], context: str=None) -> None:
    valid_fields = self.store.get_fields_from_index(index)
    if unwrap(field.name) not in valid_fields + excepted:
      suggestions = difflib.get_close_matches(field.name, valid_fields, n=3, cutoff=0.5)

      msg = f'`{field.name}` is not a valid field for `{index}`'
      msg += '.' if not context else f' in `{context}`.'

      if suggestions:
        raise QDBParseError(
            msg +
            f'\n* did you mean: {', '.join(suggestions)}?'
        )
      else:
        raise QDBParseError(
            msg +
            f'\n* available fields: {', '.join(valid_fields)}'
        )

  def validate_aggregate(self, index, func: str, field: str) -> None:
    if func not in AGGFUNC:
      suggestions = difflib.get_close_matches(func, AGGFUNC, n=3, cutoff=0.5)
      msg = f'`{func}` no such aggregate function in `{index}:@[{func}:{field}]`.'

      if suggestions:
        raise QDBParseError(
            msg +
            f'\n* did you mean {', '.join(suggestions)}?'
        )
      else:
        raise QDBParseError(
            msg +
            f'\n* available aggregate functions: {', '.join(sorted(AGGFUNC))}'
        )

  def _split_csv_quoted(self, s: str) -> list[str]:
    vals, cur, in_quote, esc = [], '', None, False
    for c in s:
      if esc:
        cur += c
        esc = False
        continue
      if c == '\\':
        cur += c
        esc = True
        continue
      if c in ('"', "'"):
        cur += c
        in_quote = None if in_quote == c else c
        continue
      if c == ',' and not in_quote:
        vals.append(cur.strip())
        cur = ''
      else:
        cur += c
    if cur.strip():
      vals.append(cur.strip())

    return vals

  def _parse_condition(self, part: str, fields: list, sort: list) -> Optional[QDBParserCond]:
    # IN-style syntax: optional sort, field(value1[,..., valueN])

    in_match = re.match(
        r'^(?P<sort>\+\+|--)?(?P<field>[^@\s:!()]+)'
        r'(?P<neg>!)?\((?P<body>.*)\)$', part
    )

    if in_match and part == unwrap(part, extract_func=True):
      field = in_match.group('field').strip()

      values_raw = in_match.group('body')
      if not values_raw or not values_raw.strip():
        raise QDBParseError(f'missing values in: `{part}`')

      values = self._split_csv_quoted(values_raw)

      if not values:
        raise QDBParseError(f'missing values in: `{part}`.')

      values = [
          coerce_number(unquote(v.strip())) if not is_virtual(field)
          else unquote(v.strip())
          for v in in_match.group('body').split(',')
      ]

      if field not in fields:
        fields.append(QDBParserField(
          field[1:] if field[0] == '#' else field,
          False if field[0] == '#' else True
        ))

      if in_match.group('sort'):
        sort.append({
          'order': SORTPREFIX[in_match.group('sort')],
          'field': field[1:] if field[0] == '#' else field
          })

      return QDBParserCond(
          field[1:] if field[0] == '#' else field,
          'ni' if in_match.group('neg') else 'in',
          values,
      )

    match = re.match(
        r'^(?P<sort>\+\+|--)?(?P<field>[$@#]?\w+(?:\([^\)]+\))?)'
        r'(?P<op>\*\*|!\*|!=|<=|>=|=|<|>|!?\^|!?\$)?'
        r'(?P<value>.+)?$', part
    )

    # match = re.match(
    #     r'^(?P<sort>\+\+|--)?(?P<field>[^=><!*^$]+)'
    #     r'(?P<op>\*\*|!\*|!=|<=|>=|=|<|>|!?\^|!?\$)?'
    #     r'(?P<value>.+)?$', part
    # )

    if not match:
      raise QDBParseError(f'invalid expression: `{part}`')

    groups = match.groupdict()
    field = groups['field'].strip()

    if unwrap(field) not in fields and not field.startswith('@['):
      fields.append(QDBParserField(
        field[1:] if field[0] =='#' else field,
        False if field[0] == '#' else True))

    if groups['sort']:
      sort.append({'order': SORTPREFIX[groups['sort']], 'field': field})

    if not groups['value'] and groups['op']:
      raise QDBParseError(f'missing value in condition: `{part}`')

    if groups['op']:
      return QDBParserCond(
          field[1:] if field[0] == '#' else field,
          OP[groups['op']],
          groups['value'].strip() if groups['value'] else '',
      )

    return None

  def parse(self, expr: str, index_hint: str=None) -> dict:
    q_p = r'''(["'])(?:(?=(\\?))\2.)*?\1'''
    q_r = re.compile(q_p)
    q_v = {}

    def store_quoted(m):
      key = f'__Q{len(q_v)}__'
      quoted = m.group(0)[1:-1]
      unescaped = bytes(quoted, 'utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')
      q_v[key] = unescaped
      return key

    def validate_quoted_expr(expr: str):
      stack = []
      quote_type = ''
      for i, c in enumerate(expr):
        if c in ('"', "'"):
          if i == 0:
            quote_type = c
          if c == quote_type:
            if stack and stack[-1] == c:
              stack.pop()
            else:
              stack.append(c)
      if stack:
        raise QDBParseError(f'unbalanced quotes in expression: `{expr}`.')

    def safe_split_colon(s: str) -> list:
      parts = []
      cur = ''
      br_depth = 0
      pr_depth = 0
      in_quote = None
      escape = False

      for pos, c in enumerate(s, 1):
        if escape:
          cur += c
          escape = False
          continue

        if c == '\\':
          cur += c
          escape = True
          continue

        if c in ('"', "'"):
          cur += c
          if in_quote is None:
            in_quote = c
          elif in_quote == c:
            in_quote = None
          continue

        if in_quote:
          cur += c
          continue

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
        raise QDBParseError(
            f'mismatched brackets at position {pos} in expression:\n'
            f'`{expr}`.')
      if pr_depth != 0:
        raise QDBParseError(
            f'mismatched parentheses at position {pos} in expression:\n'
            f'`{expr}`')

      if cur:
        parts.append(cur)

      return parts

    expr_safe = q_r.sub(store_quoted, expr)
    if not expr_safe.strip():
      raise QDBParseError('empty expression.')

    parts = safe_split_colon(expr_safe)
    validate_quoted_expr(expr)

    if self.store.is_index(parts[0]):
      index = parts[0]
      parts = parts[1:]
    else:
      index = index_hint or self.main_index

    if expr == '*':
      raise QDBParseError('`*` only allowed after an index.')

    if parts == ['*']:
      return QDBParserExpr(
          index,
          [QDBParserField('*', True)],
          [],
          None,
          None
      )

    if '*' in parts:
      raise QDBParseError('`*` only allowed after an index.')

    fields = []
    sort_info = []
    conditions = []
    aggregations = []
    agg_fields = []
    fields_to_check = []
    index_fields = self.store.get_fields_from_index(index)

    for part in parts:
      agg_match = re.match(r'^@\[(?P<aggs>[^\]]+)\]$', part)
      if agg_match:
        aggs = agg_match.group('aggs')

        if not aggs:
          raise QDBParseError(f'invalid syntax: `@[{aggs}]`')

        item_r = r'(?P<sort>\+\+|--)?(?P<op>\w+):(?P<field>[$@]?\w+(?:\([^\)]+\))?|\*)'

        items = aggs.split(',')

        for item in items:
          item = item.strip()
          m = re.match(item_r, item)
          if m:
            agg_sort = m.group('sort') or None
            op = m.group('op')
            f = m.group('field')

            f = QDBParserField(f, True)

            self.validate_aggregate(index, op, f)
            self.validate_field(index, f, context=f'{index}:@[{item}]', excepted=['*'] if op == 'count' else [])

            aggregations.append(QDBParserAgg(op, f.name))

            composite_field = f'{index}:{op}{':'+f.name if f.name != '*' else ''}'
            if composite_field not in agg_fields:
              agg_fields.append(QDBParserField(composite_field, True))
              if agg_sort:
                sort_info.append({'order': SORTPREFIX[agg_sort], 'field': composite_field})
          else:
            raise QDBParseError(f'syntax error in: `@[{item}]`')
      else:
        for k, v in q_v.items():
          part = part.replace(k, v)
        conditions.append(self._parse_condition(part, fields, sort_info))

    # Field validity check
    for field in fields:
      self.validate_field(index, field, excepted=agg_fields)
      # check for fields without condition
      if field in agg_fields:
        continue

    return QDBParserExpr(
        index,
        fields + agg_fields,
        conditions,
        sort_info if sort_info else None,
        aggregations if aggregations else None
    )
