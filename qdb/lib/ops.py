import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import operator

OP = {
  '=':  'eq', # equal
  '!=': 'ne', # not equal
  '>':  'gt', # greater than
  '>=': 'ge', # greater or equal
  '<':  'lt', # less than
  '<=': 'le', # less than or equal
  '^':  'sw', # starts with
  '!^': 'ns', # not starts with
  '$':  'dw', # ends with
  '!$': 'nd', # not ends with
  '**': 'ct', # contains
  '!*': 'nc', # not contains
  'in': 'in', # in
  'ni': 'ni', # not in
}

REVOP = { # for error display
  sop: op
  for op, sop in OP.items()
}

BINOP = ('AND', 'OR')

OPFUNC = {
  'eq': operator.eq,
  'ne': operator.ne,
  'gt': operator.gt,
  'ge': operator.ge,
  'lt': operator.lt,
  'le': operator.le,
}

AGGFUNC = (
    'avg',
    'sum',
    'min',
    'max',
    'count',
)

SORTPREFIX = {
  '++': 'asc',
  '--': 'desc',
}

VIRTUAL = (
    '@id',
    '@hkey',
)

OTHER = (
    '@autoid',
    '@epoch',
    '@epochreal',
)

OPTIONS = (
  '@QDB_USERS',
)
