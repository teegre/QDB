import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import operator

OP = {
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

VIRTUAL = ('@autoid', '@id', '@hkey')
