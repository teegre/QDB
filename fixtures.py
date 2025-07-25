import os
import sys

from faker import Faker
from random import choice, randint
from time import perf_counter

from qdb.lib.qdb import QDB

qdb = QDB('persons.qdb')

os.environ['__QDB_QUIET__'] = '1'

if not qdb.is_db_empty():
  print(f'`{qdb.store.database_name}` already exists.', file=sys.stderr)
  exit(0)

fake = Faker('en_US')

def populate_database():

  # Country x10
  for i in range(1, 11):
    ID = f'country:{str(i).zfill(2)}'
    data = fake.country()
    code = data[:2].upper()
    if qdb.w(ID, 'name', data, 'code', code) != 0:
      return 1
    print('COUNTRIES:', int(100*i/10), end='%\r' if i < 10 else '%\n', flush=True)

  # City x100
  for i in range(1, 101):
    ID = f'city:{str(i).zfill(3)}'
    foreignID = f'country:{str(randint(1,10)).zfill(2)}'
    name = fake.city()
    postcode = fake.postalcode()
    if qdb.w(ID, 'name', name, 'postcode', postcode,'country', foreignID) != 0:
      return 1
    print('CITIES:', int(100*i/100), end='%\r' if i < 100 else '%\n', flush=True)

  # Address x5000
  for i in range(1, 5001):
    ID = f'address:{str(i).zfill(4)}'
    foreignID = f'city:{str(randint(1,100)).zfill(3)}'
    data = fake.street_address()
    if qdb.w(ID, 'street', data, 'city', foreignID) != 0:
      return 1
    print('ADDRESSES:', int(100*i/5000), end='%\r' if i < 5000 else '%\n', flush=True)

  astro = {
    'astro:01': 'aries',
    'astro:02': 'taurus',
    'astro:03': 'gemini',
    'astro:04': 'cancer',
    'astro:05': 'leo',
    'astro:06': 'virgo',
    'astro:07': 'libra',
    'astro:08': 'scorpio',
    'astro:09': 'sagittarius',
    'astro:10': 'capricorn',
    'astro:11': 'aquarius',
    'astro:12': 'pisces',
  }

  # Astro x12
  i = 1
  for k, v in astro.items():
    if qdb.w(k, 'sign', v) != 0:
      return 1
    print('ASTRO:', int(100*i/12), end='%\r' if i < 12 else '%\n', flush=True)
    i += 1

  # Person x10000
  for i in range(1, 10001):
    ID = f'person:{str(i).zfill(5)}'
    foreignID = f'address:{str(randint(1,5000)).zfill(4)}'
    data = fake.name()
    if qdb.w(ID, 'name', data, 'age', str(randint(1,100)), 'zodiac', choice(list(astro.keys()))  , 'address', foreignID) != 0:
      return 1
    print('PERSONS:', int(100*i/10000), end='%\r' if i < 10000 else '%\n', flush=True)

  print()
  print('!! ALRIGHT!!')
  print()

  qdb.store.commit()

  return 0

t1 = perf_counter()
rs = populate_database()
t2 = perf_counter()

print(f'{"Built" if rs == 0 else "Failed"} in {(t2-t1):.4f}s.', file=sys.stderr)
print()

if rs:
  exit(rs)

qdb.store.initialize()

print('database schema:')
qdb.schema()

print()
print(len(qdb.store.reverse_refs), 'references.')
print(len(qdb.store.refs), 'referenced hkeys.')
print()
print('Query: what is the number of person per astrological sign?')
print('Q astro ++@id:sign person:@[count:*]')
qdb.q('astro', '++@id:sign', 'person:@[count:*]')
print()
del os.environ['__QDB_QUIET__']
exit(rs)
