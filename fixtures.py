from faker import Faker
from random import choice, randint
import sys
from time import perf_counter

from src.qdb import QDB
from src.utils import performance_measurement

qdb = QDB('persons2.qdb')
fake = Faker('en_US')

def populate_database():

  # Country x10
  print('COUNTRIES:')

  for i in range(1, 11):
    ID = f'country:{str(i).zfill(2)}'
    data = fake.country()
    if qdb.w(ID, 'name', data) != 0:
      return 1
    print(int(100*i/10), end='%\r ' if i < 10 else '%\n', flush=True)


  # City x100
  print('CITIES:')

  for i in range(1, 101):
    ID = f'city:{str(i).zfill(3)}'
    foreignID = f'country:{str(randint(1,10)).zfill(2)}'
    data = fake.city()
    if qdb.w(ID, 'name', data, 'country', foreignID) != 0:
      return 1
    print(int(100*i/100), end='%\r ' if i < 100 else '%\n', flush=True)

  # Address x5000
  print('ADDRESSES:')

  for i in range(1, 5001):
    ID = f'address:{str(i).zfill(4)}'
    foreignID = f'city:{str(randint(1,100)).zfill(3)}'
    data = fake.street_address()
    if qdb.w(ID, 'street', data, 'city', foreignID) != 0:
      return 1
    print(int(100*i/5000), end='%\r ' if i < 5000 else '%\n', flush=True)

  astro = {
    'astro:01': { 'sign': 'aries' },
    'astro:02': { 'sign': 'taurus' },
    'astro:03': { 'sign': 'gemini' },
    'astro:04': { 'sign': 'cancer' },
    'astro:05': { 'sign': 'leo' },
    'astro:06': { 'sign': 'virgo' },
    'astro:07': { 'sign': 'libra' },
    'astro:08': { 'sign': 'scorpio' },
    'astro:09': { 'sign': 'sagittarius' },
    'astro:10': { 'sign': 'capricorn' },
    'astro:11': { 'sign': 'aquarius' },
    'astro:12': { 'sign': 'pisces' },
  }

  # Astro x12
  print('ASTRO')

  i = 1
  for k, v in astro.items():
    if qdb.w(k, 'sign', v['sign']) != 0:
      return 1
    print(int(100*i/12), end='%\r' if i < 12 else '%\n', flush=True)
    i += 1

  # Person x10000
  print('PERSONS:')

  for i in range(1, 10001):
    ID = f'person:{str(i).zfill(5)}'
    foreignID = f'address:{str(randint(1,5000)).zfill(4)}'
    data = fake.name()
    if qdb.w(ID, 'name', data, 'age', str(randint(1,100)), 'zodiac', choice(list(astro.keys()))  , 'address', foreignID) != 0:
      return 1
    print(int(100*i/10000), end='%\r ' if i < 10000 else '%\n', flush=True)

  print('ALRIGHT!')

  if qdb.store.compact() != 0:
    return 1

  return 0

t1 = perf_counter()
rs = populate_database()
t2 = perf_counter()

print(f'{"Build" if rs == 0 else "Failed"} in {(t2-t1):.4f}s.', file=sys.stderr)
del qdb
exit(rs)
