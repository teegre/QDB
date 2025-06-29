from faker import Faker
from random import randint

from src.qdb import QDB
qdb = QDB('persons.qdb')

fake = Faker('en_US')

# Country x10
print('COUNTRIES:')

for i in range(1, 11):
  ID = f'country:{str(i).zfill(2)}'
  data = fake.country()
  if qdb.hset(ID, 'name', data) != 0:
    exit(1)
  print(int(100*i/10), end='%\r ' if i < 10 else '%\n', flush=True)


# City x100
print('CITIES:')

for i in range(1, 101):
  ID = f'city:{str(i).zfill(3)}'
  foreignID = f'country:{str(randint(1,10)).zfill(2)}'
  data = fake.city()
  if qdb.hset(ID, 'name', data, 'country', foreignID) != 0:
    exit(1)
  print(int(100*i/100), end='%\r ' if i < 100 else '%\n', flush=True)

# Address x5000
print('ADDRESSES:')

for i in range(1, 5001):
  ID = f'address:{str(i).zfill(4)}'
  foreignID = f'city:{str(randint(1,100)).zfill(3)}'
  data = fake.street_address()
  if qdb.hset(ID, 'street', data, 'city', foreignID) != 0:
    exit(1)
  print(int(100*i/5000), end='%\r ' if i < 5000 else '%\n', flush=True)

# Person x10000
print('PERSONS:')

for i in range(1, 10001):
  ID = f'person:{str(i).zfill(5)}'
  foreignID = f'address:{str(randint(1,5000)).zfill(4)}'
  data = fake.name()
  if qdb.hset(ID, 'name', data, 'age', str(randint(21,100)) , 'address', foreignID) != 0:
    exit(1)
  print(int(100*i/10000), end='%\r ' if i < 10000 else '%\n', flush=True)
  
print('ALRIGHT!')

if qdb.store.compact() != 0:
  exit(1)

del qdb
exit(0)
