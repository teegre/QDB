import hashlib
import io
import json
import logging
import os
import select
import socket
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb.lib.exception import QDBAuthenticationError, QDBError
from qdb.lib.utils import isset, getuser, getsessionenv, setenv, splitcmd, authorize

__SESSIONS_PATH__ = '/tmp/qdb-sessions.json'

def savesessions(sessions: dict):
  with open(__SESSIONS_PATH__, 'w') as f:
    f.write(json.dumps(sessions))

def loadsessions() -> dict:
  if os.path.exists(__SESSIONS_PATH__):
    with open(__SESSIONS_PATH__) as f:
      return json.loads(f.read())
  return {}

def session_path_encode(db_path: str):
  return hashlib.sha1(f'{getuser()}:{db_path}'.encode()).hexdigest()

def getsession(session_name: str) -> str:
  sessions = loadsessions()
  return sessions.get(session_name, '')

def setsession(client: object) -> str:
  sessions: dict = loadsessions()

  db_path = client.qdb.store.database_path
  db_name = client.qdb.store.database_name
  db_user = getuser()

  db_session_hash = session_path_encode(db_path)

  if db_name in sessions:
    session_hash = sessions.get(db_name).partition(',')[0]
    # a session has the same name, check session hash
    if session_hash == db_session_hash:
      # not supposed to happen
      raise QDBError(f'\x1b[1m{db_name}\x1b[0m, session already exists.')

    # add suffix to current name
    suffix = 2
    while db_name in sessions:
      db_name = f'{db_name}-{suffix}'
      suffix += 1

  sessions[db_name] = f'{db_session_hash},/tmp/qdb-{db_user}-{db_name}.sock'

  savesessions(sessions)

  setenv('session', db_name)

  return f'/tmp/qdb-{db_user}-{db_name}.sock'

def listsessions() -> int:
  sessions = loadsessions()
  if not sessions:
    print('* no active session.', file=sys.stderr)
    return 1
  for session, p in sessions.items():
    user = p.partition(',')[2].split('-')[1]
    print(f'* \x1b[1m{session}\x1b[0m ({user})')
  print()
  count = len(sessions)
  print(f'{count} active session{"s" if count > 1 else ""} found.', file=sys.stderr)
  return 0

def getsockpath(session_name: str, user: str=None) -> str:
  currentuser = getuser() if user is None else user
  return f'/tmp/qdb-{currentuser}-{session_name}.sock'

def runserver(session_path: str, client: 'QDBClient'):
  if not client.qdb.store.isdatabase:
    print('nope', file=sys.stderr)
    return 1
  try:
    client.qdb.store.build_indexed_fields(quiet=True)
    sock_path = setsession(client)
    session_name = getsessionenv()
  except QDBError as e:
    print(e, file=sys.stderr)
    return 1

  if isset('log'):
    logging.basicConfig(
        filename=client.qdb.store.database_path+'.log',
        level=logging.INFO,
        format=f'%(asctime)s|%(levelname)s({session_name}): %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )
    logger = logging.getLogger(__name__)
    logger.info(f'<-- session opened')

  if not isset('quiet'):
    print(f'\x1b[1m{session_name}\x1b[0m: session \x1b[32mopened\x1b[0m')

  server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  server.bind(sock_path)
  server.listen(1)

  while not client.stop_event.is_set():
    r, _, _ = select.select([server], [], [], 0.01)
    if r:
      conn, _ = server.accept()
      with conn:
        cmd = conn.recv(4096).decode().strip()
        if isset('log'):
          logger.info(f'received: {cmd}')
        if cmd.upper() == 'PING':
          if isset('quiet'):
            conn.sendall(b'\x01\x02\x030\n')
            continue
          response = cmd.replace('i', 'o').replace('I', 'O')
          conn.sendall(b'\x01\x02' + response.encode() + b'\n\x030\n')
          continue

        if cmd.startswith('__qdbusrchk__'):
          if not client.qdb.users.hasusers:
            conn.sendall(b'\x01\x02\x030\n')
            continue
          command = splitcmd(cmd)
          usr, pwd = command[1], command[2]
          if usr != getuser():
            if isset('log'):
              logger.warn('received unauthorized connection')
            conn.sendall(b'\x01\x02Unauthorized connection.\n\x031\n')
            continue
          try:
            authorize(client.qdb.users, usr, pwd)
            if isset('log'):
              logger.info('connection successful')
            conn.sendall(b'\x01\x02\x030\n')
            continue
          except QDBAuthenticationError:
            if isset('log'):
              logger.warn('connection refused')
            conn.sendall(b'\x01\x02Connection refused\n\x031\n')
            continue

        if cmd.upper() == 'CLOSE':
          if isset('log'):
            logger.info(f'closing session')
          if isset('quiet'):
            conn.sendall(b'\x01\x02\x030\n')
            break
          conn.sendall(
              b'\x01\x02' +
              f'\x1b[1m{session_name}\x1b[0m: session \033[31mclosed\033[0m.\n'.encode() +
              b'\x030\n'
          )
          break

        stdout, stderr = io.StringIO(), io.StringIO()
        oldout, olderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = stdout, stderr

        try:
          ret = client.execute(cmd)
          out = stdout.getvalue().encode()
          err = stderr.getvalue().encode()
          payload = b'\x01' + out + b'\x02' + err + b'\x03' + str(ret).encode() + b'\n'
          conn.sendall(payload)
        except KeyboardInterrupt: # HOW?
          conn.sendall(b'\x01\x02\x031\n')
          break
        except QDBError as e:
          logger.error(e)
          conn.sendall(b'\x01\x02' + str(e).encode() + b'\n\x031\n')
          continue
        except Exception as e:
          if isset('log'):
            logger.error(f'internal error: {e}')
          continue
        finally:
          sys.stdout, sys.stderr = oldout, olderr
          client.stop_event.wait(0.01)
  server.close()
  os.unlink(sock_path)
  sessions = loadsessions()
  sessions.pop(session_name, None)
  if sessions:
    savesessions(sessions)
  else:
    os.remove(__SESSIONS_PATH__)

  if isset('log'):
    logger.info(f'session closed -->')

  return 0

def isserver(session_name: str, database_path: str=None) -> bool:
  session = getsession(session_name)
  if database_path and session:
    session_hash = session_path_encode(database_path)
    return session_hash == session.partition(',')[0]
  return False if not getsession(session_name) else True
