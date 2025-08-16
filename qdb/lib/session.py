import io
import os
import socket
import sys

from typing import Callable

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb.lib.exception import QDBAuthenticationError, QDBError
from qdb.lib.utils import isset, getuser, splitcmd, authorize

def getsockpath(db_name: str, user: str=None) -> str:
  currentuser = getuser() if user is None else user
  return f'/tmp/qdb-{currentuser}-{db_name}.sock'

def runserver(db_name: str, client: object):
  sock_path = getsockpath(db_name)
  if os.path.exists(sock_path):
    os.remove(sock_path)
  server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  server.bind(sock_path)
  server.listen(1)

  while True:
    conn, _ = server.accept()
    with conn:
      cmd = conn.recv(4096).decode().strip()
      if cmd.startswith('QDBUSRCHK'):
        if not client.qdb.users.hasusers:
          conn.sendall(b'\x01\x02\x030\n')
          continue
        command = splitcmd(cmd)
        usr, pwd = command[1], command[2]
        if usr != getuser():
          conn.sendall(b'\x01\x02Error: connection refused.\n\x031\n')
          continue
        try:
          authorize(client.qdb.users, usr, pwd)
          conn.sendall(b'\x01\x02\x030\n')
          continue
        except QDBAuthenticationError:
          conn.sendall(b'\x01\x02Error: connection refused\n\x031\n')
          continue

      if cmd.upper() == 'PING':
        if isset('quiet'):
          conn.sendall(b'\x01\x02\x030\n')
          continue
        response = cmd.replace('i', 'o').replace('I', 'O')
        conn.sendall(b'\x01\x02' + response.encode() + b'\n\x030\n')
        continue
      if cmd.upper() == 'CLOSESESSION':
        if isset('quiet'):
          conn.sendall(b'\x01\x02\x030\n')
          break
        conn.sendall(
            b'\x01\x02' + 
            f'QDB: `{db_name}`, session \033[31mclosed\033[0m.\n'.encode() +
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
      except KeyboardInterrupt:
        conn.sendall(b'\x01\x02\x031\n')
        break
      except QDBError as e:
        conn.sendall(b'\x01\x02' + str(e).encode() + b'\n\x031\n')
        print(f'{e}', file=sys.stderr)
        break
      finally:
        sys.stdout, sys.stderr = oldout, olderr
  server.close()
  os.remove(sock_path)
  return 0

def isserver(db_name: str, user: str=None) -> bool:
  sock_path = getsockpath(db_name, user)
  return os.path.exists(sock_path)
