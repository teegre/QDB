import os
import socket
import sys

from typing import Callable

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb.lib.exception import QDBError

def getsockpath(db_name: str) -> str:
  return f'/tmp/qdb-{os.getuid()}-{os.path.basename(db_name)}.sock'

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
      if cmd.upper() == 'PING':
        response = cmd.replace('i', 'o').replace('I', 'O')
        sys.stdout.write(response + '\n')
        sys.stdout.flush()
        conn.sendall('0\n'.encode())
        continue
      if cmd.upper() == 'ENDSESSION':
        conn.sendall('0\n'.encode())
        break
      try:
        ret = client.execute(cmd)
        conn.sendall(f'{str(ret) + '\n'}'.encode())
      except QDBError as e:
        conn.sendall(f'QDB: {e}')
        return 1
  server.close()
  os.remove(sock_path)
  print(f'QDB: `{db_name}`, session closed.', file=sys.stderr)
  return 0

def isserver(db_name: str) -> bool:
  sock_path = getsockpath(db_name)
  return os.path.exists(sock_path)
