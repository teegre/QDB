import argparse
import os
import readline
import shlex
import socket
import stat
import subprocess
import sys

from pathlib import Path
from time import perf_counter

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb import __version__
from qdb.lib.exception import QDBError
from qdb.lib.qdb import QDB
from qdb.lib.session import runserver, isserver, getsockpath
from qdb.lib.utils import authorize, getuser, isset, setenv, spinner, splitcmd

def has_piped_input():
  mode = os.fstat(0).st_mode
  return not stat.S_ISCHR(mode)

def dbname(db_path) -> str:
  return os.path.splitext(os.path.basename(db_path))[0]

def opensession(db_path: str):
  db_name = dbname(db_path)
  if isserver(db_name):
    raise QDBError(f'Error: session already opened for `{db_name}`.')

  subprocess.Popen(
      [sys.executable, __file__, db_path, '__QDB_RUNSERVER__'],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
      env=os.environ.copy()
  )

  if not isset('quiet'):
    print(f'QDB: `{db_name}`, session \033[32mopened\033[0m.', file=sys.stderr)

def sendcommand(sock_path, command) -> int:
  try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
      client.connect(sock_path)
      client.sendall((command.strip() + '\n').encode())

      chunks = []
      while True:
        chunk = client.recv(4096)
        if not chunk:
          raise QDBError('Error: no response from server.')
        chunks.append(chunk)
        if b'\x03' in chunk:
          break

      data = b''.join(chunks)
      _,   afterout = data.split(b'\x01', 1)
      out, aftererr = afterout.split(b'\x02', 1)
      err, retcode  = aftererr.split(b'\x03', 1)

      if out:
        try:
          sys.stdout.write(out.decode())
        except BrokenPipeError:
          raise QDBError('Error: broken pipe.')
      if err:
        sys.stderr.write(err.decode())

      ret = retcode.decode().strip()

      try:
        return int(ret)
      except ValueError:
        raise QDBError(f'Error: invalid return code from server: {ret}')

  except ConnectionRefusedError:
    raise QDBError('Error: unable to connect to server.')

class QDBCompleter:
  def __init__(self, qdb: QDB):
    self.qdb = qdb
    self.commands = sorted(self.qdb.commands.keys())

  def complete(self, text, state):
    line = shlex.split(readline.get_line_buffer())

    if text:
      self.matches = [c for c in self.commands if c.startswith(text)]
    else:
      self.matches = self.commands
    try:
      return self.matches[state]
    except IndexError:
      return None

class QDBClient:
  def __init__(self, name: str, username: str=None, password: str=None, command: str=None):
    self.db_name = dbname(name)
    if not isserver(self.db_name, username):
      self.qdb = QDB(name, load=QDB.do_load_database(command))
      if self.qdb.store.isdatabase and not self.qdb.users.hasusers and (username or password):
        raise QDBError(f'Error: `{username}`, unknown user.')
      if self.qdb.users.hasusers and not isset('user'):
        authorize(self.qdb.users, username, password)
      if password:
        del password
      self.history_file = os.path.join(
          os.path.expanduser('~'),
          '.qdb_hist'
      )
    else:
      setenv('user', username if username else getuser())

  @classmethod
  def hide_cursor(cls):
    print('\x1b[?25l', end='', flush=True, file=sys.stderr)

  @classmethod
  def show_cursor(cls):
    print('\x1b[?25h', end='', flush=True, file=sys.stderr)

  def execute(self, command: str) -> int:
    try:
      parts = splitcmd(command)
    except ValueError as e:
      print(f'QDB: {e}.', file=sys.stderr)
      return 1
    if not parts:
      return 0

    cmd = parts[0]
    args = parts[1:]

    func = self.qdb.commands.get(cmd.upper(), self.qdb.error)
    try:
      return func(args[0], *args[1:])
    except (IndexError, TypeError):
      try:
        return func()
      except TypeError:
        print(f'{cmd.upper()}: arguments missing.', file=sys.stderr)
        return 1

  def runserver(self) -> int:
    try:
      return runserver(self.db_name, self)
    except KeyboardInterrupt:
      os.remove(getsockpath(self.db_name))
      return 1

  def stopserver(self, db_name: str):
    stopserver(db_name)

  def pipe_commands(self) -> int:
    if self.qdb.auth_required and not isset('user'):
      authorize(self.qdb.users)

    setenv('pipe')

    if not isset('quiet'):
      self.hide_cursor()
      spin = iter(spinner())

    line_count = 1

    t1 = perf_counter()

    try:
      for line in sys.stdin:
        if line[0] == '#': # Comment
          line_count += 1
          continue
        ret = self.execute(line.strip('\n'))
        if line_count % 10000 == 0:
          self.qdb.store.commit(quiet=True)
        if ret != 0:
          print(f'QDB: Line {line_count}: command failed: `{line.strip("\n")}`.`', file=sys.stderr)
          return 1
        if not isset('quiet'):
          print(f'\r{next(spin)} {line_count}', end='', file=sys.stderr)
        line_count += 1
    except KeyboardInterrupt:
      print()
      print(f'QDB: Interrupted by user at line {line_count}.', file=sys.stderr)

    if not isset('quiet'):
      t2 = perf_counter()
      print()
      print(f'\nProcessed: {(t2-t1):.4f}s')
    QDBClient.show_cursor()
    return 0

  def _set_prompt(self) -> str:
    indicator = f'[{self.db_name}](-)' if self.qdb.store.is_db_empty else f'[{self.db_name}](+)'
    indicator = f'[{self.db_name}](!)' if self.qdb.store.haschanged else indicator
    prompt = f'{indicator} > '
    return prompt

  def _confirm(self, msg: str) -> bool:
    response = input(msg + ' [y/N]: ')
    return response.lower() == 'y'

  def run_repl(self):
    print(f'QDB version {__version__}')
    print(f'This program is free software.')
    print(f'It is distributed AS IS with no WARRANTY.')
    print()
    print('(c) 2025 Stéphane MEYER (Teegre)')
    print()
    if not self.qdb.store.is_db_empty:
      print(f'** {self.qdb.store.database_size} keys.')
      print(f'** {len(self.qdb.store.reverse_refs.keys())} references.')
      print(f'** {len(self.qdb.store.refs.keys())} referenced hkeys.')
      print()
    else:
      if self.qdb.store.io.isdatabase:
        print('** Empty database.')
      else:
        print('** New database.')
      print()

    setenv('repl')

    try:
      readline.read_history_file(self.history_file)
    except FileNotFoundError:
      Path(self.history_file).touch(mode=0o600)

    readline.set_completer(QDBCompleter(self.qdb).complete)
    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind(r'"[" "\C-v[]\e[D"')
    readline.parse_and_bind(r'"(" "\C-v()\e[D"')

    while True:
      try:
        command = input(self._set_prompt())
        ret = self.execute(command)
      except KeyboardInterrupt:
        print()
        continue
      except EOFError:
        print()
        if self.qdb.store.haschanged:
          if not self._confirm(
              f'{self.database_name}: Uncommitted changes!'
              f'\n{self.database_name}: Quit anyway?'
          ):
            continue
        readline.write_history_file(self.history_file)
        break
      except QDBError as e:
        print(e, file=sys.stderr)
      except Exception as e:
        print(f'Internal error: {e}', file=sys.stderr)

  def process_commands(self, command: str=None, pipe: bool=False):
    if has_piped_input():
      if not pipe:
        print('QDB: `--pipe` option is missing.', file=sys.stderr)
        return 1
    if pipe:
      return self.pipe_commands()
    if command is not None:
      return self.execute(command)
    self.run_repl()

def main() -> int:
  parser = argparse.ArgumentParser(
      prog='qdb',
      description='Command Line Interface For the QDB database engine.',
      epilog='If no option is provided, starts an interactive shell.'
  )
  parser.add_argument('database', help='path to the QDB database')
  parser.add_argument('-d', '--dump', help='dump database as QDB commands', action='store_true')
  parser.add_argument('-p', '--pipe', help='reads commands from stdin', action='store_true')
  parser.add_argument('-q', '--quiet', help='be quiet', action='store_true')
  parser.add_argument('-f', '--nofield', help='never show field names', action='store_true')
  parser.add_argument('-u', '--username', metavar='username')
  parser.add_argument('-w', '--password', metavar='password')
  parser.add_argument('-v', '--version', action='version', version=f'QDB version {__version__}')
  parser.add_argument('command', help='QDB command', nargs='?', default=None)
  args = parser.parse_args()

  if args.pipe and (args.command or not has_piped_input()):
    print('QDB: too many options.', file=sys.stderr)
    return 1

  if args.quiet:
    setenv('quiet')

  if args.nofield:
    setenv('hushf')

  try:
    client = QDBClient(args.database, args.username, args.password, command=args.command)
  except QDBError as e:
    print('QDB:', e, file=sys.stderr)
    return 1

  if args.command:

    if args.command.upper() == 'OPENSESSION':
      try:
        opensession(args.database)
      except QDBError as e:
        print(f'QDB: {e}', file=sys.stderr)
        return 1
      return 0

    if args.command == '__QDB_RUNSERVER__':
      return runserver(dbname(args.database), client)

    if args.command.upper() in ('CLOSESESSION', 'PING'):
      if not isserver(client.db_name):
        print(f'QDB: Error: no opened session for `{client.db_name}`.', file=sys.stderr)
        return 1

    if isserver(client.db_name, getuser()):
      sock_path = getsockpath(client.db_name, getuser())
      try:
        ret = sendcommand(sock_path, f'QDBUSRCHK {args.username} {args.password}')
        if int(ret) == 1:
          return 1
        ret = sendcommand(sock_path, args.command)
        return int(ret)
      except QDBError as e:
        print(f'QDB: {e}', file=sys.stderr)
        return 1

  if isserver(client.db_name, getuser()) and (not args.command or args.pipe):
    # no command in session mode, error.
    if args.pipe:
      print(f'QDB: Error: session mode: \033[3m--pipe\033[0m not allowed.')
    else:
      print(f'QDB: Error: session mode: missing command.', file=sys.stderr)
    return 1

  if args.dump:
    try:
      client.qdb.dump()
      return 0
    except QDBError as e:
      print(e, file=sys.stderr)
      return 1

  try:
    return client.process_commands(args.command, args.pipe)
  except QDBError as e:
    if has_piped_input() and not isset('quiet'):
      print()
    print(e, file=sys.stderr)
    sys.stderr.close()
    return 1

if __name__ == "__main__":
    ret = main()
    QDBClient.show_cursor()
    sys.exit(ret)
