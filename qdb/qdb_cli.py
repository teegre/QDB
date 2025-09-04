import argparse
import os
import readline
import shlex
import signal
import socket
import stat
import subprocess
import sys
import threading

from pathlib import Path
from time import perf_counter, sleep

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb import __version__
from qdb.lib.exception import QDBError
from qdb.lib.qdb import QDB
from qdb.lib.session import runserver, isserver, getsockpath
from qdb.lib.utils import (
    authorize,
    getuser,
    isset,
    loader,
    list_sessions,
    setenv,
    spinner,
    splitcmd,
)

def has_piped_input() -> bool:
  mode = os.fstat(0).st_mode
  return not stat.S_ISCHR(mode)

def dbname(db_path: str) -> str:
  db_path = os.path.abspath(db_path)
  name, ext = os.path.splitext(os.path.basename(db_path))
  if ext and ext.lower() != '.qdb' and not os.path.exists(db_path):
    raise QDBError(f'Error: \x1b[1m{name+ext}\x1b[0m, invalid database name.')
  if not ext:
    db_path += '.qdb'
  return name

def opensession(database_path: str):
  db_name = dbname(database_path)
  if isserver(db_name, database_path):
    raise QDBError(f'\x1b[1m{db_name}\x1b[0m: a session is already opened.')

  subprocess.Popen(
      [sys.executable, __file__, database_path, '__QDB_RUNSERVER__'],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
      env=os.environ.copy()
  )

  if not isset('quiet'):
    print(f'\x1b[1m{db_name}\x1b[0m: session \033[32mopened\033[0m.', file=sys.stderr)

def sendcommand(sock_path, command) -> int:
  try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
      try:
        client.connect(sock_path)
      except FileNotFoundError:
        raise QDBError(f'Error: \x1b[1msession\x1b[0m is \x1b[31mclosed\x1b[0m.')

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
          return 1
      if err:
        sys.stderr.write(err.decode())

      ret = retcode.decode().strip()

      try:
        return int(ret)
      except ValueError:
        raise QDBError(f'Error: invalid return code from server: {ret}')

  except ConnectionRefusedError:
    os.unlink(sock_path)
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
  def __init__(self, database: str, username: str=None, password: str=None, command: str=None):
    self.db_name = dbname(database)
    self.db_path = os.path.abspath(database)
    if not isserver(self.db_name, self.db_path):
      self.qdb = QDB(self.db_path, load=QDB.do_load_database(command))
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
    if not sys.stderr.closed:
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
    finally:
      self.show_cursor()

    if not isset('quiet'):
      t2 = perf_counter()
      print()
      print(f'\nProcessed: {(t2-t1):.4f}s')
    return 0

  def _set_prompt(self) -> str:
    indicator = f'{self.db_name}'
    state = '-' if self.qdb.store.is_db_empty else '+'
    state = '!' if self.qdb.store.haschanged else state
    prompt = f'* {indicator} ({state}) qdb ) '
    return prompt

  def _confirm(self, msg: str) -> bool:
    response = input(msg + ' [y/N]: ')
    return response.lower() == 'y'

  def run_repl(self):
    def load_animation(stop_event: threading.Event):
      load = iter(loader())
      while not stop_event.is_set():
        print(f'\r{next(load)}', end='')
        sleep(0.1)

    setenv('repl')

    stop_event = threading.Event()
    thread = threading.Thread(target=load_animation, args=(stop_event,))
    self.hide_cursor()
    thread.start()
    self.qdb.store.build_indexed_fields(quiet=True)
    stop_event.set()
    thread.join()
    print(f'\r\x1b[1mQDB\x1b[0m version {__version__}')
    self.show_cursor()

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
        if command.lower() == 'purge' and self.qdb.store.haschanged:
          print(f'{self.db_name}: You must \033[1mCOMMIT\033[0m your changes prior to \033[3mPURGE\033[0m')
          continue
        ret = self.execute(command)
      except KeyboardInterrupt:
        print()
        continue
      except EOFError:
        print()
        if self.qdb.store.haschanged:
          if not self._confirm(
              f'{self.db_name}: Uncommitted changes!'
              f'\n{self.db_name}: Quit anyway?'
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
      self.qdb.store.build_indexed_fields(quiet=True)
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

  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument('-l', '--sessions', help='list active sessions', action='store_true')
  group.add_argument('database', help='path to a QDB database or name of a QDB session', nargs='?')

  parser.add_argument('-p', '--pipe', help='reads commands from stdin', action='store_true')
  parser.add_argument('-q', '--quiet', help='be quiet', action='store_true')
  parser.add_argument('-f', '--nofield', help='never show field names', action='store_true')
  parser.add_argument('-u', '--username', metavar='username')
  parser.add_argument('-w', '--password', metavar='password')
  parser.add_argument('-d', '--dump', help='dump database as W commands', action='store_true')
  parser.add_argument('-v', '--version', action='version', version=f'\x1b[1mQDB\x1b[0m version {__version__}')
  parser.add_argument('command', help='QDB command', nargs='?', default=None)

  args = parser.parse_args()

  if args.sessions:
    disallowed = {k for k, v in vars(args).items() if v not in (None, False) and k != 'sessions'}
    if disallowed:
      print('QDB: \x1b[3m--sessions\x1b[0m cannot be combined with other options.', file=sys.stderr)
      return 1
    return list_sessions()

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

    if args.command.upper() == 'OPEN':
      try:
        opensession(client.db_path)
      except QDBError as e:
        print(f'QDB: {e}', file=sys.stderr)
        return 1
      return 0

    if args.command == '__QDB_RUNSERVER__':
      stop_event = threading.Event()

      def handle_signal(signum, frame):
        stop_event.set()

      signal.signal(signal.SIGTERM, handle_signal)
      signal.signal(signal.SIGINT, handle_signal)

      client.stop_event = stop_event

      client.qdb.store.build_indexed_fields(quiet=True)

      return runserver(client.db_path, client)

    if args.command.upper() in ('CLOSE', 'PING'):
      if not isserver(client.db_name):
        user = getuser() if not args.username else args.username
        print( f'User \x1b[1m{user}\x1b[0m has no \x1b[1m{client.db_name}\x1b[0m session.', file=sys.stderr)
        return 1

    if isserver(client.db_name):
      sock_path = getsockpath(client.db_name)
      try:
        if args.command.upper() != 'PING':
          ret = sendcommand(sock_path, f'__qdbusrchk__ {args.username} {args.password}')
          args.password = ''
          if int(ret) == 1:
            return 1
        ret = sendcommand(sock_path, args.command)
        return int(ret)
      except QDBError as e:
        print(f'QDB: {e}', file=sys.stderr)
        return 1

  if isserver(client.db_name) and (not args.command or args.pipe):
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
