import argparse
import os
import readline
import shlex
import sys

from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb import __version__
from qdb.lib.exception import QDBError
from qdb.lib.qdb import QDB
from qdb.lib.utils import authorize

class QDBCompleter:
  def __init__(self, qdb: QDB):
    self.qdb = qdb
    self.commands = sorted(self.qdb.commands.keys())

  def complete(self, text, state):
    line = shlex.split(readline.get_line_buffer())

    if text:
      self.matches = [c for c in self.commands if c.startswith(text)]
    else:
      self.matches = []
    try:
      return self.matches[state]
    except IndexError:
      return None

class QDBClient:
  def __init__(self, name: str, username: str=None, password: str=None, command: str=None):
    self.qdb = QDB(name, load=QDB.do_load_database(command))
    if self.qdb.users is not None and self.qdb.users.hasusers:
      authorize(self.qdb.users, username, password)
    if password:
      del password
    self.database_name = self.qdb.store.database_name
    self.history_file = os.path.join(
        os.path.expanduser('~'),
        '.qdb_hist'
    )

  def execute(self, command: str) -> int:
    parts = shlex.split(command)
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

  def pipe_commands(self) -> int:
    ret = 0
    line_count = 1
    for line in sys.stdin:
      ret = self.execute(line.strip('\n'))
      if ret != 0:
        print(f'QDB: Line {line_count}: command failed: `{line.strip()}`.`', file=sys.stderr)
        return ret
      line_count += 1
    return ret

  def _set_prompt(self) -> str:
    indicator = f'[{self.database_name}](-)' if self.qdb.store.is_db_empty else f'[{self.database_name}](+)'
    indicator = f'[{self.database_name}](!)' if self.qdb.store.haschanged else indicator
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
      print(f'-- {len(self.qdb.store.keystore.keys())} hkeys.') # FIXME: what about regular keys?
      print(f'-- {len(self.qdb.store.reverse_refs.keys())} references.')
      print(f'-- {len(self.qdb.store.refs.keys())} referenced hkeys.')
      print()
    else:
      if self.qdb.store.io.isdatabase:
        print('-- Empty database.')
      else:
        print('-- New database.')
      print()

    os.environ['__QDB_REPL__'] = '1'

    try:
      readline.read_history_file(self.history_file)
    except FileNotFoundError:
      Path(self.history_file).touch(mode=0o600)

    readline.set_completer(QDBCompleter(self.qdb).complete)
    readline.parse_and_bind('tab: complete')

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
    if pipe and command:
      print('QDB: too many options.', file=sys.stderr)
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
  parser.add_argument('command', help='QDB command', nargs='?', default=None)
  parser.add_argument('database', help='path to the QDB database')
  parser.add_argument('-d', '--dump', help='dump database as JSON', action='store_true')
  parser.add_argument('-p', '--pipe', help='reads commands from stdin', action='store_true')
  parser.add_argument('-q', '--quiet', help='be quiet', action='store_true')
  parser.add_argument('-u', '--username')
  parser.add_argument('-w', '--password')
  args = parser.parse_args()

  if args.quiet:
    from os import environ
    environ['__QDB_QUIET__'] = '1'

  try:
    client = QDBClient(args.database, args.username, args.password, command=args.command)
  except QDBError as e:
    print('QDB:', e, file=sys.stderr)
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
    print(e, file=sys.stderr)
    return 1

if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
