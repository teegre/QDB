import argparse
import os
import readline
import shlex
import sys

from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from qdb import __version__
from qdb.lib.qdb import QDB

class Client:
  def __init__(self, name: str):
    self.qdb = QDB(name)
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

  def pipe_commands(self):
    ret = 0
    pos = 1
    try:
      for line in sys.stdin:
        ret = self.execute(line)
        if ret != 0:
          print(f'Line {pos}: command failed: `{line.strip()}`.`', file=sys.stderr)
          return ret
        pos += 1
    finally:
      self.qdb.flush()
      return ret

  def set_prompt(self):
    indicator = '-' if self.qdb.store.is_db_empty else '+'
    indicator = '!' if self.qdb.store.has_changed else indicator
    prompt = f'{indicator} > '
    return prompt

  def run_repl(self):
    print(f'QDB version {__version__}')
    print(f'This program is free software.')
    print(f'It is distributed AS IS with no WARRANTY.')
    print()
    print('(c) 2025 Stéphane MEYER (Teegre)')
    print()
    if not self.qdb.store.is_db_empty:
      print(f'-- {len(self.qdb.store.keystore.keys())} hkeys.')
      print(f'-- {len(self.qdb.store.reverse_refs.keys())} references.')
      print(f'-- {len(self.qdb.store.refs.keys())} referenced hkeys.')
      print()
    try:
      readline.read_history_file(self.history_file)
    except FileNotFoundError:
      Path(self.history_file).touch(mode=0o600)

    while True:
      try:
        command = input(self.set_prompt())
        ret = self.execute(command)
      except KeyboardInterrupt:
        print()
        continue
      except EOFError:
        print()
        readline.write_history_file(self.history_file)
        break
      except Exception as e:
        print(f'Error: {e}.', file=sys.stderr)

        
  def process_commands(self, command: str=None, pipe: bool=False):
    if pipe:
      return self.pipe_commands()
    if command is not None:
      return self.execute(command)
    self.run_repl()


def main() -> int:
  parser = argparse.ArgumentParser(description='QDB CLI')
  parser.add_argument('db_path', help='Path to the QDB database directory')
  parser.add_argument('-p', '--pipe', help='Reads from stdin', action='store_true')
  parser.add_argument('-q', '--quiet', help='Do not show performance time', action='store_true')
  parser.add_argument('command', help='QDB command', nargs='?', default=None)
  args = parser.parse_args()

  if args.quiet:
    from os import environ
    environ['__QDB_QUIET__'] = '1'

  client = Client(args.db_path)
  return client.process_commands(args.command, args.pipe)

if __name__ == "__main__":
    sys.exit(main())
