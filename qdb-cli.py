import argparse
import sys

from src.qdb import QDB

class Client:
  def __init__(self, name: str):
    self.qdb = QDB(name)

  def execute(self, command: str) -> int:
    parts = command.strip().split()
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

  def process_commands(self, command: str=None):
    if command is not None:
      return self.execute(command)

    ret = 0
    try:
      for line in sys.stdin:
        ret = self.execute(line)
        if ret != 0:
          print(f'Command failed with code {ret}: `{line.strip()}`.`', file=sys.stderr)
    finally:
      self.qdb.flush()
      return ret
        

def main() -> int:
  parser = argparse.ArgumentParser(description='QDB CLI')
  parser.add_argument('db_path', help='Path to the QDB database directory')
  parser.add_argument('command', help='QDB command', nargs='?', default=None)
  args = parser.parse_args()

  client = Client(args.db_path)
  return client.process_commands(args.command)

if __name__ == "__main__":
    sys.exit(main())
