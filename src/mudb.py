import argparse
import sys

from microdb import MicroDB

class Client:
  def __init__(self, name: str):
    self.db = MicroDB(name)

  def execute(self, command: str) -> int:
    parts = command.strip().split()
    if not parts:
      return 0

    cmd = parts[0]
    args = parts[1:]

    func = self.db.commands.get(cmd.upper(), self.db.error)
    try:
      return func(args[0], *args[1:])
    except IndexError:
      try:
        return func()
      except TypeError:
        print(f'{cmd.upper()}: arguments missing.', file=sys.stderr)
        return 1
    except TypeError:
      print(f'{cmd.upper()}: arguments missing.', file=sys.stderr)

  def process_commands(self):
    ret = 0
    try:
      for line in sys.stdin:
        ret = self.execute(line)
        if ret != 0:
          print(f'Command failed with code {ret}: {line.strip()}', file=sys.stderr)
    finally:
      self.db.flush()
      return ret
        

def main() -> int:
  parser = argparse.ArgumentParser(description='µDB CLI')
  parser.add_argument('db_path', help='Path to the µDB database directory')
  args = parser.parse_args()

  client = Client(args.db_path)
  return client.process_commands()

if __name__ == "__main__":
    sys.exit(main())
