import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class MDBQueryError(Exception):
  pass
class MDBParseError(Exception):
  pass

