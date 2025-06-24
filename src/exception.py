import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class MDBError(Exception):
  pass
class MDBParseError(MDBError):
  pass
class MDBQueryError(MDBError):
  pass
class MDBQueryNoData(MDBError):
  pass
class MDBWriteError(MDBError):
  pass
class MDBReadError(MDBError):
  pass
