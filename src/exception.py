import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class QDBError(Exception):
  pass

class QDBParseError(QDBError):
  pass

class QDBQueryError(QDBError):
  pass

class QDBQueryNoData(QDBError):
  pass

class QDBHkeyError(QDBError):
  pass

class QDBWriteError(QDBError):
  pass

class QDBReadError(QDBError):
  pass
