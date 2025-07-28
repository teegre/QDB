import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class QDBError(Exception):
  pass

class QDBNoDatabaseError(QDBError):
  pass

class QDBAuthenticationError(QDBError):
  pass

class QDBAuthenticationCancelledError(QDBError):
  pass

class QDBNoAdminError(QDBError):
  pass

class QDBUnauthorizedError(QDBError):
  pass

class QDBUnknownUserError(QDBError):
  pass

class QDBParseError(QDBError):
  pass

class QDBQueryError(QDBError):
  pass

class QDBQueryNoData(QDBError):
  pass

class QDBKeyError(QDBError):
  pass

class QDBHkeyError(QDBError):
  pass

class QDBIODataIntegrityError(QDBError):
  pass

class QDBIOReadError(QDBError):
  pass

class QDBIOWriteError(QDBError):
  pass

class QDBIOMissingLogError(QDBError):
  pass

class QDBIOCompactionError(QDBError):
  pass
