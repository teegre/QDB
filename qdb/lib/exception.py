import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

class QDBError(Exception):
  def __init__(self, message: str, name: str='error'):
    self.message = message
    self.name = name
    super().__init__(self.message)
  def __str__(self):
    return f'* \x1b[1m\x1b[31m{self.name}\x1b[0m: {self.message}'

class QDBNoDatabaseError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'no database'

class QDBAuthenticationError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'authentication error'

class QDBAuthenticationCancelledError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'authentication error'

class QDBNoAdminError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'no admin error'

class QDBUnauthorizedError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'forbidden'

class QDBUnknownUserError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'user error'

class QDBParseError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'parse error'

class QDBQueryError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'query error'

class QDBQueryNoData(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'no data'

class QDBKeyError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'key error'

class QDBHkeyError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'hkey error'

class QDBIODataIntegrityError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'data integrity error'

class QDBIOReadError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'io read error'

class QDBIOWriteError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'io write error'

class QDBIOMissingLogError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'missing log error'

class QDBIOCompactionError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'compaction error'

class QDBSessionError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'session mode error'

class QDBInternalError(QDBError):
  def __init__(self, message: str):
    self.message = message
    self.name = 'internal error'
