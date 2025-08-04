import bcrypt
import grp
import json
import os
import pwd
import sys
import tarfile
import time

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from enum import Enum, auto
from io import BytesIO
from tarfile import TarInfo

from qdb.lib.exception import (
    QDBUnknownUserError,
    QDBAuthenticationError,
    QDBNoAdminError,
)

class QDBAuthType(Enum):
  QDB_ADMIN = auto()
  QDB_READONLY = auto()
  QDB_FORBIDDEN = auto()

AUTH_TYPE = {
    1: 'admin',
    2: 'readonly',
    3: 'forbidden'
}

class QDBUsers:
  def __init__(self, db_path: str):
    self._database_path = db_path
    self.users = {}
    self.filename = '.users'
    self._users_ops = {}
    self.haschanged = False
    self._load()

  def _load(self):
    if not os.path.exists(self._database_path):
      self.users = {}
      return
    with tarfile.open(self._database_path, 'r') as tar:
      user_files = [u for u in tar.getnames() if u.startswith('.users')]
      if not user_files:
        self.users = {}
        return
      try:
        for filename in user_files:
          user_file = tar.extractfile(filename)
          users_ops = json.load(user_file)
          for user, op in users_ops.items():
            if 'add' in op:
              self.users[user] = op['add']
            elif 'del' in op:
              self.users.pop(user, None)
            else:
              self.users[user] = op
      except KeyError:
        self.users = {}

  def _save(self):
    if not self._users_ops:
      return
    data = json.dumps(self._users_ops, indent=2).encode()
    user_info = tarfile.TarInfo(self.filename + '_' + str(len(self.users) + 1))
    self.set_user_info(user_info)
    user_info.size = len(data)
    user_info.mtime = time.time()

    mode = 'a' if os.path.exists(self._database_path) else 'w'

    with tarfile.open(self._database_path, mode) as tar:
      tar.addfile(user_info, BytesIO(data))

    self.haschanged = True

    self._users_ops.clear()

  @classmethod
  def set_user_info(cls, info: TarInfo):
    uid = os.getuid()
    gid = os.getgid()

    current_user = self.getuser()
    if current_user:
      uname = gname = current_user
    else:
      uname = pwd.getpwuid(uid).pw_name
      gname = grp.getgrgid(gid).gr_name

    info.uid = uid
    info.gid = gid
    info.uname = uname
    info.gname = gname

  @property
  def hasadmin(self) -> bool:
    for userinfo in self.users.values():
      auth = userinfo['auth']
      if QDBAuthType(auth) == QDBAuthType.QDB_ADMIN:
        return True
    return False

  def add_user(self, username: str, password: str, auth_type: QDBAuthType.QDB_READONLY):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    self.users[username] = {
        'hash': hashed.decode(),
        'auth': auth_type.value
    }
    self._users_ops[username] = {'add': self.users[username]}

  def remove_user(self, username: str):
    if self.getuser() == username:
      raise QDBNoAdminError('Forbidden: cannot delete current user.')
    user_info = self.users.pop(username, None)
    if user_info:
      self._users_ops[username] = {'del': None}
    else:
      raise QDBUnknownUserError(f'Error: `{username}`, no such user.')

  def authenticate(self, username: str, password: str):
    user = self.users.get(username)
    if not user:
      raise QDBAuthenticationError('Invalid username or password.')
    if not bcrypt.checkpw(password.encode(), user['hash'].encode()):
      raise QDBAuthenticationError('Invalid username or password.')
    os.environ['__QDB_USER__'] = username

  def get_auth(self, username: str) -> str:
    return self.users.get(username, {}).get('auth', QDBAuthType.QDB_FORBIDDEN)

  def getuser(self) -> str:
    return os.getenv('__QDB_USER__')

  def list_users(self):
    return ' | '.join(n + f' ({AUTH_TYPE[a["auth"]]})' for n, a in self.users.items())

  @property
  def hasusers(self) -> bool:
    return len(self.users) > 0

  @property
  def unsaved(self) -> bool:
    return len(self._users_ops) > 0
