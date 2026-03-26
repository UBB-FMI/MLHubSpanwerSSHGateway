from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from threading import RLock


class UserAuthError(Exception):
    """Base error for local user authentication and config validation."""


class UnknownUserError(UserAuthError):
    """Raised when the inbound SSH username does not exist."""


class InvalidPasswordError(UserAuthError):
    """Raised when the inbound SSH password does not match."""


class UserConfigError(UserAuthError):
    """Raised when a configured upstream target is invalid."""


@dataclass(frozen=True, slots=True)
class UserRecord:
    password: str
    upstream_host: str
    upstream_port: int


class UserDirectory:
    def __init__(self, users: Mapping[str, UserRecord] | None = None):
        self._lock = RLock()
        self._users = dict(users or {})

    def replace_users(self, users: Mapping[str, UserRecord]) -> None:
        with self._lock:
            self._users = dict(users)

    def clear(self) -> None:
        with self._lock:
            self._users.clear()

    def snapshot(self) -> dict[str, UserRecord]:
        with self._lock:
            return dict(self._users)

    def has_user(self, username: str) -> bool:
        with self._lock:
            return username in self._users

    def register_user(self, username: str, user: UserRecord) -> UserRecord:
        normalized_user = self.validate_user_record(user)
        with self._lock:
            self._users[username] = normalized_user
        return normalized_user

    def unregister_user(self, username: str) -> UserRecord | None:
        with self._lock:
            return self._users.pop(username, None)

    def get_user(self, username: str) -> UserRecord:
        with self._lock:
            try:
                return self._users[username]
            except KeyError as exc:
                raise UnknownUserError(f"unknown SSH user: {username}") from exc

    def validate_user_record(self, user: UserRecord) -> UserRecord:
        if not user.upstream_host:
            raise UserConfigError("upstream_host must not be empty")
        if user.upstream_port <= 0 or user.upstream_port > 65535:
            raise UserConfigError("upstream_port must be between 1 and 65535")
        return user


class UserAuthenticator:
    def __init__(self, directory: UserDirectory | None = None):
        self._directory = USER_DIRECTORY if directory is None else directory

    def is_known_user(self, username: str) -> bool:
        return self._directory.has_user(username)

    def authenticate(self, username: str, password: str) -> UserRecord:
        user = self._directory.get_user(username)
        self._directory.validate_user_record(user)
        if password != user.password:
            raise InvalidPasswordError(f"invalid password for SSH user: {username}")
        return user


USER_DIRECTORY = UserDirectory()


def set_users(users: Mapping[str, UserRecord]) -> None:
    USER_DIRECTORY.replace_users(users)


def clear_users() -> None:
    USER_DIRECTORY.clear()


def snapshot_users() -> dict[str, UserRecord]:
    return USER_DIRECTORY.snapshot()


def register_user(username: str, user: UserRecord) -> UserRecord:
    return USER_DIRECTORY.register_user(username, user)


def unregister_user(username: str) -> UserRecord | None:
    return USER_DIRECTORY.unregister_user(username)


def get_user(username: str) -> UserRecord:
    return USER_DIRECTORY.get_user(username)


def validate_user_record(user: UserRecord) -> UserRecord:
    return USER_DIRECTORY.validate_user_record(user)


def authenticate_user(username: str, password: str) -> UserRecord:
    return UserAuthenticator().authenticate(username, password)
