from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


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
    client_key_path: str
    known_hosts_path: str


# Edit this mapping for real deployments.
USERS: dict[str, UserRecord] = {
    "example": UserRecord(
        password="change-me",
        upstream_host="192.168.104.119",
        upstream_port=22,
        client_key_path="~/.ssh/NOPASS_RSA",
        known_hosts_path="~/.ssh/known_hosts",
    ),
    "root": UserRecord(
        password="change-me",
        upstream_host="192.168.104.119",
        upstream_port=22,
        client_key_path="~/.ssh/NOPASS_RSA",
        known_hosts_path="~/.ssh/known_hosts",
    ),
}


class UserDirectory:
    def __init__(self, users: Mapping[str, UserRecord] | None = None):
        self._users = USERS if users is None else users

    def get_user(self, username: str) -> UserRecord:
        try:
            return self._users[username]
        except KeyError as exc:
            raise UnknownUserError(f"unknown SSH user: {username}") from exc

    def validate_user_record(self, user: UserRecord) -> UserRecord:
        if not user.upstream_host:
            raise UserConfigError("upstream_host must not be empty")
        if user.upstream_port <= 0 or user.upstream_port > 65535:
            raise UserConfigError("upstream_port must be between 1 and 65535")

        client_key_path = Path(user.client_key_path).expanduser()
        if not client_key_path.is_file():
            raise UserConfigError(f"client key does not exist or is not a file: {client_key_path}")

        known_hosts_path = Path(user.known_hosts_path).expanduser()
        if not known_hosts_path.is_file():
            raise UserConfigError(f"known_hosts does not exist or is not a file: {known_hosts_path}")

        return user


class UserAuthenticator:
    def __init__(self, directory: UserDirectory | None = None):
        self._directory = UserDirectory() if directory is None else directory

    def authenticate(self, username: str, password: str) -> UserRecord:
        user = self._directory.validate_user_record(self._directory.get_user(username))
        if password != user.password:
            raise InvalidPasswordError(f"invalid password for SSH user: {username}")
        return user


def get_user(username: str) -> UserRecord:
    return UserDirectory().get_user(username)


def validate_user_record(user: UserRecord) -> UserRecord:
    return UserDirectory().validate_user_record(user)


def authenticate_user(username: str, password: str) -> UserRecord:
    return UserAuthenticator().authenticate(username, password)
