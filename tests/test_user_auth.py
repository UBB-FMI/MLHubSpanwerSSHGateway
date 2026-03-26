from __future__ import annotations

import pytest

from user_auth import (
    InvalidPasswordError,
    UnknownUserError,
    UserConfigError,
    UserRecord,
    authenticate_user,
    register_user,
    snapshot_users,
    unregister_user,
)


def make_user() -> UserRecord:
    return UserRecord(
        password="secret",
        upstream_host="127.0.0.1",
        upstream_port=2222,
    )


def test_valid_password_lookup() -> None:
    user = make_user()
    register_user("alice", user)
    assert authenticate_user("alice", "secret") == user


def test_invalid_password_rejected() -> None:
    register_user("alice", make_user())
    with pytest.raises(InvalidPasswordError):
        authenticate_user("alice", "wrong")


def test_unknown_username_rejected() -> None:
    with pytest.raises(UnknownUserError):
        authenticate_user("alice", "secret")


def test_missing_upstream_host_rejected() -> None:
    with pytest.raises(UserConfigError):
        register_user(
            "alice",
            UserRecord(password="secret", upstream_host="", upstream_port=2222),
        )


def test_invalid_upstream_port_rejected() -> None:
    with pytest.raises(UserConfigError):
        register_user(
            "alice",
            UserRecord(password="secret", upstream_host="127.0.0.1", upstream_port=70000),
        )


def test_unregister_user_removes_mapping() -> None:
    register_user("alice", make_user())
    removed = unregister_user("alice")

    assert removed == make_user()
    assert snapshot_users() == {}
