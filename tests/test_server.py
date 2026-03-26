from __future__ import annotations

from server import ActiveConnectionRegistry


class FakeConnection:
    def __init__(self) -> None:
        self.disconnect_count = 0

    def force_disconnect(self) -> None:
        self.disconnect_count += 1


def test_active_connection_registry_disconnects_all_connections_for_user() -> None:
    registry = ActiveConnectionRegistry()
    first = FakeConnection()
    second = FakeConnection()
    third = FakeConnection()

    registry.register("alice", first)  # type: ignore[arg-type]
    registry.register("alice", second)  # type: ignore[arg-type]
    registry.register("bob", third)  # type: ignore[arg-type]

    registry.disconnect_user("alice")

    assert first.disconnect_count == 1
    assert second.disconnect_count == 1
    assert third.disconnect_count == 0
