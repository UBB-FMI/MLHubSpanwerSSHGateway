from __future__ import annotations

from session import PendingSessionRequest


class FakeBridge:
    def __init__(self) -> None:
        self.resizes: list[tuple[int, int, int, int]] = []

    def resize_terminal(self, width: int, height: int, pixel_width: int, pixel_height: int) -> None:
        self.resizes.append((width, height, pixel_width, pixel_height))


def test_pending_session_request_records_exec_env_and_pty() -> None:
    request = PendingSessionRequest(7)
    request.add_environment("LANG", "C.UTF-8")
    request.set_pty("xterm", 120, 40, 0, 0)
    request.set_exec("printf test")

    snapshot = request.snapshot()

    assert snapshot.env == {"LANG": "C.UTF-8"}
    assert snapshot.pty is not None
    assert snapshot.pty.term_type == "xterm"
    assert snapshot.kind == "exec"
    assert snapshot.command == "printf test"
    assert request.ready.is_set() is True


def test_pending_session_resize_is_forwarded_to_live_bridge() -> None:
    request = PendingSessionRequest(11)
    bridge = FakeBridge()
    request.bind_bridge(bridge)  # type: ignore[arg-type]

    request.set_resize(132, 43, 10, 20)

    assert request.snapshot().resize == (132, 43, 10, 20)
    assert bridge.resizes == [(132, 43, 10, 20)]
