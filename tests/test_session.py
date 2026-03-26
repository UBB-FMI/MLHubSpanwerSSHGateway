from __future__ import annotations

import logging

from session import SessionRelay


class FakeServerChannel:
    def __init__(self) -> None:
        self.exit_statuses: list[int] = []
        self.exit_signals: list[tuple[str, bool, str, str]] = []
        self.eof_count = 0
        self.close_count = 0
        self.pause_count = 0
        self.resume_count = 0
        self.requests: list[tuple[bytes, tuple[bytes, ...]]] = []
        self.logger = logging.getLogger(__name__)

    def write(self, data: bytes, datatype: int | None = None) -> None:
        pass

    def write_eof(self) -> None:
        self.eof_count += 1

    def exit(self, status: int) -> None:
        self.exit_statuses.append(status)

    def exit_with_signal(self, signal: str, core_dumped: bool, msg: str, lang: str) -> None:
        self.exit_signals.append((signal, core_dumped, msg, lang))

    def close(self) -> None:
        self.close_count += 1

    def _send_request(self, request: bytes, *args: bytes) -> None:
        self.requests.append((request, args))

    def pause_reading(self) -> None:
        self.pause_count += 1

    def resume_reading(self) -> None:
        self.resume_count += 1


class BrokenUpstreamChannel:
    def __init__(self) -> None:
        self.closed = False
        self.eof_count = 0

    def write(self, data: bytes, datatype: int | None = None) -> None:
        raise BrokenPipeError("closed")

    def write_eof(self) -> None:
        self.eof_count += 1

    def change_terminal_size(self, width: int, height: int, pixwidth: int, pixheight: int) -> None:
        raise BrokenPipeError("closed")

    def send_signal(self, signal: str) -> None:
        raise BrokenPipeError("closed")

    def pause_reading(self) -> None:
        raise BrokenPipeError("closed")

    def resume_reading(self) -> None:
        raise BrokenPipeError("closed")

    def close(self) -> None:
        self.closed = True


def test_upstream_connection_lost_sends_exit_and_eof_without_force_closing_client_channel() -> None:
    relay = SessionRelay(object())  # type: ignore[arg-type]
    server_chan = FakeServerChannel()
    relay.bind_server_channel(server_chan)  # type: ignore[arg-type]
    relay.record_exit_status(0)

    relay.upstream_connection_lost(None)

    assert server_chan.exit_statuses == []
    assert server_chan.requests and server_chan.requests[0][0] == b"exit-status"
    assert server_chan.eof_count == 1
    assert server_chan.close_count == 0


def test_late_client_events_after_upstream_close_are_dropped() -> None:
    relay = SessionRelay(object())  # type: ignore[arg-type]
    relay.bind_upstream_channel(BrokenUpstreamChannel())  # type: ignore[arg-type]

    relay.forward_client_data(b"payload", None)
    relay.forward_client_eof()
    relay.forward_terminal_resize(80, 24, 0, 0)
    relay.forward_signal("TERM")
    relay.pause_upstream_reading()
    relay.resume_upstream_reading()


def test_client_eof_after_upstream_close_does_not_force_close_channel() -> None:
    relay = SessionRelay(object())  # type: ignore[arg-type]
    server_chan = FakeServerChannel()
    relay.bind_server_channel(server_chan)  # type: ignore[arg-type]
    relay._mark_upstream_closed()  # noqa: SLF001

    assert relay.forward_client_eof() is True
    assert server_chan.close_count == 0


def test_client_channel_loss_propagates_eof_and_close_upstream() -> None:
    relay = SessionRelay(object())  # type: ignore[arg-type]
    upstream_chan = BrokenUpstreamChannel()
    relay.bind_upstream_channel(upstream_chan)  # type: ignore[arg-type]

    relay.client_connection_lost(None)

    assert upstream_chan.eof_count == 1
    assert upstream_chan.closed is True


def test_client_read_flow_control_is_left_unpaused() -> None:
    relay = SessionRelay(object())  # type: ignore[arg-type]
    server_chan = FakeServerChannel()
    relay.bind_server_channel(server_chan)  # type: ignore[arg-type]

    relay.pause_client_reading()
    relay.resume_client_reading()

    assert server_chan.pause_count == 0
    assert server_chan.resume_count == 0
