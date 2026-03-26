from __future__ import annotations

import logging

from asyncssh_compat import _process_eof_allow_duplicate


class _FakePacket:
    def __init__(self) -> None:
        self.checked = 0

    def check_end(self) -> None:
        self.checked += 1


class _FakeChannel:
    def __init__(self, recv_state: str) -> None:
        self._recv_state = recv_state
        self.logger = logging.getLogger(__name__)


def test_duplicate_eof_is_ignored_after_client_already_sent_eof() -> None:
    packet = _FakePacket()
    channel = _FakeChannel("eof_pending")

    _process_eof_allow_duplicate(channel, 0, 0, packet)  # type: ignore[arg-type]

    assert packet.checked == 1
