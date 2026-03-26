from __future__ import annotations

import asyncio
import logging

import asyncssh


LOG = logging.getLogger(__name__)


class SessionRelay:
    def __init__(self, upstream_conn: asyncssh.SSHClientConnection):
        self._upstream_conn = upstream_conn
        self._server_chan: asyncssh.SSHServerChannel[bytes] | None = None
        self._upstream_chan: asyncssh.SSHClientChannel[bytes] | None = None
        self._pending_data: list[tuple[bytes, int | None]] = []
        self._pending_eof = False
        self._pending_resize: tuple[int, int, int, int] | None = None
        self._pending_signals: list[str] = []
        self._startup_task: asyncio.Task[None] | None = None

    def bind_server_channel(self, chan: asyncssh.SSHServerChannel[bytes]) -> None:
        self._server_chan = chan

    def bind_upstream_channel(self, chan: asyncssh.SSHClientChannel[bytes]) -> None:
        self._upstream_chan = chan

    def start(self) -> None:
        self._startup_task = asyncio.create_task(self._open_upstream_session())

    def forward_client_data(self, data: bytes, datatype: int | None) -> None:
        if self._upstream_chan is None:
            self._pending_data.append((data, datatype))
            return
        self._upstream_chan.write(data, datatype)

    def forward_client_eof(self) -> bool:
        if self._upstream_chan is None:
            self._pending_eof = True
        else:
            self._upstream_chan.write_eof()
        return True

    def forward_terminal_resize(self, width: int, height: int, pixwidth: int, pixheight: int) -> None:
        resize = (width, height, pixwidth, pixheight)
        if self._upstream_chan is None:
            self._pending_resize = resize
            return
        self._upstream_chan.change_terminal_size(*resize)

    def forward_signal(self, signal: str) -> None:
        if self._upstream_chan is None:
            self._pending_signals.append(signal)
            return
        self._upstream_chan.send_signal(signal)

    def write_to_client(self, data: bytes, datatype: int | None) -> None:
        if self._server_chan is not None:
            self._server_chan.write(data, datatype)

    def write_eof_to_client(self) -> None:
        if self._server_chan is not None:
            self._server_chan.write_eof()

    def send_exit_status(self, status: int) -> None:
        if self._server_chan is not None:
            self._server_chan.exit(status)

    def send_exit_signal(self, signal: str, core_dumped: bool, msg: str, lang: str) -> None:
        if self._server_chan is not None:
            self._server_chan.exit_with_signal(signal, core_dumped, msg, lang)

    def close_client_channel(self) -> None:
        if self._server_chan is not None:
            self._server_chan.close()

    def close(self) -> None:
        if self._startup_task is not None and not self._startup_task.done():
            self._startup_task.cancel()
        if self._upstream_chan is not None:
            self._upstream_chan.close()

    async def _open_upstream_session(self) -> None:
        server_chan = self._require_server_chan()

        kwargs: dict[str, object] = {"encoding": None}
        command = server_chan.get_command()
        subsystem = server_chan.get_subsystem()
        environment = server_chan.get_environment()
        term_type = server_chan.get_terminal_type()

        if command is not None:
            kwargs["command"] = command
        if subsystem is not None:
            kwargs["subsystem"] = subsystem
        if environment:
            kwargs["env"] = environment
        if term_type:
            kwargs["request_pty"] = True
            kwargs["term_type"] = term_type
            kwargs["term_size"] = server_chan.get_terminal_size()
            kwargs["term_modes"] = server_chan.get_terminal_modes()

        try:
            upstream_chan, _ = await self._upstream_conn.create_session(lambda: UpstreamClientSession(self), **kwargs)
        except Exception:
            LOG.exception("failed to open upstream session")
            server_chan.exit(255)
            server_chan.close()
            return

        self._upstream_chan = upstream_chan

        if self._pending_resize is not None:
            upstream_chan.change_terminal_size(*self._pending_resize)

        for signal in self._pending_signals:
            upstream_chan.send_signal(signal)
        self._pending_signals.clear()

        for data, datatype in self._pending_data:
            upstream_chan.write(data, datatype)
        self._pending_data.clear()

        if self._pending_eof:
            upstream_chan.write_eof()

    def _require_server_chan(self) -> asyncssh.SSHServerChannel[bytes]:
        if self._server_chan is None:
            raise RuntimeError("server channel is not ready")
        return self._server_chan


class UpstreamClientSession(asyncssh.SSHClientSession[bytes]):
    def __init__(self, relay: SessionRelay):
        self._relay = relay

    def connection_made(self, chan: asyncssh.SSHClientChannel[bytes]) -> None:
        self._relay.bind_upstream_channel(chan)

    def data_received(self, data: bytes, datatype: int | None) -> None:
        self._relay.write_to_client(data, datatype)

    def eof_received(self) -> bool:
        self._relay.write_eof_to_client()
        return True

    def exit_status_received(self, status: int) -> None:
        self._relay.send_exit_status(status)

    def exit_signal_received(self, signal: str, core_dumped: bool, msg: str, lang: str) -> None:
        self._relay.send_exit_signal(signal, core_dumped, msg, lang)

    def connection_lost(self, exc: Exception | None) -> None:
        self._relay.close_client_channel()


class ProxyServerSession(asyncssh.SSHServerSession[bytes]):
    def __init__(self, upstream_conn: asyncssh.SSHClientConnection):
        self._relay = SessionRelay(upstream_conn)

    def connection_made(self, chan: asyncssh.SSHServerChannel[bytes]) -> None:
        self._relay.bind_server_channel(chan)

    def shell_requested(self) -> bool:
        return True

    def exec_requested(self, command: str) -> bool:
        return True

    def subsystem_requested(self, subsystem: str) -> bool:
        return True

    def pty_requested(self, term_type: str, term_size: tuple[int, int, int, int], term_modes: dict[int, int]) -> bool:
        return True

    def session_started(self) -> None:
        self._relay.start()

    def data_received(self, data: bytes, datatype: int | None) -> None:
        self._relay.forward_client_data(data, datatype)

    def eof_received(self) -> bool:
        return self._relay.forward_client_eof()

    def terminal_size_changed(self, width: int, height: int, pixwidth: int, pixheight: int) -> None:
        self._relay.forward_terminal_resize(width, height, pixwidth, pixheight)

    def signal_received(self, signal: str) -> None:
        self._relay.forward_signal(signal)

    def connection_lost(self, exc: Exception | None) -> None:
        self._relay.close()
