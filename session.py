from __future__ import annotations

import asyncio
import logging
import time

import asyncssh
from asyncssh.packet import Boolean, String, UInt32


LOG = logging.getLogger(__name__)
CLIENT_CHANNEL_CLOSE_GRACE = 1.0
CLIENT_WRITE_FLUSH_TIMEOUT = 5.0
CLIENT_WRITE_FLUSH_INTERVAL = 0.01
CLIENT_PROGRESS_LOG_BYTES = 1 << 20


class SessionRelay:
    def __init__(self, upstream_conn: asyncssh.SSHClientConnection):
        self._upstream_conn = upstream_conn
        self._server_chan: asyncssh.SSHServerChannel[bytes] | None = None
        self._upstream_chan: asyncssh.SSHClientChannel[bytes] | None = None
        self._upstream_closed = False
        self._pending_data: list[tuple[bytes, int | None]] = []
        self._pending_eof = False
        self._client_eof_forwarded = False
        self._pending_resize: tuple[int, int, int, int] | None = None
        self._pending_signals: list[str] = []
        self._pending_exit_status: int | None = None
        self._pending_exit_signal: tuple[str, bool, str, str] | None = None
        self._startup_task: asyncio.Task[None] | None = None
        self._upstream_read_paused = False
        self._client_exit_sent = False
        self._close_client_handle: asyncio.TimerHandle | None = None
        self._finalize_client_task: asyncio.Task[None] | None = None
        self._client_bytes_forwarded = 0
        self._next_client_progress_log = CLIENT_PROGRESS_LOG_BYTES

    def bind_server_channel(self, chan: asyncssh.SSHServerChannel[bytes]) -> None:
        self._server_chan = chan

    def bind_upstream_channel(self, chan: asyncssh.SSHClientChannel[bytes]) -> None:
        self._upstream_chan = chan
        self._upstream_closed = False

    def start(self) -> None:
        self._startup_task = asyncio.create_task(self._open_upstream_session())

    def pause_client_reading(self) -> None:
        # Keep stdin delivery transparent. SSHJ/PyCharm uploads queue EOF behind
        # the final data frames, and pausing the inbound session channel here can
        # leave the remote writer waiting forever for its terminating EOF.
        return

    def resume_client_reading(self) -> None:
        return

    def pause_upstream_reading(self) -> None:
        if self._upstream_chan is not None and not self._upstream_read_paused:
            try:
                self._upstream_chan.pause_reading()
            except (BrokenPipeError, OSError):
                LOG.debug("dropping pause request for closed upstream channel")
                self._mark_upstream_closed()
                return
            self._upstream_read_paused = True

    def resume_upstream_reading(self) -> None:
        if self._upstream_chan is not None and self._upstream_read_paused:
            try:
                self._upstream_chan.resume_reading()
            except (BrokenPipeError, OSError):
                LOG.debug("dropping resume request for closed upstream channel")
                self._mark_upstream_closed()
                return
            self._upstream_read_paused = False

    def forward_client_data(self, data: bytes, datatype: int | None) -> None:
        if self._upstream_closed:
            LOG.debug("dropping data for closed upstream channel")
            return

        self._client_bytes_forwarded += len(data)
        if self._server_chan is not None and self._client_bytes_forwarded >= self._next_client_progress_log:
            self._server_chan.logger.info(
                "Forwarded %d bytes of client stdin upstream",
                self._client_bytes_forwarded,
            )
            while self._client_bytes_forwarded >= self._next_client_progress_log:
                self._next_client_progress_log += CLIENT_PROGRESS_LOG_BYTES

        if self._upstream_chan is None:
            self._pending_data.append((data, datatype))
            return
        try:
            self._upstream_chan.write(data, datatype)
        except (BrokenPipeError, OSError):
            LOG.debug("dropping data for closed upstream channel")
            self._mark_upstream_closed()

    def forward_client_eof(self) -> bool:
        self._client_eof_forwarded = True
        if self._server_chan is not None:
            self._server_chan.logger.info(
                "Forwarding client EOF upstream after %d bytes",
                self._client_bytes_forwarded,
            )
        if self._upstream_closed:
            return True
        if self._upstream_chan is None:
            self._pending_eof = True
        else:
            try:
                self._upstream_chan.write_eof()
            except (BrokenPipeError, OSError):
                LOG.debug("dropping EOF for closed upstream channel")
                self._mark_upstream_closed()
        return True

    def forward_terminal_resize(self, width: int, height: int, pixwidth: int, pixheight: int) -> None:
        resize = (width, height, pixwidth, pixheight)
        if self._upstream_closed:
            return
        if self._upstream_chan is None:
            self._pending_resize = resize
            return
        try:
            self._upstream_chan.change_terminal_size(*resize)
        except (BrokenPipeError, OSError):
            LOG.debug("dropping terminal resize for closed upstream channel")
            self._mark_upstream_closed()

    def forward_signal(self, signal: str) -> None:
        if self._upstream_closed:
            return
        if self._upstream_chan is None:
            self._pending_signals.append(signal)
            return
        try:
            self._upstream_chan.send_signal(signal)
        except (BrokenPipeError, OSError):
            LOG.debug("dropping signal for closed upstream channel")
            self._mark_upstream_closed()

    def write_to_client(self, data: bytes, datatype: int | None) -> None:
        if self._server_chan is not None:
            try:
                self._server_chan.write(data, datatype)
            except (BrokenPipeError, OSError):
                LOG.debug("dropping data for closed client channel")

    def write_eof_to_client(self) -> None:
        if self._server_chan is not None:
            try:
                self._server_chan.write_eof()
            except (BrokenPipeError, OSError):
                LOG.debug("dropping EOF for closed client channel")

    def send_exit_status(self, status: int) -> None:
        if self._server_chan is not None:
            try:
                if not self._client_exit_sent:
                    status &= 0xFF
                    self._server_chan.logger.info("Sending exit status %d", status)
                    self._server_chan._send_request(b"exit-status", UInt32(status))  # noqa: SLF001
                    self._client_exit_sent = True
            except (BrokenPipeError, OSError):
                LOG.debug("dropping exit status for closed client channel")

    def send_exit_signal(self, signal: str, core_dumped: bool, msg: str, lang: str) -> None:
        if self._server_chan is not None:
            try:
                if not self._client_exit_sent:
                    self._server_chan.logger.info("Sending exit signal %s", signal)
                    self._server_chan.logger.debug1("  Core dumped: %s", core_dumped)
                    self._server_chan.logger.debug1("  Message: %s", msg)
                    self._server_chan._send_request(  # noqa: SLF001
                        b"exit-signal",
                        String(signal),
                        Boolean(core_dumped),
                        String(msg),
                        String(lang),
                    )
                    self._client_exit_sent = True
            except (BrokenPipeError, OSError):
                LOG.debug("dropping exit signal for closed client channel")

    def close_client_channel(self) -> None:
        self._cancel_scheduled_client_close()
        if self._server_chan is not None:
            try:
                self._server_chan.close()
            except (BrokenPipeError, OSError):
                LOG.debug("client channel already closed")

    def record_exit_status(self, status: int) -> None:
        self._pending_exit_status = status
        self._pending_exit_signal = None

    def record_exit_signal(self, signal: str, core_dumped: bool, msg: str, lang: str) -> None:
        self._pending_exit_signal = (signal, core_dumped, msg, lang)
        self._pending_exit_status = None

    def upstream_connection_lost(self, exc: Exception | None) -> None:
        if self._server_chan is not None:
            self._server_chan.logger.info(
                "Upstream session closed after %d bytes, client_eof_forwarded=%s, exc=%s",
                self._client_bytes_forwarded,
                self._client_eof_forwarded,
                exc,
            )
        self._mark_upstream_closed()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._finalize_client_channel_now()
            return

        if self._finalize_client_task is None or self._finalize_client_task.done():
            self._finalize_client_task = loop.create_task(self._finalize_client_channel())

    def _finalize_client_channel_now(self) -> None:
        if self._pending_exit_signal is not None:
            self.send_exit_signal(*self._pending_exit_signal)
        elif self._pending_exit_status is not None:
            self.send_exit_status(self._pending_exit_status)

        self.write_eof_to_client()
        self._schedule_client_close()

    async def _finalize_client_channel(self) -> None:
        try:
            await self._wait_for_client_output_flush()
            self._finalize_client_channel_now()
        finally:
            self._finalize_client_task = None

    def client_connection_lost(self, exc: Exception | None) -> None:
        server_chan = self._server_chan
        if server_chan is not None:
            server_chan.logger.info(
                "Client session closed after %d bytes, client_eof_forwarded=%s, exc=%s",
                self._client_bytes_forwarded,
                self._client_eof_forwarded,
                exc,
            )
        self._cancel_finalize_client_task()
        self._cancel_scheduled_client_close()
        self._server_chan = None

        if self._startup_task is not None and not self._startup_task.done():
            self._startup_task.cancel()

        if self._upstream_chan is None:
            return

        try:
            self._upstream_chan.write_eof()
        except (BrokenPipeError, OSError):
            LOG.debug("dropping upstream EOF during client channel shutdown")
        self._upstream_chan.close()

    def _mark_upstream_closed(self) -> None:
        self._upstream_chan = None
        self._upstream_closed = True
        self._upstream_read_paused = False
        self._pending_data.clear()
        self._pending_eof = False
        self._pending_resize = None
        self._pending_signals.clear()

    def _schedule_client_close(self) -> None:
        if self._server_chan is None:
            return
        if self._close_client_handle is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._close_client_handle = loop.call_later(CLIENT_CHANNEL_CLOSE_GRACE, self.close_client_channel)

    def _cancel_scheduled_client_close(self) -> None:
        if self._close_client_handle is not None:
            self._close_client_handle.cancel()
            self._close_client_handle = None

    def _cancel_finalize_client_task(self) -> None:
        if self._finalize_client_task is not None:
            self._finalize_client_task.cancel()
            self._finalize_client_task = None

    async def _wait_for_client_output_flush(self) -> None:
        if self._server_chan is None:
            return

        deadline = time.monotonic() + CLIENT_WRITE_FLUSH_TIMEOUT
        while self._server_chan is not None:
            try:
                pending = self._server_chan.get_write_buffer_size()
            except (AttributeError, BrokenPipeError, OSError):
                return

            if pending == 0:
                return

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                LOG.debug("timed out waiting for client channel output to flush")
                return

            await asyncio.sleep(min(CLIENT_WRITE_FLUSH_INTERVAL, remaining))

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

    def pause_writing(self) -> None:
        self._relay.pause_client_reading()

    def resume_writing(self) -> None:
        self._relay.resume_client_reading()

    def exit_status_received(self, status: int) -> None:
        self._relay.record_exit_status(status)

    def exit_signal_received(self, signal: str, core_dumped: bool, msg: str, lang: str) -> None:
        self._relay.record_exit_signal(signal, core_dumped, msg, lang)

    def connection_lost(self, exc: Exception | None) -> None:
        self._relay.upstream_connection_lost(exc)


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

    def pause_writing(self) -> None:
        self._relay.pause_upstream_reading()

    def resume_writing(self) -> None:
        self._relay.resume_upstream_reading()

    def terminal_size_changed(self, width: int, height: int, pixwidth: int, pixheight: int) -> None:
        self._relay.forward_terminal_resize(width, height, pixwidth, pixheight)

    def signal_received(self, signal: str) -> None:
        self._relay.forward_signal(signal)

    def connection_lost(self, exc: Exception | None) -> None:
        self._relay.client_connection_lost(exc)
