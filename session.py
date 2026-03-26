from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

import paramiko

from ssh_common import (
    close_channel_quietly,
    configure_channel_timeout,
    pump_bytes,
    shutdown_write_quietly,
)
from upstream import UpstreamSSHConnection


LOG = logging.getLogger(__name__)
SESSION_REQUEST_TIMEOUT = 10.0


@dataclass(slots=True)
class PtyRequest:
    term_type: str
    width: int
    height: int
    pixel_width: int
    pixel_height: int


@dataclass(slots=True)
class SessionSnapshot:
    env: dict[str, str]
    pty: PtyRequest | None
    resize: tuple[int, int, int, int] | None
    kind: str | None
    command: str | None
    subsystem: str | None


@dataclass(slots=True)
class PendingSessionRequest:
    channel_id: int
    ready: threading.Event = field(default_factory=threading.Event)
    env: dict[str, str] = field(default_factory=dict)
    pty: PtyRequest | None = None
    resize: tuple[int, int, int, int] | None = None
    kind: str | None = None
    command: str | None = None
    subsystem: str | None = None
    bridge: SessionBridge | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def snapshot(self) -> SessionSnapshot:
        with self._lock:
            return SessionSnapshot(
                env=dict(self.env),
                pty=self.pty,
                resize=self.resize,
                kind=self.kind,
                command=self.command,
                subsystem=self.subsystem,
            )

    def add_environment(self, name: str, value: str) -> None:
        with self._lock:
            self.env[name] = value

    def set_pty(
        self,
        term_type: str,
        width: int,
        height: int,
        pixel_width: int,
        pixel_height: int,
    ) -> None:
        with self._lock:
            self.pty = PtyRequest(term_type, width, height, pixel_width, pixel_height)

    def set_shell(self) -> None:
        with self._lock:
            self.kind = "shell"
            self.command = None
            self.subsystem = None
            self.ready.set()

    def set_exec(self, command: str) -> None:
        with self._lock:
            self.kind = "exec"
            self.command = command
            self.subsystem = None
            self.ready.set()

    def set_subsystem(self, subsystem: str) -> None:
        with self._lock:
            self.kind = "subsystem"
            self.command = None
            self.subsystem = subsystem
            self.ready.set()

    def set_resize(self, width: int, height: int, pixel_width: int, pixel_height: int) -> None:
        with self._lock:
            self.resize = (width, height, pixel_width, pixel_height)
            bridge = self.bridge

        if bridge is not None:
            bridge.resize_terminal(width, height, pixel_width, pixel_height)

    def bind_bridge(self, bridge: SessionBridge) -> None:
        with self._lock:
            self.bridge = bridge


class SessionBridge:
    def __init__(
        self,
        request: PendingSessionRequest,
        inbound_channel: paramiko.Channel,
        upstream_conn: UpstreamSSHConnection,
        on_close,
    ):
        self._request = request
        self._inbound_channel = inbound_channel
        self._upstream_conn = upstream_conn
        self._upstream_channel: paramiko.Channel | None = None
        self._on_close = on_close
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"session-bridge-{request.channel_id}",
            daemon=True,
        )

    def start(self) -> None:
        configure_channel_timeout(self._inbound_channel)
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    def close(self) -> None:
        self._stop_event.set()
        close_channel_quietly(self._upstream_channel)
        close_channel_quietly(self._inbound_channel)

    def resize_terminal(self, width: int, height: int, pixel_width: int, pixel_height: int) -> None:
        if self._upstream_channel is None:
            return
        try:
            self._upstream_channel.resize_pty(
                width=width,
                height=height,
                width_pixels=pixel_width,
                height_pixels=pixel_height,
            )
        except Exception:
            LOG.debug("failed to resize upstream PTY", exc_info=True)

    def _run(self) -> None:
        try:
            if not self._request.ready.wait(timeout=SESSION_REQUEST_TIMEOUT):
                LOG.warning("timed out waiting for session request on channel %s", self._request.channel_id)
                return

            snapshot = self._request.snapshot()
            if snapshot.kind is None:
                return

            upstream_channel = self._open_upstream_channel(snapshot)
            self._upstream_channel = upstream_channel
            self._request.bind_bridge(self)

            stdin_thread = threading.Thread(target=self._pump_client_stdin, name=f"stdin-{self._request.channel_id}", daemon=True)
            stdout_thread = threading.Thread(target=self._pump_upstream_stdout, name=f"stdout-{self._request.channel_id}", daemon=True)
            threads = [stdin_thread, stdout_thread]

            stderr_thread: threading.Thread | None = None
            if snapshot.pty is None:
                stderr_thread = threading.Thread(
                    target=self._pump_upstream_stderr,
                    name=f"stderr-{self._request.channel_id}",
                    daemon=True,
                )
                threads.append(stderr_thread)

            for thread in threads:
                thread.start()

            stdout_thread.join()
            if stderr_thread is not None:
                stderr_thread.join()

            exit_status = self._read_exit_status(upstream_channel)
            if exit_status is not None:
                self._send_exit_status(exit_status)

            shutdown_write_quietly(self._inbound_channel)
            stdin_thread.join(timeout=1.0)
        except Exception:
            LOG.exception("session relay failed on channel %s", self._request.channel_id)
            self._send_exit_status(255)
            shutdown_write_quietly(self._inbound_channel)
        finally:
            self.close()
            self._on_close(self)

    def _open_upstream_channel(self, snapshot: SessionSnapshot) -> paramiko.Channel:
        channel = self._upstream_conn.open_session()
        configure_channel_timeout(channel)

        for name, value in snapshot.env.items():
            try:
                channel.set_environment_variable(name, value)
            except Exception:
                LOG.debug("upstream rejected environment variable %s", name, exc_info=True)

        if snapshot.pty is not None:
            channel.get_pty(
                term=snapshot.pty.term_type,
                width=snapshot.pty.width,
                height=snapshot.pty.height,
                width_pixels=snapshot.pty.pixel_width,
                height_pixels=snapshot.pty.pixel_height,
            )

        if snapshot.kind == "shell":
            channel.invoke_shell()
        elif snapshot.kind == "exec" and snapshot.command is not None:
            channel.exec_command(snapshot.command)
        elif snapshot.kind == "subsystem" and snapshot.subsystem is not None:
            channel.invoke_subsystem(snapshot.subsystem)
        else:
            raise RuntimeError(f"unsupported session request kind: {snapshot.kind}")

        if snapshot.resize is not None and snapshot.pty is not None:
            self.resize_terminal(*snapshot.resize)

        return channel

    def _pump_client_stdin(self) -> None:
        if self._upstream_channel is None:
            return
        try:
            pump_bytes(self._inbound_channel, self._upstream_channel, stop_event=self._stop_event)
        finally:
            shutdown_write_quietly(self._upstream_channel)

    def _pump_upstream_stdout(self) -> None:
        if self._upstream_channel is None:
            return
        pump_bytes(self._upstream_channel, self._inbound_channel, stop_event=self._stop_event)

    def _pump_upstream_stderr(self) -> None:
        if self._upstream_channel is None:
            return
        pump_bytes(
            self._upstream_channel,
            self._inbound_channel,
            recv_stderr=True,
            send_stderr=True,
            stop_event=self._stop_event,
        )

    def _read_exit_status(self, upstream_channel: paramiko.Channel) -> int | None:
        try:
            status = upstream_channel.recv_exit_status()
        except Exception:
            return None
        return status if status >= 0 else None

    def _send_exit_status(self, status: int) -> None:
        try:
            self._inbound_channel.send_exit_status(status & 0xFF)
        except Exception:
            LOG.debug("failed to send exit status to client", exc_info=True)
