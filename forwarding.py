from __future__ import annotations

import logging
import threading

import paramiko

from ssh_common import close_channel_quietly, configure_channel_timeout, pump_bytes, shutdown_write_quietly
from upstream import UpstreamSSHConnection


LOG = logging.getLogger(__name__)


class TCPChannelBridge:
    def __init__(self, left_channel: paramiko.Channel, right_channel: paramiko.Channel, name: str, on_close):
        self._left_channel = left_channel
        self._right_channel = right_channel
        self._name = name
        self._on_close = on_close
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)

    def start(self) -> None:
        configure_channel_timeout(self._left_channel)
        configure_channel_timeout(self._right_channel)
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    def close(self) -> None:
        self._stop_event.set()
        close_channel_quietly(self._left_channel)
        close_channel_quietly(self._right_channel)

    def _run(self) -> None:
        left_to_right = threading.Thread(
            target=self._pump,
            args=(self._left_channel, self._right_channel),
            name=f"{self._name}-left-to-right",
            daemon=True,
        )
        right_to_left = threading.Thread(
            target=self._pump,
            args=(self._right_channel, self._left_channel),
            name=f"{self._name}-right-to-left",
            daemon=True,
        )

        left_to_right.start()
        right_to_left.start()
        left_to_right.join()
        right_to_left.join()

        self.close()
        self._on_close(self)

    def _pump(self, source: paramiko.Channel, destination: paramiko.Channel) -> None:
        try:
            pump_bytes(source, destination, stop_event=self._stop_event)
        finally:
            shutdown_write_quietly(destination)


class ReverseTCPListener:
    def __init__(self, upstream_conn: UpstreamSSHConnection, listen_host: str, assigned_port: int):
        self._upstream_conn = upstream_conn
        self._listen_host = listen_host
        self._assigned_port = assigned_port

    @property
    def listen_host(self) -> str:
        return self._listen_host

    @property
    def assigned_port(self) -> int:
        return self._assigned_port

    def close(self) -> None:
        self._upstream_conn.cancel_port_forward(self._listen_host, self._assigned_port)


class RemotePortForwarder:
    def create_listener(self, connection, listen_host: str, listen_port: int) -> ReverseTCPListener | bool:
        upstream_conn = connection.require_upstream()

        def handle_upstream_channel(
            upstream_channel: paramiko.Channel,
            origin: tuple[str, int],
            server: tuple[str, int],
        ) -> None:
            inbound_channel = connection.open_forwarded_channel(origin, server)
            if inbound_channel is None:
                close_channel_quietly(upstream_channel)
                return

            bridge = TCPChannelBridge(
                inbound_channel,
                upstream_channel,
                name=f"reverse-forward-{listen_host}:{server[1]}",
                on_close=connection.unregister_bridge,
            )
            connection.register_bridge(bridge)
            bridge.start()

        try:
            assigned_port = upstream_conn.request_port_forward(listen_host, listen_port, handler=handle_upstream_channel)
        except Exception as exc:
            LOG.exception(
                "failed to establish upstream remote forwarding listener on %s:%s: %s",
                listen_host,
                listen_port,
                exc,
            )
            return False

        LOG.info("forwarding remote TCP listener %s:%s through upstream", listen_host, assigned_port)
        return ReverseTCPListener(upstream_conn, listen_host, assigned_port)


class DirectTCPBridge:
    def __init__(
        self,
        inbound_channel: paramiko.Channel,
        upstream_conn: UpstreamSSHConnection,
        destination: tuple[str, int],
        origin: tuple[str, int],
        on_close,
    ):
        self._inbound_channel = inbound_channel
        self._upstream_conn = upstream_conn
        self._destination = destination
        self._origin = origin
        self._on_close = on_close
        self._thread = threading.Thread(
            target=self._run,
            name=f"direct-tcpip-{destination[0]}:{destination[1]}",
            daemon=True,
        )
        self._bridge: TCPChannelBridge | None = None

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    def close(self) -> None:
        if self._bridge is not None:
            self._bridge.close()
        else:
            close_channel_quietly(self._inbound_channel)

    def _run(self) -> None:
        try:
            upstream_channel = self._upstream_conn.open_direct_tcpip(self._destination, self._origin)
        except Exception:
            LOG.exception("failed to open upstream direct-tcpip %s:%s", *self._destination)
            close_channel_quietly(self._inbound_channel)
            self._on_close(self)
            return

        bridge = TCPChannelBridge(
            self._inbound_channel,
            upstream_channel,
            name=f"direct-tcpip-{self._destination[0]}:{self._destination[1]}",
            on_close=self._handle_bridge_close,
        )
        self._bridge = bridge
        bridge.start()

    def _handle_bridge_close(self, _bridge: TCPChannelBridge) -> None:
        self._on_close(self)
