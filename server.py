from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass
from typing import Callable

import paramiko

from forwarding import DirectTCPBridge, RemotePortForwarder, ReverseTCPListener
from session import PendingSessionRequest, SessionBridge
from ssh_common import SESSION_CHANNEL_WINDOW, close_channel_quietly, close_socket_quietly, close_transport_quietly
from upstream import UpstreamConnectionFactory, UpstreamSSHConnection
from user_auth import UnknownUserError, UserAuthError, UserAuthenticator, UserRecord


LOG = logging.getLogger(__name__)


class ActiveConnectionRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._connections_by_username: dict[str, set[ProxySSHConnection]] = {}

    def register(self, username: str, connection: ProxySSHConnection) -> None:
        with self._lock:
            self._connections_by_username.setdefault(username, set()).add(connection)

    def unregister(self, username: str | None, connection: ProxySSHConnection) -> None:
        if not username:
            return
        with self._lock:
            active_connections = self._connections_by_username.get(username)
            if not active_connections:
                return
            active_connections.discard(connection)
            if not active_connections:
                self._connections_by_username.pop(username, None)

    def disconnect_user(self, username: str) -> None:
        with self._lock:
            targets = tuple(self._connections_by_username.get(username, ()))

        for connection in targets:
            connection.force_disconnect()


@dataclass(frozen=True, slots=True)
class DirectTCPRequest:
    channel_id: int
    origin: tuple[str, int]
    destination: tuple[str, int]


class ProxyServerInterface(paramiko.ServerInterface):
    def __init__(self, connection: ProxySSHConnection):
        self._connection = connection

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        return self._connection.authenticate_password(username, password)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            self._connection.register_session_request(chanid)
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_direct_tcpip_request(
        self,
        chanid: int,
        origin: tuple[str, int],
        destination: tuple[str, int],
    ) -> int:
        self._connection.register_direct_tcpip_request(chanid, origin, destination)
        return paramiko.OPEN_SUCCEEDED

    def check_channel_env_request(self, channel: paramiko.Channel, name: bytes | str, value: bytes | str) -> bool:
        self._connection.add_environment(channel.get_id(), _to_text(name), _to_text(value))
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes | str,
        width: int,
        height: int,
        pixel_width: int,
        pixel_height: int,
        modes,
    ) -> bool:
        self._connection.set_pty_request(
            channel.get_id(),
            _to_text(term),
            width,
            height,
            pixel_width,
            pixel_height,
        )
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self._connection.set_shell_request(channel.get_id())
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes | str) -> bool:
        self._connection.set_exec_request(channel.get_id(), _to_text(command))
        return True

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        self._connection.set_subsystem_request(channel.get_id(), name)
        return True

    def check_channel_window_change_request(
        self,
        channel: paramiko.Channel,
        width: int,
        height: int,
        pixel_width: int,
        pixel_height: int,
    ) -> bool:
        self._connection.set_terminal_resize(channel.get_id(), width, height, pixel_width, pixel_height)
        return True

    def check_port_forward_request(self, address: str, port: int) -> int:
        listener = self._connection.create_reverse_listener(address, port)
        if listener is False:
            return False  # type: ignore[return-value]
        return listener.assigned_port

    def cancel_port_forward_request(self, address: str, port: int) -> None:
        self._connection.cancel_reverse_listener(address, port)


class ProxySSHConnection:
    def __init__(
        self,
        client_sock: socket.socket,
        peer: tuple[str, int] | None,
        host_keys: list[paramiko.PKey],
        authenticator: UserAuthenticator,
        upstream_factory: UpstreamConnectionFactory,
        remote_forwarder: RemotePortForwarder,
        active_connections: ActiveConnectionRegistry,
        on_close: Callable[[ProxySSHConnection], None] | None = None,
    ):
        self._client_sock = client_sock
        self._peer = peer
        self._host_keys = host_keys
        self._authenticator = authenticator
        self._upstream_factory = upstream_factory
        self._remote_forwarder = remote_forwarder
        self._active_connections = active_connections
        self._on_close = on_close

        self._lock = threading.RLock()
        self._thread = threading.Thread(target=self._serve, name=f"ssh-conn-{peer}", daemon=True)
        self._closed = threading.Event()
        self._transport: paramiko.Transport | None = None
        self._server_interface = ProxyServerInterface(self)
        self._username: str | None = None
        self._user_record: UserRecord | None = None
        self._upstream_conn: UpstreamSSHConnection | None = None
        self._pending_sessions: dict[int, PendingSessionRequest] = {}
        self._pending_direct_tcp: dict[int, DirectTCPRequest] = {}
        self._active_bridges: set[object] = set()
        self._reverse_listeners: dict[tuple[str, int], ReverseTCPListener] = {}

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    def force_disconnect(self) -> None:
        if self._closed.is_set():
            return

        self._closed.set()

        with self._lock:
            bridges = tuple(self._active_bridges)
            listeners = tuple(self._reverse_listeners.values())
            self._reverse_listeners.clear()

        for bridge in bridges:
            try:
                bridge.close()
            except Exception:
                LOG.debug("bridge close failed", exc_info=True)

        for listener in listeners:
            try:
                listener.close()
            except Exception:
                LOG.debug("reverse listener close failed", exc_info=True)

        if self._upstream_conn is not None:
            self._upstream_conn.close()
            self._upstream_conn = None

        close_transport_quietly(self._transport)
        close_socket_quietly(self._client_sock)

    def authenticate_password(self, username: str, password: str) -> int:
        try:
            user = self._authenticator.authenticate(username, password)
        except UnknownUserError as exc:
            LOG.warning("closing inbound SSH connection for unknown user %s", username)
            self.force_disconnect()
            LOG.debug("unknown user auth error", exc_info=exc)
            return paramiko.AUTH_FAILED
        except UserAuthError as exc:
            LOG.warning("local auth rejected for %s: %s", username, exc)
            return paramiko.AUTH_FAILED

        try:
            upstream_conn = self._upstream_factory.connect(username, user)
        except Exception as exc:
            LOG.exception("failed to open upstream SSH connection for %s: %s", username, exc)
            return paramiko.AUTH_FAILED

        with self._lock:
            self._username = username
            self._user_record = user
            self._upstream_conn = upstream_conn

        self._active_connections.register(username, self)
        LOG.info(
            "local auth succeeded for %s, upstream connected to %s:%s as %s",
            username,
            user.upstream_host,
            user.upstream_port,
            username,
        )
        return paramiko.AUTH_SUCCESSFUL

    def register_session_request(self, channel_id: int) -> None:
        with self._lock:
            self._pending_sessions[channel_id] = PendingSessionRequest(channel_id)

    def register_direct_tcpip_request(
        self,
        channel_id: int,
        origin: tuple[str, int],
        destination: tuple[str, int],
    ) -> None:
        with self._lock:
            self._pending_direct_tcp[channel_id] = DirectTCPRequest(channel_id, origin, destination)
        LOG.info("forwarding direct-tcpip %s:%s from %s:%s", destination[0], destination[1], origin[0], origin[1])

    def add_environment(self, channel_id: int, name: str, value: str) -> None:
        request = self._get_session_request(channel_id)
        if request is not None:
            request.add_environment(name, value)

    def set_pty_request(
        self,
        channel_id: int,
        term_type: str,
        width: int,
        height: int,
        pixel_width: int,
        pixel_height: int,
    ) -> None:
        request = self._get_session_request(channel_id)
        if request is not None:
            request.set_pty(term_type, width, height, pixel_width, pixel_height)

    def set_shell_request(self, channel_id: int) -> None:
        request = self._get_session_request(channel_id)
        if request is not None:
            request.set_shell()

    def set_exec_request(self, channel_id: int, command: str) -> None:
        request = self._get_session_request(channel_id)
        if request is not None:
            request.set_exec(command)

    def set_subsystem_request(self, channel_id: int, subsystem: str) -> None:
        request = self._get_session_request(channel_id)
        if request is not None:
            request.set_subsystem(subsystem)

    def set_terminal_resize(
        self,
        channel_id: int,
        width: int,
        height: int,
        pixel_width: int,
        pixel_height: int,
    ) -> None:
        request = self._get_session_request(channel_id)
        if request is not None:
            request.set_resize(width, height, pixel_width, pixel_height)

    def create_reverse_listener(self, listen_host: str, listen_port: int) -> ReverseTCPListener | bool:
        listener = self._remote_forwarder.create_listener(self, listen_host, listen_port)
        if listener is False:
            return False
        with self._lock:
            self._reverse_listeners[(listener.listen_host, listener.assigned_port)] = listener
        return listener

    def cancel_reverse_listener(self, listen_host: str, listen_port: int) -> None:
        with self._lock:
            listener = self._reverse_listeners.pop((listen_host, listen_port), None)

        if listener is not None:
            listener.close()

    def require_upstream(self) -> UpstreamSSHConnection:
        if self._upstream_conn is None:
            raise paramiko.SSHException("upstream SSH connection is not ready")
        return self._upstream_conn

    def open_forwarded_channel(
        self,
        origin: tuple[str, int],
        server: tuple[str, int],
    ) -> paramiko.Channel | None:
        if self._transport is None or not self._transport.is_active():
            return None
        try:
            return self._transport.open_forwarded_tcpip_channel(origin, server)
        except Exception:
            LOG.exception("failed to open forwarded-tcpip channel back to client")
            return None

    def register_bridge(self, bridge: object) -> None:
        with self._lock:
            self._active_bridges.add(bridge)

    def unregister_bridge(self, bridge: object) -> None:
        with self._lock:
            self._active_bridges.discard(bridge)

    def _serve(self) -> None:
        LOG.info("accepted inbound SSH connection from %s", self._peer)
        exc: Exception | None = None

        try:
            transport = paramiko.Transport(self._client_sock, default_window_size=SESSION_CHANNEL_WINDOW)
            self._transport = transport
            for host_key in self._host_keys:
                transport.add_server_key(host_key)

            transport.start_server(server=self._server_interface)

            while transport.is_active() and not self._closed.is_set():
                channel = transport.accept(timeout=0.2)
                if channel is None:
                    continue
                self._dispatch_channel(channel)
        except Exception as err:
            exc = err
        finally:
            self.force_disconnect()
            self._active_connections.unregister(self._username, self)
            if exc:
                LOG.info("inbound SSH connection closed with error: %s", exc)
            else:
                LOG.info("inbound SSH connection closed")
            if self._on_close is not None:
                self._on_close(self)

    def _dispatch_channel(self, channel: paramiko.Channel) -> None:
        channel_id = channel.get_id()
        with self._lock:
            session_request = self._pending_sessions.get(channel_id)
            direct_request = self._pending_direct_tcp.pop(channel_id, None)

        if session_request is not None:
            bridge = SessionBridge(
                session_request,
                channel,
                self.require_upstream(),
                lambda closed_bridge, pending_channel_id=channel_id: self._complete_session_bridge(
                    pending_channel_id, closed_bridge
                ),
            )
            self.register_bridge(bridge)
            bridge.start()
            return

        if direct_request is not None:
            bridge = DirectTCPBridge(
                channel,
                self.require_upstream(),
                direct_request.destination,
                direct_request.origin,
                self.unregister_bridge,
            )
            self.register_bridge(bridge)
            bridge.start()
            return

        close_channel_quietly(channel)

    def _get_session_request(self, channel_id: int) -> PendingSessionRequest | None:
        with self._lock:
            return self._pending_sessions.get(channel_id)

    def _complete_session_bridge(self, channel_id: int, bridge: SessionBridge) -> None:
        with self._lock:
            self._pending_sessions.pop(channel_id, None)
        self.unregister_bridge(bridge)


class ProxyServerFactory:
    def __init__(
        self,
        authenticator: UserAuthenticator,
        upstream_factory: UpstreamConnectionFactory,
        remote_forwarder: RemotePortForwarder | None = None,
        active_connections: ActiveConnectionRegistry | None = None,
    ):
        self._authenticator = authenticator
        self._upstream_factory = upstream_factory
        self._remote_forwarder = RemotePortForwarder() if remote_forwarder is None else remote_forwarder
        self._active_connections = ActiveConnectionRegistry() if active_connections is None else active_connections

    def create_connection(
        self,
        client_sock: socket.socket,
        peer: tuple[str, int] | None,
        host_keys: list[paramiko.PKey],
        on_close: Callable[[ProxySSHConnection], None] | None = None,
    ) -> ProxySSHConnection:
        return ProxySSHConnection(
            client_sock=client_sock,
            peer=peer,
            host_keys=host_keys,
            authenticator=self._authenticator,
            upstream_factory=self._upstream_factory,
            remote_forwarder=self._remote_forwarder,
            active_connections=self._active_connections,
            on_close=on_close,
        )

    def disconnect_user(self, username: str) -> None:
        self._active_connections.disconnect_user(username)


def _to_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
