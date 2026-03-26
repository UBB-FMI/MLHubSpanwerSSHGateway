from __future__ import annotations

import logging

import asyncssh

from forwarding import RemotePortForwarder
from session import ProxyServerSession
from upstream import UpstreamConnectionFactory
from user_auth import UserAuthError, UserAuthenticator, UserRecord


LOG = logging.getLogger(__name__)


class ActiveConnectionRegistry:
    def __init__(self) -> None:
        self._connections_by_username: dict[str, set[ProxySSHServer]] = {}

    def register(self, username: str, server: ProxySSHServer) -> None:
        self._connections_by_username.setdefault(username, set()).add(server)

    def unregister(self, username: str | None, server: ProxySSHServer) -> None:
        if not username:
            return
        active_connections = self._connections_by_username.get(username)
        if not active_connections:
            return
        active_connections.discard(server)
        if not active_connections:
            self._connections_by_username.pop(username, None)

    def disconnect_user(self, username: str) -> None:
        for server in tuple(self._connections_by_username.get(username, ())):
            server.force_disconnect()


class ProxySSHServer(asyncssh.SSHServer):
    def __init__(self, authenticator: UserAuthenticator, upstream_factory: UpstreamConnectionFactory, remote_forwarder: RemotePortForwarder, active_connections: ActiveConnectionRegistry) -> None:  # fmt: skip
        self._authenticator = authenticator
        self._upstream_factory = upstream_factory
        self._remote_forwarder = remote_forwarder
        self._active_connections = active_connections
        self._conn: asyncssh.SSHServerConnection | None = None
        self._username: str | None = None
        self._user_record: UserRecord | None = None
        self._upstream_conn: asyncssh.SSHClientConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        LOG.info("accepted inbound SSH connection from %s", peer)

    def connection_lost(self, exc: Exception | None) -> None:
        self._active_connections.unregister(self._username, self)

        if exc:
            LOG.info("inbound SSH connection closed with error: %s", exc)
        else:
            LOG.info("inbound SSH connection closed")

        if self._upstream_conn is not None:
            self._upstream_conn.close()
            self._upstream_conn = None

    def force_disconnect(self) -> None:
        if self._upstream_conn is not None:
            self._upstream_conn.close()
            self._upstream_conn = None
        if self._conn is not None:
            self._conn.close()

    def begin_auth(self, username: str) -> bool:
        self._active_connections.unregister(self._username, self)
        self._username = username
        self._user_record = None

        if not self._authenticator.is_known_user(username):
            LOG.warning("closing inbound SSH connection for unknown user %s", username)
            if self._conn is not None:
                self._conn.close()
            return False

        self._active_connections.register(username, self)
        return True

    def public_key_auth_supported(self) -> bool:
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        try:
            user = self._authenticator.authenticate(username, password)
        except UserAuthError as exc:
            LOG.warning("local auth rejected for %s: %s", username, exc)
            return False

        try:
            self._upstream_conn = await self._upstream_factory.connect(username, user)
        except Exception as exc:
            LOG.exception("failed to open upstream SSH connection for %s: %s", username, exc)
            self._upstream_conn = None
            self._user_record = None
            return False

        self._user_record = user
        LOG.info(
            "local auth succeeded for %s, upstream connected to %s:%s as %s",
            username,
            user.upstream_host,
            user.upstream_port,
            username,
        )
        return True

    def session_requested(self) -> ProxyServerSession:
        return ProxyServerSession(self._require_upstream())

    def connection_requested(self, dest_host: str, dest_port: int, orig_host: str, orig_port: int) -> asyncssh.SSHClientConnection:  # fmt: skip
        LOG.info("forwarding direct-tcpip %s:%s from %s:%s", dest_host, dest_port, orig_host, orig_port)
        return self._require_upstream()

    async def server_requested(self, listen_host: str, listen_port: int) -> asyncssh.SSHListener | bool:
        return await self._remote_forwarder.create_listener(
            self._require_conn(), self._require_upstream(), listen_host, listen_port
        )

    def _require_conn(self) -> asyncssh.SSHServerConnection:
        if self._conn is None:
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "proxy server connection is not ready")
        return self._conn

    def _require_upstream(self) -> asyncssh.SSHClientConnection:
        if self._upstream_conn is None:
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "upstream SSH connection is not ready")
        return self._upstream_conn


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

    def create(self) -> ProxySSHServer:
        return ProxySSHServer(
            authenticator=self._authenticator,
            upstream_factory=self._upstream_factory,
            remote_forwarder=self._remote_forwarder,
            active_connections=self._active_connections,
        )

    def disconnect_user(self, username: str) -> None:
        self._active_connections.disconnect_user(username)
