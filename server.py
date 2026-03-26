from __future__ import annotations

import logging

import asyncssh
from forwarding import RemotePortForwarder
from session import ProxyServerSession
from upstream import UpstreamConnectionFactory
from user_auth import UserAuthError, UserAuthenticator, UserRecord


LOG = logging.getLogger(__name__)


class ProxySSHServer(asyncssh.SSHServer):
    def __init__(self, authenticator: UserAuthenticator, upstream_factory: UpstreamConnectionFactory, remote_forwarder: RemotePortForwarder) -> None:  # fmt: skip
        self._authenticator = authenticator
        self._upstream_factory = upstream_factory
        self._remote_forwarder = remote_forwarder
        self._conn: asyncssh.SSHServerConnection | None = None
        self._username: str | None = None
        self._user_record: UserRecord | None = None
        self._upstream_conn: asyncssh.SSHClientConnection | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername")
        LOG.info("accepted inbound SSH connection from %s", peer)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            LOG.info("inbound SSH connection closed with error: %s", exc)
        else:
            LOG.info("inbound SSH connection closed")

        if self._upstream_conn is not None:
            self._upstream_conn.close()
            self._upstream_conn = None

    def begin_auth(self, username: str) -> bool:
        self._username = username
        self._user_record = None
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
    def __init__(self, authenticator: UserAuthenticator | None = None, upstream_factory: UpstreamConnectionFactory | None = None, remote_forwarder: RemotePortForwarder | None = None):  # fmt: skip
        self._authenticator = UserAuthenticator() if authenticator is None else authenticator
        self._upstream_factory = UpstreamConnectionFactory() if upstream_factory is None else upstream_factory
        self._remote_forwarder = RemotePortForwarder() if remote_forwarder is None else remote_forwarder

    def create(self) -> ProxySSHServer:
        return ProxySSHServer(
            authenticator=self._authenticator,
            upstream_factory=self._upstream_factory,
            remote_forwarder=self._remote_forwarder,
        )
