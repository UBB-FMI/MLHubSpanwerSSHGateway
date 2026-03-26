from __future__ import annotations

import socket
from pathlib import Path

import paramiko

from ssh_common import SESSION_CHANNEL_WINDOW, close_socket_quietly, close_transport_quietly
from user_auth import UserRecord


DEFAULT_CONNECT_TIMEOUT = 10


class UpstreamSSHConnection:
    def __init__(self, sock: socket.socket, transport: paramiko.Transport):
        self._sock = sock
        self._transport = transport

    @property
    def transport(self) -> paramiko.Transport:
        return self._transport

    def open_session(self) -> paramiko.Channel:
        return self._transport.open_session(window_size=SESSION_CHANNEL_WINDOW)

    def open_direct_tcpip(
        self,
        destination: tuple[str, int],
        origin: tuple[str, int],
    ) -> paramiko.Channel:
        return self._transport.open_channel(
            "direct-tcpip",
            dest_addr=destination,
            src_addr=origin,
            window_size=SESSION_CHANNEL_WINDOW,
        )

    def request_port_forward(self, address: str, port: int, handler) -> int:
        return int(self._transport.request_port_forward(address, port, handler=handler))

    def cancel_port_forward(self, address: str, port: int) -> None:
        self._transport.cancel_port_forward(address, port)

    def is_active(self) -> bool:
        return self._transport.is_active()

    def close(self) -> None:
        close_transport_quietly(self._transport)
        close_socket_quietly(self._sock)


class UpstreamConnectionFactory:
    def __init__(
        self,
        client_key_path: str,
        known_hosts_path: str = "",
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    ):
        self._client_key_path = self._require_file(client_key_path, "client key")
        self._known_hosts_path = known_hosts_path
        self._connect_timeout = connect_timeout
        self._pkey = self._load_private_key(self._client_key_path)

    def _require_file(self, raw_path: str, description: str) -> Path:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"{description} does not exist or is not a file: {path}")
        return path

    def _load_private_key(self, path: Path) -> paramiko.PKey:
        loaders = (
            paramiko.Ed25519Key.from_private_key_file,
            paramiko.RSAKey.from_private_key_file,
            paramiko.ECDSAKey.from_private_key_file,
        )

        last_error: Exception | None = None
        for loader in loaders:
            try:
                return loader(str(path))
            except Exception as exc:
                last_error = exc

        raise ValueError(f"unsupported upstream private key format: {path}") from last_error

    def connect(self, username: str, user: UserRecord) -> UpstreamSSHConnection:
        sock = socket.create_connection((user.upstream_host, user.upstream_port), timeout=self._connect_timeout)
        transport = paramiko.Transport(sock, default_window_size=SESSION_CHANNEL_WINDOW)
        transport.start_client(timeout=self._connect_timeout)
        transport.auth_publickey(username, self._pkey)

        if not transport.is_authenticated():
            close_transport_quietly(transport)
            close_socket_quietly(sock)
            raise paramiko.AuthenticationException(f"upstream public-key auth failed for {username}")

        return UpstreamSSHConnection(sock, transport)
