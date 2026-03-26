from __future__ import annotations

import argparse
import asyncio
import logging
import socket
import threading
from dataclasses import dataclass
from pathlib import Path

from control import GatewayControlService
from host_keys import ServerHostKeyManager
from server import ProxySSHConnection, ProxyServerFactory
from upstream import DEFAULT_CONNECT_TIMEOUT, UpstreamConnectionFactory
from user_auth import USER_DIRECTORY, UserAuthenticator


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SERVER_HOST_KEY = PROJECT_ROOT / "assets" / "server-host-key"


def _server_port(server: asyncio.AbstractServer | None) -> int | None:
    if server is None or not server.sockets:
        return None
    return int(server.sockets[0].getsockname()[1])


@dataclass(frozen=True, slots=True)
class ListenerConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 2222
    server_host_key: str = str(DEFAULT_SERVER_HOST_KEY)
    control_listen_host: str = "0.0.0.0"
    control_listen_port: int = 2223
    control_shared_secret: str = ""
    upstream_client_key: str = ""
    upstream_known_hosts: str = ""
    upstream_connect_timeout: int = DEFAULT_CONNECT_TIMEOUT


class ThreadedSSHAcceptor:
    def __init__(self, listen_host: str, listen_port: int, host_keys, server_factory: ProxyServerFactory):
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._host_keys = host_keys
        self._server_factory = server_factory
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((listen_host, listen_port))
        self._sock.listen()
        self._sock.settimeout(0.5)
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._connections: set[ProxySSHConnection] = set()
        self._thread = threading.Thread(target=self._accept_loop, name="ssh-listener", daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._closed.is_set():
            return

        self._closed.set()
        try:
            self._sock.close()
        except OSError:
            LOG.debug("failed to close SSH listener socket", exc_info=True)

        with self._lock:
            connections = tuple(self._connections)

        for connection in connections:
            connection.force_disconnect()

    async def wait_closed(self) -> None:
        await asyncio.to_thread(self._join_threads)

    def get_port(self) -> int:
        return int(self._sock.getsockname()[1])

    def _accept_loop(self) -> None:
        while not self._closed.is_set():
            try:
                client_sock, peer = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            connection = self._server_factory.create_connection(
                client_sock,
                peer,
                self._host_keys,
                on_close=self._discard_connection,
            )
            with self._lock:
                self._connections.add(connection)
            connection.start()

    def _discard_connection(self, connection: ProxySSHConnection) -> None:
        with self._lock:
            self._connections.discard(connection)

    def _join_threads(self) -> None:
        self._thread.join(timeout=5)
        with self._lock:
            connections = tuple(self._connections)
        for connection in connections:
            connection.join(timeout=5)


class ProxyListeners:
    def __init__(self, ssh_acceptor: ThreadedSSHAcceptor, control_server: asyncio.AbstractServer | None = None):
        self._ssh_acceptor = ssh_acceptor
        self._control_server = control_server

    def close(self) -> None:
        self._ssh_acceptor.close()
        if self._control_server is not None:
            self._control_server.close()

    async def wait_closed(self) -> None:
        await self._ssh_acceptor.wait_closed()
        if self._control_server is not None:
            await self._control_server.wait_closed()

    def get_port(self) -> int:
        return int(self._ssh_acceptor.get_port())

    def get_control_port(self) -> int | None:
        return _server_port(self._control_server)


class ProxyApplication:
    def __init__(
        self,
        server_factory: ProxyServerFactory | None = None,
        control_service: GatewayControlService | None = None,
    ):
        self._server_factory = server_factory
        self._control_service = control_service

    async def serve(self, config: ListenerConfig) -> ProxyListeners:
        host_key_manager = ServerHostKeyManager(config.server_host_key)
        host_key_manager.ensure_host_keys()
        host_keys = host_key_manager.load_host_keys()

        server_factory = self._server_factory
        if server_factory is None:
            upstream_factory = UpstreamConnectionFactory(
                config.upstream_client_key,
                config.upstream_known_hosts,
                connect_timeout=config.upstream_connect_timeout,
            )
            server_factory = ProxyServerFactory(UserAuthenticator(USER_DIRECTORY), upstream_factory)

        ssh_acceptor = ThreadedSSHAcceptor(
            config.listen_host,
            config.listen_port,
            host_keys,
            server_factory,
        )

        control_server = None
        if config.control_shared_secret:
            control_service = self._control_service
            if control_service is None:
                control_service = GatewayControlService(
                    config.control_shared_secret,
                    USER_DIRECTORY,
                    server_factory.disconnect_user,
                )
            control_server = await asyncio.start_server(
                control_service.handle_client,
                config.control_listen_host,
                config.control_listen_port,
            )

        return ProxyListeners(ssh_acceptor, control_server)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Paramiko SSH transport proxy")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default=2222, type=int)
    parser.add_argument(
        "--server-host-key", default=str(DEFAULT_SERVER_HOST_KEY), help="Path to the proxy SSH host private key"
    )
    parser.add_argument("--control-listen-host", default="0.0.0.0")
    parser.add_argument("--control-listen-port", default=2223, type=int)
    parser.add_argument(
        "--control-shared-secret",
        required=True,
        help="Shared secret used to encrypt and authenticate control channel messages.",
    )
    parser.add_argument("--upstream-client-key", required=True)
    parser.add_argument("--upstream-known-hosts", default="", help="Ignored. Upstream host keys are always trusted.")
    parser.add_argument("--upstream-connect-timeout", default=DEFAULT_CONNECT_TIMEOUT, type=int)
    return parser.parse_args(argv)


async def serve(
    listen_host: str = "0.0.0.0",
    listen_port: int = 2222,
    server_host_key: str = str(DEFAULT_SERVER_HOST_KEY),
    *,
    control_listen_host: str = "0.0.0.0",
    control_listen_port: int = 2223,
    control_shared_secret: str = "",
    upstream_client_key: str = "",
    upstream_known_hosts: str = "",
    upstream_connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> ProxyListeners:
    config = ListenerConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        server_host_key=server_host_key,
        control_listen_host=control_listen_host,
        control_listen_port=control_listen_port,
        control_shared_secret=control_shared_secret,
        upstream_client_key=upstream_client_key,
        upstream_known_hosts=upstream_known_hosts,
        upstream_connect_timeout=upstream_connect_timeout,
    )
    return await ProxyApplication().serve(config)


async def run(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    listeners = await ProxyApplication().serve(
        ListenerConfig(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            server_host_key=args.server_host_key,
            control_listen_host=args.control_listen_host,
            control_listen_port=args.control_listen_port,
            control_shared_secret=args.control_shared_secret,
            upstream_client_key=args.upstream_client_key,
            upstream_known_hosts=args.upstream_known_hosts,
            upstream_connect_timeout=args.upstream_connect_timeout,
        )
    )
    LOG.info("SSH listener on %s:%s", args.listen_host, listeners.get_port())
    control_port = listeners.get_control_port()
    if control_port is not None:
        LOG.info("control listener on %s:%s", args.control_listen_host, control_port)
    await listeners.wait_closed()


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


__all__ = ["DEFAULT_SERVER_HOST_KEY", "ListenerConfig", "ProxyApplication", "ProxyListeners", "main", "serve"]


def main(argv: list[str] | None = None) -> None:
    configure_logging()
    asyncio.run(run(argv))


if __name__ == "__main__":
    main()
