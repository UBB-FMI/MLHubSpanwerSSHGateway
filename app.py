from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from control import GatewayControlService
from host_keys import ServerHostKeyManager
from server import ProxyServerFactory
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


class ProxyListeners:
    def __init__(self, ssh_acceptor: asyncssh.SSHAcceptor, control_server: asyncio.AbstractServer | None = None):
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
        host_key_paths = ServerHostKeyManager(config.server_host_key).ensure_host_keys()

        server_factory = self._server_factory
        if server_factory is None:
            upstream_factory = UpstreamConnectionFactory(
                config.upstream_client_key,
                config.upstream_known_hosts,
                connect_timeout=config.upstream_connect_timeout,
            )
            server_factory = ProxyServerFactory(UserAuthenticator(USER_DIRECTORY), upstream_factory)

        ssh_acceptor = await asyncssh.create_server(
            server_factory.create,
            config.listen_host,
            config.listen_port,
            server_host_keys=[str(path) for path in host_key_paths],
            encoding=None,
            line_editor=False,
            password_auth=True,
            public_key_auth=False,
            kbdint_auth=False,
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
    parser = argparse.ArgumentParser(description="AsyncSSH SSH transport proxy")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default=2222, type=int)
    parser.add_argument(
        "--server-host-key", default=str(DEFAULT_SERVER_HOST_KEY), help="Path to the proxy SSH host private key"
    )
    parser.add_argument("--control-listen-host", default="0.0.0.0")
    parser.add_argument("--control-listen-port", default=2223, type=int)
    parser.add_argument("--control-shared-secret", required=True)
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
