from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

import asyncssh
from host_keys import ServerHostKeyManager
from server import ProxyServerFactory


LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SERVER_HOST_KEY = PROJECT_ROOT / "assets" / "server-host-key"


@dataclass(frozen=True, slots=True)
class ListenerConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 2222
    server_host_key: str = str(DEFAULT_SERVER_HOST_KEY)


class ProxyApplication:
    def __init__(self, server_factory: ProxyServerFactory | None = None):
        self._server_factory = ProxyServerFactory() if server_factory is None else server_factory

    async def serve(self, config: ListenerConfig) -> asyncssh.SSHAcceptor:
        host_key_paths = ServerHostKeyManager(config.server_host_key).ensure_host_keys()
        return await asyncssh.create_server(
            self._server_factory.create,
            config.listen_host,
            config.listen_port,
            server_host_keys=[str(path) for path in host_key_paths],
            encoding=None,
            line_editor=False,
            password_auth=True,
            public_key_auth=False,
            kbdint_auth=False,
        )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AsyncSSH SSH transport proxy")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default=2222, type=int)
    parser.add_argument(
        "--server-host-key", default=str(DEFAULT_SERVER_HOST_KEY), help="Path to the proxy SSH host private key"
    )
    return parser.parse_args(argv)


async def serve(listen_host: str = "0.0.0.0", listen_port: int = 2222, server_host_key: str = str(DEFAULT_SERVER_HOST_KEY)) -> asyncssh.SSHAcceptor:  # fmt: skip
    config = ListenerConfig(listen_host=listen_host, listen_port=listen_port, server_host_key=server_host_key)
    return await ProxyApplication().serve(config)


async def run(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    server = await ProxyApplication().serve(ListenerConfig(args.listen_host, args.listen_port, args.server_host_key))
    LOG.info("listening on %s:%s", args.listen_host, server.get_port())
    await server.wait_closed()


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)


def main(argv: list[str] | None = None) -> None:
    configure_logging()
    asyncio.run(run(argv))


if __name__ == "__main__":
    main()
