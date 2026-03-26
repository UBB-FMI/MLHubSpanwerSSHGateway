from __future__ import annotations

import logging
from typing import cast

import asyncssh


LOG = logging.getLogger(__name__)


class ReverseTCPListener(asyncssh.SSHListener):
    """Wrap an upstream remote listener so AsyncSSH can return it to the client."""

    def __init__(self, upstream_listener: asyncssh.SSHListener):
        self._upstream_listener = upstream_listener

    def close(self) -> None:
        self._upstream_listener.close()

    async def wait_closed(self) -> None:
        await self._upstream_listener.wait_closed()

    def get_port(self) -> int:
        return self._upstream_listener.get_port()


class RemotePortForwarder:
    async def create_listener(self, inbound_conn: asyncssh.SSHServerConnection, upstream_conn: asyncssh.SSHClientConnection, listen_host: str, listen_port: int) -> asyncssh.SSHListener | bool:  # fmt: skip
        assigned_port = {"value": listen_port}

        async def session_factory(orig_host: str, orig_port: int) -> asyncssh.SSHForwarder:
            _, peer = await inbound_conn.create_connection(
                cast("asyncssh.SSHTCPSessionFactory[bytes]", asyncssh.SSHForwarder),
                listen_host,
                assigned_port["value"],
                orig_host,
                orig_port,
                encoding=None,
            )
            return asyncssh.SSHForwarder(cast(asyncssh.SSHForwarder, peer))

        try:
            upstream_listener = await upstream_conn.create_server(
                session_factory, listen_host, listen_port, encoding=None
            )
        except Exception as exc:
            LOG.exception(
                "failed to establish upstream remote forwarding listener on %s:%s: %s", listen_host, listen_port, exc
            )
            return False

        assigned_port["value"] = upstream_listener.get_port()
        LOG.info("forwarding remote TCP listener %s:%s through upstream", listen_host, assigned_port["value"])
        return ReverseTCPListener(upstream_listener)
