from __future__ import annotations

from pathlib import Path

import asyncssh
from user_auth import UserRecord


DEFAULT_CONNECT_TIMEOUT = 10


class UpstreamConnectionFactory:
    def __init__(self, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT):
        self._connect_timeout = connect_timeout

    async def connect(self, username: str, user: UserRecord) -> asyncssh.SSHClientConnection:
        client_key_path = Path(user.client_key_path).expanduser()
        known_hosts_path = Path(user.known_hosts_path).expanduser()

        return await asyncssh.connect(
            user.upstream_host,
            user.upstream_port,
            username=username,
            client_keys=[str(client_key_path)],
            known_hosts=str(known_hosts_path),
            config=None,
            public_key_auth=True,
            password_auth=False,
            kbdint_auth=False,
            agent_path="",
            connect_timeout=self._connect_timeout,
            encoding=None,
        )
