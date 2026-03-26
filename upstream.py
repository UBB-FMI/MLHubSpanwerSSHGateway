from __future__ import annotations

from pathlib import Path

import asyncssh

from user_auth import UserRecord


DEFAULT_CONNECT_TIMEOUT = 10


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

    def _require_file(self, raw_path: str, description: str) -> Path:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"{description} does not exist or is not a file: {path}")
        return path

    async def connect(self, username: str, user: UserRecord) -> asyncssh.SSHClientConnection:
        return await asyncssh.connect(
            user.upstream_host,
            user.upstream_port,
            username=username,
            client_keys=[str(self._client_key_path)],
            known_hosts=None,
            config=None,
            public_key_auth=True,
            password_auth=False,
            kbdint_auth=False,
            agent_path="",
            connect_timeout=self._connect_timeout,
            encoding=None,
        )
