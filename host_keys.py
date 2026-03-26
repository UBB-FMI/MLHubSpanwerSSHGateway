from __future__ import annotations

import os
from pathlib import Path

import asyncssh


class ServerHostKeyManager:
    def __init__(self, base_path: str | os.PathLike[str]):
        self._base_path = Path(base_path)

    def ensure_host_keys(self) -> list[Path]:
        ed25519_path = self._ensure_host_key(self._base_path, "ssh-ed25519")
        rsa_path = self._ensure_host_key(Path(f"{ed25519_path}.rsa"), "ssh-rsa")
        return [ed25519_path, rsa_path]

    def _ensure_host_key(self, path: Path, algorithm: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            key = asyncssh.generate_private_key(algorithm)
            path.write_bytes(key.export_private_key())
            os.chmod(path, 0o600)
        return path
