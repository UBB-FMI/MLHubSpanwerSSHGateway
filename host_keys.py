from __future__ import annotations

import os
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


class ServerHostKeyManager:
    def __init__(self, base_path: str | os.PathLike[str]):
        self._base_path = Path(base_path)

    def ensure_host_keys(self) -> list[Path]:
        ed25519_path = self._ensure_ed25519_key(self._base_path)
        rsa_path = self._ensure_rsa_key(Path(f"{ed25519_path}.rsa"))
        return [ed25519_path, rsa_path]

    def load_host_keys(self) -> list[paramiko.PKey]:
        ed25519_path, rsa_path = self.ensure_host_keys()
        return [
            paramiko.Ed25519Key.from_private_key_file(str(ed25519_path)),
            paramiko.RSAKey.from_private_key_file(str(rsa_path)),
        ]

    def _ensure_ed25519_key(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            key = ed25519.Ed25519PrivateKey.generate()
            path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.OpenSSH,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            os.chmod(path, 0o600)
        return path

    def _ensure_rsa_key(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path.write_bytes(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            os.chmod(path, 0o600)
        return path
