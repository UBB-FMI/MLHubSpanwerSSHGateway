from __future__ import annotations

import subprocess
from pathlib import Path

from host_keys import ServerHostKeyManager


def test_host_key_manager_generates_loadable_openssh_keys(tmp_path: Path) -> None:
    base_path = tmp_path / "server-host-key"
    manager = ServerHostKeyManager(base_path)

    paths = manager.ensure_host_keys()
    loaded = manager.load_host_keys()

    assert [path.name for path in paths] == ["server-host-key", "server-host-key.rsa"]
    assert len(loaded) == 2

    for path in paths:
        completed = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip()
