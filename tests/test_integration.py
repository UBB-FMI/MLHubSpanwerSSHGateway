from __future__ import annotations

import asyncio
import socket
import subprocess
import time
from contextlib import closing
from pathlib import Path

import asyncssh
import pytest

from conftest import send_control_request


def allocate_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_ssh_exec_succeeds(
    proxy_server,
    proxy_openssh_env,
    openssh_common_args,
    target_server,
) -> None:
    completed = subprocess.run(
        [
            "ssh",
            *openssh_common_args,
            f"{proxy_server.host}",
            "cat",
            str(target_server.data_file),
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert target_server.data_file.read_text() == completed.stdout


@pytest.mark.asyncio
async def test_bad_password_rejected(proxy_server) -> None:
    with pytest.raises(asyncssh.PermissionDenied):
        await asyncssh.connect(
            proxy_server.host,
            proxy_server.port,
            username=proxy_server.username,
            password="wrong-password",
            known_hosts=None,
            public_key_auth=False,
            kbdint_auth=False,
        )


@pytest.mark.asyncio
async def test_unknown_username_is_closed_immediately(proxy_server) -> None:
    with pytest.raises((asyncssh.PermissionDenied, asyncssh.DisconnectError, ConnectionResetError, OSError)):
        await asyncssh.connect(
            proxy_server.host,
            proxy_server.port,
            username="md5_unknown",
            password="wrong-password",
            known_hosts=None,
            public_key_auth=False,
            kbdint_auth=False,
        )


def test_sftp_downloads_file(
    tmp_path: Path,
    proxy_server,
    proxy_openssh_env,
    target_server,
) -> None:
    download_dir = tmp_path / "download"
    download_dir.mkdir()

    completed = subprocess.run(
        [
            "sftp",
            "-P",
            str(proxy_server.port),
            "-o",
            f"User={proxy_server.username}",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{proxy_server.host}:{target_server.data_file}",
            str(download_dir),
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )

    downloaded = download_dir / target_server.data_file.name
    assert completed.returncode == 0, completed.stderr
    assert downloaded.read_text() == target_server.data_file.read_text()


def test_rsync_transfers_file(
    tmp_path: Path,
    proxy_server,
    proxy_openssh_env,
    target_server,
) -> None:
    download_dir = tmp_path / "rsync"
    download_dir.mkdir()
    ssh_cmd = (
        f"ssh -p {proxy_server.port} "
        f"-o User={proxy_server.username} "
        "-o PreferredAuthentications=password "
        "-o PubkeyAuthentication=no "
        "-o NumberOfPasswordPrompts=1 "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null"
    )

    completed = subprocess.run(
        [
            "rsync",
            "-e",
            ssh_cmd,
            f"{proxy_server.host}:{target_server.data_file}",
            str(download_dir / ""),
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )

    downloaded = download_dir / target_server.data_file.name
    assert completed.returncode == 0, completed.stderr
    assert downloaded.read_text() == target_server.data_file.read_text()


def test_local_port_forwarding(
    proxy_server,
    proxy_openssh_env,
    openssh_common_args,
    http_server,
) -> None:
    _, http_port = http_server
    local_port = allocate_port()
    proc = subprocess.Popen(
        [
            "ssh",
            *openssh_common_args,
            "-L",
            f"{local_port}:127.0.0.1:{http_port}",
            "-N",
            proxy_server.host,
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with subprocess.Popen(
                    ["curl", "-fsS", f"http://127.0.0.1:{local_port}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ) as curl_proc:
                    stdout, _ = curl_proc.communicate(timeout=2)
                    if curl_proc.returncode == 0:
                        assert "forwarded http ok" in stdout
                        return
            except subprocess.TimeoutExpired:
                pass

            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read())
            time.sleep(0.2)
        raise AssertionError("local forwarded port never became reachable")
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_remote_port_forwarding(
    proxy_server,
    proxy_openssh_env,
    openssh_common_args,
    http_server,
) -> None:
    _, http_port = http_server
    remote_port = allocate_port()
    forward_proc = subprocess.Popen(
        [
            "ssh",
            *openssh_common_args,
            "-R",
            f"127.0.0.1:{remote_port}:127.0.0.1:{http_port}",
            "-N",
            proxy_server.host,
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            remote_cmd = (
                'python3 -c "import urllib.request; '
                f"print(urllib.request.urlopen('http://127.0.0.1:{remote_port}', timeout=2).read().decode())"
                '"'
            )
            completed = subprocess.run(
                [
                    "ssh",
                    *openssh_common_args,
                    proxy_server.host,
                    remote_cmd,
                ],
                env=proxy_openssh_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
                check=False,
            )
            if completed.returncode == 0 and "forwarded http ok" in completed.stdout:
                return

            if forward_proc.poll() is not None:
                raise AssertionError(forward_proc.stderr.read())
            time.sleep(0.5)
        raise AssertionError("remote forwarded port never became reachable")
    finally:
        forward_proc.terminate()
        forward_proc.wait(timeout=5)


@pytest.mark.asyncio
async def test_multiple_channels_share_one_connection(proxy_server) -> None:
    async with asyncssh.connect(
        proxy_server.host,
        proxy_server.port,
        username=proxy_server.username,
        password=proxy_server.password,
        known_hosts=None,
        public_key_auth=False,
        kbdint_auth=False,
    ) as conn:
        first, second = await asyncio.gather(
            conn.run("printf first", check=True),
            conn.run("printf second", check=True),
        )

    assert first.stdout == "first"
    assert second.stdout == "second"


def test_unregister_rejects_new_auth(proxy_server, proxy_openssh_env) -> None:
    response = send_control_request(
        proxy_server.host,
        proxy_server.control_port,
        {
            "secret": proxy_server.control_secret,
            "action": "unregister",
            "username": proxy_server.username,
        },
    )
    assert response == {"ok": True}

    completed = subprocess.run(
        [
            "ssh",
            "-p",
            str(proxy_server.port),
            "-o",
            f"User={proxy_server.username}",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            proxy_server.host,
            "true",
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode != 0


def test_unregister_drops_forwarded_connections(
    proxy_server,
    proxy_openssh_env,
    openssh_common_args,
    http_server,
) -> None:
    _, http_port = http_server
    local_port = allocate_port()
    proc = subprocess.Popen(
        [
            "ssh",
            *openssh_common_args,
            "-L",
            f"{local_port}:127.0.0.1:{http_port}",
            "-N",
            proxy_server.host,
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            completed = subprocess.run(
                ["curl", "-fsS", f"http://127.0.0.1:{local_port}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
            if completed.returncode == 0 and "forwarded http ok" in completed.stdout:
                break
            if proc.poll() is not None:
                raise AssertionError(proc.stderr.read())
            time.sleep(0.2)
        else:
            raise AssertionError("local forwarded port never became reachable")

        response = send_control_request(
            proxy_server.host,
            proxy_server.control_port,
            {
                "secret": proxy_server.control_secret,
                "action": "unregister",
                "username": proxy_server.username,
            },
        )
        assert response == {"ok": True}

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            completed = subprocess.run(
                ["curl", "-fsS", f"http://127.0.0.1:{local_port}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
            if completed.returncode != 0:
                return
            if proc.poll() is not None:
                return
            time.sleep(0.2)
        raise AssertionError("forwarded port stayed reachable after unregister")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
