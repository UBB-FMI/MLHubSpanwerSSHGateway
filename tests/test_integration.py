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


async def _read_until(reader: asyncssh.SSHReader[str], marker: str, timeout: float = 5.0) -> str:
    chunks: list[str] = []
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=deadline - time.monotonic())
        if not chunk:
            raise AssertionError(f"stream closed before marker {marker!r} was seen; received={''.join(chunks)!r}")
        chunks.append(chunk)
        joined = "".join(chunks)
        if marker in joined:
            return joined

    raise AssertionError(f"timed out waiting for marker {marker!r}; received={''.join(chunks)!r}")


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


def test_binary_exec_upload_with_stdin(
    tmp_path: Path,
    proxy_server,
    proxy_openssh_env,
    openssh_common_args,
    target_server,
) -> None:
    payload = bytes(range(256)) * 1024
    remote_path = f"/tmp/proxy-binary-upload-{int(time.time() * 1000)}.bin"

    completed = subprocess.run(
        [
            "ssh",
            *openssh_common_args,
            proxy_server.host,
            f"dd of={remote_path} status=none",
        ],
        env=proxy_openssh_env,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")

    download = subprocess.run(
        [
            "ssh",
            *openssh_common_args,
            proxy_server.host,
            f"cat {remote_path}",
        ],
        env=proxy_openssh_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )

    assert download.returncode == 0, download.stderr.decode("utf-8", errors="replace")
    if download.stdout != payload:
        first_diff = next(
            (
                index
                for index, (left, right) in enumerate(zip(download.stdout, payload))
                if left != right
            ),
            None,
        )
        raise AssertionError(
            "binary upload mismatch: "
            f"expected_len={len(payload)} actual_len={len(download.stdout)} first_diff={first_diff}"
        )


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


@pytest.mark.asyncio
async def test_interactive_shell_survives_parallel_execs(proxy_server) -> None:
    async with asyncssh.connect(
        proxy_server.host,
        proxy_server.port,
        username=proxy_server.username,
        password=proxy_server.password,
        known_hosts=None,
        public_key_auth=False,
        kbdint_auth=False,
    ) as conn:
        process = await conn.create_process(term_type="xterm", encoding="utf-8")

        ready_marker = f"shell-ready-{time.time_ns()}"
        process.stdin.write(f"printf '{ready_marker}\\n'\n")
        await process.stdin.drain()
        await _read_until(process.stdout, ready_marker)

        first, second = await asyncio.gather(
            conn.run("printf first", check=True, term_type="xterm"),
            conn.run("printf second", check=True, term_type="xterm"),
        )

        assert first.stdout == "first"
        assert second.stdout == "second"

        after_marker = f"shell-after-{time.time_ns()}"
        process.stdin.write(f"printf '{after_marker}\\n'\nexit\n")
        await process.stdin.drain()
        shell_output = await _read_until(process.stdout, after_marker)
        assert after_marker in shell_output

        await asyncio.wait_for(process.wait(), timeout=5)


@pytest.mark.asyncio
async def test_late_client_stdin_after_exec_exit_does_not_drop_connection(proxy_server) -> None:
    async with asyncssh.connect(
        proxy_server.host,
        proxy_server.port,
        username=proxy_server.username,
        password=proxy_server.password,
        known_hosts=None,
        public_key_auth=False,
        kbdint_auth=False,
    ) as conn:
        process = await conn.create_process("sleep 0.05", term_type="xterm", encoding="utf-8", send_eof=False)

        async def spam_stdin() -> None:
            try:
                for _ in range(64):
                    process.stdin.write("runner-upload-data\n" * 128)
                    await process.stdin.drain()
                    await asyncio.sleep(0.01)
            except (BrokenPipeError, ConnectionError, OSError):
                pass
            finally:
                try:
                    process.stdin.write_eof()
                except (BrokenPipeError, ConnectionError, OSError):
                    pass

        await asyncio.gather(spam_stdin(), process.wait())

        completed = await conn.run("printf still-alive", check=True, term_type="xterm")
        assert completed.stdout == "still-alive"


@pytest.mark.asyncio
async def test_binary_upload_survives_parallel_probe_channels(proxy_server) -> None:
    remote_path = f"/tmp/proxy-parallel-upload-{time.time_ns()}.bin"
    payload = (bytes(range(256)) * 8192)[:1_572_864]

    async with asyncssh.connect(
        proxy_server.host,
        proxy_server.port,
        username=proxy_server.username,
        password=proxy_server.password,
        known_hosts=None,
        public_key_auth=False,
        kbdint_auth=False,
    ) as conn:
        process = await conn.create_process(f"dd of={remote_path} status=none", encoding=None, send_eof=False)

        async def upload() -> None:
            chunk_size = 65536
            for offset in range(0, len(payload), chunk_size):
                process.stdin.write(payload[offset : offset + chunk_size])
                await process.stdin.drain()
                if offset == 262144:
                    await asyncio.sleep(0.1)
            process.stdin.write_eof()

        async def probes() -> tuple[asyncssh.SSHCompletedProcess, asyncssh.SSHCompletedProcess]:
            await asyncio.sleep(0.05)
            return await asyncio.gather(
                conn.run("/bin/sh -c 'uname -s || uname -o && uname -m'", check=True),
                conn.run('cmd /c "set OS & set PROCESSOR_ARCHITECTURE"', check=False),
            )

        (_, dd_result), (uname_result, cmd_result) = await asyncio.gather(
            asyncio.gather(upload(), process.wait(check=False)),
            probes(),
        )

        assert dd_result.exit_status == 0
        assert uname_result.stdout.strip().startswith("Linux")
        assert cmd_result.exit_status == 127

        size_result = await conn.run(f"wc -c < {remote_path}", check=True)
        assert int(size_result.stdout.strip()) == len(payload)


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
