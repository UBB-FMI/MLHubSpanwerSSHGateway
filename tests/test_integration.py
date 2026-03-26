from __future__ import annotations

import socket
import subprocess
import threading
import time
from contextlib import closing
from pathlib import Path

import paramiko
import pytest

from conftest import send_control_request


def allocate_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _connect_paramiko(proxy_server) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        proxy_server.host,
        port=proxy_server.port,
        username=proxy_server.username,
        password=proxy_server.password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )
    return client


def _read_until(channel: paramiko.Channel, marker: str, timeout: float = 5.0) -> str:
    chunks: list[str] = []
    deadline = time.monotonic() + timeout
    channel.settimeout(0.2)

    while time.monotonic() < deadline:
        try:
            chunk = channel.recv(4096)
        except socket.timeout:
            continue

        if not chunk:
            raise AssertionError(f"stream closed before marker {marker!r} was seen; received={''.join(chunks)!r}")

        chunks.append(chunk.decode("utf-8", errors="replace"))
        joined = "".join(chunks)
        if marker in joined:
            return joined

    raise AssertionError(f"timed out waiting for marker {marker!r}; received={''.join(chunks)!r}")


def _send_all(channel: paramiko.Channel, data: bytes) -> None:
    view = memoryview(data)
    channel.settimeout(0.2)

    while view:
        try:
            sent = channel.send(view)
        except socket.timeout:
            continue

        if sent <= 0:
            raise BrokenPipeError("channel closed while sending")

        view = view[sent:]


def _run_transport_command(
    transport: paramiko.Transport,
    command: str,
    *,
    term_type: str | None = None,
) -> tuple[str, str, int]:
    channel = transport.open_session()
    channel.settimeout(0.2)
    if term_type is not None:
        channel.get_pty(term=term_type)
    channel.exec_command(command)

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    while True:
        drained = False

        while channel.recv_ready():
            stdout_chunks.append(channel.recv(65536))
            drained = True

        while channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(65536))
            drained = True

        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break

        if not drained:
            time.sleep(0.01)

    exit_status = channel.recv_exit_status()
    channel.close()
    return (
        b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        exit_status,
    )


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


def test_bad_password_rejected(proxy_server) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with pytest.raises(paramiko.AuthenticationException):
        client.connect(
            proxy_server.host,
            port=proxy_server.port,
            username=proxy_server.username,
            password="wrong-password",
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )


def test_unknown_username_is_closed_immediately(proxy_server) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    with pytest.raises((paramiko.AuthenticationException, paramiko.SSHException, EOFError, ConnectionResetError, OSError)):
        client.connect(
            proxy_server.host,
            port=proxy_server.port,
            username="md5_unknown",
            password="wrong-password",
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
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


def test_multiple_channels_share_one_connection(proxy_server) -> None:
    client = _connect_paramiko(proxy_server)
    try:
        transport = client.get_transport()
        assert transport is not None

        first_channel = transport.open_session()
        second_channel = transport.open_session()
        first_channel.exec_command("printf first")
        second_channel.exec_command("printf second")

        first = first_channel.recv(64).decode("utf-8", errors="replace")
        second = second_channel.recv(64).decode("utf-8", errors="replace")
        assert first_channel.recv_exit_status() == 0
        assert second_channel.recv_exit_status() == 0
        assert first == "first"
        assert second == "second"
    finally:
        client.close()


def test_interactive_shell_survives_parallel_execs(proxy_server) -> None:
    client = _connect_paramiko(proxy_server)
    try:
        transport = client.get_transport()
        assert transport is not None

        shell = transport.open_session()
        shell.get_pty(term="xterm")
        shell.invoke_shell()

        ready_marker = f"shell-ready-{time.time_ns()}"
        shell.send(f"printf '{ready_marker}\\n'\n")
        assert ready_marker in _read_until(shell, ready_marker)

        first_result: list[tuple[str, str, int]] = []
        second_result: list[tuple[str, str, int]] = []

        def run_first() -> None:
            first_result.append(_run_transport_command(transport, "printf first", term_type="xterm"))

        def run_second() -> None:
            second_result.append(_run_transport_command(transport, "printf second", term_type="xterm"))

        first_thread = threading.Thread(target=run_first, daemon=True)
        second_thread = threading.Thread(target=run_second, daemon=True)
        first_thread.start()
        second_thread.start()
        first_thread.join(timeout=10)
        second_thread.join(timeout=10)

        assert first_result == [("first", "", 0)]
        assert second_result == [("second", "", 0)]

        after_marker = f"shell-after-{time.time_ns()}"
        shell.send(f"printf '{after_marker}\\n'\nexit\n")
        shell_output = _read_until(shell, after_marker)
        assert after_marker in shell_output
        assert shell.recv_exit_status() == 0
    finally:
        client.close()


def test_late_client_stdin_after_exec_exit_does_not_drop_connection(proxy_server) -> None:
    client = _connect_paramiko(proxy_server)
    try:
        transport = client.get_transport()
        assert transport is not None

        channel = transport.open_session()
        channel.settimeout(0.2)
        channel.get_pty(term="xterm")
        channel.exec_command("sleep 0.05")

        try:
            for _ in range(64):
                _send_all(channel, ("runner-upload-data\n" * 128).encode("utf-8"))
                time.sleep(0.01)
        except (BrokenPipeError, EOFError, OSError):
            pass
        finally:
            try:
                channel.shutdown_write()
            except Exception:
                pass

        assert channel.recv_exit_status() == 0

        stdout, _, status = _run_transport_command(transport, "printf still-alive", term_type="xterm")
        assert status == 0
        assert stdout == "still-alive"
    finally:
        client.close()


def test_binary_upload_survives_parallel_probe_channels(proxy_server) -> None:
    remote_path = f"/tmp/proxy-parallel-upload-{time.time_ns()}.bin"
    payload = (bytes(range(256)) * 8192)[:1_572_864]
    client = _connect_paramiko(proxy_server)
    try:
        transport = client.get_transport()
        assert transport is not None

        upload_channel = transport.open_session()
        upload_channel.settimeout(0.2)
        upload_channel.exec_command(f"dd of={remote_path} status=none")
        upload_error: list[BaseException] = []

        def upload() -> None:
            try:
                chunk_size = 65536
                for offset in range(0, len(payload), chunk_size):
                    _send_all(upload_channel, payload[offset : offset + chunk_size])
                    if offset == 262144:
                        time.sleep(0.1)
                upload_channel.shutdown_write()
            except BaseException as exc:  # noqa: BLE001
                upload_error.append(exc)

        upload_thread = threading.Thread(target=upload, daemon=True)
        upload_thread.start()
        time.sleep(0.05)

        uname_stdout, _, uname_status = _run_transport_command(
            transport,
            "/bin/sh -c 'uname -s || uname -o && uname -m'",
        )
        _, _, cmd_status = _run_transport_command(
            transport,
            'cmd /c "set OS & set PROCESSOR_ARCHITECTURE"',
        )

        upload_thread.join(timeout=10)
        assert not upload_thread.is_alive()
        assert not upload_error, upload_error[0] if upload_error else None
        assert upload_channel.recv_exit_status() == 0
        assert uname_status == 0
        assert uname_stdout.strip().startswith("Linux")
        assert cmd_status == 127

        size_stdout, _, size_status = _run_transport_command(transport, f"wc -c < {remote_path}")
        assert size_status == 0
        assert int(size_stdout.strip()) == len(payload)
    finally:
        client.close()


def test_large_binary_upload_crosses_window_with_parallel_probe_channels(proxy_server) -> None:
    remote_path = f"/tmp/proxy-large-parallel-upload-{time.time_ns()}.bin"
    payload = (bytes(range(256)) * 12288)[:2_621_440]
    client = _connect_paramiko(proxy_server)
    try:
        transport = client.get_transport()
        assert transport is not None

        upload_channel = transport.open_session()
        upload_channel.settimeout(0.2)
        upload_channel.exec_command(f"dd of={remote_path} status=none")
        upload_error: list[BaseException] = []

        def upload() -> None:
            try:
                chunk_size = 65536
                for offset in range(0, len(payload), chunk_size):
                    _send_all(upload_channel, payload[offset : offset + chunk_size])
                    if offset in {262144, 1310720}:
                        time.sleep(0.1)
                upload_channel.shutdown_write()
            except BaseException as exc:  # noqa: BLE001
                upload_error.append(exc)

        upload_thread = threading.Thread(target=upload, daemon=True)
        upload_thread.start()
        time.sleep(0.05)

        uname_stdout, _, uname_status = _run_transport_command(
            transport,
            "/bin/sh -c 'uname -s || uname -o && uname -m'",
        )
        _, _, cmd_status = _run_transport_command(
            transport,
            'cmd /c "set OS & set PROCESSOR_ARCHITECTURE"',
        )

        upload_thread.join(timeout=15)
        assert not upload_thread.is_alive()
        assert not upload_error, upload_error[0] if upload_error else None
        assert upload_channel.recv_exit_status() == 0
        assert uname_status == 0
        assert uname_stdout.strip().startswith("Linux")
        assert cmd_status == 127

        size_stdout, _, size_status = _run_transport_command(transport, f"wc -c < {remote_path}")
        assert size_status == 0
        assert int(size_stdout.strip()) == len(payload)
    finally:
        client.close()


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
