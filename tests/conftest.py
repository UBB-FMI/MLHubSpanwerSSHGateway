from __future__ import annotations

import asyncio
import getpass
import os
import socket
import stat
import subprocess
import textwrap
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pytest

from app import serve
from control_crypto import ControlCryptoError, EncryptedControlCodec
import user_auth


def allocate_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                return

        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out waiting for {host}:{port}")
        time.sleep(0.05)


def write_askpass_script(tmp_path: Path, password: str) -> Path:
    script_path = tmp_path / "askpass.sh"
    script_path.write_text(f"#!/bin/sh\nprintf '%s\\n' {password!r}\n")
    script_path.chmod(script_path.stat().st_mode | stat.S_IXUSR)
    return script_path


def openssh_password_env(tmp_path: Path, password: str) -> dict[str, str]:
    askpass = write_askpass_script(tmp_path, password)
    env = os.environ.copy()
    env.update(
        {
            "DISPLAY": "test-askpass",
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
        }
    )
    return env


def known_hosts_line(host: str, port: int, host_key_path: Path) -> str:
    public_key = subprocess.check_output(
        ["ssh-keygen", "-y", "-f", str(host_key_path)],
        text=True,
    ).strip()
    return f"[{host}]:{port} {public_key}\n"


def run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 20.0,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    return completed


def send_control_request(host: str, port: int, payload: dict[str, object], timeout: float = 5.0) -> dict[str, object]:
    secret = payload.get("secret")
    if not isinstance(secret, str) or not secret:
        raise AssertionError("control request payload must include a non-empty secret")

    codec = EncryptedControlCodec(secret)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(codec.encode(payload))
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while not response.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    if not response:
        raise AssertionError("control server returned no response")
    try:
        return codec.decode(response)
    except ControlCryptoError:
        return codec.decode_plaintext(response, description="control response")


@dataclass(frozen=True, slots=True)
class TargetServer:
    host: str
    port: int
    username: str
    host_key_path: Path
    client_key_path: Path
    data_file: Path


@dataclass(frozen=True, slots=True)
class ProxyServer:
    host: str
    port: int
    host_key_path: Path
    username: str
    password: str
    control_port: int
    control_secret: str


class ProxyRunner:
    def __init__(
        self,
        host: str,
        port: int,
        host_key_path: Path,
        control_host: str,
        control_port: int,
        control_secret: str,
        upstream_client_key: Path,
        upstream_known_hosts: Path,
    ):
        self._host = host
        self._port = port
        self._host_key_path = host_key_path
        self._control_host = control_host
        self._control_port = control_port
        self._control_secret = control_secret
        self._upstream_client_key = upstream_client_key
        self._upstream_known_hosts = upstream_known_hosts
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._error: Exception | None = None
        self._acceptor = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="proxy-server", daemon=True)
        self._thread.start()
        if not self._started.wait(timeout=10):
            raise TimeoutError("proxy server thread did not start")
        if self._error is not None:
            raise self._error

    def stop(self) -> None:
        if self._loop is None:
            return
        self._loop.call_soon_threadsafe(self._stop_now)

        if self._thread is not None:
            self._thread.join(timeout=10)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._acceptor = self._loop.run_until_complete(
                serve(
                    self._host,
                    self._port,
                    str(self._host_key_path),
                    control_listen_host=self._control_host,
                    control_listen_port=self._control_port,
                    control_shared_secret=self._control_secret,
                    upstream_client_key=str(self._upstream_client_key),
                    upstream_known_hosts=str(self._upstream_known_hosts),
                )
            )
        except Exception as exc:
            self._error = exc
            self._started.set()
            self._loop.close()
            return

        self._started.set()
        self._loop.run_forever()
        if self._acceptor is not None:
            self._acceptor.close()
        self._loop.close()

    def _stop_now(self) -> None:
        if self._acceptor is not None:
            self._acceptor.close()
        assert self._loop is not None
        self._loop.stop()


@pytest.fixture(autouse=True)
def clear_runtime_users() -> None:
    user_auth.clear_users()
    yield
    user_auth.clear_users()


@pytest.fixture()
def current_username() -> str:
    return getpass.getuser()


@pytest.fixture()
def target_server(tmp_path: Path, current_username: str) -> TargetServer:
    host = "127.0.0.1"
    port = allocate_port()
    host_key_path = tmp_path / "target_host_key"
    client_key_path = tmp_path / "proxy_client_key"
    authorized_keys_path = tmp_path / "authorized_keys"
    sshd_config_path = tmp_path / "sshd_config"
    pid_path = tmp_path / "sshd.pid"
    data_file = tmp_path / "target-data.txt"
    data_file.write_text("transport proxy fixture data\n")

    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key_path)])
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(client_key_path)])

    authorized_keys_path.write_text((client_key_path.with_suffix(".pub")).read_text())
    authorized_keys_path.chmod(0o600)
    sshd_config_path.write_text(
        textwrap.dedent(
            f"""\
            Port {port}
            ListenAddress {host}
            HostKey {host_key_path}
            PidFile {pid_path}
            AuthorizedKeysFile {authorized_keys_path}
            PasswordAuthentication no
            PubkeyAuthentication yes
            ChallengeResponseAuthentication no
            KbdInteractiveAuthentication no
            PermitRootLogin no
            AllowUsers {current_username}
            UsePAM no
            StrictModes no
            AllowTcpForwarding yes
            GatewayPorts yes
            LogLevel VERBOSE
            Subsystem sftp internal-sftp
            """
        )
    )

    proc = subprocess.Popen(
        ["/usr/bin/sshd", "-D", "-e", "-f", str(sshd_config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        try:
            wait_port(host, port)
        except TimeoutError as exc:
            stderr = proc.stderr.read() if proc.stderr else ""
            raise TimeoutError(f"{exc}\nsshd stderr:\n{stderr}") from exc
        yield TargetServer(
            host=host,
            port=port,
            username=current_username,
            host_key_path=host_key_path,
            client_key_path=client_key_path,
            data_file=data_file,
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture()
def proxy_server(
    tmp_path: Path,
    target_server: TargetServer,
) -> ProxyServer:
    proxy_host = "127.0.0.1"
    proxy_port = allocate_port()
    control_port = allocate_port()
    proxy_host_key_path = tmp_path / "proxy_host_key"
    known_hosts_path = tmp_path / "known_hosts"
    username = target_server.username
    password = "wonderland"
    control_secret = "shared-control-secret"

    known_hosts_path.write_text(
        known_hosts_line(target_server.host, target_server.port, target_server.host_key_path)
    )

    runner = ProxyRunner(
        proxy_host,
        proxy_port,
        proxy_host_key_path,
        proxy_host,
        control_port,
        control_secret,
        target_server.client_key_path,
        known_hosts_path,
    )
    runner.start()
    try:
        wait_port(proxy_host, proxy_port)
        wait_port(proxy_host, control_port)
        response = send_control_request(
            proxy_host,
            control_port,
            {
                "secret": control_secret,
                "action": "register",
                "username": username,
                "password": password,
                "upstream_host": target_server.host,
                "upstream_port": target_server.port,
            },
        )
        assert response == {"ok": True}
        yield ProxyServer(
            host=proxy_host,
            port=proxy_port,
            host_key_path=proxy_host_key_path,
            username=username,
            password=password,
            control_port=control_port,
            control_secret=control_secret,
        )
    finally:
        runner.stop()


@pytest.fixture()
def proxy_openssh_env(tmp_path: Path, proxy_server: ProxyServer) -> dict[str, str]:
    return openssh_password_env(tmp_path, proxy_server.password)


@pytest.fixture()
def openssh_common_args(proxy_server: ProxyServer) -> list[str]:
    return [
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
    ]


@pytest.fixture()
def http_server(tmp_path: Path) -> tuple[subprocess.Popen[str], int]:
    port = allocate_port()
    docroot = tmp_path / "http"
    docroot.mkdir()
    (docroot / "index.html").write_text("forwarded http ok\n")

    proc = subprocess.Popen(
        ["python3", "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        cwd=docroot,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_port("127.0.0.1", port)
        yield proc, port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture(autouse=True)
def ensure_pythonpath(monkeypatch: pytest.MonkeyPatch) -> None:
    package_pythonpath = str(Path(__file__).resolve().parents[1] / "src")
    existing = os.environ.get("PYTHONPATH")
    if existing:
        monkeypatch.setenv("PYTHONPATH", f"{package_pythonpath}:{existing}")
    else:
        monkeypatch.setenv("PYTHONPATH", package_pythonpath)
