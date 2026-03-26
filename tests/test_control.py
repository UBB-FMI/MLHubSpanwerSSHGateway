from __future__ import annotations

import json
import socket

import user_auth

from conftest import send_control_request


def test_register_and_unregister_update_runtime_registry(proxy_server) -> None:
    response = send_control_request(
        proxy_server.host,
        proxy_server.control_port,
        {
            "secret": proxy_server.control_secret,
            "action": "register",
            "username": "md5_example",
            "password": "OnlyLettersPasswordOnlyLettersAB",
            "upstream_host": "10.0.0.15",
            "upstream_port": 22,
        },
    )

    assert response == {"ok": True}
    assert user_auth.get_user("md5_example").upstream_host == "10.0.0.15"

    response = send_control_request(
        proxy_server.host,
        proxy_server.control_port,
        {
            "secret": proxy_server.control_secret,
            "action": "unregister",
            "username": "md5_example",
        },
    )

    assert response == {"ok": True}
    assert "md5_example" not in user_auth.snapshot_users()


def test_control_rejects_bad_secret(proxy_server) -> None:
    response = send_control_request(
        proxy_server.host,
        proxy_server.control_port,
        {
            "secret": "wrong-secret",
            "action": "register",
            "username": "md5_example",
            "password": "OnlyLettersPasswordOnlyLettersAB",
            "upstream_host": "10.0.0.15",
            "upstream_port": 22,
        },
    )

    assert response["ok"] is False
    assert "invalid shared secret or encrypted payload" in response["error"]


def test_control_rejects_malformed_json(proxy_server) -> None:
    with socket.create_connection((proxy_server.host, proxy_server.control_port), timeout=5.0) as sock:
        sock.sendall(b'{"secret": "bad-json"\n')
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while not response.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    parsed = json.loads(response.decode("utf-8"))
    assert parsed["ok"] is False
    assert "invalid control envelope" in parsed["error"]


def test_control_rejects_plaintext_json_payload(proxy_server) -> None:
    plaintext_payload = {
        "secret": proxy_server.control_secret,
        "action": "register",
        "username": "md5_plaintext",
        "password": "OnlyLettersPasswordOnlyLettersAB",
        "upstream_host": "10.0.0.15",
        "upstream_port": 22,
    }

    with socket.create_connection((proxy_server.host, proxy_server.control_port), timeout=5.0) as sock:
        sock.sendall((json.dumps(plaintext_payload) + "\n").encode("utf-8"))
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while not response.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

    parsed = json.loads(response.decode("utf-8"))
    assert parsed["ok"] is False
    assert "plaintext control payloads are not supported" in parsed["error"]
