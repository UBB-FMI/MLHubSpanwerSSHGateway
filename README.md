# MLHubSpawner SSH Gateway

This project is a small SSH proxy built with `asyncssh`.

It accepts inbound SSH connections on the gateway, validates the inbound username/password against a local Python mapping, opens a second SSH connection to an upstream host using a configured private key, and then relays the SSH session and forwarding requests through that upstream connection.

## What It Does

- Listens for SSH connections, by default on `0.0.0.0:2222`
- Authenticates inbound users with password auth only
- Maps each allowed username to an upstream host and SSH key
- Connects upstream with public-key authentication
- Relays shell, exec, and subsystem sessions
- Relays PTY requests, environment variables, terminal resize events, EOF, and signals
- Supports direct TCP forwarding and reverse remote port forwarding
- Auto-generates server host keys under `assets/` if they do not exist

## Requirements

- Python 3.10+
- An upstream SSH server reachable from this machine
- A valid private key file for each configured user
- A valid `known_hosts` file for upstream host verification

Install dependencies with:

```bash
python -m pip install -r requirements.txt
```

## Running

Start the proxy from the repository root:

```bash
python app.py
```

Optional CLI arguments:

```bash
python app.py --listen-host 0.0.0.0 --listen-port 2222 --server-host-key assets/server-host-key
```

Defaults:

- `--listen-host`: `0.0.0.0`
- `--listen-port`: `2222`
- `--server-host-key`: `assets/server-host-key`

On first startup, the server creates:

- `assets/server-host-key`
- `assets/server-host-key.rsa`

## Configuration

User configuration lives directly in [`user_auth.py`](./user_auth.py).

Each entry in `USERS` defines:

- Inbound SSH password
- Upstream SSH host
- Upstream SSH port
- Path to the client private key used for the upstream connection
- Path to the `known_hosts` file used to verify the upstream server

Example shape:

```python
USERS = {
    "alice": UserRecord(
        password="replace-this",
        upstream_host="192.168.1.10",
        upstream_port=22,
        client_key_path="~/.ssh/id_ed25519",
        known_hosts_path="~/.ssh/known_hosts",
    ),
}
```

Before running, update the placeholder entries in `user_auth.py` to match your environment.

## Authentication Model

Inbound client to this proxy:

- Username/password authentication is enabled
- Public key auth is disabled
- Keyboard-interactive auth is disabled

Proxy to upstream server:

- Public key auth is enabled
- Password auth is disabled
- Keyboard-interactive auth is disabled
- SSH agent use is disabled
- SSH config loading is disabled

## How the Proxy Flow Works

1. A client connects to the proxy over SSH.
2. The proxy validates the username and password against `USERS`.
3. The proxy verifies that the configured private key and `known_hosts` files exist.
4. The proxy connects to the configured upstream SSH server as the same username.
5. Session traffic and forwarding requests are relayed between the inbound and upstream connections.

## Files

- [`app.py`](./app.py): CLI entrypoint and server startup
- [`server.py`](./server.py): inbound SSH server and authentication flow
- [`session.py`](./session.py): shell/exec/subsystem relay logic
- [`forwarding.py`](./forwarding.py): remote and direct TCP forwarding support
- [`upstream.py`](./upstream.py): upstream SSH connection factory
- [`user_auth.py`](./user_auth.py): local user directory and validation
- [`host_keys.py`](./host_keys.py): host key generation and persistence

## Notes and Limitations

- User definitions are currently hard-coded in Python.
- Passwords are stored in plaintext in `user_auth.py`.
- Inbound public-key authentication is not supported.
- This project does not currently load configuration from environment variables or a config file.
- This repo contains the gateway implementation only; deployment, systemd service setup, and firewalling are not included.
