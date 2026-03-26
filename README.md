# MLHubSpawner SSH Gateway

This project is a small SSH proxy built with `asyncssh`.

It accepts inbound SSH connections on the gateway, validates the inbound username/password against an in-memory registry populated by `MLHubSpawner`, opens a second SSH connection to the registered upstream host using a configured private key, and then relays the SSH session and forwarding requests through that upstream connection.

## What It Does

- Listens for SSH connections, by default on `0.0.0.0:2222`
- Listens for control messages, by default on `0.0.0.0:2223`
- Authenticates inbound users with password auth only
- Keeps username/password/upstream-host mappings in memory only
- Connects upstream with public-key authentication
- Relays shell, exec, and subsystem sessions
- Relays PTY requests, environment variables, terminal resize events, EOF, and signals
- Supports direct TCP forwarding and reverse remote port forwarding
- Drops active SSH sessions and tunnels when a user is unregistered
- Auto-generates server host keys under `assets/` if they do not exist

## Requirements

- Python 3.10+
- A trusted `MLHubSpawner` instance able to reach the control port
- An upstream SSH server reachable from this machine
- A valid private key file used by the gateway for upstream connections

Install dependencies with:

```bash
python -m pip install -r requirements.txt
```

## Running

Start the proxy from the repository root:

```bash
python app.py \
  --control-shared-secret 'replace-me' \
  --upstream-client-key ~/.ssh/id_ed25519
```

Optional CLI arguments:

```bash
python app.py \
  --listen-host 0.0.0.0 \
  --listen-port 2222 \
  --server-host-key assets/server-host-key \
  --control-listen-host 0.0.0.0 \
  --control-listen-port 2223 \
  --control-shared-secret 'replace-me' \
  --upstream-client-key ~/.ssh/id_ed25519
```

Defaults:

- `--listen-host`: `0.0.0.0`
- `--listen-port`: `2222`
- `--server-host-key`: `assets/server-host-key`
- `--control-listen-host`: `0.0.0.0`
- `--control-listen-port`: `2223`

On first startup, the server creates:

- `assets/server-host-key`
- `assets/server-host-key.rsa`

## Control Channel

`MLHubSpawner` registers and unregisters users over a newline-delimited encrypted JSON TCP protocol.

Authenticated requests and responses are wrapped in an encrypted envelope:

```json
{"version":1,"nonce":"<base64 nonce>","ciphertext":"<base64 ciphertext>"}
```

The gateway and `MLHubSpawner` derive an AES-GCM key from `--control-shared-secret`, so the shared secret is used to both authenticate and encrypt the control traffic. Use a long random secret.

Malformed or unauthenticated requests receive a plaintext error response because the server cannot trust that the caller has the right key yet.

Encrypted register payload contents:

```json
{"secret":"shared-secret","action":"register","username":"md5_xxx","password":"OnlyLettersPasswordOnlyLettersAB","upstream_host":"10.0.0.5","upstream_port":22}
```

Encrypted unregister payload contents:

```json
{"secret":"shared-secret","action":"unregister","username":"md5_xxx"}
```

Decrypted success response contents:

```json
{"ok":true}
```

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
2. The proxy checks whether the username exists in the in-memory runtime registry.
3. If the username is unknown, the proxy closes the connection immediately.
4. If the username is known, the proxy validates the submitted password against the registered value.
5. The proxy connects to the registered upstream SSH server as the same username.
6. Session traffic and forwarding requests are relayed between the inbound and upstream connections.

## Files

- [`app.py`](./app.py): repo-root runner for `python app.py`
- [`app.py`](./app.py): SSH and control listener startup
- [`control.py`](./control.py): control-channel protocol handling
- [`server.py`](./server.py): inbound SSH auth flow and active connection tracking
- [`session.py`](./session.py): shell/exec/subsystem relay logic
- [`forwarding.py`](./forwarding.py): remote and direct TCP forwarding support
- [`upstream.py`](./upstream.py): upstream SSH connection factory
- [`user_auth.py`](./user_auth.py): runtime in-memory user registry
- [`host_keys.py`](./host_keys.py): host key generation and persistence

## Notes and Limitations

- User definitions are not persisted; gateway access is lost if the gateway or `MLHubSpawner` restarts.
- Passwords are stored in plaintext in process memory only.
- Inbound public-key authentication is not supported.
- This project does not currently load configuration from environment variables or a config file.
- This repo contains the gateway implementation only; deployment, systemd service setup, and firewalling are not included.
