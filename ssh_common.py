from __future__ import annotations

import logging
import socket
import threading
from typing import Protocol


LOG = logging.getLogger(__name__)
SESSION_CHANNEL_WINDOW = 8 * 1024 * 1024
CHANNEL_READ_SIZE = 65536
CHANNEL_IO_TIMEOUT = 0.5


class SupportsChannelIO(Protocol):
    def close(self) -> None: ...

    def settimeout(self, timeout: float | None) -> None: ...

    def shutdown_write(self) -> None: ...


def configure_channel_timeout(channel: SupportsChannelIO, timeout: float = CHANNEL_IO_TIMEOUT) -> None:
    try:
        channel.settimeout(timeout)
    except Exception:
        LOG.debug("failed to configure channel timeout", exc_info=True)


def close_channel_quietly(channel: SupportsChannelIO | None) -> None:
    if channel is None:
        return
    try:
        channel.close()
    except Exception:
        LOG.debug("channel close failed", exc_info=True)


def shutdown_write_quietly(channel: SupportsChannelIO | None) -> None:
    if channel is None:
        return
    try:
        channel.shutdown_write()
    except Exception:
        LOG.debug("channel shutdown_write failed", exc_info=True)


def close_transport_quietly(transport) -> None:
    if transport is None:
        return
    try:
        transport.close()
    except Exception:
        LOG.debug("transport close failed", exc_info=True)


def close_socket_quietly(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        LOG.debug("socket close failed", exc_info=True)


def send_bytes(channel, data: bytes, *, stderr: bool = False) -> bool:
    sender = channel.send_stderr if stderr else channel.send
    view = memoryview(data)

    while view:
        try:
            sent = sender(view)
        except socket.timeout:
            continue
        except Exception:
            return False

        if sent <= 0:
            return False

        view = view[sent:]

    return True


def pump_bytes(
    source,
    destination,
    *,
    recv_stderr: bool = False,
    send_stderr: bool = False,
    stop_event: threading.Event | None = None,
) -> None:
    receiver = source.recv_stderr if recv_stderr else source.recv

    while stop_event is None or not stop_event.is_set():
        try:
            chunk = receiver(CHANNEL_READ_SIZE)
        except socket.timeout:
            continue
        except Exception:
            break

        if not chunk:
            break

        if not send_bytes(destination, chunk, stderr=send_stderr):
            break
