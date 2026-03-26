from __future__ import annotations

import logging

from asyncssh.channel import MSG_CHANNEL_EOF, ProtocolError, SSHChannel
from asyncssh.packet import SSHPacket


LOG = logging.getLogger(__name__)
_PATCHED = False
_ORIGINAL_PROCESS_EOF = SSHChannel._process_eof


def _process_eof_allow_duplicate(
    self: SSHChannel,
    pkttype: int,
    pktid: int,
    packet: SSHPacket,
) -> None:
    if self._recv_state != "open":
        if self._recv_state in {"eof_pending", "eof", "close_pending", "closed"}:
            packet.check_end()
            debug = getattr(self.logger, "debug1", self.logger.debug)
            debug("Ignoring duplicate EOF")
            return
        raise ProtocolError("Channel not open for sending")

    _ORIGINAL_PROCESS_EOF(self, pkttype, pktid, packet)


def install_asyncssh_compat_patches() -> None:
    global _PATCHED

    if _PATCHED:
        return

    SSHChannel._process_eof = _process_eof_allow_duplicate
    SSHChannel._packet_handlers = {
        **SSHChannel._packet_handlers,
        MSG_CHANNEL_EOF: _process_eof_allow_duplicate,
    }
    _PATCHED = True
    LOG.debug("installed AsyncSSH compatibility patches")


__all__ = ["install_asyncssh_compat_patches"]
