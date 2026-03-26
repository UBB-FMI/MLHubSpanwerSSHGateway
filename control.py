from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping

from user_auth import UserDirectory, UserRecord


LOG = logging.getLogger(__name__)


class ControlRequestError(Exception):
    """Raised when an incoming control request is invalid."""


class GatewayControlService:
    def __init__(
        self,
        shared_secret: str,
        directory: UserDirectory,
        on_unregister: Callable[[str], Awaitable[None] | None],
    ):
        self._shared_secret = shared_secret
        self._directory = directory
        self._on_unregister = on_unregister

    async def handle_client(self, reader, writer) -> None:
        try:
            line = await reader.readline()
            payload = self._parse_request_line(line)
            response = await self.process_request(payload)
        except ControlRequestError as exc:
            response = {"ok": False, "error": str(exc)}
        except Exception:
            LOG.exception("unexpected control channel failure")
            response = {"ok": False, "error": "internal server error"}

        writer.write((json.dumps(response) + "\n").encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    def _parse_request_line(self, line: bytes) -> Mapping[str, object]:
        if not line:
            raise ControlRequestError("missing request payload")
        try:
            payload = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ControlRequestError(f"invalid JSON payload: {exc}") from exc
        if not isinstance(payload, dict):
            raise ControlRequestError("control payload must be a JSON object")
        return payload

    async def process_request(self, payload: Mapping[str, object]) -> dict[str, object]:
        if str(payload.get("secret", "")) != self._shared_secret:
            raise ControlRequestError("invalid shared secret")

        action = self._require_string(payload, "action")
        if action == "register":
            username = self._require_string(payload, "username")
            password = self._require_string(payload, "password")
            upstream_host = self._require_string(payload, "upstream_host")
            upstream_port = self._require_int(payload, "upstream_port")
            self._directory.register_user(
                username,
                UserRecord(password=password, upstream_host=upstream_host, upstream_port=upstream_port),
            )
            LOG.info("registered SSH gateway mapping for %s -> %s:%s", username, upstream_host, upstream_port)
            return {"ok": True}

        if action == "unregister":
            username = self._require_string(payload, "username")
            self._directory.unregister_user(username)
            maybe_awaitable = self._on_unregister(username)
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable
            LOG.info("unregistered SSH gateway mapping for %s", username)
            return {"ok": True}

        raise ControlRequestError(f"unsupported action: {action}")

    def _require_string(self, payload: Mapping[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            raise ControlRequestError(f"{key} must be a non-empty string")
        return value

    def _require_int(self, payload: Mapping[str, object], key: str) -> int:
        value = payload.get(key)
        if not isinstance(value, int):
            raise ControlRequestError(f"{key} must be an integer")
        return value
