"""
Dedicated streaming terminal WebSocket endpoint.

  WS /api/ws/servers/{server_id}/terminal

One connection per browser tab. One active command per connection.
Guardrails (block list, confirm list, rate limit, hygiene, timeout) are
enforced inside ServerService.stream_command — unchanged from the HTTP path.

Auth is stubbed for local dev (principal = "local-dev"). When P4.1 JWT lands,
replace the _resolve_principal() stub with a real token check.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.modules.servers.service import ServerService

logger = logging.getLogger(__name__)
router = APIRouter()
_service = ServerService()


def _resolve_principal(token: Optional[str]) -> str:
    """Auth stub — accepts any token, returns a fixed principal for now."""
    return "local-dev"


@router.websocket("/ws/servers/{server_id}/terminal")
async def terminal_ws(websocket: WebSocket, server_id: str):
    await websocket.accept()

    # Per-connection state
    active_abort_event: Optional[asyncio.Event] = None
    active_stdin_queue: Optional[asyncio.Queue] = None
    active_task: Optional[asyncio.Task] = None
    principal: str = "local-dev"

    async def _send(payload: dict):
        try:
            await websocket.send_text(json.dumps(payload))
        except Exception:
            pass

    # --- Handshake ---
    await _send({"type": "hello", "server_id": server_id, "protocol_version": 1})

    try:
        # Expect auth message first
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        msg = json.loads(raw)
        if msg.get("type") != "auth":
            await _send({"type": "error", "code": "auth_failed",
                         "message": "Expected auth message"})
            await websocket.close(code=4001)
            return

        principal = _resolve_principal(msg.get("token"))
        await _send({"type": "auth_ok", "principal": principal})

        # --- Message loop ---
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await _send({"type": "error", "code": "invalid_message",
                              "message": "JSON parse error"})
                continue

            action = msg.get("action")

            if action == "run":
                if active_task and not active_task.done():
                    await _send({"type": "error", "code": "already_running",
                                 "message": "A command is already running"})
                    continue

                command = msg.get("command", "")
                confirmed = bool(msg.get("confirmed", False))
                timeout_s = msg.get("timeout_s", 60)

                abort_event = asyncio.Event()
                stdin_queue: asyncio.Queue[str] = asyncio.Queue()
                active_abort_event = abort_event
                active_stdin_queue = stdin_queue

                async def _run_command(
                    cmd=command, conf=confirmed, t_s=timeout_s,
                    evt=abort_event, sq=stdin_queue,
                ):
                    nonlocal active_abort_event, active_task, active_stdin_queue
                    try:
                        async for event in _service.stream_command(
                            server_id,
                            cmd,
                            evt,
                            confirmed=conf,
                            timeout_s=t_s,
                            principal_id=principal,
                            stdin_queue=sq,
                        ):
                            await _send(event)
                    except Exception as exc:
                        logger.exception("terminal stream error: %s", exc)
                        await _send({"type": "error", "code": "internal",
                                     "message": str(exc)})
                    finally:
                        active_abort_event = None
                        active_stdin_queue = None
                        active_task = None

                active_task = asyncio.create_task(_run_command())

            elif action == "abort":
                if active_abort_event:
                    active_abort_event.set()
                else:
                    await _send({"type": "error", "code": "invalid_message",
                                 "message": "No command is running"})

            elif action == "input":
                data = msg.get("data", "")
                if active_stdin_queue and active_task and not active_task.done():
                    await active_stdin_queue.put(data)
                # Silently ignore if no command is running (race condition is normal)

            else:
                await _send({"type": "error", "code": "invalid_message",
                              "message": f"Unknown action: {action!r}"})

    except asyncio.TimeoutError:
        await _send({"type": "error", "code": "auth_failed",
                     "message": "Auth timeout"})
        await websocket.close(code=4001)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.exception("terminal_ws unhandled error: %s", exc)
    finally:
        # Signal abort to any running command so it can clean up and write audit.
        if active_abort_event:
            active_abort_event.set()
        if active_task and not active_task.done():
            try:
                await asyncio.wait_for(active_task, timeout=5)
            except (asyncio.TimeoutError, Exception):
                pass
