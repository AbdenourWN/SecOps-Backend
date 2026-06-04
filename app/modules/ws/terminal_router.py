"""
Dedicated streaming terminal WebSocket endpoint.

  WS /api/ws/servers/{server_id}/terminal

One connection per browser tab. One active command per connection.
Guardrails (block list, confirm list, rate limit, hygiene, timeout) are
enforced inside ServerService.stream_command — unchanged from the HTTP path.

Auth (Phase 20.1): the connection is authenticated from the access-token cookie
before the upgrade — it requires a valid session, an operator/admin role (viewers
cannot run commands), and access to THIS server. The principal is the
authenticated user id.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.auth import ACCESS_COOKIE, authenticate_access_token
from app.core.constants import UserRole
from app.modules.servers.service import ServerService

logger = logging.getLogger(__name__)
router = APIRouter()
_service = ServerService()


@router.websocket("/ws/servers/{server_id}/terminal")
async def terminal_ws(websocket: WebSocket, server_id: str):
    # Authenticate + authorize before accepting (Phase 20.1). Terminal = command
    # execution, so it requires a valid session, operator/admin role, and access
    # to this specific server.
    user = await authenticate_access_token(websocket.cookies.get(ACCESS_COOKIE))
    if user is None:
        await websocket.close(code=4401)  # unauthenticated
        return
    if not (user.is_admin or user.role == UserRole.OPERATOR.value):
        await websocket.close(code=4403)  # viewers cannot run commands
        return
    if not user.can_access_server(server_id):
        await websocket.close(code=4403)  # not authorized for this server
        return

    await websocket.accept()

    # Per-connection state
    active_abort_event: Optional[asyncio.Event] = None
    active_stdin_queue: Optional[asyncio.Queue] = None
    active_task: Optional[asyncio.Task] = None
    principal: str = user.id

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

        # Principal is the cookie-authenticated user; the frame is kept for
        # protocol compatibility (its token is no longer trusted).
        await _send({"type": "auth_ok", "principal": principal, "username": user.username})

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
