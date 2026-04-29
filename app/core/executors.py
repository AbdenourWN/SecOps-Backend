from __future__ import annotations

import asyncio
import logging
import queue as _queue
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Dict, Any, Literal, Optional

import base64
import paramiko
import winrm
import winrm.protocol

logger = logging.getLogger(__name__)

# How recently the connection was used before we skip the liveness probe (seconds)
_LIVENESS_SKIP_WINDOW_S = 10.0

# Timeout constants used by run_command and all callers.
DEFAULT_COMMAND_TIMEOUT_S = 60
MAX_COMMAND_TIMEOUT_S = 300


# ---------------------------------------------------------------------------
# Streaming primitives
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    stream: Literal["stdout", "stderr"]
    data: str


@dataclass
class ChunkDone:
    exit_code: int
    status: Literal["success", "failed", "timeout", "aborted"]


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseExecutor(ABC):
    def __init__(self, ip: str, port: int, credential: Optional[Dict[str, str]] = None):
        self.ip = ip
        self.port = port
        self.credential = credential or {}
        self._last_used_at: float = 0.0

    @abstractmethod
    async def _ensure_connected(self) -> None:
        """Guarantee a live connection. Reconnects if dead. Called before every use."""

    @abstractmethod
    async def close(self) -> None:
        """Cleanly disconnect. Called by connection pool on eviction / shutdown."""

    @abstractmethod
    def stream_command(
        self,
        command: str,
        abort_event: asyncio.Event,
        timeout_s: int = 60,
        stdin_queue: Optional[asyncio.Queue] = None,
    ) -> AsyncIterator[Chunk | ChunkDone]:
        """Yield Chunk items then a single ChunkDone."""

    async def run_command(
        self, command: str, timeout_s: int = DEFAULT_COMMAND_TIMEOUT_S
    ) -> Dict[str, Any]:
        """Buffered wrapper — used by scheduler helpers and HTTP health paths.

        Timeout is enforced inside the executor's stream_command(), which kills
        the remote process when the deadline is reached. No outer asyncio.wait_for
        needed — callers should pass timeout_s here instead.
        """
        abort = asyncio.Event()
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        done: ChunkDone | None = None
        async for item in self.stream_command(command, abort, timeout_s):
            if isinstance(item, Chunk):
                if item.stream == "stdout":
                    stdout_parts.append(item.data)
                else:
                    stderr_parts.append(item.data)
            elif isinstance(item, ChunkDone):
                done = item

        out = "".join(stdout_parts).strip()
        err = "".join(stderr_parts).strip()
        status = done.status if done else "failed"

        if status == "success":
            if err:
                return {"status": "error", "output": out, "error": err}
            return {"status": "success", "output": out}
        if status == "timeout":
            return {"status": "timeout", "output": out, "error": err or "Timed out"}
        if status == "aborted":
            return {"status": "aborted", "output": out, "error": err}
        return {"status": "failed", "output": out, "error": err or "Command failed"}

    @abstractmethod
    async def check_health(self) -> bool:
        """TCP ping — does NOT use the pooled connection. Always direct."""


# ---------------------------------------------------------------------------
# Linux (SSH / Paramiko)
# ---------------------------------------------------------------------------

class LinuxExecutor(BaseExecutor):

    def __init__(self, ip: str, port: int, credential: Optional[Dict[str, str]] = None):
        super().__init__(ip, port, credential)
        self._client: Optional[paramiko.SSHClient] = None

    async def _ensure_connected(self) -> None:
        loop = asyncio.get_event_loop()
        now = loop.time()
        transport = self._client.get_transport() if self._client else None

        if transport and transport.is_active():
            # Recently used → trust the local state, skip probe
            if (now - self._last_used_at) < _LIVENESS_SKIP_WINDOW_S:
                return
            # Idle connection → quick session-open probe (detects silent NAT drops)
            try:
                def _probe():
                    ch = transport.open_session()
                    ch.close()
                await asyncio.wait_for(loop.run_in_executor(None, _probe), timeout=3.0)
                logger.debug("[pool] SSH reused %s", self.ip)
                self._last_used_at = now
                return
            except Exception:
                logger.info("[pool] SSH liveness probe failed for %s — reconnecting", self.ip)

        # Connect fresh
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.ip,
            port=self.port,
            username=self.credential.get("username"),
            password=self.credential.get("password"),
            timeout=10,
        )
        client.get_transport().set_keepalive(30)
        self._client = client
        self._last_used_at = asyncio.get_event_loop().time()
        logger.info("[pool] SSH fresh connection to %s", self.ip)

    async def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    async def stream_command(
        self,
        command: str,
        abort_event: asyncio.Event,
        timeout_s: int = 60,
        stdin_queue: Optional[asyncio.Queue] = None,
    ) -> AsyncIterator[Chunk | ChunkDone]:
        # _ensure_connected must have been called by the pool before this.
        # If called outside pool context (e.g. run_command), call it here.
        if not self._client or not self._client.get_transport() or \
                not self._client.get_transport().is_active():
            await self._ensure_connected()

        loop = asyncio.get_event_loop()
        chunk_queue: asyncio.Queue[Chunk | ChunkDone | BaseException] = asyncio.Queue()
        thread_stdin: _queue.Queue[str] = _queue.Queue()
        transport = self._client.get_transport()

        def _worker():
            try:
                channel = transport.open_session()
                channel.exec_command(command)

                while True:
                    # Forward any stdin data queued by the async side
                    while True:
                        try:
                            data = thread_stdin.get_nowait()
                            channel.send(data)
                        except _queue.Empty:
                            break

                    if abort_event.is_set():
                        # Drain remaining output before closing
                        while channel.recv_ready():
                            data = channel.recv(4096).decode("utf-8", errors="replace")
                            if data:
                                loop.call_soon_threadsafe(
                                    chunk_queue.put_nowait,
                                    Chunk(stream="stdout", data=data),
                                )
                        while channel.recv_stderr_ready():
                            data = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                            if data:
                                loop.call_soon_threadsafe(
                                    chunk_queue.put_nowait,
                                    Chunk(stream="stderr", data=data),
                                )
                        channel.close()
                        loop.call_soon_threadsafe(
                            chunk_queue.put_nowait,
                            ChunkDone(exit_code=-1, status="aborted"),
                        )
                        return

                    got_data = False
                    if channel.recv_ready():
                        data = channel.recv(4096).decode("utf-8", errors="replace")
                        if data:
                            got_data = True
                            loop.call_soon_threadsafe(
                                chunk_queue.put_nowait,
                                Chunk(stream="stdout", data=data),
                            )

                    if channel.recv_stderr_ready():
                        data = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                        if data:
                            got_data = True
                            loop.call_soon_threadsafe(
                                chunk_queue.put_nowait,
                                Chunk(stream="stderr", data=data),
                            )

                    if channel.exit_status_ready():
                        exit_code = channel.recv_exit_status()
                        # Final drain
                        while channel.recv_ready():
                            data = channel.recv(4096).decode("utf-8", errors="replace")
                            if data:
                                loop.call_soon_threadsafe(
                                    chunk_queue.put_nowait,
                                    Chunk(stream="stdout", data=data),
                                )
                        while channel.recv_stderr_ready():
                            data = channel.recv_stderr(4096).decode("utf-8", errors="replace")
                            if data:
                                loop.call_soon_threadsafe(
                                    chunk_queue.put_nowait,
                                    Chunk(stream="stderr", data=data),
                                )
                        status = "success" if exit_code == 0 else "failed"
                        loop.call_soon_threadsafe(
                            chunk_queue.put_nowait,
                            ChunkDone(exit_code=exit_code, status=status),
                        )
                        channel.close()
                        return

                    if not got_data:
                        time.sleep(0.05)  # avoid busy-loop

            except Exception as exc:
                loop.call_soon_threadsafe(chunk_queue.put_nowait, exc)

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()

        deadline = loop.time() + timeout_s
        timed_out = False

        while True:
            # Bridge asyncio stdin_queue → thread
            if stdin_queue:
                while not stdin_queue.empty():
                    try:
                        data = stdin_queue.get_nowait()
                        thread_stdin.put_nowait(data)
                    except Exception:
                        break

            remaining = deadline - loop.time()

            if remaining <= 0 and not timed_out:
                timed_out = True
                abort_event.set()

            wait = 0.2 if not abort_event.is_set() else 0.05

            try:
                item = await asyncio.wait_for(chunk_queue.get(), timeout=wait)
            except asyncio.TimeoutError:
                if abort_event.is_set():
                    # Give worker ~150 ms to flush remaining data
                    await asyncio.sleep(0.15)
                    while True:
                        try:
                            pending = chunk_queue.get_nowait()
                            if isinstance(pending, Chunk):
                                yield pending
                            elif isinstance(pending, ChunkDone):
                                yield pending
                                return
                        except Exception:
                            break
                    yield ChunkDone(
                        exit_code=-1,
                        status="timeout" if timed_out else "aborted",
                    )
                    return
                continue

            if isinstance(item, BaseException):
                yield ChunkDone(exit_code=-1, status="failed")
                return
            yield item
            if isinstance(item, ChunkDone):
                self._last_used_at = asyncio.get_event_loop().time()
                return

    async def check_health(self) -> bool:
        """SSH banner-grab — independent of the pooled connection.

        TCP-only "is the port open" isn't enough: a half-broken sshd or a stale
        port-forward will accept the connection but never serve. A real sshd
        sends `SSH-2.0-...` within ~100ms of accept; if we don't see that, the
        service isn't actually usable.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, self.port), timeout=3
            )
            try:
                banner = await asyncio.wait_for(reader.readline(), timeout=2)
                ok = banner.startswith(b"SSH-")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return ok
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False


# ---------------------------------------------------------------------------
# Windows (WinRM / pywinrm protocol-level polling)
# ---------------------------------------------------------------------------

class WindowsExecutor(BaseExecutor):
    def __init__(self, ip: str, port: int, credential: Optional[Dict[str, str]] = None):
        super().__init__(ip, port, credential)
        if port == 22:
            self.port = 5985
        self._protocol: Optional[winrm.protocol.Protocol] = None

    def _make_protocol(self) -> winrm.protocol.Protocol:
        return winrm.protocol.Protocol(
            endpoint=f"http://{self.ip}:{self.port}/wsman",
            transport="ntlm",
            username=self.credential.get("username"),
            password=self.credential.get("password"),
        )

    async def _ensure_connected(self) -> None:
        # WinRM/NTLM: each open_shell() consumes an auth token. Reusing the
        # Protocol object across separate open_shell() calls causes "Invalid MIC"
        # SpnegoErrors on the second call. Always create a fresh Protocol so each
        # command sequence gets a clean NTLM handshake.
        # The per-server pool lock (not session reuse) is what prevents NTLM
        # collision between concurrent callers.
        self._protocol = self._make_protocol()
        self._last_used_at = asyncio.get_event_loop().time()
        logger.debug("[pool] WinRM protocol ready for %s", self.ip)

    async def close(self) -> None:
        self._protocol = None

    async def stream_command(
        self,
        command: str,
        abort_event: asyncio.Event,
        timeout_s: int = 60,
        stdin_queue: Optional[asyncio.Queue] = None,
    ) -> AsyncIterator[Chunk | ChunkDone]:
        if not self._protocol:
            await self._ensure_connected()

        loop = asyncio.get_event_loop()

        # Use -EncodedCommand (Base64 UTF-16LE) so the command string is opaque
        # to the cmd.exe shell — no quoting issues regardless of what the command
        # contains (semicolons, double-quotes, dollar signs, etc.).
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        ps_command = f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"
        protocol = self._protocol

        shell_id = await loop.run_in_executor(None, protocol.open_shell)
        cmd_id = await loop.run_in_executor(
            None, lambda: protocol.run_command(shell_id, ps_command)
        )

        deadline = loop.time() + timeout_s
        timed_out = False

        try:
            while True:
                # Forward stdin if any
                if stdin_queue:
                    while not stdin_queue.empty():
                        try:
                            data = stdin_queue.get_nowait()
                            await loop.run_in_executor(
                                None,
                                lambda d=data: protocol.send_input(shell_id, cmd_id, d),
                            )
                        except Exception:
                            break

                if abort_event.is_set():
                    await loop.run_in_executor(
                        None, lambda: protocol.cleanup_command(shell_id, cmd_id)
                    )
                    yield ChunkDone(exit_code=-1, status="aborted")
                    return

                if loop.time() >= deadline and not timed_out:
                    timed_out = True
                    abort_event.set()
                    await loop.run_in_executor(
                        None, lambda: protocol.cleanup_command(shell_id, cmd_id)
                    )
                    yield ChunkDone(exit_code=-1, status="timeout")
                    return

                # pywinrm returns (stdout, stderr, return_code) — 3 values.
                # return_code is None while running, an int when finished.
                std_out_b, std_err_b, exit_status = await loop.run_in_executor(
                    None,
                    lambda: protocol.get_command_output(shell_id, cmd_id),
                )
                done = exit_status is not None

                if std_out_b:
                    yield Chunk(stream="stdout", data=std_out_b.decode("utf-8", errors="replace"))

                if std_err_b:
                    err_text = std_err_b.decode("utf-8", errors="replace")
                    # CLIXML is PowerShell host-formatting (progress bars, "Preparing
                    # modules for first use.", etc.) written to stderr on every fresh
                    # PS session.  It is never an actionable error — drop it silently
                    # so callers see a clean exit status and no false "error" results.
                    if not err_text.lstrip().startswith("#< CLIXML"):
                        yield Chunk(stream="stderr", data=err_text)

                if done:
                    status = "success" if exit_status == 0 else "failed"
                    yield ChunkDone(exit_code=exit_status, status=status)
                    self._last_used_at = asyncio.get_event_loop().time()
                    return

                await asyncio.sleep(0.2)
        finally:
            try:
                await loop.run_in_executor(None, lambda: protocol.close_shell(shell_id))
            except Exception:
                pass
            # Reset so the next call gets a completely fresh NTLM auth context.
            # WinRM auth tokens are per-handshake; reusing them across separate
            # command sequences causes SpnegoError (Invalid MIC).
            self._protocol = None

    async def run_command(
        self, command: str, timeout_s: int = DEFAULT_COMMAND_TIMEOUT_S
    ) -> dict:
        abort = asyncio.Event()
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        done: ChunkDone | None = None
        async for item in self.stream_command(command, abort, timeout_s):
            if isinstance(item, Chunk):
                if item.stream == "stdout":
                    stdout_parts.append(item.data)
                else:
                    stderr_parts.append(item.data)
            elif isinstance(item, ChunkDone):
                done = item

        out = "".join(stdout_parts).strip()
        err = "".join(stderr_parts).strip()
        status = done.status if done else "failed"

        if status == "success":
            if err:
                return {"status": "error", "output": out, "error": err}
            return {"status": "success", "output": out}
        if status == "timeout":
            return {"status": "timeout", "output": out, "error": err or "Timed out"}
        if status == "aborted":
            return {"status": "aborted", "output": out, "error": err}
        return {"status": "failed", "output": out, "error": err or "Command failed"}

    async def check_health(self) -> bool:
        """WinRM HTTP probe — independent of the pooled connection.

        WinRM speaks HTTP. A bare TCP connect succeeds even if the WinRM
        service is uninstalled and another process has bound the port. Sending
        `HEAD /wsman` and checking for any HTTP-shaped reply (200/401/405 are
        all fine — they prove the service is alive) catches that case.

        Note: this assumes WinRM-over-HTTP. WinRM-over-HTTPS (port 5986) needs
        a TLS handshake — `asyncio.open_connection(ssl=...)` — which we'll add
        if/when HTTPS support lands.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, self.port), timeout=3
            )
            try:
                writer.write(
                    b"HEAD /wsman HTTP/1.1\r\nHost: " + self.ip.encode()
                    + b"\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=2)
                ok = line.startswith(b"HTTP/")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return ok
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_server_executor(server_doc: Dict, plain_password: str = "") -> BaseExecutor:
    os_type = server_doc.get("os_type", "linux")
    ip = server_doc["ip_address"]
    port = server_doc.get("port", 22)
    creds = {"username": "unknown", "password": plain_password}

    if os_type == "windows":
        return WindowsExecutor(ip, port, creds)
    return LinuxExecutor(ip, port, creds)
