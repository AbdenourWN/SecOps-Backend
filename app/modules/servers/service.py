from app.core.constants import (
    Collections, WSTopic,
    NotificationType, NotificationCategory, NotificationSeverity,
)
import asyncio
import logging
import uuid
from typing import AsyncIterator, Optional, Union

from app.core.database import get_database
from app.modules.servers.schemas import ServerCreate, ServerInDB, CredentialInDB, ServerUpdate, ServerDelete, ServerStatus
from app.core.security import encrypt_password, decrypt_password
from bson import ObjectId
from datetime import datetime, timedelta, timezone
from app.core.datetime_utils import utc_now
from app.core.executors import get_server_executor, Chunk, ChunkDone, is_permission_error
# get_server_executor kept for health-check path (direct TCP, no pool)

logger = logging.getLogger(__name__)
from app.core.rate_limit import check_rate_limit
from app.modules.servers.guardrails import check_command
from app.modules.servers.audit import write_audit
from app.core.events import event_bus
from app.core.connection_pool import connection_pool, terminal_pool
from app.modules.notifications.feed import notify


# Health transition → in-app notification copy. `None` = no notification for
# that state (e.g. flips to "unknown" are too noisy to surface).
_HEALTH_NOTIF = {
    "offline": (NotificationSeverity.ERROR, "Server offline", "is no longer reachable."),
    "reachable": (NotificationSeverity.WARNING, "Server authentication failing", "is reachable but credentials are being rejected."),
    "online": (NotificationSeverity.SUCCESS, "Server back online", "has recovered and is online."),
}


def _offline_reminder_due(last_alert: Optional[datetime], now: datetime) -> bool:
    """True when a still-offline reminder email is due, per the configured
    `SERVER_OFFLINE_REMINDER_HOURS` window (0 disables reminders entirely). A
    missing timestamp counts as due (e.g. a server already offline before this
    clock existed)."""
    from app.core.config import settings
    window_s = settings.SERVER_OFFLINE_REMINDER_HOURS * 3600
    if window_s <= 0:
        return False  # reminders disabled
    if not last_alert:
        return True
    if last_alert.tzinfo is None:
        last_alert = last_alert.replace(tzinfo=timezone.utc)
    return (now - last_alert).total_seconds() >= window_s


# Health email copy per event kind: (severity, rule_name, sentence). `severity`
# MUST be one of SEVERITY_RANK in notifications/service.py (low/medium/high/
# critical) — it is filtered against each config's `min_severity`, so values
# outside that set (e.g. "info") rank as 0 and would be silently dropped.
_HEALTH_EMAIL = {
    "offline":   ("critical", "Server Offline",              "is offline and no longer reachable by the platform."),
    "reminder":  ("critical", "Server Still Offline",        "is still offline and remains unreachable by the platform."),
    "reachable": ("high",     "Server Authentication Failing", "is reachable but its credentials are being rejected — log/metric collection is failing."),
    "recovery":  ("medium",   "Server Recovered",            "has recovered and is back online."),
}


async def _send_health_email(
    server: dict,
    previous_status: str,
    kind: str,
    reason: Optional[str] = None,
    consecutive: Optional[int] = None,
) -> None:
    """
    Email the admin on a server health event — `kind` is one of `_HEALTH_EMAIL`
    (offline / still-offline reminder / auth-failing / recovery). Reuses the
    existing NotificationService email pipeline (recipients from the DB email
    config, `.env` fallback). Best-effort — never raises into the health loop.
    """
    try:
        from app.modules.notifications.service import NotificationService
        from app.modules.notifications.schemas import AlertPayload

        severity, rule_name, tail = _HEALTH_EMAIL[kind]
        hostname = server.get("hostname") or server.get("ip_address") or str(server.get("_id"))
        context = {"Previous status": previous_status or "unknown"}
        if reason:
            context["Reason"] = reason
        if consecutive:
            context["Consecutive offline checks"] = consecutive

        payload = AlertPayload(
            incident_id="",
            server_id=str(server.get("_id")),
            server_hostname=hostname,
            server_ip=server.get("ip_address", "unknown"),
            rule_name=rule_name,
            severity=severity,
            description=f"{hostname} {tail}",
            context=context,
            detected_at=utc_now(),
            action_level=3,                        # alert-only
            # A recovery is "good news" (medium) so a critical-only config would
            # otherwise drop it — force it through so whoever got the down/still-
            # down alert always learns the server came back.
            bypass_min_severity=(kind == "recovery"),
        )
        await NotificationService().send_alert(payload)
    except Exception as e:
        logger.warning("[health] %s alert email failed for %s: %s", kind, server.get('hostname'), e)


DEFAULT_COMMAND_TIMEOUT_S = 60
MAX_COMMAND_TIMEOUT_S = 300



class ServerService:
    async def _verify_ownership(self, db, server_id: ObjectId, input_secret: str) -> dict:
        """
        Private helper. Checks if the input_secret matches the stored credential.
        Returns the credential document if valid, raises error if not.
        """
        # 1. Find Server
        server = await db[Collections.SERVERS].find_one({"_id": server_id})
        if not server:
            return {"valid": False, "error": "Server not found"}

        # 2. Find Linked Credential
        cred_id = server["credential_id"] # It's an ObjectId now
        credential = await db[Collections.CREDENTIALS].find_one({"_id": ObjectId(cred_id)})
        
        if not credential:
            return {"valid": False, "error": "Critical Data Corruption: Credential missing"}

        # 3. Decrypt Stored Secret
        try:
            stored_secret = decrypt_password(credential["encrypted_secret"])
        except:
             return {"valid": False, "error": "Decryption failed"}

        # 4. Compare
        # We strip() whitespace just in case of copy-paste errors
        if input_secret.strip() != stored_secret.strip():
            return {"valid": False, "error": "Authentication Failed: Wrong current password"}

        return {"valid": True, "credential_id": cred_id, "server_data": server}
    
    async def update_all_server_statuses(self):
        from app.core.config import settings

        db = get_database()
        servers = await db[Collections.SERVERS].find().to_list(length=10000)
        logger.info("Starting health check cycle (%d servers)", len(servers))

        sem = asyncio.Semaphore(settings.MAX_CONCURRENT_SERVERS)

        async def check_one(server):
            server_id = str(server["_id"])
            previous_status = server.get("status")
            now = utc_now()

            async with sem:
                # ── Tier 1: TCP / banner-grab (no credentials needed) ──
                tcp_executor = get_server_executor(server, plain_password="")
                reachable = await tcp_executor.check_health()

                if not reachable:
                    n = (server.get("consecutive_offline_checks") or 0) + 1
                    update = {
                        "status": ServerStatus.OFFLINE,
                        "is_online": False,
                        "last_health_check": now,
                        "consecutive_offline_checks": n,
                        "auth_failure_reason": None,
                    }
                else:
                    # ── Tier 2: auth probe — run cheap command with real credentials ──
                    # The goal here is to always surface a *real* reason string when
                    # the probe fails, so the UI can show the operator what actually
                    # came back from the OS. No opaque sentinels.
                    auth_ok = False
                    fail_reason = None
                    try:
                        cred = await db[Collections.CREDENTIALS].find_one(
                            {"_id": ObjectId(server["credential_id"])}
                        )
                        if not cred:
                            fail_reason = "No credentials configured for this server"
                        else:
                            plain_secret = decrypt_password(cred["encrypted_secret"])
                            auth_executor = get_server_executor(server, plain_secret)
                            auth_executor.credential["username"] = cred["username"]
                            probe_cmd = (
                                "[System.Environment]::UserName"
                                if server.get("os_type") == "windows"
                                else "whoami"
                            )
                            result = await auth_executor.run_command(
                                probe_cmd, timeout_s=8
                            )
                            auth_ok = result.get("status") == "success"
                            if not auth_ok:
                                # Build the reason out of whatever the executor gave
                                # us — stderr, status, and exit code — so the UI
                                # shows the real OS-level message verbatim.
                                err_text = (result.get("error") or "").strip()
                                exit_code = result.get("exit_code")
                                status_str = result.get("status") or "failed"
                                if err_text:
                                    fail_reason = err_text
                                elif exit_code is not None:
                                    fail_reason = (
                                        f"Auth probe exited with code {exit_code} "
                                        f"(no error output captured)"
                                    )
                                else:
                                    fail_reason = (
                                        f"Auth probe returned status={status_str} "
                                        f"with no error output"
                                    )
                    except Exception as e:
                        # Surface the exception class + message so it is identifiable
                        # (e.g. "SpnegoError: Server returned ...", "AuthenticationException: ...").
                        fail_reason = f"{type(e).__name__}: {e}"

                    if auth_ok:
                        update = {
                            "status": ServerStatus.ONLINE,
                            "is_online": True,
                            "last_health_check": now,
                            "consecutive_offline_checks": 0,
                            "auth_failure_reason": None,
                        }
                    else:
                        update = {
                            "status": ServerStatus.REACHABLE,
                            "is_online": False,
                            "last_health_check": now,
                            "consecutive_offline_checks": 0,
                            "auth_failure_reason": fail_reason,
                        }

                new_status = update["status"]
                is_transition = previous_status != new_status

                # ── Decide the health email + maintain the still-offline clock ──
                # The reminder clock (`last_offline_alert_at`) lives on the server
                # doc so a still-offline email can fire on non-transition ticks;
                # folding it into `update` keeps this to the single write below.
                email_kind = None
                email_consecutive = None
                if new_status == "offline":
                    if is_transition:
                        email_kind = "offline"                  # just went down
                        update["last_offline_alert_at"] = now
                    elif _offline_reminder_due(server.get("last_offline_alert_at"), now):
                        email_kind = "reminder"                 # still down, throttle elapsed
                        email_consecutive = update.get("consecutive_offline_checks")
                        update["last_offline_alert_at"] = now
                elif is_transition:
                    update["last_offline_alert_at"] = None      # recovered/changed → reset clock
                    if new_status == "reachable":
                        email_kind = "reachable"                # up but auth/collection failing
                    elif new_status == "online" and previous_status in ("offline", "reachable"):
                        email_kind = "recovery"                 # back to healthy

                await db[Collections.SERVERS].update_one(
                    {"_id": server["_id"]},
                    {"$set": update},
                )

                if is_transition:
                    event_bus.emit(WSTopic.SERVERS_STATUS, "server.status_changed", {
                        "server_id": server_id,
                        "status": new_status,
                        "previous_status": previous_status,
                        "hostname": server.get("hostname"),
                    })
                    event_bus.emit(f"servers.{server_id}.status", "server.status_changed", {  # per-server topic for detail pages (flat topic above is server-filtered at the WS bridge)
                        "server_id": server_id,
                        "status": new_status,
                        "previous_status": previous_status,
                        "hostname": server.get("hostname"),
                    })
                    event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "server.status_changed", {
                        "server_id": server_id,
                        "status": new_status,
                    })

                    # In-app notification (chosen group). Dedup per server+status
                    # so a flapping host doesn't re-spam the same transition.
                    copy = _HEALTH_NOTIF.get(new_status)
                    if copy is not None:
                        sev, title, tail = copy
                        host = server.get("hostname") or server.get("ip_address") or server_id
                        reason = update.get("auth_failure_reason")
                        body = f"{host} {tail}"
                        if new_status == "reachable" and reason:
                            body = f"{host}: {reason}"
                        await notify(
                            type=NotificationType.SERVER_HEALTH_CHANGED,
                            category=NotificationCategory.SERVER,
                            severity=sev,
                            title=title,
                            body=body[:160],
                            link=f"/servers/{server_id}",
                            server_id=server_id,
                            entity_type="server",
                            entity_id=server_id,
                            dedup_key=f"server_health:{server_id}:{new_status}",
                            dedup_window_s=3600,
                        )

                # Email the admin (best-effort, fire-and-forget so SMTP latency
                # never blocks the health-check gather). Covers: went offline,
                # still-offline reminder (throttled), auth-failing, and recovery.
                if email_kind:
                    asyncio.create_task(_send_health_email(
                        server, previous_status, email_kind,
                        reason=update.get("auth_failure_reason"),
                        consecutive=email_consecutive,
                    ))

        await asyncio.gather(*[check_one(s) for s in servers], return_exceptions=True)
        logger.info("Health check complete — scanned %d servers", len(servers))
    """ 
    🚀
    CRUD Operations 
    
    """

    async def create_server(self, server_data: ServerCreate):
        db = get_database()
        
        # 1. Check if Server IP exists
        if await db[Collections.SERVERS].find_one({"ip_address": server_data.ip_address}):
            return {"status": "failed", "error": "Server with this IP already exists"}

        # --- STEP A: Handle Credential ---
        
        # Encrypt the secret from the nested input
        encrypted_secret = encrypt_password(server_data.credential.secret)
        encrypted_passphrase = None
        if server_data.credential.passphrase:
            encrypted_passphrase = encrypt_password(server_data.credential.passphrase)

        # --- LOGIC: Handle Default Port ---
        final_port = server_data.port
        if final_port is None:
            # Auto-assign based on OS
            if server_data.os_type == "windows":
                final_port = 5985
            else:
                final_port = 22

        # Prepare Credential Object
        cred_in_db = CredentialInDB(
            username=server_data.credential.username,
            type=server_data.credential.type,
            encrypted_secret=encrypted_secret,
            encrypted_passphrase=encrypted_passphrase
        )

        # Save Credential to "credentials" collection
        cred_result = await db[Collections.CREDENTIALS].insert_one(cred_in_db.model_dump())
        new_cred_id = cred_result.inserted_id 
        
        # --- STEP B: Handle Server ---

        # Prepare Server Object (Linking the ID)
        server_in_db = ServerInDB(
            hostname=server_data.hostname,
            ip_address=server_data.ip_address,
            os_type=server_data.os_type,
            port=final_port,
            credential_id=str(new_cred_id)
        )

        # Save Server to "servers" collection. Stamp the heuristic-Tier-2
        # initial state inline so the analysis service has sane defaults from
        # the very first log batch:
        #   - pattern_warmup_until: user-chosen duration (minutes) during which
        #     novel patterns are recorded silently. 0 minutes = no warm-up.
        #   - business_hours: user-supplied if provided, else Mon-Fri 09-18 UTC
        #   - log_rate_baseline: starts at 0; EMA learns it over the first
        #     ~10-20 telemetry ticks
        from datetime import datetime, timezone, timedelta
        from app.modules.heuristics.service import DEFAULT_BUSINESS_HOURS

        now = datetime.now(timezone.utc)
        server_doc = server_in_db.model_dump()
        warmup_min = server_data.warmup_minutes
        server_doc["pattern_warmup_until"] = (
            now - timedelta(seconds=1)
            if warmup_min == 0
            else now + timedelta(minutes=warmup_min)
        )
        server_doc["business_hours"] = (
            server_data.business_hours.model_dump()
            if server_data.business_hours is not None
            else DEFAULT_BUSINESS_HOURS.copy()
        )
        from app.modules.servers.schemas import DetectionConfig
        server_doc["detection_config"] = (
            server_data.detection_config.model_dump()
            if server_data.detection_config is not None
            else DetectionConfig().model_dump()
        )
        server_doc["log_rate_baseline"] = 0.0
        server_doc["log_rate_updated_at"] = None

        server_result = await db[Collections.SERVERS].insert_one(server_doc)

        event_bus.emit(WSTopic.SERVERS, "server.created", {
            "server_id": str(server_result.inserted_id),
            "hostname": server_data.hostname,
        })
        event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "server.created", {
            "server_id": str(server_result.inserted_id),
        })

        return {
            "status": "success",
            "server_id": str(server_result.inserted_id),
            "credential_id": str(new_cred_id)
        }
    
    async def get_all_servers(self, status=None, os_type=None, search=None, page: int = 1, page_size: int = 9, allowed_server_ids=None):
        db = get_database()
        query = {}
        # RBAC (Phase 20.1): None = admin (all servers); a list = restrict to the
        # principal's assigned servers (empty list → no results, as intended).
        if allowed_server_ids is not None:
            oids = []
            for sid in allowed_server_ids:
                try:
                    oids.append(ObjectId(sid))
                except Exception:
                    pass
            query["_id"] = {"$in": oids}
        if status is not None:
            query["status"] = status
        if os_type is not None:
            query["os_type"] = os_type
        if search:
            import re
            pattern = re.compile(re.escape(search), re.IGNORECASE)
            query["$or"] = [{"hostname": pattern}, {"ip_address": pattern}]
        total = await db[Collections.SERVERS].count_documents(query)
        skip = (page - 1) * page_size
        servers = await db[Collections.SERVERS].find(query).skip(skip).limit(page_size).to_list(page_size)
        return {"total": total, "page": page, "page_size": page_size, "results": servers}

    async def get_server(self, server_id: str):
        db = get_database()
        
        try:
            oid = ObjectId(server_id)
        except:
            return None
            
        server = await db[Collections.SERVERS].find_one({"_id": oid})
        return server


    # --- UPDATE Logic ---
    async def update_server(self, server_id: str, update_data: ServerUpdate):
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except:
            return {"status": "failed", "error": "Invalid Server ID"}

        # 1. SECURITY CHALLENGE: Verify the current password first
        verification = await self._verify_ownership(db, oid, update_data.current_secret)
        if not verification["valid"]:
            return {"status": "failed", "error": verification["error"]}
        
        # 2. Prepare Data to Update
        server_updates = {}
        if update_data.hostname: server_updates["hostname"] = update_data.hostname
        if update_data.ip_address:
            # Check uniqueness if IP is changing
            dup = await db[Collections.SERVERS].find_one({"ip_address": update_data.ip_address, "_id": {"$ne": oid}})
            if dup: return {"status": "failed", "error": "IP already taken"}
            server_updates["ip_address"] = update_data.ip_address
        if update_data.os_type: server_updates["os_type"] = update_data.os_type
        if update_data.port: server_updates["port"] = update_data.port
        if update_data.business_hours is not None:
            server_updates["business_hours"] = update_data.business_hours.model_dump()
        if update_data.detection_config is not None:
            server_updates["detection_config"] = update_data.detection_config.model_dump()
        if update_data.ai_autonomy_level is not None:
            server_updates["ai_autonomy_level"] = update_data.ai_autonomy_level
        if update_data.windows_event_ids is not None:
            server_updates["windows_event_ids"] = update_data.windows_event_ids
        if update_data.windows_event_ids_exclude is not None:
            server_updates["windows_event_ids_exclude"] = update_data.windows_event_ids_exclude
        # Phase 28.5 — per-server library mode selectors. The allowed-fields
        # list is explicit, so without these two branches the schema accepts
        # the values, the frontend sends them, but they get silently dropped
        # before the $set write.
        if update_data.rule_library_mode is not None:
            server_updates["rule_library_mode"] = update_data.rule_library_mode
        if update_data.script_library_mode is not None:
            server_updates["script_library_mode"] = update_data.script_library_mode

        # 3. Handle Credential Updates (If user wants to set a NEW password)
        if update_data.credential:
            cred_updates = {}
            if update_data.credential.username: 
                cred_updates["username"] = update_data.credential.username
            if update_data.credential.type: 
                cred_updates["type"] = update_data.credential.type
            if update_data.credential.secret: 
                cred_updates["encrypted_secret"] = encrypt_password(update_data.credential.secret)
            if update_data.credential.passphrase:
                cred_updates["encrypted_passphrase"] = encrypt_password(update_data.credential.passphrase)
            
            # Update the Credential Collection
            if cred_updates:
                cred_updates["updated_at"] = datetime.now(timezone.utc)
                await db[Collections.CREDENTIALS].update_one(
                    {"_id": ObjectId(verification["credential_id"])}, 
                    {"$set": cred_updates}
                )

        # 4. Update the Server Collection
        if server_updates:
            server_updates["updated_at"] = datetime.now(timezone.utc)
            await db[Collections.SERVERS].update_one({"_id": oid}, {"$set": server_updates})

        # Evict from both pools so the next access picks up fresh credentials/config
        connection_pool.evict(str(oid))
        terminal_pool.evict(str(oid))

        event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": str(oid)})

        return {"status": "success", "message": "Server and credentials updated"}

    # --- DELETE Logic ---
    async def delete_server(self, server_id: str, delete_data: ServerDelete):
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except:
            return {"status": "failed", "error": "Invalid Server ID"}

        # 1. SECURITY CHALLENGE
        verification = await self._verify_ownership(db, oid, delete_data.current_secret)
        if not verification["valid"]:
             return {"status": "failed", "error": verification["error"]}
        
        cred_id = ObjectId(verification["credential_id"])

        # 2. DELETE EVERYTHING (Cascade)
        await db[Collections.SERVERS].delete_one({"_id": oid})
        await db[Collections.CREDENTIALS].delete_one({"_id": cred_id})
        # Evict from both pools — releases all cached sessions immediately
        connection_pool.evict(str(oid))
        terminal_pool.evict(str(oid))

        event_bus.emit(WSTopic.SERVERS, "server.deleted", {"server_id": str(oid)})
        event_bus.emit(WSTopic.DASHBOARD_SUMMARY, "server.deleted", {"server_id": str(oid)})

        return {"status": "success", "message": "Server and associated credentials deleted"}

    # --- Tier 2 anomaly maintenance ---

    async def reset_pattern_warmup(
        self,
        server_id: str,
        warmup_minutes: int = 60,
        clear_known_patterns: bool = True,
    ):
        """
        Restart the novel-pattern warm-up window with a user-chosen duration.

          - warmup_minutes=0  → no warm-up; flag novel patterns immediately
          - warmup_minutes=60 → 1 hour
          - up to 525_600     → 1 year

        clear_known_patterns wipes the seen-patterns set so warm-up is
        meaningful (otherwise all current patterns are already marked seen
        and would never flag again).
        """
        from datetime import datetime, timezone, timedelta
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Server ID"}

        if not await db[Collections.SERVERS].find_one({"_id": oid}, {"_id": 1}):
            return {"status": "failed", "error": "Server not found"}

        if warmup_minutes < 0 or warmup_minutes > 525_600:
            return {"status": "failed", "error": "warmup_minutes out of range (0..525600)"}

        now = datetime.now(timezone.utc)
        new_until = (
            now - timedelta(seconds=1)
            if warmup_minutes == 0
            else now + timedelta(minutes=warmup_minutes)
        )
        await db[Collections.SERVERS].update_one(
            {"_id": oid},
            {"$set": {"pattern_warmup_until": new_until}},
        )
        if clear_known_patterns:
            await db[Collections.SERVER_LOG_PATTERNS].delete_many({"server_id": str(oid)})

        event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": str(oid)})
        return {
            "status": "success",
            "message": f"Pattern warm-up restarted ({warmup_minutes} minutes)",
            "warmup_minutes": warmup_minutes,
            "warmup_until": new_until.isoformat(),
        }

    async def reset_log_rate_baseline(self, server_id: str):
        """Reset the EMA log-rate baseline to 0 — next tick learns fresh."""
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Server ID"}

        if not await db[Collections.SERVERS].find_one({"_id": oid}, {"_id": 1}):
            return {"status": "failed", "error": "Server not found"}

        await db[Collections.SERVERS].update_one(
            {"_id": oid},
            {"$set": {"log_rate_baseline": 0.0, "log_rate_updated_at": None}},
        )
        event_bus.emit(WSTopic.SERVERS, "server.updated", {"server_id": str(oid)})
        return {"status": "success", "message": "Log rate baseline reset"}

    async def recalculate_server_stats(self, server_id: str):
        """
        Recompute open_incidents_count from actual incident documents.
        Use this to heal any counter drift caused by missed write paths.
        """
        db = get_database()
        try:
            oid = ObjectId(server_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Server ID"}

        if not await db[Collections.SERVERS].find_one({"_id": oid}, {"_id": 1}):
            return {"status": "failed", "error": "Server not found"}

        active_count = await db[Collections.INCIDENTS].count_documents({
            "server_id": server_id,
            "status": {"$in": ["open", "verifying", "investigating"]},
        })

        await db[Collections.SERVERS].update_one(
            {"_id": oid},
            {"$set": {"open_incidents_count": active_count}},
        )
        return {"status": "success", "open_incidents_count": active_count}

    async def execute_command_by_id(
        self,
        server_id: str,
        command: str,
        *,
        confirmed: bool = False,
        timeout_s: int | None = None,
        principal_id: str | None = None,
        source_ip: str | None = None,
    ):
        """
        Guardrail pipeline (defense in depth):
          rate-limit -> block-list -> confirm-list -> exec with timeout.
        Every outcome writes a row to command_audit.
        """
        db = get_database()
        started_at = datetime.now(timezone.utc)
        principal = principal_id or source_ip or "anonymous"

        # --- Server lookup ---
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            return {"status": "failed", "error": "Invalid Server ID"}

        server = await db[Collections.SERVERS].find_one({"_id": s_oid})
        if not server:
            return {"status": "failed", "error": "Server not found"}

        os_type = server.get("os_type", "linux")

        # --- 1. Rate limit ---
        rl = await check_rate_limit(principal, server_id)
        if not rl.allowed:
            await write_audit(
                server_id=server_id, command=command, status="rate_limited",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=f"rate limit exceeded (retry in {rl.retry_after_s}s)",
            )
            return {
                "status": "rate_limited",
                "retry_after_seconds": rl.retry_after_s,
                "error": "Rate limit exceeded.",
            }

        # --- 2. Guardrail check (block / confirm / allow) ---
        check = check_command(command, os_type)
        if not check.allowed:
            await write_audit(
                server_id=server_id, command=command, status="blocked",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=check.reason,
            )
            return {
                "status": "blocked",
                "blocked_reason": check.reason,
                "error": check.reason,
            }

        if check.requires_confirmation and not confirmed:
            await write_audit(
                server_id=server_id, command=command, status="requires_confirmation",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=False,
                blocked_reason=check.reason,
            )
            return {
                "status": "requires_confirmation",
                "blocked_reason": check.reason,
                "error": check.reason,
            }

        # --- 3. Acquire pooled executor and run ---
        effective_timeout = DEFAULT_COMMAND_TIMEOUT_S if timeout_s is None else \
            max(1, min(MAX_COMMAND_TIMEOUT_S, int(timeout_s)))

        try:
            async with terminal_pool.get(server_id) as executor:
                # Timeout is enforced inside the executor — it kills the remote
                # process when the deadline is reached and returns status="timeout".
                # No outer asyncio.wait_for needed.
                result = await executor.run_command(command, timeout_s=effective_timeout)
        except Exception as e:
            await write_audit(
                server_id=server_id, command=command, status="error",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed, stderr=str(e),
            )
            return {"status": "failed", "error": str(e)}

        # --- 4. Audit the run ---
        run_status = result.get("status", "error")
        audit_status = "ok" if run_status == "success" else "error"
        await write_audit(
            server_id=server_id, command=command, status=audit_status,
            started_at=started_at, principal_id=principal_id,
            source_ip=source_ip, confirmed=confirmed,
            stdout=result.get("output"),
            stderr=result.get("error"),
        )
        return result

    # ------------------------------------------------------------------
    # Streaming terminal (P7.6)
    # ------------------------------------------------------------------

    async def stream_command(
        self,
        server_id: str,
        command: str,
        abort_event: asyncio.Event,
        *,
        confirmed: bool = False,
        timeout_s: int | None = None,
        principal_id: str | None = None,
        source_ip: str | None = None,
        stdin_queue: Optional[asyncio.Queue] = None,
    ) -> AsyncIterator[dict]:
        """
        Guardrail-checked streaming command.  Yields dicts matching the WS
        protocol:  started | chunk | done | error.
        Always writes an audit row (including on abort/disconnect).
        """
        started_at = datetime.now(timezone.utc)
        principal = principal_id or source_ip or "anonymous"
        command_id = str(uuid.uuid4())

        db = get_database()
        try:
            s_oid = ObjectId(server_id)
        except Exception:
            yield {"type": "error", "command_id": None, "code": "invalid_command",
                   "message": "Invalid server ID"}
            return

        server = await db[Collections.SERVERS].find_one({"_id": s_oid})
        if not server:
            yield {"type": "error", "command_id": None, "code": "invalid_command",
                   "message": "Server not found"}
            return

        os_type = server.get("os_type", "linux")

        # --- Rate limit ---
        rl = await check_rate_limit(principal, server_id)
        if not rl.allowed:
            await write_audit(
                server_id=server_id, command=command, status="rate_limited",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=f"rate limit exceeded (retry in {rl.retry_after_s}s)",
                transport="ws",
            )
            yield {
                "type": "error", "command_id": None, "code": "rate_limited",
                "message": "Rate limit exceeded.",
                "retry_after_s": rl.retry_after_s,
            }
            return

        # --- Guardrail check ---
        check = check_command(command, os_type)
        if not check.allowed:
            await write_audit(
                server_id=server_id, command=command, status="blocked",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=confirmed,
                blocked_reason=check.reason, transport="ws",
            )
            yield {"type": "error", "command_id": None, "code": "blocked",
                   "message": check.reason}
            return

        if check.requires_confirmation and not confirmed:
            await write_audit(
                server_id=server_id, command=command, status="requires_confirmation",
                started_at=started_at, principal_id=principal_id,
                source_ip=source_ip, confirmed=False,
                blocked_reason=check.reason, transport="ws",
            )
            yield {"type": "error", "command_id": None,
                   "code": "requires_confirmation", "message": check.reason}
            return

        effective_timeout = (
            DEFAULT_COMMAND_TIMEOUT_S if timeout_s is None
            else max(1, min(MAX_COMMAND_TIMEOUT_S, int(timeout_s)))
        )

        # Acquire the terminal pool executor — separate from the scheduler pool so
        # long-running terminal sessions never block metric/log collection.
        try:
            _pool_ctx = terminal_pool.get(server_id)
            executor = await _pool_ctx.__aenter__()
        except Exception as exc:
            yield {"type": "error", "command_id": None, "code": "internal",
                   "message": str(exc)}
            return

        yield {
            "type": "started",
            "command_id": command_id,
            "command": command,
            "started_at": started_at.isoformat(),
        }

        # Rolling 4 KB preview buffers for audit
        stdout_preview_buf: list[str] = []
        stderr_preview_buf: list[str] = []
        PREVIEW_MAX = 4096
        stdout_total = 0
        stderr_total = 0
        chunk_count = 0
        seq = 0
        final_done: ChunkDone | None = None

        try:
            async for item in executor.stream_command(command, abort_event, effective_timeout, stdin_queue):
                if isinstance(item, Chunk):
                    chunk_count += 1
                    seq_val = seq
                    seq += 1
                    yield {
                        "type": "chunk",
                        "command_id": command_id,
                        "stream": item.stream,
                        "data": item.data,
                        "seq": seq_val,
                    }
                    raw = item.data.encode("utf-8", errors="replace")
                    if item.stream == "stdout":
                        stdout_total += len(raw)
                        if stdout_total <= PREVIEW_MAX:
                            stdout_preview_buf.append(item.data)
                    else:
                        stderr_total += len(raw)
                        if stderr_total <= PREVIEW_MAX:
                            stderr_preview_buf.append(item.data)

                elif isinstance(item, ChunkDone):
                    final_done = item
                    finished_at = datetime.now(timezone.utc)
                    duration_ms = int(
                        (finished_at - started_at).total_seconds() * 1000
                    )
                    yield {
                        "type": "done",
                        "command_id": command_id,
                        "exit_code": item.exit_code,
                        "duration_ms": duration_ms,
                        "status": item.status,
                        # Phase 20.6 — hint the UI when the failure looks like a
                        # privilege problem (credential lacks permission), so the
                        # operator knows to re-credential / elevate rather than
                        # treating it as a generic error.
                        "permission_error": is_permission_error(
                            "".join(stderr_preview_buf) or "".join(stdout_preview_buf)
                        ),
                    }
        finally:
            finished_at = datetime.now(timezone.utc)
            fd = final_done
            aborted = fd is not None and fd.status == "aborted"
            timed_out = fd is not None and fd.status == "timeout"
            if aborted:
                abort_reason = "user" if abort_event.is_set() else "client_disconnect"
            elif timed_out:
                abort_reason = "timeout"
            else:
                abort_reason = None

            audit_status: str
            if fd is None:
                audit_status = "error"
            elif fd.status == "success":
                audit_status = "ok"
            elif fd.status in ("timeout",):
                audit_status = "timeout"
            else:
                audit_status = "error"

            await write_audit(
                server_id=server_id,
                command=command,
                status=audit_status,  # type: ignore[arg-type]
                started_at=started_at,
                finished_at=finished_at,
                principal_id=principal_id,
                source_ip=source_ip,
                confirmed=confirmed,
                exit_code=fd.exit_code if fd else None,
                stdout="".join(stdout_preview_buf),
                stderr="".join(stderr_preview_buf),
                transport="ws",
                aborted=aborted,
                abort_reason=abort_reason,  # type: ignore[arg-type]
                stream_stats={
                    "bytes_stdout": stdout_total,
                    "bytes_stderr": stderr_total,
                    "chunk_count": chunk_count,
                },
            )
            # Release the pool lock so scheduler can proceed on this server
            await _pool_ctx.__aexit__(None, None, None)