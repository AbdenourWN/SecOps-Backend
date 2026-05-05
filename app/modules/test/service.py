from app.core.database import get_database
from app.core.executors import get_server_executor, DEFAULT_COMMAND_TIMEOUT_S
from app.core.security import decrypt_password
from app.core.datetime_utils import utc_now
from bson import ObjectId
from datetime import timedelta


# ============================================================
# FAKE LOG SCENARIOS — crafted to match existing detection rules
# Uses safe IPs (10.99.99.x) that won't affect real traffic
# ============================================================

LINUX_SYSTEM_SCENARIOS = [
    {
        "name": "ssh_brute_force",
        "description": "Simulates SSH brute force attack from 10.99.99.1",
        "commands": [
            'logger -p auth.warning "Failed password for admin from 10.99.99.1 port 22 ssh2"',
            'logger -p auth.warning "Failed password for root from 10.99.99.1 port 22 ssh2"',
            'logger -p auth.warning "Invalid user hacker from 10.99.99.1 port 22 ssh2"',
        ],
        "triggers_rule": "SSH Brute Force / Failed Login",
    },
    {
        "name": "root_login",
        "description": "Simulates a root login event",
        "commands": [
            'logger -p auth.notice "Accepted password for root from 10.99.99.2 port 22 ssh2"',
            'logger -p auth.info "session opened for user root"',
        ],
        "triggers_rule": "Root Login Detection",
    },
    {
        "name": "oom_kill",
        "description": "Simulates OOM Killer activating",
        "commands": [
            'logger -p kern.crit "Out of memory: Kill process 5678 (java)"',
        ],
        "triggers_rule": "Out of Memory (OOM) Killer",
    },
    {
        "name": "disk_full",
        "description": "Simulates disk space error",
        "commands": [
            'logger -p kern.alert "No space left on device"',
        ],
        "triggers_rule": "Disk Space Critical",
    },
    {
        "name": "new_user",
        "description": "Simulates suspicious user creation",
        "commands": [
            'logger -p auth.warning "new user: name=backdoor_user"',
        ],
        "triggers_rule": "New User Creation",
    },
    {
        "name": "sudo_abuse",
        "description": "Simulates sudo privilege abuse",
        "commands": [
            'logger -p auth.warning "sudo: hacker : user NOT in sudoers"',
        ],
        "triggers_rule": "Sudo Abuse",
    },
]

WINDOWS_SYSTEM_SCENARIOS = [
    {
        "name": "win_failed_logon",
        "description": "Simulates Windows failed logon attempt",
        "commands": [
            "Write-EventLog -LogName Application -Source 'Application' -EventId 4625 -EntryType Warning -Message 'An account failed to log on. Event ID 4625. Source: 10.99.99.1'",
        ],
        "triggers_rule": "Windows Failed Logon",
    },
    {
        "name": "win_service_crash",
        "description": "Simulates Windows service crash",
        "commands": [
            "Write-EventLog -LogName Application -Source 'Application' -EventId 7034 -EntryType Error -Message 'The nginx service terminated unexpectedly. Event ID 7034'",
        ],
        "triggers_rule": "Windows Service Crash",
    },
    {
        "name": "win_suspicious_ps",
        "description": "Simulates suspicious PowerShell execution",
        "commands": [
            "Write-EventLog -LogName Application -Source 'Application' -EventId 1000 -EntryType Warning -Message 'powershell.exe -bypass -hidden -encodedcommand detected'",
        ],
        "triggers_rule": "Suspicious PowerShell Execution",
    },
]

# ─── File-log line generators (called at simulation time so timestamps are live) ─────

def _nginx_lines(now):
    """Nginx combined log format — timestamps with explicit tz offset."""
    entries = [
        # 5 minutes ago — SQL injection attempt → should trigger rule, 200 (info level)
        (now - timedelta(minutes=5), "GET", '/search?q=1+OR+1%3D1', 200, 512),
        # 4 min ago — union select injection, 200
        (now - timedelta(minutes=4), "POST", '/login?user=admin"+union+select+1,2,3--', 200, 234),
        # 3 min ago — internal server error → error level
        (now - timedelta(minutes=3), "GET", '/api/data', 500, 0),
        # 2 min ago — bad gateway → error level
        (now - timedelta(minutes=2), "GET", '/api/users', 502, 0),
        # 1 min ago — service unavailable → error level
        (now - timedelta(minutes=1), "POST", '/api/submit', 503, 0),
        # 30s ago — normal request → info level
        (now - timedelta(seconds=30), "GET", '/index.html', 200, 4523),
        # now — normal request
        (now, "GET", '/static/style.css', 200, 1234),
    ]
    lines = []
    for ts, method, path, status, size in entries:
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'10.99.99.5 - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "secops-test/1.0"'
        )
    return lines


def _apache_lines(now):
    """Apache combined log format — same structure as nginx."""
    entries = [
        (now - timedelta(minutes=6), "GET", '/admin/config', 403, 0),
        (now - timedelta(minutes=5), "POST", '/wp-login.php', 200, 1024),
        (now - timedelta(minutes=3), "GET", '/api/v1/users', 500, 0),
        (now - timedelta(minutes=2), "GET", '/api/v1/data', 502, 0),
        (now - timedelta(minutes=1), "GET", '/health', 200, 18),
    ]
    lines = []
    for ts, method, path, status, size in entries:
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'10.99.99.6 - testuser [{ts_str}] "{method} {path} HTTP/1.1" {status} {size}'
        )
    return lines


def _json_lines(now):
    """Structured JSON logs — timestamp, level, message fields."""
    import json
    entries = [
        (now - timedelta(minutes=5), "error",    "SQL injection attempt detected from 10.99.99.5"),
        (now - timedelta(minutes=4), "warning",  "Failed password for admin from 10.99.99.1"),
        (now - timedelta(minutes=3), "error",    "Uncaught exception: NullPointerException in PaymentService"),
        (now - timedelta(minutes=2), "critical", "Out of memory: Kill process 9821 (java)"),
        (now - timedelta(minutes=1), "warning",  "sudo: hacker : user NOT in sudoers"),
        (now - timedelta(seconds=30),"info",     "Health check OK"),
        (now,                        "info",     "Request handled in 12ms"),
    ]
    lines = []
    for ts, level, message in entries:
        lines.append(json.dumps({
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "level": level,
            "message": message,
            "service": "secops-test",
            "host": "test-server",
        }))
    return lines


def _raw_lines(now):
    """Syslog-style raw lines (RFC 3164 prefix: MMM DD HH:MM:SS)."""
    entries = [
        (now - timedelta(minutes=5), "sshd",    "Failed password for admin from 10.99.99.1 port 22 ssh2"),
        (now - timedelta(minutes=4), "sshd",    "Failed password for root from 10.99.99.1 port 22 ssh2"),
        (now - timedelta(minutes=3), "sshd",    "Accepted password for root from 10.99.99.2 port 22 ssh2"),
        (now - timedelta(minutes=2), "kernel",  "Out of memory: Kill process 5678 (java)"),
        (now - timedelta(minutes=1), "useradd", "new user: name=backdoor_user, UID=1337, GID=1337"),
        (now - timedelta(seconds=45),"sudo",    "hacker : user NOT in sudoers"),
        (now,                        "sshd",    "session opened for user operator"),
    ]
    lines = []
    for ts, process, message in entries:
        ts_str = ts.strftime("%b %d %H:%M:%S").replace("  ", " ")  # single-digit day pad
        lines.append(f"{ts_str} testserver {process}[1234]: {message}")
    return lines


# Map parser_type → (generator_fn, file_suffix, log_source_name)
_PARSER_CONFIGS = {
    "nginx":  (_nginx_lines,  "nginx",  "SecOps Test — Nginx",  "nginx"),
    "apache": (_apache_lines, "apache", "SecOps Test — Apache", "apache"),
    "json":   (_json_lines,   "json",   "SecOps Test — JSON",   "json"),
    "raw":    (_raw_lines,    "raw",    "SecOps Test — Syslog", "raw"),
}


class SimulationService:

    async def _get_server_executor(self, server):
        """Helper: builds executor for a server with credentials."""
        db = get_database()
        cred = await db["credentials"].find_one(
            {"_id": ObjectId(server["credential_id"])}
        )
        if not cred:
            return None

        plain_secret = decrypt_password(cred["encrypted_secret"])
        executor = get_server_executor(server, plain_secret)
        executor.credential["username"] = cred["username"]
        return executor

    async def get_scenarios(self):
        """Returns available simulation scenarios."""
        linux = [
            {"name": s["name"], "description": s["description"], "triggers_rule": s["triggers_rule"]}
            for s in LINUX_SYSTEM_SCENARIOS
        ]
        windows = [
            {"name": s["name"], "description": s["description"], "triggers_rule": s["triggers_rule"]}
            for s in WINDOWS_SYSTEM_SCENARIOS
        ]
        file_log_parsers = list(_PARSER_CONFIGS.keys()) + ["all"]
        return {"linux": linux, "windows": windows, "file_log_parsers": file_log_parsers}

    async def simulate_system_logs(self, server_id: str = None, scenario: str = None):
        """
        Step 1: SSHes into servers and writes fake log entries
        via `logger` (Linux) or `Write-EventLog` (Windows).
        These will be picked up by the scheduler's next log collection cycle.
        """
        db = get_database()

        if server_id:
            try:
                server = await db["servers"].find_one({"_id": ObjectId(server_id)})
            except Exception:
                return {"status": "failed", "error": "Invalid server ID"}
            if not server:
                return {"status": "failed", "error": "Server not found"}
            servers = [server]
        else:
            servers = await db["servers"].find().to_list(length=100)

        if not servers:
            return {"status": "failed", "error": "No servers registered"}

        results = []

        for server in servers:
            os_type = server.get("os_type", "linux")
            hostname = server.get("hostname", server.get("ip_address"))

            if os_type == "windows":
                scenarios = WINDOWS_SYSTEM_SCENARIOS
            else:
                scenarios = LINUX_SYSTEM_SCENARIOS

            if scenario:
                scenarios = [s for s in scenarios if s["name"] == scenario]
                if not scenarios:
                    results.append({
                        "server": hostname,
                        "status": "skipped",
                        "reason": f"Scenario '{scenario}' not available for {os_type}",
                    })
                    continue

            executor = await self._get_server_executor(server)
            if not executor:
                results.append({
                    "server": hostname,
                    "status": "failed",
                    "error": "Could not build executor (missing credentials)",
                })
                continue

            server_result = {
                "server": hostname,
                "os_type": os_type,
                "scenarios_run": [],
                "status": "success",
            }

            for sc in scenarios:
                sc_result = {"name": sc["name"], "triggers_rule": sc["triggers_rule"], "commands_run": 0, "errors": []}

                for cmd in sc["commands"]:
                    result = await executor.run_command(cmd, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)
                    if result["status"] == "success":
                        sc_result["commands_run"] += 1
                    else:
                        sc_result["errors"].append(result.get("error", "Unknown error"))

                server_result["scenarios_run"].append(sc_result)

            results.append(server_result)

        return {
            "status": "success",
            "message": "Fake logs injected. Wait ~60s for the scheduler to collect them.",
            "results": results,
        }

    async def simulate_file_logs(self, server_id: str = None, parser_type: str = "nginx"):
        """
        Writes fake log files to each server and registers a LogSource with the
        matching parser_type so the FileWatcher uses the correct timestamp parser.

        parser_type: "nginx" | "apache" | "json" | "raw" | "all"
          - "all" creates one file + LogSource per parser type in a single call.
        """
        db = get_database()

        if server_id:
            try:
                server = await db["servers"].find_one({"_id": ObjectId(server_id)})
            except Exception:
                return {"status": "failed", "error": "Invalid server ID"}
            if not server:
                return {"status": "failed", "error": "Server not found"}
            servers = [server]
        else:
            servers = await db["servers"].find().to_list(length=100)

        if not servers:
            return {"status": "failed", "error": "No servers registered"}

        pt = parser_type.lower()
        if pt not in _PARSER_CONFIGS and pt != "all":
            return {
                "status": "failed",
                "error": f"Unknown parser_type '{parser_type}'. Use: nginx, apache, json, raw, all",
            }

        parsers_to_run = list(_PARSER_CONFIGS.keys()) if pt == "all" else [pt]
        results = []

        for server in servers:
            os_type = server.get("os_type", "linux")
            hostname = server.get("hostname", server.get("ip_address"))
            sid = str(server["_id"])

            executor = await self._get_server_executor(server)
            if not executor:
                results.append({"server": hostname, "status": "failed", "error": "Could not build executor"})
                continue

            now = utc_now()
            server_result = {"server": hostname, "os_type": os_type, "sources": []}

            for ptype in parsers_to_run:
                gen_fn, file_suffix, source_name, _ = _PARSER_CONFIGS[ptype]
                lines = gen_fn(now)

                # Determine file path per OS
                if os_type == "windows":
                    test_file = f"C:\\\\Temp\\\\secops_test_{file_suffix}.log"
                    lines_ps = "`n".join(line.replace("'", "''") for line in lines)
                    cmd = (
                        f"New-Item -ItemType Directory -Force -Path 'C:\\Temp' | Out-Null; "
                        f"Set-Content -Path '{test_file}' -Value '{lines_ps}'; "
                        f"Write-Output 'Written {len(lines)} lines'"
                    )
                else:
                    test_file = f"/tmp/secops_test_{file_suffix}.log"
                    # Use printf to avoid echo mangling special chars
                    escaped = "\n".join(line.replace("'", "'\\''") for line in lines)
                    cmd = f"printf '%s\\n' '{escaped}' > {test_file} && echo 'Written {len(lines)} lines'"

                write_result = await executor.run_command(cmd, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)

                if write_result["status"] == "failed":
                    server_result["sources"].append({
                        "parser_type": ptype,
                        "status": "failed",
                        "error": write_result.get("error"),
                    })
                    continue

                # Register or update the LogSource with the correct parser_type
                existing = await db["log_sources"].find_one({
                    "server_id": sid,
                    "file_path": test_file,
                })

                # Always delete and recreate so offset, inode and error_count are clean
                if existing:
                    await db["log_sources"].delete_one({"_id": existing["_id"]})

                log_source = {
                    "server_id": sid,
                    "name": source_name,
                    "file_path": test_file,
                    "parser_type": ptype,
                    "last_offset": 0,
                    "last_inode": None,
                    "last_header": None,
                    "error_count": 0,
                    "is_active": True,
                    "created_at": now,
                }
                await db["log_sources"].insert_one(log_source)
                source_status = "replaced" if existing else "created"

                server_result["sources"].append({
                    "parser_type": ptype,
                    "file_path": test_file,
                    "lines_written": len(lines),
                    "log_source": source_status,
                    "status": "success",
                })

            results.append(server_result)

        return {
            "status": "success",
            "message": (
                "Test files written and LogSources registered. "
                "Wait ~60s for the FileWatcher to pick them up. "
                "Timestamps in each file are set to real past times so the parser "
                "extracts the event time rather than the ingestion time."
            ),
            "parsers_tested": parsers_to_run,
            "results": results,
        }
