from app.core.database import get_database
from app.core.executors import get_server_executor, DEFAULT_COMMAND_TIMEOUT_S
from app.core.security import decrypt_password
from bson import ObjectId
from datetime import datetime, timezone


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

# Application-level fake log lines (for file-based injection)
FAKE_APP_LOG_LINES = [
    # SQL Injection attempts
    'GET /search?q=1+OR+1%3D1 HTTP/1.1" 200 1234',
    'POST /login?user=admin" union select 1,2,3-- HTTP/1.1" 200 567',
    # Web server errors
    'GET /api/data HTTP/1.1" 500 0',
    'GET /api/users HTTP/1.1" 502 0',
    'POST /api/submit HTTP/1.1" 503 0',
    # Simulated attack marker (matches the test rule)
    "Hacking Attempt detected from 10.99.99.5",
    # Normal looking logs (should NOT trigger rules)
    'GET /index.html HTTP/1.1" 200 4523',
    'GET /static/style.css HTTP/1.1" 200 1234',
]


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
        return {"linux": linux, "windows": windows}

    async def simulate_system_logs(self, server_id: str = None, scenario: str = None):
        """
        Step 1: SSHes into servers and writes fake log entries
        via `logger` (Linux) or `Write-EventLog` (Windows).
        These will be picked up by the scheduler's next log collection cycle.
        """
        db = get_database()

        # Fetch target servers
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

            # Pick scenarios based on OS
            if os_type == "windows":
                scenarios = WINDOWS_SYSTEM_SCENARIOS
            else:
                scenarios = LINUX_SYSTEM_SCENARIOS

            # Filter to specific scenario if requested
            if scenario:
                scenarios = [s for s in scenarios if s["name"] == scenario]
                if not scenarios:
                    results.append({
                        "server": hostname,
                        "status": "skipped",
                        "reason": f"Scenario '{scenario}' not available for {os_type}",
                    })
                    continue

            # Get executor
            executor = await self._get_server_executor(server)
            if not executor:
                results.append({
                    "server": hostname,
                    "status": "failed",
                    "error": "Could not build executor (missing credentials)",
                })
                continue

            # Execute all commands
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

    async def simulate_file_logs(self, server_id: str = None):
        """
        Step 2 & 3: Creates a test log file on each server,
        writes fake application logs to it, and auto-registers
        a logSource so the FileWatcher picks it up.
        """
        db = get_database()

        # Fetch target servers
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
            sid = str(server["_id"])

            # Determine test file path based on OS
            if os_type == "windows":
                test_file = "C:\\\\Temp\\\\secops_test.log"
                # PowerShell: create directory if needed, then append lines
                lines_escaped = "`n".join(FAKE_APP_LOG_LINES)
                cmd = (
                    f"New-Item -ItemType Directory -Force -Path 'C:\\Temp' | Out-Null; "
                    f"Add-Content -Path '{test_file}' -Value '{lines_escaped}'; "
                    f"Write-Output 'Written {len(FAKE_APP_LOG_LINES)} lines'"
                )
            else:
                test_file = "/tmp/secops_test.log"
                # Bash: append each line
                lines_cmd = " && ".join(
                    [f'echo "{line}" >> {test_file}' for line in FAKE_APP_LOG_LINES]
                )
                cmd = lines_cmd + f" && echo 'Written {len(FAKE_APP_LOG_LINES)} lines'"

            # Get executor
            executor = await self._get_server_executor(server)
            if not executor:
                results.append({
                    "server": hostname,
                    "status": "failed",
                    "error": "Could not build executor",
                })
                continue

            # Write the file
            write_result = await executor.run_command(cmd, timeout_s=DEFAULT_COMMAND_TIMEOUT_S)

            if write_result["status"] == "failed":
                results.append({
                    "server": hostname,
                    "status": "failed",
                    "error": write_result.get("error"),
                })
                continue

            # Auto-register logSource (if not already registered)
            existing = await db["log_sources"].find_one({
                "server_id": sid,
                "file_path": test_file,
            })

            if not existing:
                log_source = {
                    "server_id": sid,
                    "name": "SecOps Test Log",
                    "file_path": test_file,
                    "parser_type": "raw",
                    "last_offset": 0,
                    "last_inode": None,
                    "last_header": None,
                    "error_count": 0,
                    "is_active": True,
                    "created_at": datetime.now(timezone.utc),
                }
                await db["log_sources"].insert_one(log_source)
                source_status = "created"
            else:
                source_status = "already_exists"

            results.append({
                "server": hostname,
                "os_type": os_type,
                "status": "success",
                "file_path": test_file,
                "lines_written": len(FAKE_APP_LOG_LINES),
                "log_source": source_status,
            })

        return {
            "status": "success",
            "message": "Test files written and logSources registered. Wait ~60s for the FileWatcher to pick them up.",
            "results": results,
        }
