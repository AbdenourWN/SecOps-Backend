"""
seed.py — Standalone database seeder for SecOps Backend.

Run once after deploying on a new server to pre-load default scripts and rules.
Safe to re-run: it checks existing data before inserting anything.

Usage:
    cd SecOps-Backend
    source venv/bin/activate        # (Linux) or venv\Scripts\activate (Windows)
    python seed.py
"""

import asyncio
import sys
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME   = os.getenv("DB_NAME", "secops_db")


# ─────────────────────────────────────────────
# SCRIPTS (same data as AutomationService.seed_default_scripts)
# ─────────────────────────────────────────────
DEFAULT_SCRIPTS = [
    # ── Linux ──────────────────────────────────
    {
        "name": "Block IP (iptables)",
        "description": "Blocks an IP address using iptables firewall rules.",
        "language": "bash",
        "target_os": "linux",
        "content": "iptables -A INPUT -s {{source_ip}} -j DROP && echo 'Blocked {{source_ip}}'",
    },
    {
        "name": "Restart Service (systemctl)",
        "description": "Restarts a Linux service via systemctl.",
        "language": "bash",
        "target_os": "linux",
        "content": "systemctl restart {{service_name}} && systemctl status {{service_name}} --no-pager",
    },
    {
        "name": "Kill Process by PID",
        "description": "Force kills a process by its PID.",
        "language": "bash",
        "target_os": "linux",
        "content": "kill -9 {{process_id}} && echo 'Killed process {{process_id}}'",
    },
    {
        "name": "Clear Temp Files",
        "description": "Removes temp files older than 7 days to free disk space.",
        "language": "bash",
        "target_os": "linux",
        "content": "find /tmp -type f -mtime +7 -delete && echo 'Cleaned /tmp' && df -h /",
    },
    # ── Windows ────────────────────────────────
    {
        "name": "Block IP (Windows Firewall)",
        "description": "Blocks an IP using Windows Firewall.",
        "language": "powershell",
        "target_os": "windows",
        "content": "New-NetFirewallRule -DisplayName 'SecOps Block {{source_ip}}' -Direction Inbound -Action Block -RemoteAddress {{source_ip}}; Write-Output 'Blocked {{source_ip}}'",
    },
    {
        "name": "Restart Service (Windows)",
        "description": "Restarts a Windows service.",
        "language": "powershell",
        "target_os": "windows",
        "content": "Restart-Service -Name '{{service_name}}' -Force; Get-Service -Name '{{service_name}}'",
    },
]


# ─────────────────────────────────────────────
# RULES (same data as AnalysisService.seed_default_rules)
# remediation_script_name is resolved to an ID at runtime.
# ─────────────────────────────────────────────
DEFAULT_RULES = [
    # ── Linux ──────────────────────────────────
    {
        "name": "SSH Brute Force / Failed Login",
        "pattern": r"(?i)(?:failed password|authentication failure|invalid user)\s+for\s+(?P<username>\S+)\s+from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})",
        "severity": "medium",
        "action_level": 2,
        "enabled": True,
        "os_type": "linux",
        "tags": ["security", "auth", "ssh"],
        "remediation_script_name": "Block IP (iptables)",
    },
    {
        "name": "Sudo Abuse",
        "pattern": r"(?i)sudo:\s+(?P<username>\S+)\s*:\s*(?:command not found|incorrect password|user NOT in sudoers)",
        "severity": "medium",
        "action_level": 2,
        "enabled": True,
        "os_type": "linux",
        "tags": ["security", "privilege"],
    },
    {
        "name": "Root Login Detection",
        "pattern": r"(?i)accepted password for root|session opened for user root",
        "severity": "high",
        "action_level": 2,
        "enabled": True,
        "os_type": "linux",
        "tags": ["security", "root"],
    },
    {
        "name": "Out of Memory (OOM) Killer",
        "pattern": r"(?i)(?:Out of memory|Kill process)\s+(?P<process_id>\d+)\s+\((?P<process_name>\S+)\)",
        "severity": "critical",
        "action_level": 2,
        "enabled": True,
        "os_type": "linux",
        "tags": ["system", "stability", "memory"],
        "remediation_script_name": "Kill Process by PID",
    },
    {
        "name": "Disk Space Critical",
        "pattern": r"(?i)(No space left on device|I/O error|EXT4-fs error)",
        "severity": "critical",
        "action_level": 2,
        "enabled": True,
        "os_type": "linux",
        "tags": ["system", "storage"],
        "remediation_script_name": "Clear Temp Files",
    },
    {
        "name": "New User Creation",
        "pattern": r"(?i)(?:new user|new group): name=(?P<username>\S+)",
        "severity": "medium",
        "action_level": 3,
        "enabled": True,
        "os_type": "linux",
        "tags": ["security", "persistence"],
    },
    # ── Windows ────────────────────────────────
    {
        "name": "Windows Failed Logon",
        "pattern": r"(?i)(?:audit failure|an account failed to log on|event id 4625)",
        "severity": "medium",
        "action_level": 2,
        "enabled": True,
        "os_type": "windows",
        "tags": ["security", "auth"],
        "remediation_script_name": "Block IP (Windows Firewall)",
    },
    {
        "name": "Windows Defender Malware Detected",
        "pattern": r"(?i)(?:windows defender|antimalware).*(?:detected|malware|threat)",
        "severity": "critical",
        "action_level": 3,
        "enabled": True,
        "os_type": "windows",
        "tags": ["security", "malware"],
    },
    {
        "name": "Windows Service Crash",
        "pattern": r"(?i)(?:service terminated unexpectedly|service hung|event id 7034)",
        "severity": "high",
        "action_level": 2,
        "enabled": True,
        "os_type": "windows",
        "tags": ["system", "stability"],
        "remediation_script_name": "Restart Service (Windows)",
    },
    {
        "name": "Suspicious PowerShell Execution",
        "pattern": r"(?i)(?:powershell).*(?:bypass|hidden|encodedcommand|downloadstring)",
        "severity": "high",
        "action_level": 2,
        "enabled": True,
        "os_type": "windows",
        "tags": ["security", "execution"],
    },
    {
        "name": "Windows Security Log Cleared",
        "pattern": r"(?i)(?:audit log was cleared|event id 1102)",
        "severity": "critical",
        "action_level": 2,
        "enabled": True,
        "os_type": "windows",
        "tags": ["security", "evasion"],
    },
    # ── Common / Web ───────────────────────────
    {
        "name": "Web Server 500 Error Flood",
        "pattern": r"HTTP\/1\.[01].*\" 50[0-9] ",
        "severity": "medium",
        "action_level": 3,
        "enabled": True,
        "os_type": "common",
        "tags": ["app", "web"],
    },
    {
        "name": "SQL Injection Attempt",
        "pattern": r"(?i)(union select|OR 1=1|drop table|information_schema|waitfor delay)",
        "severity": "critical",
        "action_level": 2,
        "enabled": True,
        "os_type": "common",
        "tags": ["security", "web", "sqli"],
        "remediation_script_name": "Block IP (iptables)",
    },
    {
        "name": "Simulated Attack",
        "pattern": "Hacking Attempt",
        "severity": "critical",
        "action_level": 1,
        "enabled": True,
        "os_type": "common",
        "tags": ["test"],
        "remediation_script_name": "Block IP (iptables)",
    },
]


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _header(title: str):
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")


async def _verify_scripts(db) -> dict:
    """Returns a name→id map of all scripts currently in the DB."""
    docs = await db["scripts"].find({}, {"name": 1}).to_list(length=200)
    return {d["name"]: str(d["_id"]) for d in docs}


async def _verify_rules(db) -> list[str]:
    """Returns list of rule names currently in the DB."""
    docs = await db["rules"].find({}, {"name": 1}).to_list(length=200)
    return [d["name"] for d in docs]


# ─────────────────────────────────────────────
# SEEDERS
# ─────────────────────────────────────────────

async def seed_scripts(db) -> dict:
    """
    Inserts scripts that don't already exist (matched by name).
    Returns the full name→id map after seeding.
    """
    _header("Scripts")

    existing = await _verify_scripts(db)

    if existing:
        print(f"  Found {len(existing)} existing script(s):")
        for name in existing:
            print(f"    ✓  {name}")
    else:
        print("  No scripts found — inserting defaults.")

    to_insert = [
        s for s in DEFAULT_SCRIPTS if s["name"] not in existing
    ]

    if not to_insert:
        print("  Nothing to insert — all default scripts already present.")
        return existing

    now = datetime.now(timezone.utc)
    for s in to_insert:
        s["created_at"] = now
        s["updated_at"] = now

    result = await db["scripts"].insert_many(to_insert)

    print(f"\n  Inserted {len(result.inserted_ids)} new script(s):")
    for s in to_insert:
        print(f"    +  {s['name']}")

    # Return refreshed map so rules can resolve IDs
    return await _verify_scripts(db)


async def seed_rules(db, script_lookup: dict):
    """
    Inserts rules that don't already exist (matched by name).
    Resolves remediation_script_name → _id using script_lookup.
    """
    _header("Rules")

    existing_names = await _verify_rules(db)

    if existing_names:
        print(f"  Found {len(existing_names)} existing rule(s):")
        for name in existing_names:
            print(f"    ✓  {name}")
    else:
        print("  No rules found — inserting defaults.")

    to_insert = [
        r for r in DEFAULT_RULES if r["name"] not in existing_names
    ]

    if not to_insert:
        print("  Nothing to insert — all default rules already present.")
        return

    unresolved = []
    for rule in to_insert:
        script_name = rule.pop("remediation_script_name", None)
        if script_name:
            script_id = script_lookup.get(script_name)
            if script_id:
                rule["remediation_script_id"] = script_id
            else:
                unresolved.append((rule["name"], script_name))

    await db["rules"].insert_many(to_insert)

    linked   = sum(1 for r in to_insert if r.get("remediation_script_id"))
    unlinked = len(to_insert) - linked

    print(f"\n  Inserted {len(to_insert)} new rule(s):")
    for r in to_insert:
        script_id = r.get("remediation_script_id", "—")
        link_tag  = f"→ script {script_id}" if r.get("remediation_script_id") else "(no remediation)"
        print(f"    +  {r['name']}  {link_tag}")

    if unresolved:
        print(f"\n  WARNING — {len(unresolved)} script(s) not found for linking:")
        for rule_name, script_name in unresolved:
            print(f"    ?  Rule '{rule_name}' expected script '{script_name}'")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

async def main():
    print(f"\n{'=' * 50}")
    print(f"  SecOps DB Seeder")
    print(f"  Target: {MONGO_URI}  DB: {DB_NAME}")
    print(f"{'=' * 50}")

    client = AsyncIOMotorClient(MONGO_URI)

    try:
        await client.admin.command("ping")
        print("\n  MongoDB connection OK")
    except Exception as e:
        print(f"\n  ERROR: Cannot connect to MongoDB — {e}")
        client.close()
        sys.exit(1)

    db = client[DB_NAME]

    # Scripts must be seeded first — rules reference their IDs
    script_lookup = await seed_scripts(db)
    await seed_rules(db, script_lookup)

    # ── Final summary ──────────────────────────
    _header("Summary")
    scripts_total = await db["scripts"].count_documents({})
    rules_total   = await db["rules"].count_documents({})
    rules_linked  = await db["rules"].count_documents(
        {"remediation_script_id": {"$exists": True}}
    )
    print(f"  Scripts : {scripts_total}")
    print(f"  Rules   : {rules_total}  ({rules_linked} linked to a script)")
    print()

    client.close()


if __name__ == "__main__":
    asyncio.run(main())
