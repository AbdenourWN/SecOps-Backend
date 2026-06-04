"""
seed.py — Standalone database seeder for SecOps Backend.

Run manually after deploying or when you want to populate / refresh defaults.
The backend never auto-seeds on startup — this file is the single source of truth.

Usage:
    cd SecOps-Backend
    source venv/bin/activate        # (Linux) or venv\\Scripts\\activate (Windows)
    python seed.py

Safe to re-run: per-name idempotent inserts. Existing documents are never modified.
"""

import asyncio
import re as _re
import sys
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME   = os.getenv("DB_NAME", "secops_db")


# =============================================================================
# SCRIPTS  (23 total)
# Fields: name, description, language, target_os, category, enabled, content
# category: "diagnostic" | "containment" | "recovery"
# =============================================================================

DEFAULT_SCRIPTS = [

    # ── DIAGNOSTIC (read-only, zero risk) ────────────────────────────────────

    {
        "name": "Capture Process Snapshot (Linux)",
        "description": "Read-only snapshot of running processes sorted by CPU/memory. Captures forensic state at incident time for triage — does NOT kill or modify anything.",
        "language": "bash", "target_os": "linux", "category": "diagnostic", "enabled": True,
        "content": "echo '=== TOP PROCESSES (CPU) ===' && ps auxf --sort=-%cpu | head -30 && echo '' && echo '=== MEMORY ===' && free -h && echo '' && echo '=== LOAD ===' && uptime",
    },
    {
        "name": "Capture Process Snapshot (Windows)",
        "description": "Read-only snapshot of running processes sorted by CPU/memory. Captures forensic state at incident time for triage — does NOT kill or modify anything.",
        "language": "powershell", "target_os": "windows", "category": "diagnostic", "enabled": True,
        "content": "Write-Output '=== TOP PROCESSES (CPU) ==='; Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Name,Id,CPU,WorkingSet | Format-Table; Write-Output '=== MEMORY ==='; Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List",
    },
    {
        "name": "Capture Network Connections (Linux)",
        "description": "Read-only snapshot of all established TCP/UDP connections with process ownership. Useful for detecting C2 channels or lateral movement.",
        "language": "bash", "target_os": "linux", "category": "diagnostic", "enabled": True,
        "content": "echo '=== ESTABLISHED CONNECTIONS ===' && ss -tupn state established && echo '' && echo '=== LISTENING PORTS ===' && ss -tlnp",
    },
    {
        "name": "Capture Network Connections (Windows)",
        "description": "Read-only snapshot of all TCP connections and listening ports. Useful for detecting C2 channels or lateral movement.",
        "language": "powershell", "target_os": "windows", "category": "diagnostic", "enabled": True,
        "content": "Write-Output '=== ESTABLISHED ==='; Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table; Write-Output '=== LISTENING ==='; Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table",
    },
    {
        "name": "Capture Recent Auth (Linux)",
        "description": "Read-only list of the last 20 successful and 10 failed logins. Useful for tracing credential abuse and privilege escalation.",
        "language": "bash", "target_os": "linux", "category": "diagnostic", "enabled": True,
        "content": "echo '=== LAST LOGINS ===' && last -n 20 && echo '' && echo '=== FAILED LOGINS ===' && lastb -n 10 2>/dev/null || echo '(no lastb data)'",
    },
    {
        "name": "Capture Recent Auth (Windows)",
        "description": "Read-only list of recent successful (4624) and failed (4625) logon events from the Security log.",
        "language": "powershell", "target_os": "windows", "category": "diagnostic", "enabled": True,
        "content": "Get-WinEvent -LogName Security -MaxEvents 30 -FilterXPath \"*[System[EventID=4624 or EventID=4625]]\" -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | Format-List",
    },
    {
        "name": "Capture Scheduled Jobs (Linux)",
        "description": "Read-only listing of all crontabs and systemd timers. Useful for detecting persistence via scheduled tasks.",
        "language": "bash", "target_os": "linux", "category": "diagnostic", "enabled": True,
        "content": "echo '=== CRONTABS ===' && for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u $u 2>/dev/null && echo \"--- $u ---\"; done; echo '' && echo '=== SYSTEMD TIMERS ===' && systemctl list-timers --all 2>/dev/null | head -30",
    },
    {
        "name": "Capture Scheduled Jobs (Windows)",
        "description": "Read-only listing of all non-disabled scheduled tasks. Useful for detecting persistence via WMI or task scheduler.",
        "language": "powershell", "target_os": "windows", "category": "diagnostic", "enabled": True,
        "content": "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName,TaskPath,State,Author | Format-Table -AutoSize",
    },

    # ── CONTAINMENT (reversible, targeted) ───────────────────────────────────

    {
        "name": "Block IP (iptables)",
        "description": "Adds an iptables INPUT DROP rule for the specified source IP. Reversible with: iptables -D INPUT -s <ip> -j DROP. Requires root/sudo.",
        "language": "bash", "target_os": "linux", "category": "containment", "enabled": True,
        "content": "iptables -A INPUT -s {{source_ip}} -j DROP && echo 'Blocked {{source_ip}} on {{hostname}}'",
    },
    {
        "name": "Block IP (Windows Firewall)",
        "description": "Creates a Windows Firewall inbound block rule for the specified source IP. Reversible by removing the rule via Firewall settings or Remove-NetFirewallRule.",
        "language": "powershell", "target_os": "windows", "category": "containment", "enabled": True,
        "content": "New-NetFirewallRule -DisplayName 'SecOps Block {{source_ip}}' -Direction Inbound -Action Block -RemoteAddress {{source_ip}} -ErrorAction SilentlyContinue; Write-Output 'Blocked {{source_ip}} on {{hostname}}'",
    },
    {
        "name": "Disable User Account (Linux)",
        "description": "Locks the specified user account with usermod -L (password-based login disabled). Reversible with: usermod -U <username>. Does NOT delete the account.",
        "language": "bash", "target_os": "linux", "category": "containment", "enabled": True,
        "content": "usermod -L {{username}} && echo 'Locked account {{username}} on {{hostname}}'",
    },
    {
        "name": "Disable User Account (Windows)",
        "description": "Disables the specified local user account. Reversible with: Enable-LocalUser -Name <username>. Does NOT delete the account.",
        "language": "powershell", "target_os": "windows", "category": "containment", "enabled": True,
        "content": "Disable-LocalUser -Name '{{username}}' -ErrorAction SilentlyContinue; Get-LocalUser -Name '{{username}}' | Select-Object Name,Enabled",
    },
    {
        "name": "Revoke User Sessions (Linux)",
        "description": "Force-terminates all active sessions for the specified user (pkill by username). The user can log back in unless the account is also disabled.",
        "language": "bash", "target_os": "linux", "category": "containment", "enabled": True,
        "content": "pkill -KILL -u {{username}} 2>&1 && echo 'Sessions terminated for {{username}}' || echo 'No active sessions for {{username}}'",
    },
    {
        "name": "Revoke User Sessions (Windows)",
        "description": "Terminates all active Remote Desktop / interactive logon sessions for the specified user. The user can re-authenticate unless the account is also disabled.",
        "language": "powershell", "target_os": "windows", "category": "containment", "enabled": True,
        "content": "$sessions = query user 2>$null | Select-String '{{username}}'; if ($sessions) { $sessions | ForEach-Object { $id = ($_ -split '\\s+')[3]; logoff $id }; Write-Output 'Sessions terminated for {{username}}' } else { Write-Output 'No active sessions for {{username}}' }",
    },

    # ── RECOVERY (restorative, minor impact) ─────────────────────────────────

    {
        "name": "Restart Service (systemctl)",
        "description": "Restarts the specified systemd service and prints its new status. Use for service crashes or unresponsive daemons.",
        "language": "bash", "target_os": "linux", "category": "recovery", "enabled": True,
        "content": "systemctl restart {{service_name}} && systemctl status {{service_name}} --no-pager -l",
    },
    {
        "name": "Restart Service (Windows)",
        "description": "Restarts the specified Windows service and confirms its new state. Use for service crashes or hangs.",
        "language": "powershell", "target_os": "windows", "category": "recovery", "enabled": True,
        "content": "Restart-Service -Name '{{service_name}}' -Force -ErrorAction SilentlyContinue; Get-Service -Name '{{service_name}}' | Select-Object Name,Status",
    },
    {
        "name": "Flush DNS Cache (Linux)",
        "description": "Flushes the system DNS resolver cache. Helps after DNS poisoning or to force re-resolution of recently changed records.",
        "language": "bash", "target_os": "linux", "category": "recovery", "enabled": True,
        "content": "resolvectl flush-caches 2>/dev/null && echo 'DNS cache flushed' || (systemd-resolve --flush-caches 2>/dev/null && echo 'DNS cache flushed') || echo 'DNS flush not available'",
    },
    {
        "name": "Flush DNS Cache (Windows)",
        "description": "Flushes the Windows DNS resolver cache. Helps after DNS poisoning or to force re-resolution of recently changed records.",
        "language": "powershell", "target_os": "windows", "category": "recovery", "enabled": True,
        "content": "ipconfig /flushdns",
    },
    {
        "name": "Clear Temp Files (Linux)",
        "description": "Deletes files in /tmp older than 7 days. Low risk — only targets time-bounded temp files. Frees disk space after a space-critical alert.",
        "language": "bash", "target_os": "linux", "category": "recovery", "enabled": True,
        "content": "find /tmp -type f -mtime +7 -delete 2>/dev/null; echo 'Temp files older than 7 days removed'; df -h /",
    },
    {
        "name": "Clear Temp Files (Windows)",
        "description": "Deletes files in %TEMP% older than 7 days. Low risk — only targets time-bounded temp files. Frees disk space after a space-critical alert.",
        "language": "powershell", "target_os": "windows", "category": "recovery", "enabled": True,
        "content": "Get-ChildItem $env:TEMP -Recurse -ErrorAction SilentlyContinue | Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue; Write-Output 'Old temp files removed'; Get-PSDrive C | Select-Object Used,Free",
    },
    {
        "name": "Kill Process by PID (Linux)",
        "description": "Force-kills a process by the PID captured from the alert (e.g., OOM Killer events). Only use when the PID is reliably extracted from the incident context.",
        "language": "bash", "target_os": "linux", "category": "containment", "enabled": True,
        "content": "kill -9 {{process_id}} 2>&1 && echo 'Killed process {{process_id}} on {{hostname}}' || echo 'Process {{process_id}} not found'",
    },
]


# =============================================================================
# RULES  (55 total)
# Fields: name, description, pattern, severity, action_level, enabled, os_type,
#         tags, remediation_script_name (→ Linux/default), remediation_script_name_windows
# =============================================================================

DEFAULT_RULES = [

    # ──────────────────────────────────────────────────────────────────────────
    # LINUX — Authentication & Privilege (6)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "SSH Brute Force / Failed Login",
        "description": "Repeated SSH authentication failures indicate a brute-force or credential-stuffing attack. The source IP and targeted username are extracted for automated blocking.",
        "pattern": r"(?i)(?:failed password|authentication failure|invalid user)\s+for\s+(?P<username>\S+)\s+from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})",
        "severity": "medium", "action_level": 2, "enabled": True, "os_type": "linux",
        "tags": ["security", "auth", "ssh"],
        "remediation_script_name": "Block IP (iptables)",
    },
    {
        "name": "Sudo Abuse / Privilege Escalation",
        "description": "A user attempted a privileged sudo command they are not authorised to run, entered a wrong password, or was not found in the sudoers file. Indicates potential privilege escalation.",
        "pattern": r"(?i)sudo:\s+(?P<username>\S+)\s*:\s*(?:command not found|incorrect password attempt|user NOT in sudoers|not allowed to run sudo)",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "privilege"],
    },
    {
        "name": "Root Login Detected",
        "description": "A direct login as root was accepted via SSH or a root session was opened. Root logins bypass normal audit trails and should be investigated immediately.",
        "pattern": r"(?i)(?:accepted password for root|session opened for user root)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "root"],
    },
    {
        "name": "New User Account Created",
        "description": "A new user account was added to the system. Could indicate legitimate administration or attacker persistence (backdoor account).",
        "pattern": r"(?i)(?:new user|useradd).*?(?:name=|user ')(?P<username>\S+)",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "persistence"],
    },
    {
        "name": "FTP Brute Force Attempt",
        "description": "Repeated FTP authentication failures from a single IP suggest a brute-force attack against FTP credentials.",
        "pattern": r"(?i)(?:vsftpd|proftpd|pure-ftpd|ftpd).*?(?:failed|bad|invalid).*?(?:login|password|authentication).*?from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})",
        "severity": "medium", "action_level": 2, "enabled": True, "os_type": "linux",
        "tags": ["security", "auth", "ftp"],
        "remediation_script_name": "Block IP (iptables)",
    },
    {
        "name": "PAM Account Lockout",
        "description": "A user account was locked by PAM due to too many failed authentication attempts. Indicates either an attack or a misconfigured service.",
        "pattern": r"(?i)pam.*?(?:account locked|user locked out|too many failures|maximum.*failures).*?user\s+(?P<username>\S+)",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "auth"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # LINUX — Execution & Persistence (5)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Crontab Modified",
        "description": "A crontab entry was edited, replaced, or a new cron job was created. Attackers frequently use cron for persistence.",
        "pattern": r"(?i)(?:cron|crontab).*?(?P<username>\S+).*?(?:edited|new crontab|replace|BEGIN EDIT|END EDIT)",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "persistence"],
    },
    {
        "name": "New Systemd Service Created",
        "description": "A new systemd service unit was enabled or started. Attackers install services for persistent code execution.",
        "pattern": r"(?i)systemd.*?(?:created symlink|enabled|loaded).*?(?P<service_name>\S+\.service)",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "persistence"],
    },
    {
        "name": "SSH Authorized Key Added",
        "description": "A new SSH public key was added to an authorized_keys file. This can provide persistent password-less access for an attacker.",
        "pattern": r"(?i)(?:authorized_keys.*added|ssh.*public key.*added|key.*authorized).*?(?:for|user)\s+(?P<username>\S+)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "persistence", "ssh"],
    },
    {
        "name": "SUID Binary Created or Modified",
        "description": "A file's SUID/SGID bit was set. Attackers create SUID binaries as a privilege escalation mechanism.",
        "pattern": r"(?i)(?:chmod.*[ug]\+s|chmod.*[24][0-7]{3,})\s+(?P<path>\S+)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "privilege", "persistence"],
    },
    {
        "name": "Kernel Module Loaded",
        "description": "A kernel module was dynamically loaded. Rootkits often hide themselves as kernel modules. Review the module name.",
        "pattern": r"(?i)(?:insmod|modprobe|kernel:.*loading module)\s+(?P<module_name>\S+)",
        "severity": "high", "action_level": 2, "enabled": True, "os_type": "linux",
        "tags": ["security", "rootkit", "kernel"],
        "remediation_script_name": "Capture Process Snapshot (Linux)",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # LINUX — Defense Evasion (3)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Bash History Cleared",
        "description": "A user cleared or disabled shell command history. This is a strong indicator of an attacker covering their tracks post-compromise.",
        "pattern": r"(?i)(?:history\s+-c|unset\s+HISTFILE|HISTSIZE\s*=\s*0|truncate.*bash_history|>\s*~/\.bash_history)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "evasion"],
    },
    {
        "name": "Auditd / Logging Service Stopped",
        "description": "The audit daemon or a key logging service was stopped or disabled. Attackers often disable audit logging before or during an attack.",
        "pattern": r"(?i)(?:auditd|audit\s+daemon|rsyslog|syslog).*?(?:stopped|disabled|killed|failed|service.*failed)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "evasion"],
    },
    {
        "name": "Firewall Rules Flushed",
        "description": "iptables or nftables rules were completely flushed, removing all existing firewall protections. This may precede an attack or be part of one.",
        "pattern": r"(?i)(?:iptables\s+.*-F\b|nft\s+flush|iptables-restore.*--flush)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["security", "evasion", "network"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # LINUX — System & Stability (6)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "OOM Killer Activated",
        "description": "The kernel Out-of-Memory killer terminated a process due to memory exhaustion. Could indicate a memory leak, resource abuse, or DoS attack.",
        "pattern": r"(?i)(?:Out of memory|Kill process|oom_kill_process)\s+(?P<process_id>\d+)\s+\((?P<process_name>[^)]+)\)",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "linux",
        "tags": ["system", "stability", "memory"],
        "remediation_script_name": "Capture Process Snapshot (Linux)",
    },
    {
        "name": "Disk Space Critical",
        "description": "The filesystem is full or reported an I/O error. The recovery script removes temp files older than 7 days to free space.",
        "pattern": r"(?i)(?:No space left on device|EXT4-fs error|I\/O error.*(?:dev|disk)|filesystem.*full)",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "linux",
        "tags": ["system", "storage"],
        "remediation_script_name": "Clear Temp Files (Linux)",
    },
    {
        "name": "Kernel Panic",
        "description": "The Linux kernel encountered a fatal, unrecoverable error (panic). The server may reboot or halt. Immediate investigation is required.",
        "pattern": r"(?i)(?:Kernel panic|kernel BUG at|general protection fault|Oops:.*\[#)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["system", "stability", "kernel"],
    },
    {
        "name": "Hardware / MCE Error",
        "description": "A Machine Check Exception (MCE) indicates a hardware error (CPU, memory, bus). Repeated MCEs suggest failing hardware.",
        "pattern": r"(?i)(?:mce:.*error|hardware error|Machine Check Exception|EDAC.*CE|corrected.*machine check)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["system", "hardware"],
    },
    {
        "name": "SMART Disk Failure Warning",
        "description": "S.M.A.R.T. reported a reallocated sector, pending sector, or uncorrectable error. The disk is likely failing and data may be at risk.",
        "pattern": r"(?i)(?:smartd|SMART.*error|reallocated sector|pending sector|uncorrectable.*error|ATA.*error|ata.*failed command)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["system", "hardware", "storage"],
    },
    {
        "name": "Swap / Memory Pressure",
        "description": "The system is under critical memory pressure and is actively swapping. This severely degrades performance and may indicate resource exhaustion or attack.",
        "pattern": r"(?i)(?:kswapd.*consuming|memory pressure.*critical|swap.*exhausted|out of swap|oom.*pressure)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "linux",
        "tags": ["system", "stability", "memory"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # WINDOWS — Authentication (5)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Windows Failed Logon (Event 4625)",
        "description": "A Windows account failed to authenticate. Repeated failures from the same source indicate brute-force or credential stuffing. A forensic auth capture is triggered.",
        "pattern": r"(?i)(?:an account failed to log on|audit failure|event id.*4625)",
        "severity": "medium", "action_level": 2, "enabled": True, "os_type": "windows",
        "tags": ["security", "auth"],
        "remediation_script_name_windows": "Capture Recent Auth (Windows)",
    },
    {
        "name": "Windows Account Lockout (Event 4740)",
        "description": "A Windows user account was locked out after exceeding the failed-attempt threshold. May indicate a brute-force attack or a misconfigured service.",
        "pattern": r"(?i)(?:an account was locked out|event id.*4740)(?:.*account name[:\s]+(?P<username>\S+))?",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "auth"],
    },
    {
        "name": "Kerberos Pre-Authentication Failure (Event 4771)",
        "description": "A Kerberos authentication request failed. High volumes from a single IP indicate password spraying or Kerberos brute force.",
        "pattern": r"(?i)(?:kerberos.*pre-authentication failed|pre-authentication.*failed|event id.*4771)(?:.*client address[:\s]+(?P<source_ip>[\d.]+))?",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "auth", "kerberos"],
    },
    {
        "name": "Explicit Credential Use (Event 4648)",
        "description": "A logon was attempted using explicitly supplied credentials (RunAs, WMI, remote commands). Common in lateral movement and pass-the-hash attacks.",
        "pattern": r"(?i)(?:a logon was attempted using explicit credentials|event id.*4648)(?:.*account name[:\s]+(?P<username>\S+))?",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "lateral-movement"],
    },
    {
        "name": "New Local Admin Added (Event 4732)",
        "description": "A member was added to the local Administrators group. Attackers add accounts to privileged groups for persistence.",
        "pattern": r"(?i)(?:a member was added to a security-enabled.*group|event id.*4732)(?:.*member.*account name[:\s]+(?P<username>\S+))?",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "privilege", "persistence"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # WINDOWS — Credential Access & Malware (4)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Windows Defender Malware Detected",
        "description": "Windows Defender or another AV engine detected, quarantined, or removed a threat. Review the threat name and affected path.",
        "pattern": r"(?i)(?:windows defender|antimalware|security intelligence).*?(?:detected|found|quarantined|removed|threat)(?:.*?threat name[:\s]+(?P<threat_name>[^\r\n,]+))?",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "malware"],
    },
    {
        "name": "LSASS Memory Access (Credential Dump Indicator)",
        "description": "Suspicious access to the LSASS process memory was detected. This is a primary indicator of credential dumping tools like Mimikatz.",
        "pattern": r"(?i)(?:lsass.*access|lsass.*memory|local security authority.*process.*access|event id.*4656.*lsass)",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "windows",
        "tags": ["security", "credential-access"],
        "remediation_script_name_windows": "Capture Process Snapshot (Windows)",
    },
    {
        "name": "AMSI Bypass Attempt",
        "description": "The Antimalware Scan Interface (AMSI) was bypassed or disabled. Attackers bypass AMSI to execute obfuscated scripts without detection.",
        "pattern": r"(?i)(?:amsi.*bypass|amsicontext|AmsiScanBuffer|amsi.*disabled|[Aa]msi[Ii]nitialize.*fail)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "evasion", "malware"],
    },
    {
        "name": "Mimikatz / Credential Dumping Keywords",
        "description": "Keywords associated with the Mimikatz credential-theft framework were detected in logs. Investigate immediately.",
        "pattern": r"(?i)(?:mimikatz|sekurlsa|lsadump|kerberos::ptc|pass[- ]the[- ]hash|pass[- ]the[- ]ticket|golden ticket|wce\.exe|fgdump)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "credential-access", "malware"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # WINDOWS — Execution & Persistence (4)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Suspicious PowerShell Execution",
        "description": "PowerShell was invoked with flags or techniques commonly used to execute hidden or obfuscated payloads (bypass, encoded commands, download cradles).",
        "pattern": r"(?i)powershell.*(?:-[Ee][Nn][Cc](?:oded)?[Cc]ommand\b|[Bb]ypass|[Ww]indow[Ss]tyle.*[Hh]idden|[Dd]ownload[Ss]tring|[Ii][Ee][Xx]\b|[Ii]nvoke-[Ee]xpression|[Ff]rom[Bb]ase64[Ss]tring|[Nn]ew-[Oo]bject.*[Ww]eb[Cc]lient)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "execution", "evasion"],
    },
    {
        "name": "Scheduled Task Created (Event 4698)",
        "description": "A new scheduled task was registered. Attackers create scheduled tasks for persistence and code execution.",
        "pattern": r"(?i)(?:a scheduled task was created|event id.*4698|Register-ScheduledTask|schtasks.*\/create)(?:.*task name[:\s]+(?P<task_name>[^\r\n]+))?",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "persistence"],
    },
    {
        "name": "Registry Run Key Modified",
        "description": "A registry autorun key was modified. This is one of the most common Windows persistence techniques.",
        "pattern": r"(?i)(?:SetValue|RegSetValue|registry.*write).*?(?:HKLM|HKCU).*?(?:Run|RunOnce|RunServices|Winlogon)(?:.*?(?P<key>[^\r\n]+))?",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "persistence", "registry"],
    },
    {
        "name": "WMI Persistence Installed",
        "description": "A WMI event subscription (filter + consumer + binding) was created. This is a stealthy, fileless persistence technique.",
        "pattern": r"(?i)(?:__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding|wmic.*\/namespace.*subscription)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "persistence", "wmi"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # WINDOWS — Defense Evasion (4)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Windows Defender Disabled",
        "description": "Windows Defender real-time protection was disabled. This is a common attacker technique to avoid detection before deploying malware.",
        "pattern": r"(?i)(?:windows defender.*disabled|real.?time protection.*(?:turned off|disabled)|MpCmdRun.*disable|DisableRealtimeMonitoring.*true)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "evasion", "defense"],
    },
    {
        "name": "Windows Firewall Profile Disabled",
        "description": "A Windows Firewall profile (Domain, Private, or Public) was disabled. Removing the firewall exposes the host to direct attacks.",
        "pattern": r"(?i)(?:windows firewall.*(?:disabled|turned off)|Set-NetFirewallProfile.*-Enabled.*False|netsh.*firewall.*off|netsh.*advfirewall.*off)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "evasion", "network"],
    },
    {
        "name": "Windows Event Log Service Stopped",
        "description": "The Windows Event Log service was stopped, preventing further audit trail collection. This is a strong attacker anti-forensics indicator.",
        "pattern": r"(?i)(?:windows event log.*stopped|event log service.*stopped|wevtutil.*clear|Stop-Service.*EventLog)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "evasion"],
    },
    {
        "name": "Windows Security Log Cleared (Event 1102)",
        "description": "The Windows Security audit log was cleared. This event only fires when the log is explicitly cleared, which is uncommon in normal operation.",
        "pattern": r"(?i)(?:audit log was cleared|the security log was cleared|event id.*1102)(?:.*account name[:\s]+(?P<username>\S+))?",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["security", "evasion"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # WINDOWS — System & Stability (3)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Windows Service Crash (Event 7034)",
        "description": "A Windows service terminated unexpectedly. Repeated crashes may indicate a bug, resource exhaustion, or an attacker stopping security services.",
        "pattern": r"(?i)(?:service terminated unexpectedly|event id.*7034|service.*stopped unexpectedly)(?:.*?service\s+(?P<service_name>[^.\r\n]+?)(?:\s+(?:terminated|stopped)|\.))?",
        "severity": "high", "action_level": 2, "enabled": True, "os_type": "windows",
        "tags": ["system", "stability"],
        "remediation_script_name_windows": "Capture Process Snapshot (Windows)",
    },
    {
        "name": "BSOD / Kernel-Power Critical (Event 41)",
        "description": "Windows recorded a critical kernel-power event (dirty reboot / BSOD). Investigate minidump for the stop code and root cause.",
        "pattern": r"(?i)(?:kernel.power.*event id.*41|critical.*process.*died|memory.management.*blue|bugcheck.*0x|WHEA-Logger|machine check exception|page_fault_in_nonpaged)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["system", "stability", "kernel"],
    },
    {
        "name": "Critical Process Terminated (Event 4108)",
        "description": "A critical system process (e.g., csrss.exe, lsass.exe) terminated unexpectedly. This can indicate malware, a crash, or an active attack.",
        "pattern": r"(?i)(?:critical process.*died|event id.*4108|csrss.*terminated|wininit.*terminated|services\.exe.*terminated)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "windows",
        "tags": ["system", "stability"],
    },

    # ──────────────────────────────────────────────────────────────────────────
    # COMMON / Web / Cross-platform (15)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "Simulated Attack",
        "description": "A test rule that fires on the phrase 'Hacking Attempt'. Used for end-to-end testing of the detection-to-remediation pipeline. The source IP must be present in the log line.",
        "pattern": r"(?i)Hacking Attempt.*?from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})",
        "severity": "critical", "action_level": 1, "enabled": True, "os_type": "common",
        "tags": ["test"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "SQL Injection Attempt",
        "description": "SQL injection keywords were detected in an HTTP request from a known source IP. Works best with web access logs where the client IP starts the log line.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?i)(?:union\s+select|OR\s+1\s*=\s*1|drop\s+table|information_schema|waitfor\s+delay|benchmark\s*\(|sleep\s*\(\d)",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "web", "sqli"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "XSS Attempt",
        "description": "Cross-Site Scripting payload detected in an HTTP request. The script/event handler injection keywords indicate an attempt to inject malicious JavaScript.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?i)(?:<script|javascript:|onerror\s*=|onload\s*=|onfocus\s*=|eval\s*\(|document\.cookie|window\.location|alert\s*\(.*xss)",
        "severity": "high", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "web", "xss"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "Path Traversal Attempt",
        "description": "Directory traversal sequences (../../) were detected in an HTTP request. Attackers use path traversal to read arbitrary files outside the web root.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)",
        "severity": "high", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "web", "traversal"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "Command Injection Attempt",
        "description": "OS command injection syntax (shell metacharacters, command separators) was detected in an HTTP request.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?:;\s*(?:id|whoami|cat\s+\/etc|rm\s+-r|wget\s+http|curl\s+http)|\|\s*(?:id|whoami|bash|sh|cmd)|%3b(?:id|whoami)|%60(?:id|whoami)|\$\(id\)|\$\(whoami\))",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "web", "injection"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "LFI / RFI Attempt",
        "description": "Local or Remote File Inclusion indicators were found in an HTTP request. Attackers use LFI to read system files and RFI to execute remote code.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?i)(?:(?:file|php|data|expect|zip)://|%00|null\s*byte|php://(?:input|filter|wrapper|memory)|data://text|/proc/self/environ|/etc/passwd\x00)",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "web", "lfi", "rfi"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "Scanner / Fuzzer User-Agent Detected",
        "description": "A well-known security scanner or fuzzer user-agent string was detected. This indicates active reconnaissance against the web application.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?i)(?P<user_agent>nmap|nikto|sqlmap|masscan|openvas|nessus|acunetix|burp\s*suite|dirbuster|gobuster|ffuf|hydra|medusa|wfuzz|nuclei|zap)",
        "severity": "high", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "recon", "scanner"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
    {
        "name": "Web Server 500 Error Flood",
        "description": "Multiple HTTP 5xx server errors detected. May indicate a crashing application, misconfiguration, or an attack causing server-side errors.",
        "pattern": r"HTTP\/1\.[01][^\"]*\"\s+5[0-9][0-9]\s",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "common",
        "tags": ["app", "web", "stability"],
    },
    {
        "name": "Reverse Shell Indicators",
        "description": "Network-based reverse shell techniques were detected in logs. A reverse shell gives an attacker interactive access to a compromised system.",
        "pattern": r"(?i)(?:bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+/bin/|ncat.*-e\s+/bin/|python.*socket.*connect|perl.*socket|ruby.*socket.*connect|powershell.*-[Nn]o[Pp].*-[Cc].*iex|meterpreter|metasploit)",
        "severity": "critical", "action_level": 2, "enabled": True, "os_type": "common",
        "tags": ["security", "execution", "c2"],
        "remediation_script_name": "Capture Process Snapshot (Linux)",
        "remediation_script_name_windows": "Capture Process Snapshot (Windows)",
    },
    {
        "name": "Excessive 4xx HTTP Errors",
        "description": "A high number of HTTP 401/403 Unauthorized/Forbidden responses suggests credential brute-forcing or unauthorized resource enumeration.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?HTTP\/1\.[01][^\"]*\"\s+(?:401|403)\s",
        "severity": "medium", "action_level": 3, "enabled": True, "os_type": "common",
        "tags": ["security", "web", "auth"],
    },
    {
        "name": "DNS Tunneling Indicators",
        "description": "Patterns associated with DNS-based data exfiltration or C2 tunneling (iodine, dnscat, unusually long subdomains) were detected.",
        "pattern": r"(?i)(?:dnscat|iodine|dns2tcp|dns.*exfil|dns.*tunnel|long.*subdomain.*base64|[a-zA-Z0-9+/]{50,}\.(?:[a-z]{2,6}\.){2,}[a-z]{2,6})",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "common",
        "tags": ["security", "c2", "exfiltration", "dns"],
    },
    {
        "name": "Lateral Movement Indicators",
        "description": "Tools or techniques associated with lateral movement (PsExec, CrackMapExec, Impacket) were detected. Indicates an attacker spreading within the network.",
        "pattern": r"(?i)(?:psexec|wmiexec|smbexec|crackmapexec|impacket|psremoting|winrm.*from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})|evil-winrm)",
        "severity": "critical", "action_level": 3, "enabled": True, "os_type": "common",
        "tags": ["security", "lateral-movement"],
    },
    {
        "name": "Data Exfiltration (Large Outbound POST)",
        "description": "An unusually large HTTP POST body (>500KB) was detected. Could indicate bulk data exfiltration. Review the destination and content type.",
        "pattern": r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}).*?\bPOST\b.*?\s(?P<bytes>[1-9]\d{5,})\s",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "common",
        "tags": ["security", "exfiltration", "web"],
    },
    {
        "name": "Tor / Anonymisation Proxy Traffic",
        "description": "Traffic originating from or destined to Tor exit nodes or known anonymisation proxies was detected. Attackers use Tor to mask their origin.",
        "pattern": r"(?i)(?:tor\.exit|\.onion\b|torsocks|torify|proxychains|socks5.*127\.0\.0\.1.*9050|socks.*9150)",
        "severity": "high", "action_level": 3, "enabled": True, "os_type": "common",
        "tags": ["security", "c2", "anonymisation"],
    },
    {
        "name": "Known Malicious IP Hit",
        "description": "Traffic from an IP address on the demo threat-intelligence list was detected. In production, replace these with live threat-intel feed IPs.",
        "pattern": r"(?P<source_ip>(?:192\.168\.100\.66|10\.66\.66\.66|172\.16\.66\.66|203\.0\.113\.66|198\.51\.100\.66))",
        "severity": "critical", "action_level": 1, "enabled": True, "os_type": "common",
        "tags": ["security", "threat-intel"],
        "remediation_script_name": "Block IP (iptables)",
        "remediation_script_name_windows": "Block IP (Windows Firewall)",
    },
]


# =============================================================================
# PAIRING VALIDATOR
# =============================================================================

def _validate_rule_script_pairing(rules_to_insert: list, all_scripts: list) -> bool:
    """
    For every rule linked to a script, confirm every {{placeholder}} in that
    script's content is either:
    - a named capture group in the rule's regex pattern, OR
    - auto-injected (hostname, os_type)

    Returns True if valid. Prints errors and returns False if not.
    """
    AUTO_VARS = {"hostname", "os_type"}
    script_map = {s["name"]: s for s in all_scripts}
    errors = []

    for rule in rules_to_insert:
        for field in ("remediation_script_name", "remediation_script_name_windows"):
            script_name = rule.get(field)
            if not script_name:
                continue
            script = script_map.get(script_name)
            if not script:
                errors.append(f"  Rule '{rule['name']}': script '{script_name}' not found in DEFAULT_SCRIPTS")
                continue

            placeholders = {p.strip() for p in _re.findall(r"\{\{(\s*\w+\s*)\}\}", script["content"])}
            captured = set(_re.findall(r"\?P<(\w+)>", rule["pattern"]))
            missing = placeholders - captured - AUTO_VARS

            if missing:
                errors.append(
                    f"  Rule '{rule['name']}' → '{script_name}': "
                    f"placeholder(s) {missing} not captured by regex"
                )

    if errors:
        print("\n❌ PAIRING VALIDATION FAILED — fix these before seeding:")
        for e in errors:
            print(e)
        return False

    l1 = sum(1 for r in rules_to_insert if r.get("action_level") == 1)
    l2 = sum(1 for r in rules_to_insert if r.get("action_level") == 2)
    l3 = sum(1 for r in rules_to_insert if r.get("action_level") == 3)
    linked = sum(1 for r in rules_to_insert if r.get("remediation_script_name") or r.get("remediation_script_name_windows"))
    print(f"  ✓ Pairing validation passed — {len(rules_to_insert)} rules total "
          f"(L1:{l1} L2:{l2} L3:{l3}), {linked} with scripts")
    return True


# =============================================================================
# HELPERS
# =============================================================================

def _header(title: str):
    print(f"\n{'─' * 55}")
    print(f"  {title}")
    print(f"{'─' * 55}")


async def _verify_scripts(db) -> dict:
    docs = await db["scripts"].find({}, {"name": 1}).to_list(length=500)
    return {d["name"]: str(d["_id"]) for d in docs}


async def _verify_rules(db) -> list[str]:
    docs = await db["rules"].find({}, {"name": 1}).to_list(length=500)
    return [d["name"] for d in docs]


# =============================================================================
# SEEDERS
# =============================================================================

async def seed_scripts(db) -> dict:
    _header("Scripts")

    existing = await _verify_scripts(db)
    if existing:
        print(f"  Found {len(existing)} existing script(s).")
    else:
        print("  No scripts found — inserting defaults.")

    to_insert = [s for s in DEFAULT_SCRIPTS if s["name"] not in existing]

    if not to_insert:
        print("  Nothing to insert — all default scripts already present.")
        return await _verify_scripts(db)

    now = datetime.now(timezone.utc)
    for s in to_insert:
        s["created_at"] = now
        s["updated_at"] = now
        # Phase 28.5 — explicit global ownership on the 23 curated scripts
        s.setdefault("owner_type", "global")
        s.setdefault("owner_id", None)

    result = await db["scripts"].insert_many(to_insert)
    by_category = {}
    for s in to_insert:
        by_category.setdefault(s.get("category", "?"), []).append(s["name"])

    print(f"\n  Inserted {len(result.inserted_ids)} new script(s):")
    for cat, names in sorted(by_category.items()):
        print(f"    [{cat}]")
        for n in names:
            print(f"      +  {n}")

    return await _verify_scripts(db)


async def seed_rules(db, script_lookup: dict):
    _header("Rules")

    # Validate pairings before touching the DB
    print("  Validating rule→script pairings…")
    if not _validate_rule_script_pairing(DEFAULT_RULES, DEFAULT_SCRIPTS):
        sys.exit(1)

    existing_names = await _verify_rules(db)
    if existing_names:
        print(f"\n  Found {len(existing_names)} existing rule(s).")
    else:
        print("  No rules found — inserting defaults.")

    to_insert = [r for r in DEFAULT_RULES if r["name"] not in existing_names]

    if not to_insert:
        print("  Nothing to insert — all default rules already present.")
        return

    now = datetime.now(timezone.utc)
    unresolved = []

    for rule in to_insert:
        # Resolve Linux/default script name → ID
        script_name = rule.pop("remediation_script_name", None)
        if script_name:
            sid = script_lookup.get(script_name)
            if sid:
                rule["remediation_script_id"] = sid
            else:
                unresolved.append((rule["name"], script_name, "linux"))

        # Resolve Windows script name → ID
        script_name_win = rule.pop("remediation_script_name_windows", None)
        if script_name_win:
            sid = script_lookup.get(script_name_win)
            if sid:
                rule["remediation_script_id_windows"] = sid
            else:
                unresolved.append((rule["name"], script_name_win, "windows"))

        rule["created_at"] = now
        rule["updated_at"] = None
        # Phase 28.5 — explicit global ownership on the 55 curated rules
        rule.setdefault("owner_type", "global")
        rule.setdefault("owner_id", None)

    await db["rules"].insert_many(to_insert)

    linked = sum(1 for r in to_insert if r.get("remediation_script_id") or r.get("remediation_script_id_windows"))
    print(f"\n  Inserted {len(to_insert)} new rule(s) ({linked} with scripts, {len(to_insert) - linked} alert-only).")

    if unresolved:
        print(f"\n  ⚠️  {len(unresolved)} script(s) not found for linking:")
        for rule_name, script_name, os_lbl in unresolved:
            print(f"      ?  '{rule_name}' ({os_lbl}) expected script '{script_name}'")


# =============================================================================
# USERS  (Phase 20.1 — auth)
# =============================================================================

async def seed_users(db):
    """Idempotently create the permanent protected admin from INITIAL_ADMIN_*.
    Skips if any admin already exists; refuses to create one without a password."""
    _header("Users")
    from app.core.security import hash_password

    existing = await db["users"].find_one({"role": "admin"})
    if existing:
        print(f"  Admin user already exists ('{existing.get('username')}') — skipping.")
        return

    username = os.getenv("INITIAL_ADMIN_USERNAME", "admin")
    password = os.getenv("INITIAL_ADMIN_PASSWORD", "")
    if not password:
        print("  ⚠️  INITIAL_ADMIN_PASSWORD is not set — no admin created.")
        print("      Set INITIAL_ADMIN_USERNAME / INITIAL_ADMIN_PASSWORD in .env, then re-run.")
        return

    await db["users"].create_index([("username", 1)], unique=True, name="idx_users_username")
    now = datetime.now(timezone.utc)
    await db["users"].insert_one({
        "username": username,
        "email": None,
        "password_hash": hash_password(password),
        "role": "admin",
        "server_ids": [],
        "is_active": True,
        "is_protected": True,
        "failed_login_count": 0,
        "locked_until": None,
        "last_login_at": None,
        "password_changed_at": now,
        "created_by": None,
        "created_at": now,
        "updated_at": now,
    })
    print(f"  ✅ Created protected admin user '{username}'.")


# =============================================================================
# MAIN
# =============================================================================

async def main():
    print(f"\n{'=' * 55}")
    print(f"  SecOps DB Seeder")
    print(f"  Target: {MONGO_URI}  DB: {DB_NAME}")
    print(f"{'=' * 55}")

    client = AsyncIOMotorClient(MONGO_URI)
    try:
        await client.admin.command("ping")
        print("\n  MongoDB connection OK")
    except Exception as e:
        print(f"\n  ERROR: Cannot connect to MongoDB — {e}")
        client.close()
        sys.exit(1)

    db = client[DB_NAME]

    # Scripts must be seeded first — rules reference script IDs by name
    script_lookup = await seed_scripts(db)
    await seed_rules(db, script_lookup)
    await seed_users(db)

    _header("Summary")
    scripts_total = await db["scripts"].count_documents({})
    rules_total   = await db["rules"].count_documents({})
    rules_linked  = await db["rules"].count_documents(
        {"$or": [
            {"remediation_script_id": {"$exists": True}},
            {"remediation_script_id_windows": {"$exists": True}},
        ]}
    )
    l1 = await db["rules"].count_documents({"action_level": 1})
    l2 = await db["rules"].count_documents({"action_level": 2})
    l3 = await db["rules"].count_documents({"action_level": 3})
    print(f"  Scripts : {scripts_total}")
    print(f"  Rules   : {rules_total}  ({rules_linked} linked to scripts)")
    print(f"  Levels  : L1={l1} L2={l2} L3={l3}")
    print()

    client.close()


if __name__ == "__main__":
    asyncio.run(main())
