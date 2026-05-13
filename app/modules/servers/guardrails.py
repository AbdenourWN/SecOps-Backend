"""
Command guardrails. Pure function of (command, os_type).

Three outcomes:
  - allowed=True, requires_confirmation=False: run the command
  - allowed=True, requires_confirmation=True:  dangerous-but-legitimate; UI must
                                               re-challenge the user, then resend
                                               with confirmed=True
  - allowed=False:                             hard-blocked; never run

Server must re-verify on every request; never trust the client-side check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Pattern


@dataclass(frozen=True)
class CheckResult:
    allowed: bool
    requires_confirmation: bool
    reason: str | None = None


@dataclass(frozen=True)
class _Rule:
    pattern: Pattern[str]
    reason: str


def _compile(rules: Iterable[tuple[str, str]]) -> tuple[_Rule, ...]:
    return tuple(_Rule(re.compile(p, re.IGNORECASE), r) for p, r in rules)


# --------------------------- LINUX ---------------------------

_LINUX_BLOCK = _compile([
    (r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+/\s*(?:$|[;&|])",
     "Recursive delete of / is blocked."),
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
     "Fork bomb pattern is blocked."),
    (r"\bmkfs(\.\w+)?\b",
     "Filesystem formatting (mkfs) is blocked."),
    (r"\bdd\b[^|]*\bof=/dev/(sd|nvme|hd|vd)",
     "Writing with dd to a raw block device is blocked."),
    (r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b",
     "Power/reboot commands are blocked."),
    (r">\s*/dev/(sd|nvme|hd|vd)\w*",
     "Redirecting output to a raw block device is blocked."),
    (r"\bwipefs\b",
     "wipefs is blocked."),
    (r"\bshred\b.*\s/dev/",
     "Shredding a block device is blocked."),
])

_LINUX_CONFIRM = _compile([
    (r"^\s*sudo\b",
     "sudo requires an interactive terminal — run the command directly without sudo over SSH."),
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*)\b",
     "Recursive delete requires confirmation."),
    (r"\bkill\s+-9\b",
     "kill -9 requires confirmation."),
    (r"\bpkill\b",
     "pkill requires confirmation."),
    (r"\bkillall\b",
     "killall requires confirmation."),
    (r"\bsystemctl\s+(stop|disable|mask)\b",
     "Stopping/disabling a service requires confirmation."),
    (r"\bservice\s+\S+\s+(stop|disable)\b",
     "Stopping a service requires confirmation."),
    (r"\biptables\s+-F\b",
     "Flushing iptables requires confirmation."),
    (r"\bufw\s+disable\b",
     "Disabling ufw requires confirmation."),
    (r"\bchmod\s+-?R?\s*777\b",
     "chmod 777 requires confirmation."),
    (r"\bchown\s+.*\broot\b",
     "chown to root requires confirmation."),
    (r"(^|\s|>|>>)/etc/(passwd|shadow|sudoers|ssh/sshd_config)",
     "Editing core auth files requires confirmation."),
    (r"\bpasswd\s+\w+",
     "Changing a user password requires confirmation."),
    (r"\buserdel\b",
     "userdel requires confirmation."),
    (r"\bcrontab\s+-r\b",
     "Removing crontab requires confirmation."),
    (r"\btruncate\s+-s\s*0\b",
     "Truncating a file requires confirmation."),
])


# --------------------------- WINDOWS ---------------------------

_WINDOWS_BLOCK = _compile([
    (r"\bFormat-Volume\b",
     "Format-Volume is blocked."),
    (r"\b(Stop|Restart)-Computer\b",
     "Stop/Restart-Computer is blocked."),
    (r"\bdiskpart\b",
     "diskpart is blocked."),
    (r"\bcipher\s+/w:",
     "cipher /w: (wipe) is blocked."),
    (r"\bClear-Disk\b",
     "Clear-Disk is blocked."),
    (r"\bRemove-Item\b[^|]*-Recurse[^|]*\s+C:\\?\s*(?:$|[;|])",
     "Recursive delete of C:\\ is blocked."),
    (r"\bshutdown(\.exe)?\b\s+(/s|/r|/p|/h)",
     "shutdown.exe is blocked."),
    (r"\bInitialize-Disk\b",
     "Initialize-Disk is blocked."),
])

_WINDOWS_CONFIRM = _compile([
    (r"\bRemove-Item\b[^|]*-Recurse\b",
     "Remove-Item -Recurse requires confirmation."),
    (r"\bStop-Process\b",
     "Stop-Process requires confirmation."),
    (r"\b(Stop|Disable)-Service\b",
     "Stop/Disable-Service requires confirmation."),
    (r"\bSet-Service\b[^|]*-StartupType\s+Disabled\b",
     "Disabling a service requires confirmation."),
    (r"\bRemove-LocalUser\b",
     "Remove-LocalUser requires confirmation."),
    (r"\bSet-LocalUser\b[^|]*-Password\b",
     "Setting a local user password requires confirmation."),
    (r"\bRemove-LocalGroupMember\b",
     "Remove-LocalGroupMember requires confirmation."),
    (r"\bNew-NetFirewallRule\b[^|]*-Action\s+Block\b",
     "Creating a blocking firewall rule requires confirmation."),
    (r"\bSet-NetFirewallProfile\b[^|]*-Enabled\s+False\b",
     "Disabling firewall requires confirmation."),
    (r"\bSet-ExecutionPolicy\b[^|]*(Bypass|Unrestricted)\b",
     "Relaxing execution policy requires confirmation."),
    (r"\breg\s+delete\b",
     "reg delete requires confirmation."),
    (r"\bRemove-ItemProperty\b[^|]*HKLM:",
     "Deleting an HKLM registry value requires confirmation."),
])


def _first_match(rules: tuple[_Rule, ...], cmd: str) -> _Rule | None:
    for rule in rules:
        if rule.pattern.search(cmd):
            return rule
    return None


def check_command(command: str, os_type: str) -> CheckResult:
    """
    Decide what to do with this command.

    Ordering matters: block-list wins over confirm-list. Fallback to Linux
    rules if the os_type is unrecognized — safer than allowing unknown hosts
    through with no guardrails.
    """
    cmd = (command or "").strip()
    if not cmd:
        return CheckResult(allowed=False, requires_confirmation=False,
                           reason="Empty command.")

    if os_type == "windows":
        block_rules = _WINDOWS_BLOCK
        confirm_rules = _WINDOWS_CONFIRM
    else:
        block_rules = _LINUX_BLOCK
        confirm_rules = _LINUX_CONFIRM

    hit = _first_match(block_rules, cmd)
    if hit:
        return CheckResult(allowed=False, requires_confirmation=False,
                           reason=hit.reason)

    hit = _first_match(confirm_rules, cmd)
    if hit:
        return CheckResult(allowed=True, requires_confirmation=True,
                           reason=hit.reason)

    return CheckResult(allowed=True, requires_confirmation=False, reason=None)
