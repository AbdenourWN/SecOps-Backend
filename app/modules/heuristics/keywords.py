"""
Default suspicious keyword list for the heuristic Tier 2 filter.

Override at runtime via the HEURISTIC_KEYWORDS env var (comma-separated).
Words are matched case-insensitive with word boundaries.
"""

DEFAULT_KEYWORDS = [
    "error", "fail", "failed", "denied", "reject", "rejected",
    "attack", "attempt", "unauthorized", "forbidden", "breach",
    "malware", "trojan", "virus", "suspicious", "anomaly", "intrusion",
    "exploit", "vulnerability", "compromise", "ransomware", "phishing",
    "brute", "hack", "blocked", "quarantine",
    "critical", "alert", "panic", "fatal", "segfault", "crash",
    "kernel", "oom",
    "escalation", "illegal", "restricted",
    "backdoor", "payload", "shellcode", "injection",
    "traversal", "csrf", "xss",
]

# Sensitive keywords used by time-of-day heuristic.
# Logs containing one of these AND timestamped outside business hours = flag.
SENSITIVE_KEYWORDS = [
    "login", "logon", "sudo", "su -", "admin",
    "powershell", "invoke-", "new-user", "adduser",
    "useradd", "passwd",
]
