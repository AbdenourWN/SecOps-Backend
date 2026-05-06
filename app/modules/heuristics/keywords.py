"""
Default suspicious keyword list for the heuristic Tier 2 filter.

Override at runtime via the HEURISTIC_KEYWORDS env var (comma-separated).
Words are matched case-insensitive with word boundaries.
"""

DEFAULT_KEYWORDS = [
    # Authentication / access failures (high signal)
    "failed", "denied", "unauthorized", "forbidden",
    "reject", "rejected",
    # Malware / threat actors
    "attack", "intrusion", "exploit", "malware", "ransomware",
    "phishing", "trojan", "virus", "backdoor", "rootkit",
    "shellcode", "payload", "brute",
    # System compromise
    "breach", "compromise", "suspicious", "hack",
    "tampered", "injected",
    # Execution / injection
    "injection", "traversal", "csrf", "xss",
    # Critical system events
    "panic", "fatal", "segfault", "crash", "oom",
    "escalation", "quarantine",
    # Web-layer / infra keywords
    "vulnerability", "anomaly",
]

# Sensitive keywords used by time-of-day heuristic.
# Logs containing one of these AND timestamped outside business hours = flag.
SENSITIVE_KEYWORDS = [
    "login", "logon", "sudo", "su -", "admin",
    "powershell", "invoke-", "new-user", "adduser",
    "useradd", "passwd",
]
