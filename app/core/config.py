from pydantic_settings import BaseSettings
from pydantic import SecretStr
from typing import Optional, Literal

class Settings(BaseSettings):
    MONGO_URI: str
    DB_NAME: str
    SECRET_KEY: str
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    MAX_CONCURRENT_SERVERS: int = 20  # Semaphore limit for parallel scheduler jobs

    # SMTP / Email Alerts
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    ALERT_FROM_EMAIL: str = ""
    ALERT_RECIPIENTS: str = ""  # Comma-separated: "a@x.com,b@x.com"
    # Re-email the admin this often while a server stays offline. 0 disables the reminder.
    SERVER_OFFLINE_REMINDER_HOURS: float = 6

    ALLOWED_ORIGINS: str = "*"  # Comma-separated: "https://security.ctt.tn,https://other.com"
    # Cookie auth needs an explicit origin — browsers reject credentialed requests
    # against a wildcard ACAO. Set this to the frontend origin in dev/prod.

    # --- Auth / RBAC (Phase 20.1) ---
    # Dedicated HS256 secret for JWT access tokens — kept SEPARATE from SECRET_KEY
    # (the Fernet key for credential encryption). Use >=32 bytes (PyJWT warns below
    # that). Empty means auth is unconfigured: token encode/decode raises and
    # startup logs a loud warning. Set in .env.
    JWT_SECRET_KEY: str = ""
    ACCESS_TOKEN_TTL_MINUTES: int = 15
    REFRESH_TOKEN_TTL_DAYS: int = 7
    LOGIN_MAX_ATTEMPTS: int = 5            # consecutive failures before temporary lockout
    LOGIN_LOCKOUT_MINUTES: int = 15
    AUTH_COOKIE_SECURE: bool = False       # True in prod (HTTPS) → cookies get the Secure flag
    AUTH_COOKIE_SAMESITE: str = "lax"      # "lax" works same-site (localhost); "none"+Secure for cross-site prod
    # Empty = host-only cookie (works when frontend+backend share one hostname, e.g.
    # localhost:3000 + localhost:8900). Set to ".example.com" when frontend and backend
    # live on different subdomains (e.g. security.example.com / api.example.com) so the
    # browser attaches the cookie to both — otherwise the frontend's optimistic auth-gate
    # middleware never sees it and redirects to /login even after a successful login.
    AUTH_COOKIE_DOMAIN: str = ""
    # First-boot bootstrap of the permanent protected admin (also seedable via seed.py).
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_PASSWORD: str = ""       # if empty, the admin is NOT auto-created (set in .env or seed)

    # LLM / AI
    LLM_PROVIDER: Literal["openrouter", "anthropic", "openai", "ollama"] = "openrouter"
    LLM_MODEL: str = "anthropic/claude-sonnet-4-6"
    LLM_TEMPERATURE: float = 0.2
    LLM_MAX_TOKENS: int = 2048
    # Server-overview analyses cover 6 evidence sources over up to 24h, so the
    # report tends to need 2-3× the budget of a single-incident triage. Tune
    # independently from `LLM_MAX_TOKENS` so triage stays cheap while overviews
    # have room to breathe through the full markdown + JSON commands block.
    # Set the env var of the same name to override the default.
    LLM_MAX_TOKENS_SERVER_OVERVIEW: int = 4096
    # OpenRouter (primary gateway — one API key → ~300 models)
    OPENROUTER_API_KEY: Optional[SecretStr] = None
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    OPENROUTER_SITE_URL: str = "https://secops-platform"
    OPENROUTER_SITE_NAME: str = "SecOps"
    # Direct providers (fallbacks; only required if LLM_PROVIDER=anthropic|openai)
    ANTHROPIC_API_KEY: Optional[SecretStr] = None
    OPENAI_API_KEY: Optional[SecretStr] = None
    # Ollama (local; only required if LLM_PROVIDER=ollama)
    OLLAMA_URL: str = "http://localhost:11434"

    # --- Logging (Phase 20.4) ---
    LOG_LEVEL: str = "INFO"   # DEBUG | INFO | WARNING | ERROR
    LOG_JSON: bool = True     # JSON lines (prod/ingestion); set False for human-readable dev logs

    # WebSocket
    WS_PING_INTERVAL: int = 20
    WS_PING_TIMEOUT: int = 25
    WS_MAX_CONNECTIONS: int = 100
    WS_MESSAGE_QUEUE_SIZE: int = 64

    class Config:
        env_file = ".env"

settings = Settings()