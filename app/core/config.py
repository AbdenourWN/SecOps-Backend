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

    # WebSocket
    WS_PING_INTERVAL: int = 20
    WS_PING_TIMEOUT: int = 25
    WS_MAX_CONNECTIONS: int = 100
    WS_MESSAGE_QUEUE_SIZE: int = 64

    class Config:
        env_file = ".env"

settings = Settings()