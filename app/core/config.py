from pydantic_settings import BaseSettings
from typing import Optional

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

    class Config:
        env_file = ".env"

settings = Settings()