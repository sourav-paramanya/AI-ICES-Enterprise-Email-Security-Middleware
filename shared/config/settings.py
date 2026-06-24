from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    APP_NAME: str = "AI-ICES"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # PostgreSQL
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "ai_ices"

    @computed_field
    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @computed_field
    @property
    def DATABASE_URL_SYNC(self) -> str:
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # RabbitMQ
    RABBITMQ_HOST: str = "localhost"
    RABBITMQ_PORT: int = 5672
    RABBITMQ_USER: str = "guest"
    RABBITMQ_PASSWORD: str = "guest"
    RABBITMQ_VHOST: str = "/"

    @computed_field
    @property
    def RABBITMQ_URL(self) -> str:
        return (
            f"amqp://{self.RABBITMQ_USER}:{self.RABBITMQ_PASSWORD}"
            f"@{self.RABBITMQ_HOST}:{self.RABBITMQ_PORT}/{self.RABBITMQ_VHOST}"
        )

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0

    @computed_field
    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return (
                f"redis://:{self.REDIS_PASSWORD}"
                f"@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
            )
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # JWT
    JWT_PRIVATE_KEY_PATH: Optional[Path] = None
    JWT_PUBLIC_KEY_PATH: Optional[Path] = None
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_MINUTES: int = 1440
    SECRET_KEY: str = "change-me-in-production"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # Service Ports
    GATEWAY_PORT: int = 8899
    CORE_HUB_PORT: int = 8000
    CORE_HUB_HOST: str = "core_hub"
    GOVERNANCE_API_PORT: int = 8080
    DASHBOARD_BACKEND_PORT: int = 3000

    # Gateway
    MILTER_TIMEOUT: int = 3
    MILTER_HOST: str = "0.0.0.0"

    # URL Protection
    URL_PROTECTION_BASE_URL: str = "http://localhost:8300"

    # Celery
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"
    CELERY_TASK_ALWAYS_EAGER: bool = False
    CELERY_WORKER_CONCURRENCY: int = 4

    # Security
    ENCRYPTION_KEY: str = "change-me-in-production"
    TLS_ENABLED: bool = True

    # Monitoring
    PROMETHEUS_ENABLED: bool = True
    SENTRY_DSN: Optional[str] = None

    # NLP / AI
    NLP_MODEL_NAME: str = "microsoft/deberta-v3-small"
    NLP_ONNX_PATH: Optional[str] = None

    # External
    THREAT_INTEL_API_KEY: Optional[str] = None
    THREAT_INTEL_API_URL: Optional[str] = None

    # Zimbra
    ZIMBRA_SOAP_URL: Optional[str] = None
    ZIMBRA_ADMIN_USER: Optional[str] = None
    ZIMBRA_ADMIN_PASSWORD: Optional[str] = None

    @computed_field
    @property
    def CELERY_BROKER(self) -> str:
        return self.CELERY_BROKER_URL or self.RABBITMQ_URL


@lru_cache
def get_settings() -> Settings:
    return Settings()
