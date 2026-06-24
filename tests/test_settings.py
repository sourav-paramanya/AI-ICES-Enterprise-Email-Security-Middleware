"""Settings validation tests."""

from shared.config.settings import Settings


class TestSettings:
    def test_default_settings_loaded(self) -> None:
        settings = Settings()
        assert settings.APP_NAME == "AI-ICES"
        assert settings.APP_VERSION == "1.0.0"

    def test_database_url_generation(self) -> None:
        settings = Settings(
            POSTGRES_USER="test_user",
            POSTGRES_PASSWORD="test_pass",
            POSTGRES_HOST="test_host",
            POSTGRES_PORT=5432,
            POSTGRES_DB="test_db",
        )
        expected = "postgresql+asyncpg://test_user:test_pass@test_host:5432/test_db"
        assert settings.DATABASE_URL == expected

    def test_rabbitmq_url_generation(self) -> None:
        settings = Settings(
            RABBITMQ_USER="test_user",
            RABBITMQ_PASSWORD="test_pass",
            RABBITMQ_HOST="test_host",
            RABBITMQ_PORT=5672,
            RABBITMQ_VHOST="test_vhost",
        )
        expected = "amqp://test_user:test_pass@test_host:5672/test_vhost"
        assert settings.RABBITMQ_URL == expected

    def test_redis_url_without_password(self) -> None:
        settings = Settings(REDIS_HOST="localhost", REDIS_PORT=6379, REDIS_PASSWORD="")
        assert settings.REDIS_URL == "redis://localhost:6379/0"

    def test_redis_url_with_password(self) -> None:
        settings = Settings(REDIS_HOST="localhost", REDIS_PORT=6379, REDIS_PASSWORD="secret")
        assert settings.REDIS_URL == "redis://:secret@localhost:6379/0"

    def test_debug_defaults_to_false(self) -> None:
        settings = Settings()
        assert settings.DEBUG is False

    def test_settings_use_env_file(self) -> None:
        settings = Settings(_env_file=None)
        assert settings.APP_NAME == "AI-ICES"
