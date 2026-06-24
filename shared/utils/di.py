import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class DIContainer:
    _instances: Dict[str, Any] = {}

    @classmethod
    def register(cls, key: str, instance: Any) -> None:
        cls._instances[key] = instance
        logger.debug("Registered dependency: %s", key)

    @classmethod
    def get(cls, key: str) -> Any:
        instance = cls._instances.get(key)
        if instance is None:
            raise KeyError(f"Dependency not found: {key}")
        return instance

    @classmethod
    def resolve(cls, key: str, default: Optional[Any] = None) -> Any:
        return cls._instances.get(key, default)

    @classmethod
    def clear(cls) -> None:
        cls._instances.clear()

    @classmethod
    def remove(cls, key: str) -> None:
        cls._instances.pop(key, None)
