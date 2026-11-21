"""Environment-driven config. Secrets come from env, never from the repo."""
import os
from dataclasses import dataclass, field


def _csv(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./dev.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-only-change-me")
    jwt_ttl_minutes: int = int(os.getenv("JWT_TTL_MINUTES", "60"))
    # Hosts/IPs/CIDRs pre-authorized because WE own them (the lab).
    lab_targets: list[str] = field(default_factory=lambda: _csv("LAB_TARGETS"))


settings = Settings()
