"""Runtime configuration, read from environment (12-factor style).

Kept intentionally dependency-free (plain ``os.getenv``) — there is no need to
pull in pydantic-settings for three optional values.
"""
import os


class Settings:
    # Optional free NVD API key raises the rate limit from 5 to 50 req / 30s.
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    # NVD is queried one CVE at a time; keep concurrency low to stay under limits.
    nvd_concurrency: int = int(os.getenv("NVD_CONCURRENCY", "3"))
    # Comma-separated allowed CORS origins ("*" for any).
    cors_origins: str = os.getenv("CORS_ORIGINS", "*")


settings = Settings()
