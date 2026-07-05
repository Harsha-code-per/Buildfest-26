"""Runtime configuration, read from environment (12-factor style).

Kept intentionally dependency-free (plain ``os.getenv``) — there is no need to
pull in pydantic-settings for three optional values.
"""
import os


class Settings:
    # Optional free NVD API key raises the rate limit from 5 to 50 req / 30s.
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    # NVD is queried one CVE at a time; space calls to stay under the per-key
    # limit (~1 req/6s unauthenticated, ~1 req/0.6s with a key). Calibration
    # knob — override NVD_DELAY if NVD changes its published rates.
    nvd_delay: float = float(os.getenv("NVD_DELAY", "0.6" if os.getenv("NVD_API_KEY") else "6.0"))
    # Comma-separated allowed CORS origins ("*" for any).
    cors_origins: str = os.getenv("CORS_ORIGINS", "*")


settings = Settings()
