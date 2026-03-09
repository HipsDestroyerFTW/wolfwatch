from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ANTHROPIC_API_KEY: str = ""
    HIBP_API_KEY: Optional[str] = None

    TOR_PROXY_HOST: str = "127.0.0.1"
    TOR_PROXY_PORT: int = 9050

    APP_SECRET_KEY: str = "dev-secret-change-in-production"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_ENV: str = "development"

    DATABASE_URL: str = "sqlite:///./wolfwatch.db"

    DEFAULT_SCAN_INTERVAL_HOURS: int = 6
    MAX_CONCURRENT_CRAWLS: int = 3

    COMPANY_NAME: str = "Wolf Industries"
    COMPANY_DOMAINS: str = "wolfindustries.com"

    # Service URLs (set by docker-compose, or override in .env)
    REDIS_URL: str = ""
    SPIDERFOOT_URL: str = ""
    SEARXNG_URL: str = ""

    # Free API keys (optional, for higher rate limits)
    GREYNOISE_API_KEY: str = ""     # community key — free at greynoise.io
    PHISHTANK_API_KEY: str = ""     # free at phishtank.org

    @property
    def tor_socks_url(self) -> str:
        return f"socks5://{self.TOR_PROXY_HOST}:{self.TOR_PROXY_PORT}"

    @property
    def company_domain_list(self) -> list[str]:
        return [d.strip() for d in self.COMPANY_DOMAINS.split(",") if d.strip()]


settings = Settings()
