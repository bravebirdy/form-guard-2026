from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = "dev"
    app_name: str = "formguard-api"

    database_url: str = ''

    trusted_proxy_cidrs: str = ""
    default_limit_per_hour: int = 60


settings = Settings()

