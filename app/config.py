from pydantic_settings import BaseSettings, SettingsConfigDict

from app.tool_catalog import default_allowed_tools_value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
    database_url: str
    kali_worker_url: str = "http://192.0.2.10:8000"
    dispatcher_poll_interval_seconds: int = 10
    kali_worker_timeout_seconds: float = 600.0
    dispatcher_stale_running_minutes: int = 30
    worker_poll_interval_seconds: int = 10
    worker_tool_timeout_seconds: int = 300
    dirb_wordlist: str = "/usr/share/dirb/wordlists/common.txt"
    allowed_scopes: str = "192.0.2.0/24,203.0.113.0/24"
    allowed_hostnames: str = ""
    allowed_domain_suffixes: str = ""
    allowed_llm_profiles: str = "internal"
    allowed_tools: str = default_allowed_tools_value()

    @property
    def allowed_scopes_list(self) -> list[str]:
        return [s.strip() for s in self.allowed_scopes.split(",") if s.strip()]

    @property
    def allowed_llm_profiles_list(self) -> list[str]:
        return [s.strip().lower() for s in self.allowed_llm_profiles.split(",") if s.strip()]

    @property
    def allowed_tools_list(self) -> list[str]:
        return [s.strip().lower() for s in self.allowed_tools.split(",") if s.strip()]

    @property
    def allowed_hostnames_list(self) -> list[str]:
        return [s.strip().lower() for s in self.allowed_hostnames.split(",") if s.strip()]

    @property
    def allowed_domain_suffixes_list(self) -> list[str]:
        return [s.strip().lower().lstrip(".") for s in self.allowed_domain_suffixes.split(",") if s.strip()]

settings = Settings()
