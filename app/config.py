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
    enforce_target_scope: bool = False
    allowed_scopes: str = "192.0.2.0/24,203.0.113.0/24"
    allowed_hostnames: str = ""
    allowed_domain_suffixes: str = ""
    allowed_llm_profiles: str = "internal"
    allowed_tools: str = default_allowed_tools_value()
    llm_base_url: str = "http://10.56.67.11/v1"
    llm_model: str = "openai/qwen3-4b-thinking-2507-heretic"
    llm_api_key: str | None = None
    llm_send_auth: bool = False
    llm_timeout_seconds: float = 60.0
    llm_context_max_history: int = 3
    cve_local_index_path: str = "data/cve_index.sqlite3"
    cve_local_index_enabled: bool = False
    cve_query_safety_limit: int = 5000
    cve_report_candidate_budget: int = 50
    max_cve_validations_per_round: int = 3

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
