from pathlib import Path

import pytest

from m2a_launcher.envfile import mask_secret, read_env_values, update_env
from m2a_launcher.menu import configure_llm, configure_worker, show_current_config

FAKE_KEY = "test-api-key-123456789"


def _answers(*items: str):
    iterator = iter(items)
    return lambda _prompt="": next(iterator)


def test_env_exists_targeted_update_preserves_content(tmp_path: Path):
    original = "# Database\nDATABASE_URL=postgresql://example\n\n# LLM\nLLM_MODEL=old\nUNKNOWN_SETTING=keep\n"
    (tmp_path / ".env").write_text(original, encoding="utf-8")
    update_env(tmp_path, {"LLM_MODEL": "new-model"})
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "# Database" in text and "# LLM" in text
    assert "DATABASE_URL=postgresql://example" in text
    assert "UNKNOWN_SETTING=keep" in text
    assert "LLM_MODEL=new-model" in text


def test_env_missing_creates_from_example_then_updates(tmp_path: Path):
    (tmp_path / ".env.example").write_text("# Template\nLLM_MODEL=default\nOTHER=1\n", encoding="utf-8")
    update_env(tmp_path, {"LLM_API_KEY": FAKE_KEY}, required_non_empty={"LLM_API_KEY"})
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "# Template" in text and "OTHER=1" in text and FAKE_KEY in text


def test_api_key_replacement_and_backup(tmp_path: Path):
    (tmp_path / ".env").write_text("LLM_API_KEY=old-test-key\n", encoding="utf-8")
    update_env(tmp_path, {"LLM_API_KEY": FAKE_KEY}, required_non_empty={"LLM_API_KEY"})
    assert read_env_values(tmp_path / ".env")["LLM_API_KEY"] == FAKE_KEY
    assert "old-test-key" in (tmp_path / ".env.backup").read_text(encoding="utf-8")


def test_api_key_model_and_base_url_append(tmp_path: Path):
    (tmp_path / ".env").write_text("OTHER=1\n", encoding="utf-8")
    update_env(tmp_path, {"LLM_API_KEY": FAKE_KEY, "LLM_MODEL": "test-model", "LLM_BASE_URL": "https://llm.example.test/v1"}, required_non_empty={"LLM_API_KEY"})
    values = read_env_values(tmp_path / ".env")
    assert values["LLM_API_KEY"] == FAKE_KEY
    assert values["LLM_MODEL"] == "test-model"
    assert values["LLM_BASE_URL"] == "https://llm.example.test/v1"


def test_empty_api_key_is_rejected_without_file_change(tmp_path: Path):
    path = tmp_path / ".env"
    path.write_text("OTHER=1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="不可為空"):
        update_env(tmp_path, {"LLM_API_KEY": ""}, required_non_empty={"LLM_API_KEY"})
    assert path.read_text(encoding="utf-8") == "OTHER=1\n"


def test_masked_api_key_and_short_key():
    masked = mask_secret(FAKE_KEY)
    assert FAKE_KEY not in masked and masked.endswith("6789")
    assert mask_secret("short") == "********"


def test_configure_llm_never_exposes_secret(tmp_path: Path, capsys):
    (tmp_path / ".env.example").write_text("LLM_MODEL=default\nLLM_BASE_URL=http://localhost/v1\nLLM_SEND_AUTH=false\n", encoding="utf-8")
    assert configure_llm(tmp_path, _answers("", "", "", "y"), lambda _prompt: FAKE_KEY)
    assert FAKE_KEY not in capsys.readouterr().out
    show_current_config(tmp_path)
    shown = capsys.readouterr().out
    assert FAKE_KEY not in shown and mask_secret(FAKE_KEY) in shown
    assert not (tmp_path / "logs").exists()


def test_debug_repr_and_log_do_not_expose_secret(tmp_path: Path, capsys):
    from m2a_launcher.config import LauncherConfig
    from m2a_launcher.runtime import make_logger
    (tmp_path / ".env").write_text(f"LLM_API_KEY={FAKE_KEY}\nM2A_LAUNCHER_DEBUG=true\n", encoding="utf-8")
    config = LauncherConfig.load(tmp_path)
    assert FAKE_KEY not in repr(config)
    show_current_config(tmp_path)
    assert FAKE_KEY not in capsys.readouterr().out
    logger = make_logger(tmp_path, config.debug)
    logger.debug("[設定] 已載入 Debug 模式")
    log_text = next((tmp_path / "logs").glob("launcher-*.log")).read_text(encoding="utf-8")
    assert FAKE_KEY not in log_text


def test_existing_api_key_can_be_kept(tmp_path: Path):
    (tmp_path / ".env").write_text(f"LLM_API_KEY={FAKE_KEY}\nLLM_MODEL=old\nLLM_BASE_URL=http://old/v1\n", encoding="utf-8")
    assert configure_llm(tmp_path, _answers("", "1", "new-model", "", "n"), lambda _prompt: pytest.fail("secret prompt must not run"))
    values = read_env_values(tmp_path / ".env")
    assert values["LLM_API_KEY"] == FAKE_KEY and values["LLM_MODEL"] == "new-model"


def test_worker_wsl_config(tmp_path: Path):
    (tmp_path / ".env").write_text("M2A_WORKER_MODE=remote\n", encoding="utf-8")
    assert configure_worker(tmp_path, _answers("1", "kali-test", "/opt/m2a-test"))
    values = read_env_values(tmp_path / ".env")
    assert values["M2A_WORKER_MODE"] == "wsl"
    assert values["M2A_WSL_DISTRO"] == "kali-test"
    assert values["M2A_WSL_WORKER_DIR"] == "/opt/m2a-test"


def test_worker_remote_config(tmp_path: Path):
    (tmp_path / ".env").write_text("M2A_WORKER_MODE=wsl\n", encoding="utf-8")
    assert configure_worker(tmp_path, _answers("2", "http://worker.example.test:8000"))
    values = read_env_values(tmp_path / ".env")
    assert values["M2A_WORKER_MODE"] == "remote"
    assert values["M2A_REMOTE_WORKER_URL"] == "http://worker.example.test:8000"


def test_env_backup_is_gitignored_by_existing_pattern():
    patterns = (Path(__file__).parents[1] / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env.*" in patterns
