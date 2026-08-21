from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from m2a_launcher.config import LauncherConfig, discover_project_root
from m2a_launcher.runtime import SingleInstance, decode_output, redact, wait_until, wsl_distros


def test_config_load_and_worker_mode(tmp_path: Path, monkeypatch):
    (tmp_path / ".env").write_text("M2A_WORKER_MODE=remote\nM2A_REMOTE_WORKER_URL=http://worker:8000\nM2A_LAUNCHER_DEBUG=true\n", encoding="utf-8")
    monkeypatch.delenv("M2A_WORKER_MODE", raising=False)
    config = LauncherConfig.load(tmp_path)
    assert config.worker_mode == "remote"
    assert config.worker_url == "http://worker:8000"
    assert config.debug is True


def test_invalid_worker_mode(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("M2A_WORKER_MODE", "invalid")
    with pytest.raises(ValueError, match="wsl 或 remote"):
        LauncherConfig.load(tmp_path)


def test_wsl_detection_decodes_utf16():
    result = Mock(returncode=0, stdout="kali-linux\r\nUbuntu\r\n".encode("utf-16-le"), stderr=b"")
    with patch("m2a_launcher.runtime.subprocess.run", return_value=result):
        assert wsl_distros() == ["kali-linux", "Ubuntu"]


def test_redaction_preserves_command_but_hides_secret():
    text = redact("component=Backend token=abc password:secret --port 8000")
    assert "abc" not in text and "secret" not in text
    assert "Backend" in text and "8000" in text


def test_decode_output_uses_utf8_and_legacy_fallback():
    assert decode_output("繁體中文".encode("utf-8")) == "繁體中文"
    assert "測試" in decode_output("測試".encode("cp950"))


def test_timeout_returns_false():
    assert wait_until(lambda: False, timeout=0) is False


def test_health_check_success():
    with patch("m2a_launcher.runtime.urllib.request.urlopen") as opened:
        opened.return_value.__enter__.return_value.status = 200
        opened.return_value.__enter__.return_value.read.return_value = b'{"status":"ok"}'
        from m2a_launcher.runtime import http_status
        assert http_status("http://127.0.0.1/health")[0] == 200


def test_single_instance_rejects_second_owner(tmp_path: Path):
    first, second = SingleInstance(tmp_path), SingleInstance(tmp_path)
    assert first.acquire() is True
    assert second.acquire() is False
    first.release()


def test_pid_tracking_uses_started_process(tmp_path: Path):
    from m2a_launcher.runtime import ProcessManager, make_logger
    manager = ProcessManager(tmp_path, make_logger(tmp_path, False))
    fake = Mock(pid=12480, stdout=Mock())
    with patch("m2a_launcher.runtime.subprocess.Popen", return_value=fake), patch("m2a_launcher.runtime.threading.Thread"):
        assert manager.start("Backend", ["python", "-V"]).pid == 12480
        assert manager.processes[0][0] == "Backend"


def test_port_collision_pid_is_reported():
    with patch("m2a_launcher.runtime.find_listening_pids", return_value=[12345]):
        from m2a_launcher.runtime import collision_details
        assert collision_details(8000) == "12345"


def test_project_root_discovery_uses_runtime_layout(tmp_path: Path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (tmp_path / "app").mkdir()
    monkeypatch.chdir(tmp_path)
    assert discover_project_root() == tmp_path


def test_frozen_project_root_prefers_valid_working_directory(tmp_path: Path, monkeypatch):
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (tmp_path / "app").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("m2a_launcher.config.sys.frozen", True, raising=False)
    monkeypatch.setattr("m2a_launcher.config.sys.executable", str(Path(__file__).parents[1] / "dist" / "M2A-Launcher" / "M2A-Launcher.exe"))
    assert discover_project_root() == tmp_path


def test_backend_health_contract():
    from fastapi.testclient import TestClient
    from app.main import app
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "M2A Backend", "version": "0.1.0"}


def test_wait_before_close_tolerates_eof():
    from m2a_launcher.main import _wait_before_close
    _wait_before_close(lambda _prompt: (_ for _ in ()).throw(EOFError()))


def test_menu_eof_exits_without_traceback(tmp_path: Path):
    from m2a_launcher.main import launch
    (tmp_path / ".env").write_text("LLM_API_KEY=test-only\n", encoding="utf-8")
    with patch("m2a_launcher.main.LauncherConfig.load", return_value=Mock(root=tmp_path)), patch(
        "builtins.input", side_effect=EOFError
    ):
        assert launch() == 1
