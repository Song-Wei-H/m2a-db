from pathlib import Path


def test_start_ui_discovers_path_ports_and_required_routes():
    script = (Path(__file__).parents[1] / "scripts" / "start-ui.ps1").read_text(encoding="utf-8")
    assert "$PSScriptRoot" in script
    assert "/openapi.json" in script
    assert "/workers/preflight" in script
    assert "/automation/targets/{target_id}/start" in script
    assert "VITE_M2A_PROXY_TARGET" in script
    assert "Get-NetTCPConnection" in script
