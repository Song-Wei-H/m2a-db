# Kali Worker Executor — long-running poller (run on Kali with DB access).
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-Location $ProjectRoot
$python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

& $python -m worker.task_poller
