# Run one poll cycle (process all currently pending tool_tasks).
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-Location $ProjectRoot
$python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

& $python -c "import asyncio; from worker.task_poller import poll_once; n=asyncio.run(poll_once()); print(f'processed={n}')"
