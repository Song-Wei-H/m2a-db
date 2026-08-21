param([switch]$Clean)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) { throw "M2A Python virtual environment was not found." }
if ($Clean -and (Test-Path -LiteralPath (Join-Path $Root "build\M2A-Launcher"))) {
    Remove-Item -Recurse -Force -LiteralPath (Join-Path $Root "build\M2A-Launcher")
}
& $Python -m PyInstaller --noconfirm --onedir --console `
  --name M2A-Launcher `
  --specpath (Join-Path $Root "build") `
  --version-file (Join-Path $PSScriptRoot "launcher-version.txt") `
  (Join-Path $Root "m2a_launcher\main.py")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "M2A-Launcher.exe built: $Root\dist\M2A-Launcher\M2A-Launcher.exe"
