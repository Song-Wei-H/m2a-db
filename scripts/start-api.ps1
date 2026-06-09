# Start FastAPI only if the port is free; fallback to 8001 when 8000 is taken.
param(
    [int]$Port = 8000,
    [int]$FallbackPort = 8001,
    [string]$HostAddress = "127.0.0.1",
    [switch]$NoFallback,
    [switch]$NoReload
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Get-ListenPids([int]$TargetPort) {
    $pids = @()
    netstat -ano | Select-String ":$TargetPort\s" | ForEach-Object {
        $line = $_.Line.Trim()
        if ($line -match "LISTENING\s+(\d+)\s*$") {
            $pids += [int]$Matches[1]
        }
    }
    $pids | Select-Object -Unique
}

$listenPids = Get-ListenPids -TargetPort $Port
$chosenPort = $Port

if ($listenPids.Count -gt 0) {
    $pidList = ($listenPids -join ", ")
    Write-Warning "Port $Port is already in use (PID: $pidList)."
    Write-Host "Check: netstat -ano | findstr :$Port"
    Write-Host "Stop:  taskkill /PID <PID> /F"

    if ($NoFallback) {
        Write-Error "Port $Port is busy. Stop the existing uvicorn or use -FallbackPort manually."
        exit 1
    }

    $fallbackPids = Get-ListenPids -TargetPort $FallbackPort
    if ($fallbackPids.Count -gt 0) {
        Write-Error "Fallback port $FallbackPort is also in use (PID: $($fallbackPids -join ', '))."
        exit 1
    }

    $chosenPort = $FallbackPort
    Write-Host "Using fallback port $chosenPort (preferred $Port was busy)."
} else {
    Write-Host "Starting API on http://${HostAddress}:$chosenPort"
}

$env:API_PORT = "$chosenPort"

$python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

$uvicornArgs = @(
    "-m", "uvicorn", "app.main:app",
    "--host", $HostAddress,
    "--port", "$chosenPort"
)
if (-not $NoReload) {
    $uvicornArgs += "--reload"
}

& $python @uvicornArgs
