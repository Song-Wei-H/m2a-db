# Start FastAPI only if the port is free; fallback to 8001 when 8000 is taken.
param(
    [int]$Port = 8000,
    [int]$FallbackPort = 8001,
    [int[]]$DiscoveryPorts = @(8000, 8001, 8002, 8003, 8004, 8005),
    [string]$HostAddress = "127.0.0.1",
    [switch]$NoFallback,
    [switch]$NoReload,
    [switch]$AllowAdditionalInstance
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

function Get-CompatibleM2AInstances {
    $instances = @()
    foreach ($candidate in $DiscoveryPorts) {
        try {
            $base = "http://${HostAddress}:$candidate"
            $schema = Invoke-RestMethod "$base/openapi.json" -TimeoutSec 2
            $paths = $schema.paths.PSObject.Properties.Name
            if ($schema.info.title -eq "M2A Pentest API" -and
                $paths -contains "/workers/preflight" -and
                $paths -contains "/automation/targets/{target_id}/retest") {
                $instances += [pscustomobject]@{
                    Port = $candidate
                    BaseUrl = $base
                    Pids = @((Get-ListenPids -TargetPort $candidate))
                }
            }
        } catch {
            # Not a compatible M2A API on this bounded port.
        }
    }
    return @($instances)
}

if (-not $AllowAdditionalInstance) {
    $existing = @(Get-CompatibleM2AInstances)
    if ($existing.Count -gt 0) {
        $description = ($existing | ForEach-Object { "$($_.BaseUrl) (PID $($_.Pids -join ','))" }) -join "; "
        Write-Host "Compatible M2A API already running: $description"
        Write-Host "Reusing the existing singleton. No additional API was started."
        exit 0
    }
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
