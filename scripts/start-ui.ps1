param(
    [int[]]$ApiPorts = @(8000, 8001, 8002, 8003, 8004, 8005),
    [int[]]$UiPorts = @(5173, 5174, 5175, 5176, 5177, 5178),
    [string]$HostAddress = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Frontend = Join-Path $Root "frontend"

if (-not (Test-Path (Join-Path $Frontend "package.json"))) {
    throw "M2A frontend not found at $Frontend. Run this script from the repository scripts directory."
}

function Test-PortFree([int]$Port) {
    -not (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Find-CompatibleApis {
    $compatible = @()
    foreach ($port in $ApiPorts) {
        $base = "http://${HostAddress}:$port"
        try {
            $schema = Invoke-RestMethod "$base/openapi.json" -TimeoutSec 2
            $paths = $schema.paths.PSObject.Properties.Name
            if ($paths -contains "/workers/preflight" -and
                $paths -contains "/automation/targets/{target_id}/start") {
                $compatible += $base
            }
            Write-Warning "Ignoring stale M2A API at $base (required routes missing)."
        } catch {
            # Not an M2A API on this port; continue bounded discovery.
        }
    }
    return @($compatible)
}

$compatibleApis = @(Find-CompatibleApis)
if ($compatibleApis.Count -eq 0) {
    throw "No compatible M2A API found on ports $($ApiPorts -join ', '). Start it with scripts\start-api.ps1, then retry."
}
if ($compatibleApis.Count -gt 1) {
    throw "Multiple compatible M2A APIs found: $($compatibleApis -join ', '). Stop duplicate API instances before starting the UI; otherwise different runtime settings can process the same target."
}
$apiBase = $compatibleApis[0]

$uiPort = $UiPorts | Where-Object { Test-PortFree $_ } | Select-Object -First 1
if (-not $uiPort) {
    throw "No free UI port found in $($UiPorts -join ', '). Stop an old Vite process or supply -UiPorts."
}

$pnpm = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
if (-not $pnpm) {
    throw "pnpm.cmd was not found. Install Node.js/pnpm before starting the UI."
}

$env:VITE_M2A_PROXY_TARGET = $apiBase
Write-Host "M2A repository: $Root"
Write-Host "Compatible API: $apiBase"
Write-Host "Starting UI: http://${HostAddress}:$uiPort"
Set-Location $Frontend
& $pnpm.Source exec vite --host $HostAddress --port $uiPort
