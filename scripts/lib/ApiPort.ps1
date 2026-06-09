# Shared helpers: find FastAPI instance that exposes open-ports route.

$script:OpenPortsPath = "/targets/{target_id}/open-ports"
$script:DecisionsPath = "/decisions/run/{target_id}"

function Test-ApiHasOpenPortsRoute {
    param([string]$BaseUrl)
    try {
        $openapi = Invoke-RestMethod -Uri "$BaseUrl/openapi.json" -Method Get -TimeoutSec 3
        $paths = $openapi.paths.PSObject.Properties.Name
        return $paths -contains $script:OpenPortsPath
    } catch {
        return $false
    }
}

function Resolve-ApiBaseUrl {
    param(
        [int]$Port = 0,
        [string]$BaseUrl = ""
    )

    if ($BaseUrl) {
        return $BaseUrl
    }

    if ($Port -gt 0) {
        return "http://127.0.0.1:$Port"
    }

    if ($env:API_PORT) {
        return "http://127.0.0.1:$($env:API_PORT)"
    }

    # Prefer instance with open-ports route (8001 often = latest after start-api fallback).
    foreach ($candidate in @(8001, 8000)) {
        $url = "http://127.0.0.1:$candidate"
        if (Test-ApiHasOpenPortsRoute -BaseUrl $url) {
            Write-Verbose "Using API at $url (has $script:OpenPortsPath)"
            return $url
        }
    }

    return "http://127.0.0.1:8000"
}

function Assert-ApiHasOpenPortsRoute {
    param([string]$BaseUrl)

    if (Test-ApiHasOpenPortsRoute -BaseUrl $BaseUrl) {
        return
    }

    Write-Error @"
API at $BaseUrl does not expose GET $script:OpenPortsPath.
Likely causes:
  1. Old uvicorn still listening (only POST /targets) — stop it and restart:
       netstat -ano | findstr :8000
       taskkill /PID <PID> /F
       .\scripts\start-api.ps1
  2. Wrong port — try: .\scripts\get-open-ports.ps1 -TargetId <id> -Port 8001
  3. Check routes: .\scripts\check-api-routes.ps1
"@
}
