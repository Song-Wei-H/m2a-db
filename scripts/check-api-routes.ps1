# Show which local API ports are listening and whether open-ports route exists.
. "$PSScriptRoot\lib\ApiPort.ps1"

$route = $script:OpenPortsPath

Write-Host "Looking for GET $route ..."
Write-Host ""

foreach ($port in @(8000, 8001, 8002)) {
    $base = "http://127.0.0.1:$port"
    try {
        $openapi = Invoke-RestMethod -Uri "$base/openapi.json" -Method Get -TimeoutSec 2
        $paths = @($openapi.paths.PSObject.Properties.Name | Sort-Object)
        $hasOpenPorts = $paths -contains $route
        $marker = if ($hasOpenPorts) { "[OK]" } else { "[OLD?]" }
        Write-Host "$marker port $port — $($openapi.info.title) v$($openapi.info.version)"
        $paths | Where-Object { $_ -like "/targets*" } | ForEach-Object { Write-Host "       $_" }
        if (-not $hasOpenPorts) {
            Write-Host "       (missing $route — restart API with .\scripts\start-api.ps1)"
        }
        Write-Host ""
    } catch {
        Write-Host "[--] port $port — not reachable"
        Write-Host ""
    }
}
