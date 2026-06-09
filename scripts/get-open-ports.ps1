# Use Invoke-RestMethod (not curl alias).
param(
    [Parameter(Mandatory = $true)]
    [int]$TargetId,
    [int]$Port = 0,
    [string]$BaseUrl = ""
)

. "$PSScriptRoot\lib\ApiPort.ps1"

$BaseUrl = Resolve-ApiBaseUrl -Port $Port -BaseUrl $BaseUrl
Assert-ApiHasOpenPortsRoute -BaseUrl $BaseUrl

try {
    Invoke-RestMethod `
        -Uri "$BaseUrl/targets/$TargetId/open-ports" `
        -Method Get
} catch {
    $resp = $_.Exception.Response
    if ($resp -and $resp.StatusCode.value__ -eq 404 -and $_.ErrorDetails.Message -match '"Not Found"') {
        Write-Error @"
HTTP 404 Not Found from $BaseUrl — route not registered on this instance.
Run: .\scripts\check-api-routes.ps1
Then restart API: taskkill old uvicorn PID, then .\scripts\start-api.ps1
"@
    }
    throw
}
