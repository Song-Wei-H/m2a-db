# Use Invoke-RestMethod (PowerShell curl alias breaks -H / -d syntax).
param(
    [string]$Target = "192.0.2.10",
    [int]$Port = 0,
    [string]$BaseUrl = ""
)

. "$PSScriptRoot\lib\ApiPort.ps1"

$BaseUrl = Resolve-ApiBaseUrl -Port $Port -BaseUrl $BaseUrl

$body = @{
    target      = $Target
    target_type = "ip"
    scope       = "internal"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "$BaseUrl/targets" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
