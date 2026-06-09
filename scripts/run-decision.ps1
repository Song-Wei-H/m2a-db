param(
    [Parameter(Mandatory = $true)]
    [int]$TargetId,
    [int]$Port = 0,
    [string]$BaseUrl = ""
)

. "$PSScriptRoot\lib\ApiPort.ps1"

$BaseUrl = Resolve-ApiBaseUrl -Port $Port -BaseUrl $BaseUrl

Invoke-RestMethod `
    -Uri "$BaseUrl/decisions/run/$TargetId" `
    -Method Post
