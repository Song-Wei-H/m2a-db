# Submit LLM-safe JSON tool proposal (no shell commands).
param(
    [string]$Tool = "httpx_basic",
    [string]$Target = "192.0.2.10",
    [string]$Reason = "Probe HTTP service on port 80",
    [string]$RiskLevel = "low",
    [string]$Profile = "internal",
    [int]$TargetId = 1,
    [int]$Port = 0,
    [string]$BaseUrl = ""
)

. "$PSScriptRoot\lib\ApiPort.ps1"
$BaseUrl = Resolve-ApiBaseUrl -Port $Port -BaseUrl $BaseUrl

$body = @{
    tool      = $Tool
    target    = $Target
    reason    = $Reason
    risk_level = $RiskLevel
    profile   = $Profile
    target_id = $TargetId
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "$BaseUrl/tools/llm-propose" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
