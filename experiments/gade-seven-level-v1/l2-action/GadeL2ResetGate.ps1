function Invoke-GadeResetGatedCase {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{12}$')][string]$RunId,
        [Parameter(Mandatory=$true)][ValidatePattern('^GADE-L2-(D7|D1)-[0-9a-f]{12}-RESET$')][string]$CaseId,
        [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._:-]{1,128}$')][string]$RequestId,
        [Parameter(Mandatory=$true)][string]$EvidencePath,
        [Parameter(Mandatory=$true)][scriptblock]$ResetRequest,
        [Parameter(Mandatory=$true)][scriptblock]$CaseAction
    )

    if (Test-Path -LiteralPath $EvidencePath) {
        throw "Reset evidence already exists; refusing to overwrite: $EvidencePath"
    }
    if ($CaseId -cnotin @("GADE-L2-D7-$RunId-RESET", "GADE-L2-D1-$RunId-RESET") -or
        $RequestId -cne "$CaseId-request") {
        throw "Reset run/case/request identity mismatch; case action was not started."
    }
    $parent = Split-Path -Parent $EvidencePath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Reset evidence directory does not exist: $parent"
    }

    $started = [DateTime]::UtcNow.ToString('o')
    $response = $null
    $requestError = $null
    try {
        $response = & $ResetRequest $CaseId $RequestId
    } catch {
        $requestError = $_.Exception.Message
    }
    $completed = [DateTime]::UtcNow.ToString('o')
    $statusProperty = if ($null -ne $response) { $response.PSObject.Properties['status'] } else { $null }
    $sessionsProperty = if ($null -ne $response) { $response.PSObject.Properties['active_sessions'] } else { $null }
    $caseProperty = if ($null -ne $response) { $response.PSObject.Properties['test_case_id'] } else { $null }
    $sessionCount = $null
    $sessionCountValid = $false
    if ($null -ne $sessionsProperty) {
        $parsedSessionCount = 0
        $sessionCountValid = [int]::TryParse([string]$sessionsProperty.Value, [ref]$parsedSessionCount)
        if ($sessionCountValid) { $sessionCount = $parsedSessionCount }
    }
    $statePassed = ($null -eq $requestError -and $null -ne $statusProperty -and $null -ne $sessionsProperty -and
        $null -ne $caseProperty -and $statusProperty.Value -ceq 'reset' -and $sessionCountValid -and
        $sessionCount -eq 0 -and $caseProperty.Value -ceq $CaseId)
    $failureReason = $requestError
    if (-not $statePassed -and [string]::IsNullOrWhiteSpace($failureReason)) {
        $failureReason = 'Reset response did not prove status=reset, active_sessions=0, and matching test_case_id.'
    }

    $evidence = [ordered]@{
        schema_version = 1
        run_id = $RunId
        case_id = $CaseId
        request_id = $RequestId
        reset_started_utc = $started
        reset_completed_utc = $completed
        reset_status = $(if ($statePassed) { 'VERIFIED' } else { 'FAILED' })
        target_response = $response
        state_verification = [ordered]@{
            passed = [bool]$statePassed
            status = $(if ($null -ne $statusProperty) { [string]$statusProperty.Value } else { $null })
            active_sessions = $sessionCount
            test_case_id = $(if ($null -ne $caseProperty) { [string]$caseProperty.Value } else { $null })
        }
        failure_reason = $failureReason
    }

    $tempPath = Join-Path $parent ('.' + [IO.Path]::GetFileName($EvidencePath) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $evidence | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($tempPath, $json, (New-Object Text.UTF8Encoding($false)))
        # File.Move is atomic within the same directory and fails if the destination exists.
        [IO.File]::Move($tempPath, $EvidencePath)
    } catch {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue }
        throw "Could not persist verified Reset evidence for run=$RunId case=$CaseId; case action was not started. $($_.Exception.Message)"
    }

    if (-not $statePassed) {
        throw "Reset failed closed for run=$RunId case=$CaseId request=$RequestId; case action was not started. $failureReason"
    }

    # The case callback is deliberately unreachable until response validation and durable evidence succeed.
    & $CaseAction
}
