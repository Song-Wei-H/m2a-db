$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'GadeL3ResetGate.ps1')

$script:assertions = 0
function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertions++
}

function Assert-Rejected([scriptblock]$Action, [string]$ExpectedText) {
    $caught = $false
    try { & $Action | Out-Null }
    catch {
        $caught = $true
        Assert-Test ($_.Exception.Message -like "*$ExpectedText*") "Unexpected rejection: $($_.Exception.Message)"
    }
    Assert-Test $caught "Expected rejection containing '$ExpectedText'."
}

function Get-FileSha256Hex([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()) }
    finally { $sha.Dispose(); $stream.Dispose() }
}

$runnerPath = Join-Path $PSScriptRoot 'Invoke-GadeL3D7D1Host.ps1'
$resetPath = Join-Path $PSScriptRoot 'GadeL3ResetGate.ps1'
$testPath = $PSCommandPath
foreach ($path in @($runnerPath, $resetPath, $testPath)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert-Test ($parseErrors.Count -eq 0) "PowerShell 5.1 AST parser reported errors in '$path': $($parseErrors -join '; ')"
}

# Verify the finalization entry point is read-only and has no partial-run resume mode.
$runnerText = Get-Content -LiteralPath $runnerPath -Raw -Encoding UTF8
$finalizeStart = $runnerText.IndexOf('function Finalize-ExistingTargetEvidence(')
$finalizeEnd = $runnerText.IndexOf('function Find-FreePort', $finalizeStart)
Assert-Test ($finalizeStart -ge 0 -and $finalizeEnd -gt $finalizeStart) 'Could not isolate the existing-run finalizer.'
$finalizeBody = $runnerText.Substring($finalizeStart, $finalizeEnd - $finalizeStart)
Assert-Test ($finalizeBody.Contains('actions_replayed=$false') -and $finalizeBody.Contains('database_touched=$false') -and
    $finalizeBody.Contains('lab_reset_performed=$false')) 'Existing-run finalization no longer records its read-only/no-replay contract.'
Assert-Test (-not $finalizeBody.Contains('Invoke-L3DriverCase') -and -not $finalizeBody.Contains('Reset-Lab')) `
    'Existing-run finalization must not execute an Action or reset the target.'
Assert-Test (-not $runnerText.Contains('param([string]$ResumeRunId)')) 'Runner must not silently expose partial-run resume.'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('GadeL3ResetRecovery-' + [guid]::NewGuid().ToString('N'))
$runId = 'ce8361fd5788'
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    $validCase = "GADE-L3-D7-$runId-RESET"
    $validRequest = "$validCase-request"
    $validPath = Join-Path $testRoot 'valid-reset.json'
    $validCounter = @{ calls = 0 }
    Invoke-GadeResetGatedCase -RunId $runId -CaseId $validCase -RequestId $validRequest -EvidencePath $validPath `
        -ResetRequest { param($caseId, $requestId) [pscustomobject]@{ status='reset'; active_sessions=0; test_case_id=$caseId } } `
        -CaseAction { $validCounter.calls++ } | Out-Null
    $validEvidence = Get-Content -LiteralPath $validPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test ($validCounter.calls -eq 1) 'Case action should run once only after verified reset.'
    Assert-Test ($validEvidence.reset_status -ceq 'VERIFIED' -and $validEvidence.state_verification.passed) 'Successful reset evidence was not verified.'
    Assert-Test ($validEvidence.run_id -ceq $runId -and $validEvidence.case_id -ceq $validCase -and $validEvidence.request_id -ceq $validRequest) 'Reset evidence identity mismatch.'
    $started = [DateTime]::MinValue; $completed = [DateTime]::MinValue
    Assert-Test ([DateTime]::TryParse($validEvidence.reset_started_utc, [ref]$started) -and
        [DateTime]::TryParse($validEvidence.reset_completed_utc, [ref]$completed) -and $completed -ge $started) 'Reset timestamps are invalid or out of order.'

    $cCase = "GADE-L3-C-$runId-RESET"
    $cRequest = "$cCase-request"
    $cPath = Join-Path $testRoot 'valid-c-reset.json'
    $cCounter = @{ calls = 0 }
    Invoke-GadeResetGatedCase -RunId $runId -CaseId $cCase -RequestId $cRequest -EvidencePath $cPath `
        -ResetRequest { param($caseId, $requestId) [pscustomobject]@{ status='reset'; active_sessions=0; test_case_id=$caseId } } `
        -CaseAction { $cCounter.calls++ } | Out-Null
    $cEvidence = Get-Content -LiteralPath $cPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test ($cCounter.calls -eq 1 -and $cEvidence.case_id -ceq $cCase -and
        $cEvidence.request_id -ceq $cRequest -and $cEvidence.reset_status -ceq 'VERIFIED') 'C reset should run exactly once after verified identity/state.'

    $cFailedPath = Join-Path $testRoot 'failed-c-reset.json'
    $cFailedCounter = @{ calls = 0 }
    Assert-Rejected {
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $cCase -RequestId $cRequest -EvidencePath $cFailedPath `
            -ResetRequest { param($caseId, $requestId) [pscustomobject]@{ status='reset'; active_sessions=1; test_case_id=$caseId } } `
            -CaseAction { $cFailedCounter.calls++ } | Out-Null
    } 'Reset failed closed'
    Assert-Test ($cFailedCounter.calls -eq 0 -and
        (Get-Content -LiteralPath $cFailedPath -Raw -Encoding UTF8 | ConvertFrom-Json).reset_status -ceq 'FAILED') 'Failed C reset must block the case callback.'

    $failedCase = "GADE-L3-D1-$runId-RESET"
    $failedRequest = "$failedCase-request"
    $failedPath = Join-Path $testRoot 'failed-reset.json'
    $failedCounter = @{ calls = 0 }
    $resetCounter = @{ calls = 0 }
    Assert-Rejected {
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $failedCase -RequestId $failedRequest -EvidencePath $failedPath `
            -ResetRequest { param($caseId, $requestId) $resetCounter.calls++; [pscustomobject]@{ status='reset'; active_sessions=1; test_case_id=$caseId } } `
            -CaseAction { $failedCounter.calls++ } | Out-Null
    } 'Reset failed closed'
    $failedEvidence = Get-Content -LiteralPath $failedPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test ($resetCounter.calls -eq 1 -and $failedCounter.calls -eq 0) 'Failed reset must block the case action.'
    Assert-Test ($failedEvidence.reset_status -ceq 'FAILED' -and -not $failedEvidence.state_verification.passed) 'Failed reset evidence was not persisted as failed.'

    $throwPath = Join-Path $testRoot 'throwing-reset.json'
    $throwCounter = @{ calls = 0 }
    Assert-Rejected {
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $validCase -RequestId $validRequest -EvidencePath $throwPath `
            -ResetRequest { throw 'synthetic local reset failure' } -CaseAction { $throwCounter.calls++ } | Out-Null
    } 'Reset failed closed'
    $throwEvidence = Get-Content -LiteralPath $throwPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test ($throwCounter.calls -eq 0 -and $throwEvidence.reset_status -ceq 'FAILED' -and
        $throwEvidence.failure_reason -like '*synthetic local reset failure*') 'Reset exception was not preserved while fail-closing the action.'

    $duplicateResetCalls = @{ calls = 0 }
    Assert-Rejected {
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $validCase -RequestId $validRequest -EvidencePath $validPath `
            -ResetRequest { $duplicateResetCalls.calls++ } -CaseAction { throw 'must not run' } | Out-Null
    } 'Reset evidence already exists'
    Assert-Test ($duplicateResetCalls.calls -eq 0) 'Existing reset evidence must prevent a repeat reset/action.'

    $mismatchPath = Join-Path $testRoot 'mismatch-reset.json'
    $mismatchResetCalls = @{ calls = 0 }
    Assert-Rejected {
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $validCase -RequestId 'wrong-request-id' -EvidencePath $mismatchPath `
            -ResetRequest { $mismatchResetCalls.calls++ } -CaseAction { throw 'must not run' } | Out-Null
    } 'identity mismatch'
    Assert-Test ($mismatchResetCalls.calls -eq 0 -and -not (Test-Path -LiteralPath $mismatchPath)) 'Identity mismatch must fail before Reset and evidence creation.'

    # The interrupted historical run lacks the artifacts required by read-only finalization.
    # The child process must reject it before Docker/log access and leave original evidence byte-identical.
    $historicalDir = Join-Path $PSScriptRoot "local-only\$runId"
    $manifestPath = Join-Path $historicalDir 'manifest.json'
    $blockerPath = Join-Path $historicalDir 'blocker-packet.json'
    Assert-Test ((Test-Path -LiteralPath $manifestPath -PathType Leaf) -and (Test-Path -LiteralPath $blockerPath -PathType Leaf)) 'Historical run evidence is unavailable for the no-mutation check.'
    $beforeManifest = Get-FileSha256Hex $manifestPath
    $beforeBlocker = Get-FileSha256Hex $blockerPath
    $beforeNames = @(Get-ChildItem -LiteralPath $historicalDir -Force | ForEach-Object Name | Sort-Object)
    $stdoutPath = Join-Path $testRoot 'finalize.stdout.log'
    $stderrPath = Join-Path $testRoot 'finalize.stderr.log'
    $argLine = '-NoProfile -ExecutionPolicy RemoteSigned -File "' + $runnerPath + '" -FinalizeExistingRunId ' + $runId
    $previousModulePath = $env:PSModulePath
    try {
        # A PowerShell 7 parent can pass its module path into this Windows PowerShell child.
        # Set the standard Windows PowerShell 5.1 module locations for this child process only.
        $env:PSModulePath = @(
            (Join-Path $PSHOME 'Modules'),
            (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'),
            (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules')
        ) -join ';'
        $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $argLine -PassThru -Wait -NoNewWindow `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    }
    finally {
        $env:PSModulePath = $previousModulePath
    }
    $finalizeOutput = ((Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue) + "`n" +
        (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue))
    Assert-Test ($process.ExitCode -ne 0 -and $finalizeOutput -match 'Required preserved evidence is missing: run-state\.json') `
        ("Incomplete-run finalization should reject before resuming or querying Docker; exit=$($process.ExitCode); output=$finalizeOutput")
    Assert-Test ((Get-FileSha256Hex $manifestPath) -ceq $beforeManifest -and
        (Get-FileSha256Hex $blockerPath) -ceq $beforeBlocker) 'Read-only recovery altered original run evidence.'
    $afterNames = @(Get-ChildItem -LiteralPath $historicalDir -Force | ForEach-Object Name | Sort-Object)
    Assert-Test (($beforeNames -join "`n") -ceq ($afterNames -join "`n")) 'Read-only recovery created or removed historical run files.'

    Write-Output "L3_RESET_RECOVERY_TEST=PASS assertions=$script:assertions powershell=$($PSVersionTable.PSVersion) old_run_resumed=false"
}
finally {
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
