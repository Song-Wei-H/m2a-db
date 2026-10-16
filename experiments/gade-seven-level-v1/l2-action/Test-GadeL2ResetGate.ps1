$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeL2ResetGate.ps1')

$script:passed = 0
function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:passed++
}
function New-TempEvidencePath {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('gade-reset-gate-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir | Out-Null
    return (Join-Path $dir 'reset.json')
}
function New-ResetResponse([string]$CaseId, [string]$Status='reset', [int]$Sessions=0) {
    return [pscustomobject]@{status=$Status;active_sessions=$Sessions;test_case_id=$CaseId}
}

$run='a0a7077dd35d'
$case='GADE-L2-D7-a0a7077dd35d-RESET'
$request="$case-request"
$mismatchPath=New-TempEvidencePath
$called=$false
try { Invoke-GadeResetGatedCase -RunId $run -CaseId 'GADE-L2-D7-ffffffffffff-RESET' -RequestId $request `
    -EvidencePath $mismatchPath -ResetRequest { param($c,$r) New-ResetResponse $c } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected identity failure.' } catch {
    Assert-Test (-not $called -and -not (Test-Path $mismatchPath)) 'Run/Case/Request identity mismatch must stop before reset or action.'
}
$path=New-TempEvidencePath
$called=$false
$result=Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
    -ResetRequest { param($c,$r) New-ResetResponse $c } -CaseAction { $script:called=$true; 'ACTION_RAN' }
$saved=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
Assert-Test ($result -ceq 'ACTION_RAN' -and $called) 'Verified reset must permit the following case.'
Assert-Test ($saved.run_id -ceq $run -and $saved.case_id -ceq $case -and $saved.request_id -ceq $request) 'Reset identity evidence was not saved.'
Assert-Test ($saved.state_verification.passed -and $saved.state_verification.active_sessions -eq 0) 'Reset state proof was not persisted.'
Assert-Test ($saved.reset_started_utc -and $saved.reset_completed_utc -and $saved.target_response.status -ceq 'reset') 'Reset timing/response evidence is incomplete.'

$called=$false; $path=New-TempEvidencePath
try { Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
    -ResetRequest { throw 'mock transport failure' } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected reset exception.' } catch {
    $failed=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Assert-Test (-not $called -and $failed.reset_status -ceq 'FAILED' -and -not $failed.state_verification.passed) 'Reset exception must block action and preserve a failed-attempt record.'
}

foreach($bad in @(@('denied',0),@('reset',1))) {
    $called=$false; $path=New-TempEvidencePath
    try { Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
        -ResetRequest { param($c,$r) New-ResetResponse $c $bad[0] $bad[1] } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected response validation failure.' } catch {
        $failed=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-Test (-not $called -and $failed.reset_status -ceq 'FAILED' -and -not $failed.state_verification.passed) 'Invalid reset state must block action and record the failed verification.'
    }
}

foreach($badResponse in @(
    [pscustomobject]@{status='reset';active_sessions='not-a-number';test_case_id=$case},
    [pscustomobject]@{status='reset';active_sessions=0}
)) {
    $called=$false; $path=New-TempEvidencePath
    try { Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
        -ResetRequest { param($c,$r) $badResponse } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected malformed response failure.' } catch {
        $failed=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-Test (-not $called -and $failed.reset_status -ceq 'FAILED') 'Malformed reset response must fail closed and be recorded.'
    }
}

$called=$false; $path=New-TempEvidencePath
try { Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
    -ResetRequest { param($c,$r) New-ResetResponse 'wrong-case' } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected case identity failure.' } catch {
    $failed=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Assert-Test (-not $called -and $failed.reset_status -ceq 'FAILED' -and -not $failed.state_verification.passed) 'Mismatched reset case identity must fail closed and be recorded.'
}

$path=New-TempEvidencePath; Set-Content -LiteralPath $path -Value 'preserve'
$called=$false
try { Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
    -ResetRequest { param($c,$r) New-ResetResponse $c } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected overwrite refusal.' } catch {
    Assert-Test (-not $called -and (Get-Content -LiteralPath $path -Raw).Trim() -ceq 'preserve') 'Existing evidence must be preserved and block action.'
}

$path=New-TempEvidencePath
New-Item -ItemType Directory -Path $path | Out-Null
$called=$false
try { Invoke-GadeResetGatedCase -RunId $run -CaseId $case -RequestId $request -EvidencePath $path `
    -ResetRequest { param($c,$r) New-ResetResponse $c } -CaseAction { $script:called=$true } | Out-Null; throw 'Expected evidence destination failure.' } catch {
    Assert-Test (-not $called -and (Test-Path -LiteralPath $path -PathType Container)) 'Evidence persistence failure must stop before the case and preserve the existing path.'
}

Write-Output "RESET_GATE_MOCK_TESTS=PASS assertions=$script:passed"
