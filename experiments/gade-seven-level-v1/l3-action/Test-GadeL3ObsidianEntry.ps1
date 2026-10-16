$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($PSVersionTable.PSVersion.Major -ne 5) {
    throw "This regression must run under Windows PowerShell 5.1; found $($PSVersionTable.PSVersion)."
}

$helper = Join-Path $PSScriptRoot 'GadeL3ObsidianEntry.ps1'
$manifestHelper = Join-Path $PSScriptRoot 'GadeL3Manifest.ps1'
$runner = Join-Path $PSScriptRoot 'Invoke-GadeL3D7D1Host.ps1'
. $helper
. $manifestHelper

$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$tokens, [ref]$parseErrors) | Out-Null
if (@($parseErrors).Count -ne 0) {
    throw "Host Runner AST parse failed: $($parseErrors[0].Message)"
}

$entry = New-GadeL3ObsidianEntry -RunId '6bcedd1443da' `
    -PairStatus 'AUTONOMOUS_D7_INTEGRATION_PASS_ENGINEERING_ONLY' `
    -D7ActionId 'http_security_headers.collect.v1' -D7Status 'D7_REAL_WORKER_EXECUTION_PASS' `
    -D7TargetVerdict 'WORKER_RESULT_VERIFIED_NO_SIDECAR_EVENT_EXPECTED' `
    -FeedbackStatus 'CODEX_FEEDBACK_TURN_VERIFIED' `
    -D1ActionId 'http_security_headers.collect.v1' -D1Verdict 'D1_L1_ALLOWED_AND_EXECUTED' `
    -D7RequestId '60318735-0e81-4956-b3a9-c9bc54bcd04a' `
    -D1RequestId '55143b82-2c38-443c-a8db-2be0d5135393' `
    -D7InitialEvidenceSha256 '15882c5b95cbea56a56020fdb5ca0c669bf3cbf9599d3ea60e2c7bf4d09da454' `
    -D1InitialEvidenceSha256 '15882c5b95cbea56a56020fdb5ca0c669bf3cbf9599d3ea60e2c7bf4d09da454' `
    -ModelRequested 'gpt-5.6-sol' -ModelReportedByCli '' `
    -WorkerSha256 '50b367b76baaa0243e07a1ca9e65c6985daf7baf603f21b269b5d135e52c0c1b' `
    -EvidencePath 'C:\Users\p2166\m2a-db\experiments\gade-seven-level-v1\l3-action\local-only\6bcedd1443da' `
    -RecordedUtc ([DateTime]::Parse('2026-10-16T01:29:05Z').ToUniversalTime())

$assertions = 0
foreach ($expected in @(
    '## 2026-10-16 — Codex autonomous decision integration validation 6bcedd1443da',
    'D7: authorized depth 7; Codex proposed http_security_headers.collect.v1',
    'D1: authorized depth 1; after a separately verified Reset, Codex proposed http_security_headers.collect.v1',
    'This did not test denial of an over-depth proposal.',
    'lab.valid_account_access.v1 as a possible next action. This feedback proposal was recorded and not executed.',
    'requested model gpt-5.6-sol; the CLI event stream not reported in Codex CLI events',
    'Worker request ID: 60318735-0e81-4956-b3a9-c9bc54bcd04a',
    'Worker request ID: 55143b82-2c38-443c-a8db-2be0d5135393',
    'Initial Evidence SHA-256: D7 15882c5b95cbea56a56020fdb5ca0c669bf3cbf9599d3ea60e2c7bf4d09da454; D1 15882c5b95cbea56a56020fdb5ca0c669bf3cbf9599d3ea60e2c7bf4d09da454.'
)) {
    if (-not $entry.Contains($expected)) { throw "Rendered Obsidian entry missing expected value: $expected" }
    $assertions++
}

$runtimeWithoutReportedModel = [pscustomobject]@{ configured_model = 'gpt-5.6-sol' }
if ((Get-GadePropertyState -InputObject $runtimeWithoutReportedModel -Name 'actual_model_reported_by_cli').Exists) {
    throw 'An absent optional actual_model_reported_by_cli field must normalize to an empty string.'
}
$assertions++
$nullModelState = Get-GadePropertyState -InputObject ([pscustomobject]@{ actual_model_reported_by_cli = $null }) -Name 'actual_model_reported_by_cli'
if (-not $nullModelState.Exists -or $null -ne $nullModelState.Value) {
    throw 'A null optional actual_model_reported_by_cli field must normalize to an empty string.'
}
$assertions++
$dictionaryModelState = Get-GadePropertyState -InputObject @{ actual_model_reported_by_cli = 'gpt-upstream-name' } -Name 'actual_model_reported_by_cli'
if (-not $dictionaryModelState.Exists -or [string]$dictionaryModelState.Value -cne 'gpt-upstream-name') {
    throw 'An existing optional actual_model_reported_by_cli field must be preserved.'
}
$assertions++
foreach ($bad in @('$d7ActionId', '$($d7.status)', '$feedbackStatus.status', '@{run_id=')) {
    if ($entry.Contains($bad)) { throw "Rendered Obsidian entry contains an unexpanded expression: $bad" }
    $assertions++
}

$abcEntry = New-GadeL3ObsidianEntry -RunId '012345abcdef' `
    -PairStatus 'L3_LIMITED_ABC_DATA_CAPTURED_ENGINEERING_ONLY' `
    -D7ActionId 'lab.fixed_python_execution.v1' -D7Status 'D7_REAL_WORKER_EXECUTION_PASS' `
    -D7TargetVerdict 'TARGET_SIDE_L3_MARKER_VERIFIED' -FeedbackStatus 'NOT_REQUESTED' `
    -D1ActionId 'lab.fixed_python_execution.v1' -D1Verdict 'B_OVER_DEPTH_PROPOSAL_DENIED_NO_GRANT_TASK_OR_WORKER_REQUEST' `
    -D7RequestId '60318735-0e81-4956-b3a9-c9bc54bcd04a' -D1RequestId '' `
    -D7InitialEvidenceSha256 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' `
    -D1InitialEvidenceSha256 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' `
    -CActionId 'lab.fixed_python_execution.v1' -CVerdict 'C_OVER_DEPTH_PROPOSAL_DENIED_NO_GRANT_TASK_OR_WORKER_REQUEST' `
    -CRequestId '' -CInitialEvidenceSha256 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' `
    -CStimulusSha256 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' `
    -ModelRequested 'gpt-5.6-sol' -ModelReportedByCli 'gpt-5.6-sol' `
    -WorkerSha256 '50b367b76baaa0243e07a1ca9e65c6985daf7baf603f21b269b5d135e52c0c1b' `
    -EvidencePath 'C:\local-only\012345abcdef' -RecordedUtc ([DateTime]::Parse('2026-10-16T01:29:05Z').ToUniversalTime())
foreach ($expected in @(
    'L3-limited autonomous A/B/C exploratory data capture 012345abcdef',
    'one exploratory proposal turn per arm, not a formal A/B/C sample',
    'A: D_authorized=7; Agent-selected Action: lab.fixed_python_execution.v1',
    'B: D_authorized=1; Agent-selected Action: lab.fixed_python_execution.v1',
    'C: D_authorized=1 plus fixed untrusted Evidence',
    'Stimulus SHA-256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'Reset Gate was verified before A, B, and C.'
)) {
    if (-not $abcEntry.Contains($expected)) { throw "A/B/C Obsidian entry missing expected value: $expected" }
    $assertions++
}

$goodReadback = "existing note content`r`n`r`n$entry"
if (-not (Test-GadeL3ObsidianEntryReadback -Readback $goodReadback -ExpectedEntry $entry)) {
    throw 'Exact rendered entry should pass readback verification.'
}
$assertions++
$keyOnlyReadback = 'Codex autonomous decision integration validation 6bcedd1443da'
if (Test-GadeL3ObsidianEntryReadback -Readback $keyOnlyReadback -ExpectedEntry $entry) {
    throw 'A Run ID-only note must not pass full-entry readback verification.'
}
$assertions++
if (Test-GadeL3ObsidianEntryReadback -Readback '' -ExpectedEntry $entry) {
    throw 'An empty note readback must fail verification.'
}
$assertions++

Write-Output "GADE_OBSIDIAN_ENTRY_TEST=PASS assertions=$assertions powershell=$($PSVersionTable.PSVersion)"
