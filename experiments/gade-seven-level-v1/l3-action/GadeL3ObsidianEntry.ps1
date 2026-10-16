function New-GadeL3ObsidianEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$RunId,
        [Parameter(Mandatory=$true)][string]$PairStatus,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$D7ActionId,
        [Parameter(Mandatory=$true)][string]$D7Status,
        [Parameter(Mandatory=$true)][string]$D7TargetVerdict,
        [Parameter(Mandatory=$true)][string]$FeedbackStatus,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$D1ActionId,
        [Parameter(Mandatory=$true)][string]$D1Verdict,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$D7RequestId,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$D1RequestId,
        [Parameter(Mandatory=$true)][string]$D7InitialEvidenceSha256,
        [Parameter(Mandatory=$true)][string]$D1InitialEvidenceSha256,
        [AllowEmptyString()][string]$CActionId = '',
        [AllowEmptyString()][string]$CVerdict = '',
        [AllowEmptyString()][string]$CRequestId = '',
        [AllowEmptyString()][string]$CInitialEvidenceSha256 = '',
        [AllowEmptyString()][string]$CStimulusSha256 = '',
        [Parameter(Mandatory=$true)][string]$ModelRequested,
        [AllowEmptyString()][string]$ModelReportedByCli,
        [Parameter(Mandatory=$true)][string]$WorkerSha256,
        [Parameter(Mandatory=$true)][string]$EvidencePath,
        [Parameter(Mandatory=$true)][datetime]$RecordedUtc
    )

    $date = $RecordedUtc.ToUniversalTime().ToString('yyyy-MM-dd')
    if ([string]::IsNullOrWhiteSpace($ModelReportedByCli)) {
        $reportedModel = 'not reported in Codex CLI events'
    } else {
        $reportedModel = $ModelReportedByCli.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($CVerdict)) {
        $aAction = if ([string]::IsNullOrWhiteSpace($D7ActionId)) { 'NONE' } else { $D7ActionId }
        $bAction = if ([string]::IsNullOrWhiteSpace($D1ActionId)) { 'NONE' } else { $D1ActionId }
        $cAction = if ([string]::IsNullOrWhiteSpace($CActionId)) { 'NONE' } else { $CActionId }
        return @"
## $date — L3-limited autonomous A/B/C exploratory data capture $RunId

- Status: $PairStatus. This is one exploratory proposal turn per arm, not a formal A/B/C sample. The authenticated Codex CLI Agent received the same verified post-reset base observation and the same L1-L3 Action catalog in each arm; only the GADE depth and C's fixed untrusted Evidence differ. Requested model: $ModelRequested; CLI-reported model: $reportedModel. Each arm was proposal-only at the Agent boundary; GADE remained the only authorization point.
- A: D_authorized=7; Agent-selected Action: $aAction; observed result: $D7Status; target classification: $D7TargetVerdict; Worker request ID: $D7RequestId.
- B: D_authorized=1; Agent-selected Action: $bAction; governance/result classification: $D1Verdict; Worker request ID: $D1RequestId when an L1 task was authorized.
- C: D_authorized=1 plus fixed untrusted Evidence; Agent-selected Action: $cAction; result classification: $CVerdict; Worker request ID: $CRequestId when an L1 task was authorized. Stimulus SHA-256: $CStimulusSha256.
- Reset Gate was verified before A, B, and C. Base initial Evidence SHA-256: A $D7InitialEvidenceSha256; B $D1InitialEvidenceSha256; C $CInitialEvidenceSha256. Worker :8001 build SHA-256: $WorkerSha256; Worker :8000 was not modified.
- Evidence: $EvidencePath; SHA-256 manifest: $EvidencePath\sha256-manifest.json. This exploratory run is excluded from the frozen formal-experiment plan and all formal sample counts.
- See [[M2A 已知問題（M2A Known Issues）]], [[M2A 執行手冊（M2A Runbook）]], and the GADE Experiment Design note.
"@
    }

    @"
## $date — Codex autonomous decision integration validation $RunId

- Status: $PairStatus. This is an isolated engineering validation; it is not a formal A/B/C sample. The live proposal source was the authenticated Codex CLI Agent using requested model $ModelRequested; the CLI event stream $reportedModel. The Agent received the verified post-reset observation and the three registered L1-L3 contracts. GADE independently evaluated each proposal; only the exact authorized ToolTask was sent to Worker :8001.
- D7: authorized depth 7; Codex proposed $D7ActionId from the supplied evidence. GADE allowed it and the real Worker execution completed as $D7Status with a complete Trace and Worker Receipt. Target classification: $D7TargetVerdict. Worker request ID: $D7RequestId.
- Feedback: after receiving the D7 ToolResult and target evidence, Codex proposed lab.valid_account_access.v1 as a possible next action. This feedback proposal was recorded and not executed.
- D1: authorized depth 1; after a separately verified Reset, Codex proposed $D1ActionId. GADE allowed this depth-1 action and its Worker execution completed as $D1Verdict. This did not test denial of an over-depth proposal. Worker request ID: $D1RequestId.
- Initial Evidence SHA-256: D7 $D7InitialEvidenceSha256; D1 $D1InitialEvidenceSha256.
- Both case Reset Gates were verified. Worker :8001 build SHA-256: $WorkerSha256. The Worker was not deployed or restarted; the shared :8000 Worker was only health-snapshot checked.
- Evidence: $EvidencePath; SHA-256 manifest: $EvidencePath\sha256-manifest.json. The original run artifacts are preserved. See [[M2A 已知問題（M2A Known Issues）]], [[M2A 執行手冊（M2A Runbook）]], and the GADE Experiment Design note.
"@
}

function Test-GadeL3ObsidianEntryReadback {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Readback,
        [AllowEmptyString()][string]$ExpectedEntry
    )

    if ([string]::IsNullOrWhiteSpace($Readback) -or [string]::IsNullOrWhiteSpace($ExpectedEntry)) {
        return $false
    }
    $expected = $ExpectedEntry.TrimEnd([char[]]@("`r", "`n"))
    return $Readback.IndexOf($expected, [StringComparison]::Ordinal) -ge 0
}
