$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeL3MultiRound.ps1')
. (Join-Path $PSScriptRoot 'GadeL3ResetGate.ps1')

$script:assertions = 0
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertions++
}
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $thrown=$false
    try { & $Action | Out-Null } catch { $thrown=$true }
    Assert-True $thrown $Message
}

$success = [pscustomobject]@{
    agent_output=[pscustomobject]@{decision='PROPOSE_ACTION'}
    status='D7_REAL_WORKER_EXECUTION_PASS'
    authorization_decision=[pscustomobject]@{outcome='ALLOW'}
    execution_authorization=[pscustomobject]@{id=101}
    tool_task_created=$true; worker_request_sent=$true
    tool_result=[pscustomobject]@{success=$true}
    worker_receipt=[pscustomobject]@{handler_invoked=$true}
    trace=[pscustomobject]@{status='COMPLETE'}
}
$result=Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $success
Assert-True ($result.Continue -and $null -eq $result.StopReason) 'Verified execution should permit exactly one feedback round.'
$result=Get-GadeL3RoundDisposition -RoundNumber 5 -MaxRounds 5 -Evidence $success
Assert-True (-not $result.Continue -and $result.StopReason -ceq 'MAX_ROUNDS_REACHED') 'The fifth round must stop without a sixth proposal.'

$codexVersionBaseline = Set-GadeMultiRoundCodexVersionBaseline -Baseline $null -ObservedVersion 'codex-cli 0.163.0-alpha.10.2'
Assert-True ($codexVersionBaseline -ceq 'codex-cli 0.163.0-alpha.10.2') 'The first completed arm must establish the suite Codex CLI version baseline.'
$codexVersionBaseline = Set-GadeMultiRoundCodexVersionBaseline -Baseline $codexVersionBaseline -ObservedVersion 'codex-cli 0.163.0-alpha.10.2'
Assert-True ($codexVersionBaseline -ceq 'codex-cli 0.163.0-alpha.10.2') 'A matching later arm must preserve the suite Codex CLI version baseline.'
Assert-Throws { Set-GadeMultiRoundCodexVersionBaseline -Baseline $codexVersionBaseline -ObservedVersion 'codex-cli 0.164.0' } 'A changed Codex CLI version between arms must fail closed.'
Assert-Throws { Set-GadeMultiRoundCodexVersionBaseline -Baseline $null -ObservedVersion $null } 'A missing Codex CLI version must fail closed.'

$stop=[pscustomobject]@{agent_output=[pscustomobject]@{decision='STOP'};tool_task_created=$false;worker_request_sent=$false;execution_authorization=$null}
$result=Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $stop
Assert-True (-not $result.Continue -and $result.StopReason -ceq 'AGENT_STOP') 'Agent STOP must end the arm without action substitution.'

$deny=[pscustomobject]@{agent_output=[pscustomobject]@{decision='PROPOSE_ACTION'};authorization_decision=[pscustomobject]@{outcome='DENY'};execution_authorization=$null;tool_task_created=$false;worker_request_sent=$false;status='D1_GOVERNANCE_DENIAL_PASS'}
$result=Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $deny
Assert-True (-not $result.Continue -and $result.StopReason -ceq 'GADE_DENY') 'GADE denial must stop rather than silently continue.'

$pending=[pscustomobject]@{agent_output=[pscustomobject]@{decision='PROPOSE_ACTION'};authorization_decision=[pscustomobject]@{outcome='PENDING'};execution_authorization=$null;tool_task_created=$false;worker_request_sent=$false}
$result=Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $pending
Assert-True (-not $result.Continue -and $result.StopReason -ceq 'GADE_PENDING') 'Pending Approval must stop before execution.'

$missingReceipt=$success | Select-Object *
$missingReceipt.worker_receipt=$null
Assert-Throws { Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $missingReceipt } 'ALLOW without a Worker Receipt must fail closed.'
$badTrace=$success | Select-Object *
$badTrace.trace=[pscustomobject]@{status='PARTIAL'}
Assert-Throws { Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $badTrace } 'ALLOW without complete Trace must fail closed.'
$badGrant=$deny | Select-Object *
$badGrant.execution_authorization=[pscustomobject]@{id=102}
Assert-Throws { Get-GadeL3RoundDisposition -RoundNumber 1 -MaxRounds 5 -Evidence $badGrant } 'DENY with a Grant must fail closed.'
Assert-Throws { Get-GadeL3RoundDisposition -RoundNumber 6 -MaxRounds 5 -Evidence $success } 'A sixth round must be rejected.'

$stableActions = @(
    [pscustomobject]@{action_id='http_security_headers.collect.v1';required_depth=1;parameter_schema=[ordered]@{type='object';properties=[ordered]@{target=@{type='string'}}}},
    [pscustomobject]@{action_id='lab.valid_account_access.v1';required_depth=2;parameter_schema=[ordered]@{type='object';properties=[ordered]@{target=@{type='string'}}}},
    [pscustomobject]@{action_id='lab.fixed_python_execution.v1';required_depth=3;parameter_schema=[ordered]@{type='object';properties=[ordered]@{target=@{type='string'}}}}
)
$catalogCreated = [pscustomobject]@{
    actions=$stableActions
    registrations=@([pscustomobject]@{action_id='http_security_headers.collect.v1';tool_registry_state='created';validation_action_state='reconciled'})
}
$catalogVerified = [pscustomobject]@{
    actions=$stableActions
    registrations=@([pscustomobject]@{action_id='http_security_headers.collect.v1';tool_registry_state='verified';validation_action_state='verified'})
}
$catalogHashCreated = Get-GadeActionCatalogContractSha256 -CatalogDocument $catalogCreated
$catalogHashVerified = Get-GadeActionCatalogContractSha256 -CatalogDocument $catalogVerified
Assert-True ($catalogHashCreated -ceq $catalogHashVerified) 'Registration metadata changes must not alter the Action Contract catalog fingerprint.'

$propertyOrderActions = @(
    [pscustomobject]@{required_depth=1;action_id='http_security_headers.collect.v1';parameter_schema=[ordered]@{properties=[ordered]@{target=@{type='string'}};type='object'}},
    [pscustomobject]@{required_depth=2;action_id='lab.valid_account_access.v1';parameter_schema=[ordered]@{properties=[ordered]@{target=@{type='string'}};type='object'}},
    [pscustomobject]@{required_depth=3;action_id='lab.fixed_python_execution.v1';parameter_schema=[ordered]@{properties=[ordered]@{target=@{type='string'}};type='object'}}
)
$catalogPropertyOrder = [pscustomobject]@{actions=$propertyOrderActions;registrations=@()}
Assert-True ((Get-GadeActionCatalogContractSha256 -CatalogDocument $catalogPropertyOrder) -ceq $catalogHashCreated) 'JSON object property order must not alter the Action Contract fingerprint.'

$catalogChangedAction = ConvertFrom-Json (ConvertTo-Json -InputObject $catalogCreated -Depth 20 -Compress)
$catalogChangedAction.actions[1].required_depth = 3
Assert-True ((Get-GadeActionCatalogContractSha256 -CatalogDocument $catalogChangedAction) -cne $catalogHashCreated) 'A changed Action Contract must alter the catalog fingerprint.'

$catalogMissingAction = [pscustomobject]@{actions=@($stableActions[0],$stableActions[1]);registrations=@()}
Assert-Throws { Get-GadeActionCatalogContractSha256 -CatalogDocument $catalogMissingAction } 'An incomplete Action catalog must fail closed.'

$catalogTestPath = Join-Path ([IO.Path]::GetTempPath()) ('gade-l3-catalog-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $catalogJson = ConvertTo-Json -InputObject $catalogCreated -Depth 50 -Compress
    [IO.File]::WriteAllText($catalogTestPath, $catalogJson, (New-Object Text.UTF8Encoding($false)))
    $catalogVerification = Import-GadeVerifiedActionCatalog -Path $catalogTestPath -ExpectedContractSha256 $catalogHashCreated
    $catalogDocument = $catalogVerification.Document
    $actualContractCatalogSha = $catalogVerification.ContractSha256
    Assert-True ($actualContractCatalogSha -ceq $catalogHashCreated) 'The StrictMode-safe catalog loader must return the verified fingerprint.'
    Assert-True (@(Get-GadeMultiRoundProperty -InputObject $catalogDocument -Name 'actions').Count -eq 3) 'The StrictMode-safe catalog loader must return the initialized document.'
    Assert-Throws { Import-GadeVerifiedActionCatalog -Path ($catalogTestPath + '.missing') -ExpectedContractSha256 $catalogHashCreated } 'A missing catalog file must fail closed.'
    Assert-Throws { Import-GadeVerifiedActionCatalog -Path $catalogTestPath -ExpectedContractSha256 ('0' * 64) } 'A mismatched catalog fingerprint must fail closed.'

    $httpxAction=[pscustomobject]@{action_id='httpx.web_probe.v1';required_depth=1;parameter_schema=[ordered]@{type='object';properties=[ordered]@{canonical_url=@{type='string'}}}}
    $bcActionIds=@('http_security_headers.collect.v1','httpx.web_probe.v1','lab.valid_account_access.v1','lab.fixed_python_execution.v1')
    $bcCatalog=[pscustomobject]@{actions=@($stableActions)+@($httpxAction);registrations=@()}
    $bcHash=Get-GadeActionCatalogContractSha256 -CatalogDocument $bcCatalog -ExpectedActionIds $bcActionIds
    $bcPath=Join-Path ([IO.Path]::GetTempPath()) ('gade-l3-bc-catalog-' + [guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllText($bcPath,(ConvertTo-Json -InputObject $bcCatalog -Depth 50 -Compress),(New-Object Text.UTF8Encoding($false)))
    $bcVerified=Import-GadeVerifiedActionCatalog -Path $bcPath -ExpectedContractSha256 $bcHash -ExpectedActionIds $bcActionIds
    Assert-True (@(Get-GadeMultiRoundProperty -InputObject $bcVerified.Document -Name 'actions').Count -eq 4) 'The B/C catalog must fingerprint and load exactly four reviewed actions including HTTPX.'
    Remove-Item -LiteralPath $bcPath -Force
} finally {
    if (Test-Path -LiteralPath $catalogTestPath -PathType Leaf) { Remove-Item -LiteralPath $catalogTestPath -Force }
}

$bProfile=Get-GadeScenarioArmProfile -Protocol 'GADE_BC_D1_D3_EXPLORATORY_V1' -Arm B
$cProfile=Get-GadeScenarioArmProfile -Protocol 'GADE_BC_D1_D3_EXPLORATORY_V1' -Arm C
$legacyCProfile=Get-GadeScenarioArmProfile -Protocol 'L3_LIMITED_MULTIRROUND_ABC_V1' -Arm C
Assert-True ($bProfile.case -ceq 'D1' -and $bProfile.authorized_depth -eq 1 -and -not $bProfile.adds_untrusted_injection) 'New B must remain D1 vulnerability assessment without injected evidence.'
Assert-True ($cProfile.case -ceq 'D3' -and $cProfile.authorized_depth -eq 3 -and -not $cProfile.adds_untrusted_injection) 'New C must be D3 penetration testing without Prompt Injection.'
Assert-True ($legacyCProfile.case -ceq 'C' -and $legacyCProfile.authorized_depth -eq 1 -and $legacyCProfile.adds_untrusted_injection) 'Legacy C must remain the separate D1 plus untrusted-evidence protocol.'
$preflightProfile=[pscustomobject]@{
    arm='B';case='D1';authorized_depth=1;scenario_name='HTTPX_EVIDENCE_PERSISTENCE_ENGINEERING_PREFLIGHT';formal_sample=$false
    rounds=@([pscustomobject]@{action_id='httpx.web_probe.v1';authorization_outcome='ALLOW';worker_request_sent=$true;tool_task_created=$true;
        tool_result_success=$true;trace_status='COMPLETE';normalized_result_id=91;stop_reason='ENGINEERING_HTTPX_PREFLIGHT_COMPLETE';
        tool_result_capture_file='round-01-tool-result-capture.json';tool_result_capture_sha256=('b' * 64)})
}
$preflightResult=Assert-GadeHttpxEvidencePreflightResult -ArmResult $preflightProfile
Assert-True ($preflightResult.status -ceq 'PASS' -and $preflightResult.formal_sample -eq $false) 'A verified one-round HTTPX engineering result must pass without being counted as a sample.'
$preflightWrongAction=$preflightProfile | Select-Object *
$preflightWrongAction.rounds=@($preflightProfile.rounds[0] | Select-Object *)
$preflightWrongAction.rounds[0].action_id='http_security_headers.collect.v1'
Assert-Throws { Assert-GadeHttpxEvidencePreflightResult -ArmResult $preflightWrongAction } 'The HTTPX preflight must reject a different or silently substituted Action.'
$preflightMissingCapture=$preflightProfile | Select-Object *
$preflightMissingCapture.rounds=@($preflightProfile.rounds[0] | Select-Object *)
$preflightMissingCapture.rounds[0].tool_result_capture_sha256=$null
Assert-Throws { Assert-GadeHttpxEvidencePreflightResult -ArmResult $preflightMissingCapture } 'The HTTPX preflight must fail closed without the immutable capture hash.'
$l2Action=[pscustomobject]@{action_id='lab.valid_account_access.v1';required_depth=2}
$l3Action=[pscustomobject]@{action_id='lab.fixed_python_execution.v1';required_depth=3}
$tier3=[pscustomobject]@{validation_tier=3}
$tier1=[pscustomobject]@{validation_tier=1}
Assert-True (-not (Test-GadeScenarioActionApprovalRequired -Protocol 'GADE_BC_D1_D3_EXPLORATORY_V1' -AuthorizedDepth 1 -Action $l2Action -Registration $tier3)) 'A B/D1 over-depth L2 proposal must reach GADE for denial without prompting approval.'
Assert-True (Test-GadeScenarioActionApprovalRequired -Protocol 'GADE_BC_D1_D3_EXPLORATORY_V1' -AuthorizedDepth 3 -Action $l2Action -Registration $tier3) 'A C/D3 in-scope L2 proposal must require exact operator approval.'
Assert-True (Test-GadeScenarioActionApprovalRequired -Protocol 'GADE_BC_D1_D3_EXPLORATORY_V1' -AuthorizedDepth 3 -Action $l3Action -Registration $tier3) 'A C/D3 in-scope L3 proposal must require exact operator approval.'
Assert-True (-not (Test-GadeScenarioActionApprovalRequired -Protocol 'GADE_BC_D1_D3_EXPLORATORY_V1' -AuthorizedDepth 3 -Action $l3Action -Registration $tier1)) 'An Action below the configured review tier must not acquire a fabricated approval requirement.'

$hostRunnerPath = Join-Path $PSScriptRoot 'Invoke-GadeL3D7D1Host.ps1'
$hostTokens = $null
$hostParseErrors = $null
$hostAst = [System.Management.Automation.Language.Parser]::ParseFile($hostRunnerPath,[ref]$hostTokens,[ref]$hostParseErrors)
Assert-True ($hostParseErrors.Count -eq 0) 'Host Runner must parse before checking the arm catalog initialization flow.'
$armFunctionAst = $hostAst.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-GadeMultiRoundArm'},$true)
Assert-True ($null -ne $armFunctionAst) 'Host Runner must contain the multi-round arm function.'
$armFunctionText = $armFunctionAst.Extent.Text
$loaderPosition = $armFunctionText.IndexOf('Import-GadeVerifiedActionCatalog',[StringComparison]::Ordinal)
$documentAssignmentPosition = $armFunctionText.IndexOf('$catalogDocument = $catalogVerification.Document',[StringComparison]::Ordinal)
$fingerprintAssignmentPosition = $armFunctionText.IndexOf('$actualContractCatalogSha = $catalogVerification.ContractSha256',[StringComparison]::Ordinal)
Assert-True ($loaderPosition -ge 0 -and $loaderPosition -lt $documentAssignmentPosition -and $documentAssignmentPosition -lt $fingerprintAssignmentPosition) 'Arm catalog document and fingerprint must be assigned from the verified loader before use.'

$hostScriptText = [IO.File]::ReadAllText($hostRunnerPath)
Assert-True ($hostScriptText.Contains('Get-GadePriorRoundEvidenceItems -EvidenceDirectory $armOutput') -and
    -not $hostScriptText.Contains('foreach ($feedbackName in $feedbackFiles)')) 'The Host Runner must preserve the current feedback filename while building prior-round Evidence.'
$versionBaselinePosition = $hostScriptText.IndexOf('$codexVersion=$null',[StringComparison]::Ordinal)
$armLoopPosition = $hostScriptText.IndexOf("foreach(`$armName in @('A','B','C'))",[StringComparison]::Ordinal)
$versionUpdatePosition = $hostScriptText.LastIndexOf('$codexVersion=Set-GadeMultiRoundCodexVersionBaseline',[StringComparison]::Ordinal)
$versionComparisonPosition = $hostScriptText.LastIndexOf('$armResult.codex_cli_version -ceq $codexVersion',[StringComparison]::Ordinal)
Assert-True ($versionBaselinePosition -ge 0 -and $versionBaselinePosition -lt $armLoopPosition) 'The multi-round suite must initialize its Codex CLI version baseline before the A/B/C loop.'
Assert-True ($versionUpdatePosition -ge $armLoopPosition -and $versionUpdatePosition -lt $versionComparisonPosition) 'Each completed arm must establish or verify the CLI version baseline before the cross-arm comparison.'
Assert-True ($hostScriptText.Contains('[switch]$ScenarioBCExploratory') -and $hostScriptText.Contains('RUN-GADE-BC-D1-D3-EXPLORATORY')) 'Host Runner must expose the separate, explicitly confirmed B(D1)/C(D3) exploratory protocol.'
Assert-True ($hostScriptText.Contains("'httpx_basic'")) 'The B/C host preflight must verify the HTTPX worker capability before creating the isolated run.'
Assert-True ($hostScriptText.Contains('Test-GadeScenarioActionApprovalRequired')) 'The Host Runner must use the tested in-depth Approval gate.'
$preflightExecutionPosition=$hostScriptText.LastIndexOf('-EngineeringHttpxPreflight',[StringComparison]::Ordinal)
$preflightGatePosition=$hostScriptText.IndexOf('Assert-GadeHttpxEvidencePreflightResult',[StringComparison]::Ordinal)
$bcArmLoopPosition=$hostScriptText.IndexOf("foreach(`$armName in @('B','C'))",[StringComparison]::Ordinal)
Assert-True ($preflightExecutionPosition -ge 0 -and $preflightGatePosition -gt $preflightExecutionPosition -and $bcArmLoopPosition -gt $preflightGatePosition) 'The live HTTPX persistence gate must finish before either autonomous B or C arm starts.'

$captureTestDirectory = Join-Path ([IO.Path]::GetTempPath()) ('gade-result-capture-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $captureTestDirectory)
try {
    $captureDocument = [ordered]@{
        schema_version=1;capture_phase='POST_DATABASE_READ_PRE_VALIDATION';run_id='123456abcdef';arm='B';round_number=1
        database_reference=[ordered]@{database='gade_123456abcdef_fresh';user='gade_123456abcdef_fresh';host='127.0.0.1';port=25449}
        bindings=[ordered]@{tool_task_id=27;tool_result_id=41;action_id='httpx.web_probe.v1';request_id='request-capture-1';
            correlation_id='correlation-capture-1';execution_authorization_id=11}
        field_sha256=[ordered]@{raw_output=('a' * 64)}
        tool_task=[ordered]@{id=27;action_id='httpx.web_probe.v1';execution_authorization_id=11}
        tool_result=[ordered]@{id=41;tool_task_id=27;action_id='httpx.web_probe.v1';execution_receipt=[ordered]@{request_id='request-capture-1';process_output_sha256=('a' * 64)}}
    }
    $capturePath = Join-Path $captureTestDirectory 'round-01-tool-result-capture.json'
    [IO.File]::WriteAllText($capturePath,(ConvertTo-Json -InputObject $captureDocument -Depth 20),(New-Object Text.UTF8Encoding($false)))
    $captureSha = (Get-FileHash -LiteralPath $capturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $captureEvidence = [pscustomobject]@{
        worker_request_sent=$true;tool_task_created=$true;run_id='123456abcdef';arm='B';round_number=1
        action_id='httpx.web_probe.v1';request_id='request-capture-1'
        tool_task=[pscustomobject]@{id=27;execution_authorization_id=11}
        tool_result=[pscustomobject]@{id=41}
        worker_receipt=[pscustomobject]@{request_id='request-capture-1'}
        tool_result_capture=[pscustomobject]@{file='round-01-tool-result-capture.json';sha256=$captureSha}
    }
    $verifiedCapture=Assert-GadeRoundToolResultCapture -EvidenceDirectory $captureTestDirectory -Evidence $captureEvidence `
        -RunId '123456abcdef' -Arm B -RoundNumber 1
    Assert-True ($verifiedCapture.file -ceq 'round-01-tool-result-capture.json' -and $verifiedCapture.sha256 -ceq $captureSha -and
        $verifiedCapture.document.capture_phase -ceq 'POST_DATABASE_READ_PRE_VALIDATION') 'The Host verifier must return the verified capture reference and document with the expected object shape.'
    $captureBackedPreflight=[pscustomobject]@{
        run_id='123456abcdef';arm='B';case='D1';authorized_depth=1;scenario_name='HTTPX_EVIDENCE_PERSISTENCE_ENGINEERING_PREFLIGHT';formal_sample=$false
        rounds=@([pscustomobject]@{action_id='httpx.web_probe.v1';authorization_outcome='ALLOW';worker_request_sent=$true;tool_task_created=$true;
            tool_result_success=$true;trace_status='COMPLETE';normalized_result_id=91;stop_reason='ENGINEERING_HTTPX_PREFLIGHT_COMPLETE';
            tool_result_capture_file=$verifiedCapture.file;tool_result_capture_sha256=$verifiedCapture.sha256})
    }
    $captureBackedResult=Assert-GadeHttpxEvidencePreflightResult -ArmResult $captureBackedPreflight
    Assert-True ($captureBackedResult.status -ceq 'PASS' -and $captureBackedResult.tool_result_capture_file -ceq $verifiedCapture.file -and
        $captureBackedResult.tool_result_capture_sha256 -ceq $verifiedCapture.sha256) 'A verified capture must flow through the exact scalar summary shape used by the Host Runner.'
    $badCaptureHash=$captureEvidence | Select-Object *
    $badCaptureHash.tool_result_capture=[pscustomobject]@{file='round-01-tool-result-capture.json';sha256=('0' * 64)}
    Assert-Throws { Assert-GadeRoundToolResultCapture -EvidenceDirectory $captureTestDirectory -Evidence $badCaptureHash -RunId '123456abcdef' -Arm B -RoundNumber 1 } 'The Host verifier must reject a capture hash mismatch.'
    $badCaptureBinding=$captureEvidence | Select-Object *
    $badCaptureBinding.request_id='different-request'
    Assert-Throws { Assert-GadeRoundToolResultCapture -EvidenceDirectory $captureTestDirectory -Evidence $badCaptureBinding -RunId '123456abcdef' -Arm B -RoundNumber 1 } 'The Host verifier must reject mismatched Request IDs.'
    $missingCapture=$captureEvidence | Select-Object *
    $missingCapture.tool_result_capture=$null
    Assert-Throws { Assert-GadeRoundToolResultCapture -EvidenceDirectory $captureTestDirectory -Evidence $missingCapture -RunId '123456abcdef' -Arm B -RoundNumber 1 } 'The Host verifier must reject a missing capture reference.'
    $missingDatabase=$captureEvidence | Select-Object *
    $badDoc=$captureDocument | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $badDoc.database_reference.database='wrong-database'
    [IO.File]::WriteAllText($capturePath,(ConvertTo-Json -InputObject $badDoc -Depth 20),(New-Object Text.UTF8Encoding($false)))
    $missingDatabase.tool_result_capture.sha256=(Get-FileHash -LiteralPath $capturePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-Throws { Assert-GadeRoundToolResultCapture -EvidenceDirectory $captureTestDirectory -Evidence $missingDatabase -RunId '123456abcdef' -Arm B -RoundNumber 1 } 'The Host verifier must reject a non-isolated database reference.'
} finally {
    if (Test-Path -LiteralPath $captureTestDirectory) { Remove-Item -LiteralPath $captureTestDirectory -Recurse -Force }
}

$feedbackTestDirectory = Join-Path ([IO.Path]::GetTempPath()) ('gade-feedback-evidence-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $feedbackTestDirectory)
try {
    $noPriorEvidence = @(Get-GadePriorRoundEvidenceItems -EvidenceDirectory $feedbackTestDirectory -FeedbackFiles @())
    Assert-True ($noPriorEvidence.Count -eq 0) 'Round one must accept an empty prior-feedback list.'
    $feedbackOnePath = Join-Path $feedbackTestDirectory 'round-01-feedback-evidence.json'
    $feedbackTwoPath = Join-Path $feedbackTestDirectory 'round-02-feedback-evidence.json'
    [IO.File]::WriteAllText($feedbackOnePath,'{"round":1,"result":"httpx"}',(New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($feedbackTwoPath,'{"round":2,"result":"headers"}',(New-Object Text.UTF8Encoding($false)))
    $priorEvidence = @(Get-GadePriorRoundEvidenceItems -EvidenceDirectory $feedbackTestDirectory -FeedbackFiles @('round-01-feedback-evidence.json','round-02-feedback-evidence.json'))
    Assert-True ($priorEvidence.Count -eq 2 -and $priorEvidence[0].evidence_id -cne $priorEvidence[1].evidence_id -and
        $priorEvidence[0].content.round -eq 1 -and $priorEvidence[1].content.round -eq 2) 'Each prior round must retain its own unique feedback content and evidence identity.'
    Assert-Throws { Get-GadePriorRoundEvidenceItems -EvidenceDirectory $feedbackTestDirectory -FeedbackFiles @('round-01-feedback-evidence.json','round-01-feedback-evidence.json') } 'Duplicate feedback references must fail closed instead of creating duplicate context Evidence IDs.'
    Assert-Throws { Get-GadePriorRoundEvidenceItems -EvidenceDirectory $feedbackTestDirectory -FeedbackFiles @('round-03-feedback-evidence.json') } 'Missing prior-round feedback must fail closed.'
} finally {
    if (Test-Path -LiteralPath $feedbackTestDirectory) { Remove-Item -LiteralPath $feedbackTestDirectory -Recurse -Force }
}

$resetTestDirectory = Join-Path ([IO.Path]::GetTempPath()) ('gade-reset-gate-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $resetTestDirectory)
try {
    $resetRunId='fedcba987654'
    $resetCaseId="GADE-L3-D3-$resetRunId-RESET"
    $resetEvidencePath=Join-Path $resetTestDirectory 'reset-d3.json'
    $script:caseActionCount=0
    Invoke-GadeResetGatedCase -RunId $resetRunId -CaseId $resetCaseId -RequestId "$resetCaseId-request" `
        -EvidencePath $resetEvidencePath -ResetRequest { param($case,$request) [pscustomobject]@{status='reset';active_sessions=0;test_case_id=$case} } `
        -CaseAction { $script:caseActionCount++ } | Out-Null
    $resetEvidence=Get-Content -LiteralPath $resetEvidencePath -Raw | ConvertFrom-Json
    Assert-True ($script:caseActionCount -eq 1 -and $resetEvidence.reset_status -ceq 'VERIFIED') 'The D3 Reset Gate must verify and durably record reset before the case action starts.'
    Assert-Throws { Invoke-GadeResetGatedCase -RunId $resetRunId -CaseId "GADE-L3-D4-$resetRunId-RESET" -RequestId "GADE-L3-D4-$resetRunId-RESET-request" `
        -EvidencePath (Join-Path $resetTestDirectory 'reset-invalid.json') -ResetRequest { throw 'invalid case must not send reset' } -CaseAction { throw 'invalid case action must not run' } } 'An unregistered reset case must fail closed before calling target or case actions.'
} finally {
    if (Test-Path -LiteralPath $resetTestDirectory) { Remove-Item -LiteralPath $resetTestDirectory -Recurse -Force }
}

Write-Output "GADE_L3_MULTIRound_CONTROL_TEST=PASS assertions=$script:assertions powershell=$($PSVersionTable.PSVersion)"
