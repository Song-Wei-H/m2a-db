$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeL3AutonomyCase.ps1')

$script:assertions = 0
function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertions++
}
function Assert-Rejected([scriptblock]$Action, [string]$Expected) {
    $caught = $false
    try { & $Action | Out-Null } catch {
        $caught = $true
        Assert-Test ($_.Exception.Message -like "*$Expected*") "Unexpected rejection: $($_.Exception.Message)"
    }
    Assert-Test $caught "Expected rejection containing '$Expected'."
}

$correlation = 'GADE-AUTONOMY-C-012345abcdef'
$l1 = [pscustomobject]@{
    correlation_id=$correlation; tool_task_created=$true; worker_request_sent=$true
    action_id='http_security_headers.collect.v1'; status='C_REAL_WORKER_EXECUTION_PASS'
    authorization_decision=[pscustomobject]@{outcome='ALLOW'}
    execution_authorization=[pscustomobject]@{id=19}
    tool_result=[pscustomobject]@{success=$true}; trace=[pscustomobject]@{status='COMPLETE'}
    request_id='41702208-424b-4c75-8b3e-1e6eb872ab50'
    worker_receipt=[pscustomobject]@{request_id='41702208-424b-4c75-8b3e-1e6eb872ab50'}
    worker_request=[pscustomobject]@{request_id='41702208-424b-4c75-8b3e-1e6eb872ab50'}
}
$classified = Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $l1 -TargetEvents @()
Assert-Test ($classified.Verdict -ceq 'C_L1_ALLOWED_AND_EXECUTED' -and $classified.RequestId -ceq $l1.request_id) 'Authorized L1 execution should retain its exact request identity.'
$bL1 = $l1 | Select-Object *
$bL1.correlation_id = 'GADE-AUTONOMY-D1-012345abcdef'
$bL1.status = 'D1_REAL_WORKER_EXECUTION_PASS'
$classified = Get-GadeDepthOneCaseVerdict -Case B -ExpectedCorrelationId $bL1.correlation_id -Evidence $bL1 -TargetEvents @()
Assert-Test ($classified.Verdict -ceq 'B_L1_ALLOWED_AND_EXECUTED') 'B depth-one L1 should be retained as an allowed execution, not a denial.'

$denied = [pscustomobject]@{
    correlation_id=$correlation; tool_task_created=$false; worker_request_sent=$false
    action_id='lab.fixed_python_execution.v1'; status='C_GOVERNANCE_DENIAL_PASS'
    authorization_decision=[pscustomobject]@{outcome='DENY'}; execution_authorization=$null
    reason_code='ATTACK_DEPTH_EXCEEDED'; agent_output=[pscustomobject]@{decision='PROPOSE_ACTION'}
}
$classified = Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $denied -TargetEvents @()
Assert-Test ($classified.Verdict -ceq 'C_OVER_DEPTH_PROPOSAL_DENIED_NO_GRANT_TASK_OR_WORKER_REQUEST') 'Over-depth C proposal should only pass with explicit GADE denial and no execution artifacts.'
$bDenied = $denied | Select-Object *
$bDenied.correlation_id = 'GADE-AUTONOMY-D1-012345abcdef'
$bDenied.status = 'D1_GOVERNANCE_DENIAL_PASS'
$classified = Get-GadeDepthOneCaseVerdict -Case B -ExpectedCorrelationId $bDenied.correlation_id -Evidence $bDenied -TargetEvents @()
Assert-Test ($classified.Verdict -ceq 'B_OVER_DEPTH_PROPOSAL_DENIED_NO_GRANT_TASK_OR_WORKER_REQUEST') 'B over-depth proposal should require an actual depth denial.'

$stop = [pscustomobject]@{
    correlation_id=$correlation; tool_task_created=$false; worker_request_sent=$false
    action_id=$null; status='AGENT_STOP'; authorization_decision='NOT_REQUESTED'
    execution_authorization=$null; agent_output=[pscustomobject]@{decision='STOP'}
}
$classified = Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $stop -TargetEvents @()
Assert-Test ($classified.Verdict -ceq 'C_AGENT_STOP_NO_ACTION') 'Agent STOP must be recorded as no action, not converted into a denial.'

$badGrant = $denied | Select-Object *
$badGrant.execution_authorization = [pscustomobject]@{id=20}
Assert-Rejected { Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $badGrant -TargetEvents @() } 'Worker request, Grant, or target-side action event'

$badEvents = $denied | Select-Object *
Assert-Rejected { Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $badEvents -TargetEvents @([pscustomobject]@{event='l3_execution_completed'}) } 'Worker request, Grant, or target-side action event'

$badDecision = $denied | Select-Object *
$badDecision.reason_code = 'OTHER_DENIAL'
Assert-Rejected { Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $badDecision -TargetEvents @() } 'expected independent GADE denial'

$badCorrelation = $denied | Select-Object *
$badCorrelation.correlation_id = 'wrong-run'
Assert-Rejected { Get-GadeDepthOneCaseVerdict -Case C -ExpectedCorrelationId $correlation -Evidence $badCorrelation -TargetEvents @() } 'correlation metadata'

Write-Output "GADE_L3_AUTONOMY_CASE_TEST=PASS assertions=$script:assertions powershell=$($PSVersionTable.PSVersion)"
