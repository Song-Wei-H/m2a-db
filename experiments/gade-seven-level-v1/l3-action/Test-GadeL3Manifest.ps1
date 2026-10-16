$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeL3Manifest.ps1')

$script:assertions = 0
function Assert-Test([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertions++
}

foreach ($path in @(
    (Join-Path $PSScriptRoot 'Invoke-GadeL3D7D1Host.ps1'),
    (Join-Path $PSScriptRoot 'GadeL3Manifest.ps1'),
    $PSCommandPath
)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert-Test ($parseErrors.Count -eq 0) "PowerShell 5.1 AST parser reported errors in '$path': $($parseErrors -join '; ')"
}

function Assert-Rejected([scriptblock]$Action, [string]$ExpectedText) {
    $caught = $false
    try { & $Action | Out-Null }
    catch {
        $caught = $true
        Assert-Test ($_.Exception.Message -like "*$ExpectedText*") "Unexpected rejection: $($_.Exception.Message)"
    }
    Assert-Test $caught "Expected fail-closed rejection containing '$ExpectedText'."
}

# Hashtable path: the existing L3 no-deploy branch must explicitly state why a PID is absent.
$alreadyDeployed = New-GadeAlreadyDeployedEvidence -WorkerSha256 ('a' * 64)
Assert-Test (Assert-GadeWorkerDeploymentEvidence $alreadyDeployed) 'Explicit no-deploy evidence should pass.'

# PSCustomObject path: a real deployment must carry an actual positive PID.
$deployed = [pscustomobject]@{
    status = 'DEPLOYED'
    shared_worker_pid = 1234
    shared_worker_pid_state = 'CAPTURED'
}
Assert-Test (Assert-GadeWorkerDeploymentEvidence $deployed) 'Captured deployment PID should pass.'

$remoteReport = New-GadeDeployedEvidence -DeploymentReport ([pscustomobject]@{ status = 'DEPLOYED'; shared_worker_pid = 2345; archive_sha256_verified = $true })
Assert-Test ($remoteReport.archive_sha256_verified -and $remoteReport.shared_worker_pid_state -ceq 'CAPTURED' -and
    (Assert-GadeWorkerDeploymentEvidence $remoteReport)) 'Normalization must preserve existing remote report fields.'
Assert-Test (-not (Get-GadePropertyState -InputObject ([pscustomobject]@{ status = 'ALREADY_DEPLOYED' }) -Name 'shared_worker_pid').Exists) `
    'Missing PSCustomObject property should be reported as absent without throwing under StrictMode.'

# Missing security/identity fields are not normalized into a pass.
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'DEPLOYED'; shared_worker_pid_state = 'CAPTURED' } } 'missing shared_worker_pid'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'DEPLOYED'; shared_worker_pid = 1234 } } 'missing shared_worker_pid'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'DEPLOYED'; shared_worker_pid = $null; shared_worker_pid_state = 'CAPTURED' } } 'did not capture'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'DEPLOYED'; shared_worker_pid = 'not-a-pid'; shared_worker_pid_state = 'CAPTURED' } } 'invalid shared Worker PID'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'ALREADY_DEPLOYED'; shared_worker_pid_state = 'NOT_CAPTURED_NO_DEPLOYMENT' } } 'missing shared_worker_pid'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'ALREADY_DEPLOYED'; shared_worker_pid = 1234; shared_worker_pid_state = 'NOT_CAPTURED_NO_DEPLOYMENT' } } 'inconsistent PID disposition'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ shared_worker_pid = $null; shared_worker_pid_state = 'NOT_CAPTURED_NO_DEPLOYMENT' } } 'missing required status'
Assert-Rejected { Assert-GadeWorkerDeploymentEvidence @{ status = 'UNKNOWN'; shared_worker_pid = $null; shared_worker_pid_state = 'NOT_CAPTURED_NO_DEPLOYMENT' } } 'unsupported status'

Write-Output "L3_MANIFEST_CONTROL_FLOW_TEST=PASS assertions=$script:assertions powershell=$($PSVersionTable.PSVersion)"
