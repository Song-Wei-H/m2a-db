function Get-GadePropertyState {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name
    )

    if ($null -eq $InputObject) {
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return [pscustomobject]@{ Exists = $true; Value = $InputObject[$Name] }
        }
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return [pscustomobject]@{ Exists = $false; Value = $null }
    }
    return [pscustomobject]@{ Exists = $true; Value = $property.Value }
}

function Set-GadePropertyValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Name,
        [AllowNull()]$Value
    )

    if ($null -eq $InputObject) {
        throw "Cannot add required Manifest field '$Name' to a null object."
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $InputObject[$Name] = $Value
        return
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        $property.Value = $Value
        return
    }
    $InputObject | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
}

function New-GadeAlreadyDeployedEvidence {
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$WorkerSha256)

    return @{
        status = 'ALREADY_DEPLOYED'
        worker_build_sha256 = $WorkerSha256
        action_loaded = $true
        scope_enforced = $true
        shared_worker_pid = $null
        shared_worker_pid_state = 'NOT_CAPTURED_NO_DEPLOYMENT'
    }
}

function New-GadeDeployedEvidence {
    param([Parameter(Mandatory = $true)][AllowNull()]$DeploymentReport)

    if ($null -eq $DeploymentReport) {
        throw 'Worker deployment returned no structured report; failing closed.'
    }
    $pidState = Get-GadePropertyState -InputObject $DeploymentReport -Name 'shared_worker_pid'
    $pidDisposition = if ($pidState.Exists -and $null -ne $pidState.Value) { 'CAPTURED' } else { 'MISSING' }
    Set-GadePropertyValue -InputObject $DeploymentReport -Name 'shared_worker_pid_state' -Value $pidDisposition
    return $DeploymentReport
}

function Assert-GadeWorkerDeploymentEvidence {
    param([Parameter(Mandatory = $true)][AllowNull()]$WorkerDeployment)

    $status = Get-GadePropertyState -InputObject $WorkerDeployment -Name 'status'
    $pidState = Get-GadePropertyState -InputObject $WorkerDeployment -Name 'shared_worker_pid'
    $pidDisposition = Get-GadePropertyState -InputObject $WorkerDeployment -Name 'shared_worker_pid_state'

    if (-not $status.Exists -or [string]::IsNullOrWhiteSpace([string]$status.Value)) {
        throw 'Worker deployment evidence is missing required status; failing closed.'
    }
    if (-not $pidState.Exists -or -not $pidDisposition.Exists) {
        throw 'Worker deployment evidence is missing shared_worker_pid or shared_worker_pid_state; failing closed.'
    }

    switch ([string]$status.Value) {
        'DEPLOYED' {
            if ([string]$pidDisposition.Value -cne 'CAPTURED' -or $null -eq $pidState.Value) {
                throw 'Deployed Worker report did not capture the shared Worker PID; failing closed.'
            }
            $parsedPid = 0L
            if (-not [long]::TryParse([string]$pidState.Value, [ref]$parsedPid) -or $parsedPid -le 0) {
                throw 'Deployed Worker report contains an invalid shared Worker PID; failing closed.'
            }
        }
        'ALREADY_DEPLOYED' {
            if ([string]$pidDisposition.Value -cne 'NOT_CAPTURED_NO_DEPLOYMENT' -or $null -ne $pidState.Value) {
                throw 'Already-deployed Worker evidence has an inconsistent PID disposition; failing closed.'
            }
        }
        default {
            throw "Worker deployment evidence has unsupported status '$($status.Value)'; failing closed."
        }
    }

    return $true
}
