Set-StrictMode -Version Latest

function Set-GadeCheckpointProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true,Position = 2)]$Value
    )
    if ($Object -is [System.Collections.IDictionary]) {
        $Object[$Name] = $Value
        return
    }
    if ($Object -isnot [System.Management.Automation.PSCustomObject]) {
        throw "Checkpoint container for '$Name' must be a PSCustomObject or IDictionary."
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
    } else {
        $property.Value = $Value
    }
}

function Get-GadeCheckpointProperty {
    param([Parameter(Mandatory = $true)]$Object,[Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { return $null }
        return [pscustomobject]@{ Name=$Name; Value=$Object[$Name] }
    }
    if ($Object -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    return $Object.PSObject.Properties[$Name]
}

function ConvertTo-GadeCheckpointPsObject {
    param([Parameter(Mandatory = $true)][AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $properties = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $properties[[string]$key] = ConvertTo-GadeCheckpointPsObject -Value $Value[$key]
        }
        return [pscustomobject]$properties
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $properties = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $properties[$property.Name] = ConvertTo-GadeCheckpointPsObject -Value $property.Value
        }
        return [pscustomobject]$properties
    }
    if ($Value -is [System.Array]) {
        $items = @()
        foreach ($item in $Value) { $items += ,(ConvertTo-GadeCheckpointPsObject -Value $item) }
        return ,$items
    }
    return $Value
}

function Assert-GadeCheckpointObject {
    param([Parameter(Mandatory = $true)]$Object,[Parameter(Mandatory = $true)][string]$Name)
    if (($Object -isnot [System.Management.Automation.PSCustomObject]) -and
        ($Object -isnot [System.Collections.IDictionary])) {
        throw "Checkpoint field '$Name' must be a JSON object, PSCustomObject, or IDictionary."
    }
}

function Assert-GadeCheckpointArray {
    param([Parameter(Mandatory = $true)]$Object,[Parameter(Mandatory = $true)][string]$Name)
    if ($Object -isnot [System.Array]) { throw "Checkpoint field '$Name' must be an array; refusing unsafe Resume." }
}

function ConvertTo-GadeIsoTimestamp {
    param([object]$Value,[Parameter(Mandatory = $true)][string]$Name)
    $parsed = [DateTimeOffset]::MinValue
    if ($Value -is [DateTimeOffset]) { $parsed = [DateTimeOffset]$Value }
    elseif ($Value -is [DateTime]) { $parsed = [DateTimeOffset]([DateTime]$Value) }
    elseif ($Value -is [string] -and [DateTimeOffset]::TryParse([string]$Value,[ref]$parsed)) { }
    else {
        throw "Checkpoint field '$Name' must be an ISO timestamp."
    }
    return $parsed.ToString('o')
}

function Assert-GadePlannedResources {
    param([Parameter(Mandatory = $true)]$Checkpoint,[Parameter(Mandatory = $true)][string]$ExpectedRunId)
    Assert-GadeCheckpointArray -Object $Checkpoint.planned_resources -Name 'planned_resources'
    $profiles = @('legacy025','fresh','legacy')
    if ($Checkpoint.planned_resources.Count -ne 3) { throw 'Checkpoint must contain exactly three planned scratch profiles.' }
    $seenPorts = @{}
    foreach ($profileName in $profiles) {
        $matches = @($Checkpoint.planned_resources | Where-Object { $_.profile -ceq $profileName })
        if ($matches.Count -ne 1) { throw "Checkpoint resource plan must contain profile '$profileName' exactly once." }
        $item = $matches[0]
        Assert-GadeCheckpointObject -Object $item -Name "planned_resources.$profileName"
        $expectedContainer = "gade-preexp-$ExpectedRunId-$profileName"
        $expectedIdentity = "gade_${ExpectedRunId}_$profileName"
        $expectedVolume = "gade_preexp_${ExpectedRunId}_$profileName"
        if ($item.container_name -cne $expectedContainer -or $item.database -cne $expectedIdentity -or
            $item.user -cne $expectedIdentity -or $item.volume -cne $expectedVolume) {
            throw "Checkpoint identity fields do not match the run-scoped allowlist for '$profileName'."
        }
        $port = 0
        if (-not [int]::TryParse([string]$item.host_port,[ref]$port) -or $port -lt 25436 -or $port -gt 25999 -or $port -eq 15432) {
            throw "Checkpoint host_port for '$profileName' is outside the test allowlist."
        }
        if ($seenPorts.ContainsKey([string]$port)) { throw "Checkpoint has duplicate host port $port." }
        $seenPorts[[string]$port] = $true
    }
}

function Normalize-GadeHostCheckpoint {
    param([Parameter(Mandatory = $true)]$Checkpoint,[Parameter(Mandatory = $true)][string]$ExpectedRunId)
    $Checkpoint = ConvertTo-GadeCheckpointPsObject -Value $Checkpoint
    Assert-GadeCheckpointObject -Object $Checkpoint -Name 'root'
    $requiredStrings = @('run_id','status','repository_head_before')
    foreach ($name in $requiredStrings) {
        $property = Get-GadeCheckpointProperty -Object $Checkpoint -Name $name
        if ($null -eq $property -or $property.Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            throw "Checkpoint required identity field '$name' is missing or has an invalid type; refusing Resume."
        }
    }
    if ($Checkpoint.run_id -cne $ExpectedRunId -or $Checkpoint.run_id -notmatch '^[0-9a-f]{12}$') {
        throw 'Checkpoint run_id does not match the requested 12-hex RunId; refusing Resume.'
    }
    if ($Checkpoint.status -notin @('RUNNING','FAILED','BLOCKED','READY')) { throw "Unsupported checkpoint status '$($Checkpoint.status)'." }
    if ($Checkpoint.repository_head_before -notmatch '^[0-9a-f]{40}$') { throw 'Checkpoint repository_head_before is invalid.' }

    $schemaProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'schema_version'
    if ($null -eq $schemaProperty -or
        (($schemaProperty.Value -isnot [int]) -and ($schemaProperty.Value -isnot [long])) -or
        [long]$schemaProperty.Value -ne 1) {
        throw 'Checkpoint schema_version is missing or unsupported; refusing Resume.'
    }
    foreach ($name in @('created_at','updated_at')) {
        $property = Get-GadeCheckpointProperty -Object $Checkpoint -Name $name
        if ($null -eq $property -and $name -eq 'updated_at') {
            # Safe metadata migration only. No stage is inferred as complete.
            $createdAt = ConvertTo-GadeIsoTimestamp -Value $Checkpoint.created_at -Name 'created_at'
            Set-GadeCheckpointProperty -Object $Checkpoint -Name 'created_at' -Value $createdAt
            Set-GadeCheckpointProperty -Object $Checkpoint -Name 'updated_at' -Value $createdAt
            continue
        }
        if ($null -eq $property) { throw "Checkpoint required timestamp '$name' is missing; refusing Resume." }
        $canonical = ConvertTo-GadeIsoTimestamp -Value $property.Value -Name $name
        if ($property.Value -isnot [string] -or $property.Value -cne $canonical) {
            Set-GadeCheckpointProperty -Object $Checkpoint -Name $name -Value $canonical
        }
    }

    foreach ($name in @('resources','stages','outputs','host_environment','experiment_inputs','experiment_outputs')) {
        $property = Get-GadeCheckpointProperty -Object $Checkpoint -Name $name
        if ($null -eq $property) { throw "Checkpoint required object '$name' is missing; refusing Resume." }
        Assert-GadeCheckpointObject -Object $property.Value -Name $name
    }
    foreach ($name in @('source_manifest','planned_resources','historical_experiment_hashes')) {
        $property = Get-GadeCheckpointProperty -Object $Checkpoint -Name $name
        if ($null -eq $property) { throw "Checkpoint required array '$name' is missing; refusing Resume." }
        Assert-GadeCheckpointArray -Object $property.Value -Name $name
    }
    if ($Checkpoint.source_manifest.Count -lt 37) { throw 'Checkpoint source_manifest does not prove all 37 migrations; refusing Resume.' }
    foreach ($entry in $Checkpoint.source_manifest) {
        Assert-GadeCheckpointObject -Object $entry -Name 'source_manifest entry'
        if ($entry.path -isnot [string] -or $entry.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Checkpoint source_manifest contains an invalid path/hash entry.'
        }
    }
    Assert-GadePlannedResources -Checkpoint $Checkpoint -ExpectedRunId $ExpectedRunId

    foreach ($stageProperty in $Checkpoint.stages.PSObject.Properties) {
        $stage = $stageProperty.Value
        Assert-GadeCheckpointObject -Object $stage -Name ("stages." + $stageProperty.Name)
        if ($stage.status -notin @('RUNNING','PASS','FAIL')) { throw "Checkpoint stage '$($stageProperty.Name)' has invalid status; refusing Resume." }
        if ($stage.status -eq 'PASS') {
            if ($null -eq (Get-GadeCheckpointProperty -Object $stage -Name 'evidence') -or
                $null -eq (Get-GadeCheckpointProperty -Object $stage -Name 'finished_at')) {
                throw "Checkpoint PASS stage '$($stageProperty.Name)' lacks completion evidence; refusing Resume."
            }
        }
    }

    $currentPhase = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'current_phase'
    if ($null -eq $currentPhase) {
        # Older schema compatibility: recover only the label from recorded stages.
        # Stage status is never changed or synthesized.
        $phaseLabel = 'PRE_RESOURCE_SETUP'
        $stageNames = @($Checkpoint.stages.PSObject.Properties.Name)
        for ($i = $stageNames.Count - 1; $i -ge 0; $i--) {
            $record = $Checkpoint.stages.PSObject.Properties[$stageNames[$i]].Value
            if ($record.status -in @('RUNNING','FAIL')) { $phaseLabel = [string]$stageNames[$i]; break }
            if ($record.status -eq 'PASS') { $phaseLabel = [string]$stageNames[$i]; break }
        }
        Set-GadeCheckpointProperty -Object $Checkpoint -Name 'current_phase' -Value $phaseLabel
    } elseif ($currentPhase.Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$currentPhase.Value)) {
        throw 'Checkpoint current_phase exists but has an invalid type/value; refusing Resume.'
    }
    return $Checkpoint
}

function Assert-GadeHostCheckpointResumeSafe {
    param([Parameter(Mandatory = $true)]$Checkpoint,[Parameter(Mandatory = $true)][string]$ExpectedRunId)
    $normalized = Normalize-GadeHostCheckpoint -Checkpoint $Checkpoint -ExpectedRunId $ExpectedRunId
    foreach ($stageProperty in $normalized.stages.PSObject.Properties) {
        $stage = $stageProperty.Value
        if ($stage.status -in @('RUNNING','FAIL') -and $stage.kind -in @('database','app-smoke')) {
            throw "Stage '$($stageProperty.Name)' is $($stage.status); do not resume/re-run potentially partial database writes in this RunId."
        }
    }
    return $normalized
}

function Save-GadeHostCheckpointAtomic {
    param([Parameter(Mandatory = $true)]$Checkpoint,[Parameter(Mandatory = $true)][string]$Path)
    $Checkpoint = ConvertTo-GadeCheckpointPsObject -Value $Checkpoint
    $runIdProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'run_id'
    if ($null -eq $runIdProperty) { throw 'Cannot save Checkpoint without run_id.' }
    $normalized = Normalize-GadeHostCheckpoint -Checkpoint $Checkpoint -ExpectedRunId ([string]$runIdProperty.Value)
    Set-GadeCheckpointProperty -Object $normalized -Name 'updated_at' -Value ([DateTimeOffset]::Now.ToString('o'))
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Checkpoint directory does not exist: $directory" }
    $tempPath = "$Path.tmp-$([guid]::NewGuid().ToString('N'))"
    $backupPath = "$Path.bak-$([guid]::NewGuid().ToString('N'))"
    try {
        $json = ConvertTo-Json -InputObject $normalized -Depth 30
        $roundTrip = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        [void](Normalize-GadeHostCheckpoint -Checkpoint $roundTrip -ExpectedRunId ([string]$normalized.run_id))
        [System.IO.File]::WriteAllText($tempPath,$json,(New-Object System.Text.UTF8Encoding($false)))
        if ([System.IO.File]::Exists($Path)) {
            try {
                [System.IO.File]::Replace($tempPath,$Path,$backupPath,$false)
            } catch {
                # Keep a verified copy of the last readable version before the
                # same-directory rename fallback (for filesystems that reject
                # File.Replace). Never remove the destination first.
                if (-not [System.IO.File]::Exists($backupPath)) {
                    [System.IO.File]::Copy($Path,$backupPath,$false)
                }
                $backupText = [System.IO.File]::ReadAllText($backupPath)
                [void](Normalize-GadeHostCheckpoint -Checkpoint (ConvertFrom-Json -InputObject $backupText -ErrorAction Stop) `
                    -ExpectedRunId ([string]$normalized.run_id))
                Move-Item -LiteralPath $tempPath -Destination $Path -Force -ErrorAction Stop
            }
        } else {
            [System.IO.File]::Move($tempPath,$Path)
        }
    } finally {
        if ([System.IO.File]::Exists($tempPath)) { [System.IO.File]::Delete($tempPath) }
    }
    return $normalized
}

function New-GadeBlockerPacket {
    param(
        [Parameter(Mandatory = $true)]$Checkpoint,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)][string]$Observed,
        [Parameter(Mandatory = $true)][string]$CheckpointPath,
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ResumeSafety = 'NOT_ASSESSED'
    )
    $baseline = 'NOT_CREATED'
    $baselineProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'baseline'
    if ($null -ne $baselineProperty -and $null -ne $baselineProperty.Value) {
        $commitProperty = Get-GadeCheckpointProperty -Object $baselineProperty.Value -Name 'commit_sha'
        if ($null -ne $commitProperty -and -not [string]::IsNullOrWhiteSpace([string]$commitProperty.Value)) {
            $baseline = [string]$commitProperty.Value
        }
    }
    $resourceIdentity = [ordered]@{ planned_resources=@(); resources=[pscustomobject]@{} }
    $plannedProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'planned_resources'
    if ($null -ne $plannedProperty -and $null -ne $plannedProperty.Value) { $resourceIdentity.planned_resources = @($plannedProperty.Value) }
    $resourcesProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'resources'
    if ($null -ne $resourcesProperty -and $null -ne $resourcesProperty.Value) { $resourceIdentity.resources = $resourcesProperty.Value }
    $resourceJson = ConvertTo-Json -InputObject ([pscustomobject]$resourceIdentity) -Depth 20 -Compress
    $text = @"
# M2A / GADE Host Validation BLOCKER PACKET

Current Phase: $PhaseName
Observed Error: $Observed
Run ID: $RunId
Resource Identity (planned and recorded): $resourceJson
Resume Safety Status: $ResumeSafety
Checkpoint: $CheckpointPath
Baseline Commit: $baseline

Original failure is preserved above. No test resource cleanup or database reset was performed.
"@
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Blocker packet directory does not exist: $directory" }
    [System.IO.File]::WriteAllText($Path,$text,(New-Object System.Text.UTF8Encoding($false)))
    return [pscustomobject]@{ path=$Path; sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant(); text=$text }
}

function Save-GadeHostFailureArtifacts {
    param(
        [Parameter(Mandatory = $true)]$Checkpoint,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)][string]$Observed,
        [Parameter(Mandatory = $true)][string]$RunDirectory,
        [Parameter(Mandatory = $true)][string]$CheckpointPath,
        [string]$ResumeSafety = 'NOT_ASSESSED'
    )
    $packetPath = Join-Path $RunDirectory 'BLOCKER_PACKET.md'
    $fallbackPath = Join-Path $RunDirectory 'BLOCKER_PACKET_FALLBACK.txt'
    $packet = $null
    $writeFailure = $null
    try {
        $packet = New-GadeBlockerPacket -Checkpoint $Checkpoint -RunId $RunId -PhaseName $PhaseName `
            -Observed $Observed -CheckpointPath $CheckpointPath -Path $packetPath -ResumeSafety $ResumeSafety
        Set-GadeCheckpointProperty -Object $Checkpoint -Name 'status' -Value 'FAILED'
        Set-GadeCheckpointProperty -Object $Checkpoint -Name 'current_phase' -Value $PhaseName
        Set-GadeCheckpointProperty -Object $Checkpoint -Name 'blocker' -Value ([pscustomobject]@{ path=$packet.path; sha256=$packet.sha256 })
        [void](Save-GadeHostCheckpointAtomic -Checkpoint $Checkpoint -Path $CheckpointPath)
    } catch {
        $writeFailure = $_.Exception.Message
        $resourceIdentity = [ordered]@{ planned_resources=@(); resources=[pscustomobject]@{} }
        $plannedProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'planned_resources'
        if ($null -ne $plannedProperty -and $null -ne $plannedProperty.Value) { $resourceIdentity.planned_resources = @($plannedProperty.Value) }
        $resourcesProperty = Get-GadeCheckpointProperty -Object $Checkpoint -Name 'resources'
        if ($null -ne $resourcesProperty -and $null -ne $resourcesProperty.Value) { $resourceIdentity.resources = $resourcesProperty.Value }
        $resourceJson = ConvertTo-Json -InputObject ([pscustomobject]$resourceIdentity) -Depth 20 -Compress
        $fallback = @"
BLOCKER_ARTIFACT_WRITE_FAILURE: $writeFailure
Original failure: $Observed
Run ID: $RunId
Failed phase: $PhaseName
Resource identity: $([string]$resourceJson)
Resume safety: $ResumeSafety
Checkpoint: $CheckpointPath
"@
        try { [System.IO.File]::WriteAllText($fallbackPath,$fallback,(New-Object System.Text.UTF8Encoding($false))) }
        catch { [Console]::Error.WriteLine("BLOCKER_FALLBACK_WRITE_FAILURE: $($_.Exception.Message)`n$fallback") }
        [Console]::Error.WriteLine("BLOCKER_ARTIFACT_WRITE_FAILURE: $writeFailure`n$fallback")
    }
    return [pscustomobject]@{ packet=$packet; fallback_path=$(if ($writeFailure) { $fallbackPath } else { $null }); write_failure=$writeFailure }
}
