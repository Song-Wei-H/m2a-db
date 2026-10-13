[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeHostCheckpoint.ps1')

$script:Passed = 0
$script:Failed = 0
$runId = '9222f642db86'
$now = [DateTimeOffset]::Now.ToString('o')

function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Throws([scriptblock]$Action,[string]$MessageFragment) {
    $thrown = $false
    try { & $Action } catch {
        $thrown = $true
        if ($MessageFragment -and $_.Exception.Message -notlike "*$MessageFragment*") {
            throw "Expected error containing '$MessageFragment'; got '$($_.Exception.Message)'"
        }
    }
    if (-not $thrown) { throw "Expected failure containing '$MessageFragment', but the operation succeeded." }
}

function Invoke-Test([string]$Name,[scriptblock]$Action) {
    try { & $Action; $script:Passed++; Write-Host "PASS $Name" }
    catch { $script:Failed++; Write-Host "FAIL $Name :: $($_.Exception.Message)" }
}

function New-TestCheckpoint {
    $manifest = @()
    for ($index=1; $index -le 37; $index++) {
        $manifest += [pscustomobject]@{ path=('initdb/{0:D3}_fixture.sql' -f $index); sha256=('a' * 64) }
    }
    $planned = @()
    $port = 25436
    foreach ($profile in @('legacy025','fresh','legacy')) {
        $planned += [pscustomobject]@{
            profile=$profile; container_name="gade-preexp-$runId-$profile"; host_port=$port
            database="gade_${runId}_$profile"; user="gade_${runId}_$profile"; volume="gade_preexp_${runId}_$profile"
        }
        $port++
    }
    return [pscustomobject]@{
        schema_version=1; run_id=$runId; status='RUNNING'; current_phase='PRE_RESOURCE_SETUP'
        created_at=$now; updated_at=$now; repository_head_before=('b' * 40)
        source_manifest=$manifest; host_environment=[pscustomobject]@{ powershell_version='5.1' }
        planned_resources=$planned; resources=[pscustomobject]@{}; stages=[pscustomobject]@{}
        outputs=[pscustomobject]@{}; historical_experiment_hashes=@()
        experiment_inputs=[pscustomobject]@{}; experiment_outputs=[pscustomobject]@{}
        baseline=$null; blocker=$null; preserved_test_marker='keep-me'
    }
}

Invoke-Test 'A: new checkpoint has a writable current_phase' {
    $checkpoint = New-TestCheckpoint
    Set-GadeCheckpointProperty -Object $checkpoint -Name 'current_phase' -Value 'Test Phase A'
    Assert-True ($checkpoint.current_phase -ceq 'Test Phase A') 'current_phase did not update on a new PSCustomObject.'
    [void](Normalize-GadeHostCheckpoint -Checkpoint $checkpoint -ExpectedRunId $runId)
}

Invoke-Test 'B: old checkpoint missing current_phase normalizes without data loss' {
    $checkpoint = New-TestCheckpoint
    $checkpoint.PSObject.Properties.Remove('current_phase')
    $checkpoint.PSObject.Properties.Remove('updated_at')
    $checkpoint.stages | Add-Member -MemberType NoteProperty -Name 'Existing PASS' -Value ([pscustomobject]@{
        status='PASS'; kind='read-only'; attempt=1; started_at=$now; finished_at=$now; evidence='saved'
    })
    $normalized = Normalize-GadeHostCheckpoint -Checkpoint $checkpoint -ExpectedRunId $runId
    Assert-True ($normalized.current_phase -ceq 'Existing PASS') 'phase label was not recovered from the existing recorded stage.'
    Assert-True ($normalized.updated_at -ceq $normalized.created_at) 'safe updated_at compatibility default was not applied.'
    Assert-True ($normalized.preserved_test_marker -ceq 'keep-me') 'normalization cleared an existing field.'
    Assert-True ($normalized.stages.'Existing PASS'.status -ceq 'PASS') 'normalization altered a stage status.'
}

Invoke-Test 'C: existing current_phase updates in place' {
    $checkpoint = New-TestCheckpoint
    Set-GadeCheckpointProperty -Object $checkpoint -Name 'current_phase' -Value 'Updated Phase'
    Assert-True ($checkpoint.current_phase -ceq 'Updated Phase') 'current_phase did not update.'
}

Invoke-Test 'D: atomic JSON save and reload preserve schema and stage fields' {
    $checkpoint = New-TestCheckpoint
    $checkpoint.stages | Add-Member -MemberType NoteProperty -Name 'Migration PASS' -Value ([pscustomobject]@{
        status='PASS'; kind='database'; attempt=1; started_at=$now; finished_at=$now; evidence=[pscustomobject]@{ log_sha256=('c' * 64) }
    })
    $testRoot = Join-Path $env:TEMP ('gade-checkpoint-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
    $path = Join-Path $testRoot 'checkpoint.json'
    try {
        [void](Save-GadeHostCheckpointAtomic -Checkpoint $checkpoint -Path $path)
        Set-GadeCheckpointProperty -Object $checkpoint -Name 'current_phase' -Value 'Second Save'
        [void](Save-GadeHostCheckpointAtomic -Checkpoint $checkpoint -Path $path)
        $saved = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        Assert-True ($saved.current_phase -ceq 'Second Save') 'reloaded current_phase was lost.'
        Assert-True ($saved.stages.'Migration PASS'.status -ceq 'PASS') 'reloaded stage status was lost.'
        Assert-True ($saved.run_id -ceq $runId) 'reloaded RunId was lost.'
        Assert-True (@(Get-ChildItem -LiteralPath $testRoot -Filter 'checkpoint.json.bak-*').Count -eq 1) 'atomic replacement did not preserve a backup of the prior readable checkpoint.'
    } finally { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}

Invoke-Test 'E: failed stage never becomes PASS during normalization or Resume validation' {
    $checkpoint = New-TestCheckpoint
    $checkpoint.stages | Add-Member -MemberType NoteProperty -Name 'Fresh migrations' -Value ([pscustomobject]@{
        status='FAIL'; kind='database'; attempt=1; started_at=$now; finished_at=$now; error='controlled failure'
    })
    Assert-Throws { Assert-GadeHostCheckpointResumeSafe -Checkpoint $checkpoint -ExpectedRunId $runId } 'do not resume/re-run'
    Assert-True ($checkpoint.stages.'Fresh migrations'.status -ceq 'FAIL') 'failed stage status was modified.'
}

Invoke-Test 'F: missing RunId/identity information rejects Resume' {
    $checkpoint = New-TestCheckpoint
    $checkpoint.PSObject.Properties.Remove('run_id')
    Assert-Throws { Assert-GadeHostCheckpointResumeSafe -Checkpoint $checkpoint -ExpectedRunId $runId } 'run_id'
}

Invoke-Test 'G: corrupted, incomplete, or interrupted database checkpoint rejects Resume' {
    $corruptPath = Join-Path $env:TEMP ('gade-checkpoint-corrupt-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        [System.IO.File]::WriteAllText($corruptPath,'{"run_id":', (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws { Get-Content -LiteralPath $corruptPath -Raw | ConvertFrom-Json -ErrorAction Stop } ''
    } finally { Remove-Item -LiteralPath $corruptPath -Force -ErrorAction SilentlyContinue }
    $incomplete = New-TestCheckpoint
    $incomplete.PSObject.Properties.Remove('stages')
    Assert-Throws { Assert-GadeHostCheckpointResumeSafe -Checkpoint $incomplete -ExpectedRunId $runId } "required object 'stages'"
    $interrupted = New-TestCheckpoint
    $interrupted.stages | Add-Member -MemberType NoteProperty -Name 'Fresh migrations' -Value ([pscustomobject]@{
        status='RUNNING'; kind='database'; attempt=1; started_at=$now
    })
    Assert-Throws { Assert-GadeHostCheckpointResumeSafe -Checkpoint $interrupted -ExpectedRunId $runId } 'do not resume/re-run'
}

Invoke-Test 'H: planned-resource and runner target safety checks remain enforced' {
    $checkpoint = New-TestCheckpoint
    Assert-GadePlannedResources -Checkpoint $checkpoint -ExpectedRunId $runId
    $unsafe = New-TestCheckpoint
    $unsafe.planned_resources[0].host_port = 15432
    Assert-Throws { Assert-GadePlannedResources -Checkpoint $unsafe -ExpectedRunId $runId } 'outside the test allowlist'
    $unsafeDb = New-TestCheckpoint
    $unsafeDb.planned_resources[0].database = 'm2a_pentest'
    Assert-Throws { Assert-GadePlannedResources -Checkpoint $unsafeDb -ExpectedRunId $runId } 'run-scoped allowlist'
    $orchestrator = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Invoke-GadePreExpHostValidation.ps1') -Raw
    $migrationRunner = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Invoke-MigrationSmoke.ps1') -Raw
    Assert-True ($orchestrator.Contains('ExpectedId') -and $orchestrator.Contains('HostIp') -and $orchestrator.Contains('volume ownership labels mismatch')) 'Orchestrator full container/volume identity checks are missing.'
    Assert-True ($orchestrator.Contains('ON_ERROR_STOP=1') -and $migrationRunner.Contains('15432') -and $migrationRunner.Contains('m2a_pentest')) 'SQL error-stop or forbidden dev-target checks are missing.'
}

Invoke-Test 'I: Hashtable checkpoints normalize to PSCustomObject without losing fields' {
    function Convert-TestValueToHashtable($Value) {
        if ($null -eq $Value) { return $null }
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            $result = @{}
            foreach ($property in $Value.PSObject.Properties) { $result[$property.Name] = Convert-TestValueToHashtable $property.Value }
            return $result
        }
        if ($Value -is [System.Array]) { $items=@(); foreach($item in $Value){ $items += ,(Convert-TestValueToHashtable $item) }; return ,$items }
        return $Value
    }
    $source = New-TestCheckpoint
    Set-GadeCheckpointProperty -Object $source -Name 'unrelated_field' -Value 'preserve-this'
    $dictionary = Convert-TestValueToHashtable $source
    $normalized = Normalize-GadeHostCheckpoint -Checkpoint $dictionary -ExpectedRunId $runId
    Assert-True ($normalized -is [System.Management.Automation.PSCustomObject]) 'Hashtable was not normalized into the checkpoint object schema.'
    Assert-True ($normalized.unrelated_field -ceq 'preserve-this') 'Hashtable normalization lost an unrelated field.'
    Assert-True ($normalized.run_id -ceq $runId) 'Hashtable normalization lost run identity.'
}

Invoke-Test 'J: blocker packet handles null baseline and records exact failure identity' {
    $checkpoint = New-TestCheckpoint
    $checkpoint.resources | Add-Member -MemberType NoteProperty -Name 'legacy025' -Value ([pscustomobject]@{
        container_name="gade-preexp-$runId-legacy025"; container_id=('d' * 64); database="gade_${runId}_legacy025"; host_port=25957
    })
    $checkpoint.stages | Add-Member -MemberType NoteProperty -Name 'Migration 025 legacy-column compatibility' -Value ([pscustomobject]@{
        status='FAIL'; kind='database'; attempt=1; started_at=$now; finished_at=$now; error='SQLAlchemy mapped columns absent'
    })
    $root = Join-Path $env:TEMP ('gade-blocker-test-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    try {
        $path = Join-Path $root 'BLOCKER_PACKET.md'
        $result = New-GadeBlockerPacket -Checkpoint $checkpoint -RunId $runId `
            -PhaseName 'Migration 025 legacy-column compatibility' -Observed 'original SQLAlchemy drift exception' `
            -CheckpointPath (Join-Path $root 'checkpoint.json') -Path $path -ResumeSafety 'UNSAFE_TO_RESUME_PARTIAL_DATABASE_WRITE'
        $content = Get-Content -LiteralPath $path -Raw
        Assert-True ($content.Contains('original SQLAlchemy drift exception')) 'blocker lost the original exception.'
        Assert-True ($content.Contains($runId) -and $content.Contains('25957') -and $content.Contains(('d' * 64))) 'blocker lost run/resource identity.'
        Assert-True ($content.Contains('UNSAFE_TO_RESUME_PARTIAL_DATABASE_WRITE')) 'blocker omitted resume safety.'
        Assert-True ($content.Contains('Baseline Commit: NOT_CREATED')) 'null baseline was not handled safely.'
        Assert-True ($result.sha256 -match '^[0-9a-f]{64}$') 'blocker packet hash is invalid.'
    } finally { Remove-Item -LiteralPath $root -Recurse -Force }
}

Invoke-Test 'K: failure artifact writer preserves original error if checkpoint save fails' {
    $checkpoint = New-TestCheckpoint
    $root = Join-Path $env:TEMP ('gade-blocker-fallback-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    try {
        $missingDirectory = Join-Path $root 'not-created'
        $result = Save-GadeHostFailureArtifacts -Checkpoint $checkpoint -RunId $runId `
            -PhaseName 'controlled failure stage' -Observed 'ORIGINAL_DB_ERROR_FOR_TEST' `
            -RunDirectory $root -CheckpointPath (Join-Path $missingDirectory 'checkpoint.json') `
            -ResumeSafety 'UNSAFE_TO_RESUME_PARTIAL_DATABASE_WRITE' 2>$null
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$result.write_failure)) 'checkpoint save failure was not reported.'
        Assert-True (Test-Path -LiteralPath $result.fallback_path) 'fallback diagnostic was not written.'
        $fallback = Get-Content -LiteralPath $result.fallback_path -Raw
        Assert-True ($fallback.Contains('ORIGINAL_DB_ERROR_FOR_TEST') -and $fallback.Contains($runId)) 'fallback omitted the original error or RunId.'
        Assert-True ($fallback.Contains('controlled failure stage') -and $fallback.Contains('UNSAFE_TO_RESUME_PARTIAL_DATABASE_WRITE')) 'fallback omitted phase or resume status.'
    } finally { Remove-Item -LiteralPath $root -Recurse -Force }
}

Invoke-Test 'L: Migration 025 compatibility fixture completes 001-037 before final ORM comparison' {
    $runner = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Invoke-MigrationSmoke.ps1') -Raw
    $modeStart = $runner.IndexOf("} elseif (`$Mode -eq 'LegacyColumn')")
    $postSchema = $runner.IndexOf('Assert-PostMigrationSchema $container.Id')
    $migration037Validation = $runner.IndexOf('Assert-Migration037Schema $container.Id')
    $ormValidation = $runner.IndexOf('Assert-OrmColumns $container.Id')
    $tailMigration = $runner.IndexOf("[int]`$_.Name.Substring(0,3) -ge 26",$modeStart)
    Assert-True ($modeStart -ge 0 -and $tailMigration -gt $modeStart) 'LegacyColumn mode does not apply the post-025 migrations.'
    Assert-True ($migration037Validation -gt $tailMigration -and $postSchema -gt $migration037Validation -and $ormValidation -gt $postSchema) '037, final schema, and ORM validators do not run after the 025 fixture reaches its terminal migration state.'
    $ormStart = $runner.IndexOf('function Assert-OrmColumns')
    $ormEnd = $runner.IndexOf('function Invoke-LegacyFixture',$ormStart)
    $ormBody = $runner.Substring($ormStart,$ormEnd-$ormStart)
    Assert-True ($ormBody.Contains('Assert-OrmColumns([string]$ContainerId)') -and $ormBody.Contains('Invoke-DockerPsql -ContainerId $ContainerId')) 'ORM validation is not bound to the exact validated container ID.'
    $schemaStart = $runner.IndexOf('function Assert-PostMigrationSchema')
    $schemaEnd = $runner.IndexOf('function Assert-OrmColumns',$schemaStart)
    $schemaBody = $runner.Substring($schemaStart,$schemaEnd-$schemaStart)
    Assert-True ($schemaBody.Contains('SCHEMA_033_036=PASS') -and -not $schemaBody.Contains('Assert-OrmColumns')) 'SCHEMA_033_036 success marker scope is incorrectly conflated with ORM validation.'
}

Write-Host "CHECKPOINT_TEST_RESULTS passed=$script:Passed failed=$script:Failed"
if ($script:Failed -ne 0) { exit 1 }
