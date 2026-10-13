[CmdletBinding()]
param(
    [switch]$PreflightOnly,
    [switch]$Resume,
    [ValidatePattern('^[0-9a-f]{12}$')]
    [string]$RunId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Runner = Join-Path $PSScriptRoot 'Invoke-MigrationSmoke.ps1'
$AppSmoke = Join-Path $PSScriptRoot 'Invoke-GadeAppSmoke.ps1'
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$DockerExe = (Get-Command docker.exe -ErrorAction Stop).Source
$TagName = 'gade-preexp-v1'
$LogDirectory = Join-Path $env:LOCALAPPDATA 'M2A\MigrationSmoke'
$RunRoot = Join-Path $RepoRoot 'reports\experiments\gade-preexp-host-validation'
$PortMinimum = 25436
$PortMaximum = 25999
$Patched025Hash = 'd088b88e230d20c7d5ab63a7a3039bb54c6e946d20b6ef36b2481c870d7f6bd3'
$AllowedGitPaths = @(
    'initdb/025_normalized_results_schema_alignment.sql',
    'initdb/037_llm_evidence_tables.sql',
    'scripts/Diagnose-MigrationSmoke.ps1',
    'scripts/Invoke-MigrationSmoke.ps1',
    'scripts/Invoke-GadePreExpHostValidation.ps1',
    'scripts/GadeHostCheckpoint.ps1',
    'scripts/Test-GadeHostCheckpoint.ps1',
    'scripts/Invoke-GadeAppSmoke.ps1',
    'scripts/gade_app_smoke.py',
    'scripts/Export-GadeLegacy037Verification.ps1',
    'tests/test_migration_037_contract.py',
    'tests/test_execution_trace.py',
    'app/execution_trace.py',
    'scripts/GadeMigration037Oracle.ps1',
    'scripts/Test-GadeMigration037Oracle.ps1',
    'docs/GADE_025_Compatibility_Repair_Audit.md',
    'docs/GADE_025_normalized_results_applied.diff',
    'docs/GADE_025_Host_Validation_Runbook.md'
)
$SourcePaths = @(
    'scripts/Invoke-MigrationSmoke.ps1', 'scripts/Invoke-GadePreExpHostValidation.ps1', 'scripts/GadeHostCheckpoint.ps1',
    'scripts/Test-GadeHostCheckpoint.ps1',
    'scripts/Invoke-GadeAppSmoke.ps1', 'scripts/gade_app_smoke.py',
    'scripts/Export-GadeLegacy037Verification.ps1',
    'tests/test_migration_037_contract.py',
    'scripts/GadeMigration037Oracle.ps1', 'scripts/Test-GadeMigration037Oracle.ps1',
    'scripts/Diagnose-MigrationSmoke.ps1', 'docs/GADE_025_Compatibility_Repair_Audit.md',
    'docs/GADE_025_normalized_results_applied.diff', 'docs/GADE_025_Host_Validation_Runbook.md',
    'app/action_contracts.py', 'app/attack_authorization.py',
    'app/execution_governance.py', 'app/execution_trace.py',
    'tests/test_execution_trace.py',
    'app/models.py', 'app/vulnerability_queue.py', 'kali_worker/app.py',
    'experiments/boundary_experiment.py', 'experiments/mode_b_provider.py',
    'experiments/data/boundary_scenarios_v1.json'
)
$CurrentPhase = 'Host preflight'
$Checkpoint = $null
$RunDirectory = $null
$Portfolios = @()

. (Join-Path $PSScriptRoot 'GadeHostCheckpoint.ps1')

function ConvertTo-WindowsArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($slashes * 2) + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) { [void]$builder.Append(('\' * $slashes)); $slashes = 0 }
        [void]$builder.Append($character)
    }
    if ($slashes -gt 0) { [void]$builder.Append(('\' * ($slashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-Process {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $RepoRoot,
        [hashtable]$Environment = @{},
        [string]$StandardInput
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $FileName
    $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($PSBoundParameters.ContainsKey('StandardInput')) { $start.RedirectStandardInput = $true }
    foreach ($key in $Environment.Keys) { $start.EnvironmentVariables[[string]$key] = [string]$Environment[$key] }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($PSBoundParameters.ContainsKey('StandardInput')) {
            $process.StandardInput.Write($StandardInput)
            $process.StandardInput.Close()
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdoutTask.GetAwaiter().GetResult()
            Stderr = $stderrTask.GetAwaiter().GetResult()
        }
    } finally { $process.Dispose() }
}

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$Arguments,
          [hashtable]$Environment = @{}, [switch]$AllowFailure)
    $result = Invoke-Process -FileName $DockerExe -Arguments $Arguments -Environment $Environment
    if (-not $AllowFailure -and $result.ExitCode -ne 0) {
        $message = ($result.Stderr -replace '[\r\n]+', ' ').Trim()
        throw "docker $($Arguments[0]) failed (exit $($result.ExitCode)): $message"
    }
    return $result
}

function Invoke-CheckedProcess {
    param([Parameter(Mandatory = $true)][string]$FileName,
          [string[]]$Arguments = @(), [string]$WorkingDirectory = $RepoRoot,
          [hashtable]$Environment = @{}, [string]$StandardInput,
          [Parameter(Mandatory = $true)][string]$Label)
    $invokeArgs = @{
        FileName = $FileName; Arguments = $Arguments; WorkingDirectory = $WorkingDirectory
        Environment = $Environment
    }
    if ($PSBoundParameters.ContainsKey('StandardInput')) { $invokeArgs.StandardInput = $StandardInput }
    $result = Invoke-Process @invokeArgs
    if ($result.ExitCode -ne 0) {
        $safeStderr = ($result.Stderr -replace '[\r\n]+', ' ').Trim()
        throw "$Label failed (exit $($result.ExitCode)): $safeStderr"
    }
    return $result
}

function Get-RunProfiles([string]$SelectedRunId, [int]$FirstPort) {
    $profiles = @(
        [pscustomobject]@{ Profile='legacy025'; Mode='LegacyColumn'; Port=$FirstPort },
        [pscustomobject]@{ Profile='fresh'; Mode='Migrations'; Port=($FirstPort + 1) },
        [pscustomobject]@{ Profile='legacy'; Mode='Legacy'; Port=($FirstPort + 2) }
    )
    foreach ($profile in $profiles) {
        $profile | Add-Member -NotePropertyName ContainerName -NotePropertyValue ("gade-preexp-{0}-{1}" -f $SelectedRunId, $profile.Profile)
        $profile | Add-Member -NotePropertyName Database -NotePropertyValue ("gade_{0}_{1}" -f $SelectedRunId, $profile.Profile)
        $profile | Add-Member -NotePropertyName User -NotePropertyValue ("gade_{0}_{1}" -f $SelectedRunId, $profile.Profile)
        $profile | Add-Member -NotePropertyName Volume -NotePropertyValue ("gade_preexp_{0}_{1}" -f $SelectedRunId, $profile.Profile)
        $profile | Add-Member -NotePropertyName HostIp -NotePropertyValue '127.0.0.1'
        $profile | Add-Member -NotePropertyName ContainerId -NotePropertyValue ''
    }
    return $profiles
}

function Test-PortAvailable([int]$Port) {
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        return $true
    } catch { return $false }
    finally { if ($null -ne $listener) { $listener.Stop() } }
}

function Get-SourceManifest {
    $entries = @()
    $migrationFiles = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'initdb') -File |
        Where-Object { $_.Name -match '^\d{3}_.+\.sql$' } | Sort-Object Name)
    if ($migrationFiles.Count -ne 37) { throw "Expected 37 numbered SQL migrations; found $($migrationFiles.Count)." }
    for ($i = 0; $i -lt $migrationFiles.Count; $i++) {
        if ([int]$migrationFiles[$i].Name.Substring(0,3) -ne ($i + 1)) { throw 'Numbered migration list is not contiguous 001–037.' }
        $relative = 'initdb/' + $migrationFiles[$i].Name
        $hash = (Get-FileHash -LiteralPath $migrationFiles[$i].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries += [pscustomobject]@{ path=$relative; sha256=$hash }
    }
    if ($entries[24].sha256 -cne $Patched025Hash) { throw 'Migration 025 SHA-256 differs from the authorized repair.' }
    foreach ($relative in $SourcePaths) {
        $path = Join-Path $RepoRoot ($relative -replace '/', '\')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required source file is missing: $relative" }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries += [pscustomobject]@{ path=$relative; sha256=$hash }
    }
    return ,$entries
}

function Get-HeadSha {
    $result = Invoke-CheckedProcess -FileName (Get-Command git.exe -ErrorAction Stop).Source `
        -Arguments @('rev-parse','HEAD') -Label 'git rev-parse'
    return $result.Stdout.Trim()
}

function Get-StringSha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-HistoricalExperimentHashes {
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $listed = Invoke-CheckedProcess -FileName $git -Arguments @('ls-files','experiments') -Label 'git ls-files experiments'
    $rows = @()
    foreach ($relative in ($listed.Stdout -split "`r?`n" | Where-Object { $_ })) {
        $full = Join-Path $RepoRoot ($relative -replace '/', '\')
        if (Test-Path -LiteralPath $full -PathType Leaf) {
            $rows += [pscustomobject]@{ path=$relative; sha256=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    }
    return ,$rows
}

function Get-GitStatusPaths {
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $result = Invoke-CheckedProcess -FileName $git -Arguments @('status','--porcelain=v1','--untracked-files=all') -Label 'git status'
    return @($result.Stdout -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $_.Substring(3).Trim('"') -replace '\\','/' })
}

function Assert-GitScope {
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $staged = Invoke-CheckedProcess -FileName $git -Arguments @('diff','--cached','--name-only') -Label 'git staged-path inspection'
    if (-not [string]::IsNullOrWhiteSpace($staged.Stdout)) {
        throw "Git index already contains staged changes. Unstage them before host validation: $($staged.Stdout -replace '[\r\n]+',', ')"
    }
    $unexpected = @(Get-GitStatusPaths | Where-Object { $AllowedGitPaths -cnotcontains $_ })
    if ($unexpected.Count -gt 0) {
        throw "Git worktree has unrelated changes; no files will be staged: $($unexpected -join ', ')"
    }
}

function Get-CheckpointStage([string]$Name) {
    if ($null -eq $Checkpoint.stages) { return $null }
    $property = $Checkpoint.stages.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Set-CheckpointProperty {
    param([Parameter(Mandatory = $true)]$Object,
          [Parameter(Mandatory = $true)][string]$Name,
          [Parameter(Mandatory = $true)]$Value)
    Set-GadeCheckpointProperty -Object $Object -Name $Name -Value $Value
}

function Save-Checkpoint {
    if ($null -eq $Checkpoint -or $null -eq $RunDirectory) { return }
    $script:Checkpoint = Save-GadeHostCheckpointAtomic -Checkpoint $Checkpoint -Path (Join-Path $RunDirectory 'checkpoint.json')
}

function Write-RunRecord([string]$Message) {
    $line = '{0} {1}' -f [DateTimeOffset]::Now.ToString('o'), $Message
    Add-Content -LiteralPath (Join-Path $RunDirectory 'orchestrator.log') -Value $line -Encoding UTF8
    Write-Host $Message
}

function Invoke-CheckpointedStage {
    param([Parameter(Mandatory = $true)][string]$Name,
          [Parameter(Mandatory = $true)][string]$Kind,
          [Parameter(Mandatory = $true)][scriptblock]$Action)
    $existing = Get-CheckpointStage $Name
    if ($null -ne $existing -and $existing.status -eq 'PASS') {
        Write-RunRecord "STAGE_SKIP name=$Name status=PASS checkpointed=true"
        return $existing.evidence
    }
    if ($null -ne $existing -and $existing.status -in @('RUNNING','FAIL') -and $Kind -in @('database','app-smoke')) {
        throw "Stage '$Name' is $($existing.status); database state may be partial. Preserve it and use a new RunId for retry."
    }
    $attempt = 1
    if ($null -ne $existing -and $null -ne $existing.attempt) { $attempt = [int]$existing.attempt + 1 }
    Set-CheckpointProperty -Object $Checkpoint.stages -Name $Name -Value ([pscustomobject]@{
        status='RUNNING'; attempt=$attempt; started_at=[DateTimeOffset]::Now.ToString('o'); kind=$Kind
    })
    $Checkpoint.status = 'RUNNING'
    $Checkpoint.current_phase = $Name
    Save-Checkpoint
    $script:CurrentPhase = $Name
    Write-RunRecord "STAGE_START name=$Name attempt=$attempt"
    try {
        $evidence = & $Action
        Set-CheckpointProperty -Object $Checkpoint.stages -Name $Name -Value ([pscustomobject]@{
            status='PASS'; attempt=$attempt; started_at=(Get-CheckpointStage $Name).started_at
            finished_at=[DateTimeOffset]::Now.ToString('o'); kind=$Kind; evidence=$evidence
        })
        $Checkpoint.current_phase = $Name
        Save-Checkpoint
        Write-RunRecord "STAGE_PASS name=$Name"
        return $evidence
    } catch {
        $originalStageError = $_
        try {
            Set-CheckpointProperty -Object $Checkpoint.stages -Name $Name -Value ([pscustomobject]@{
                status='FAIL'; attempt=$attempt; started_at=(Get-CheckpointStage $Name).started_at
                finished_at=[DateTimeOffset]::Now.ToString('o'); kind=$Kind; error=$originalStageError.Exception.Message
            })
            Set-CheckpointProperty -Object $Checkpoint -Name 'status' -Value 'FAILED'
            Save-Checkpoint
        }
        catch { Write-Host "CHECKPOINT_SAVE_FAILURE after stage error: $($_.Exception.Message)" }
        try { Write-RunRecord "STAGE_FAIL name=$Name error=$($originalStageError.Exception.Message -replace '[\r\n]+',' ')" }
        catch { Write-Host "STAGE_LOG_FAILURE after stage error: $($_.Exception.Message)" }
        throw $originalStageError
    }
}

function Get-Profile([string]$Name) {
    return @($Portfolios | Where-Object { $_.Profile -ceq $Name })[0]
}

function Get-ContainerJson([string]$ContainerName) {
    $result = Invoke-Docker -Arguments @('inspect', $ContainerName) -AllowFailure
    if ($result.ExitCode -ne 0) { return $null }
    try { return @($result.Stdout | ConvertFrom-Json -ErrorAction Stop)[0] }
    catch { throw "Docker inspect for '$ContainerName' did not return JSON." }
}

function Assert-ContainerIdentity {
    param([Parameter(Mandatory = $true)]$Profile,
          [string]$ExpectedId,
          [switch]$RequireRunning)
    $container = Get-ContainerJson $Profile.ContainerName
    if ($null -eq $container) { throw "Expected run-scoped container is missing: $($Profile.ContainerName)" }
    if ($ExpectedId -and $container.Id -cne $ExpectedId) { throw "Full container ID mismatch for $($Profile.ContainerName)." }
    if ($container.Name -cne "/$($Profile.ContainerName)" -or $container.Config.Image -cne 'postgres:16') {
        throw "Container name/image mismatch for $($Profile.Profile)."
    }
    if ($RequireRunning -and -not $container.State.Running) { throw "Container is not running: $($Profile.ContainerName)" }
    $bindings = @($container.HostConfig.PortBindings.'5432/tcp')
    $published = @($container.NetworkSettings.Ports.'5432/tcp')
    if ($bindings.Count -ne 1 -or $published.Count -ne 1 -or
        $bindings[0].HostIp -cne '127.0.0.1' -or $bindings[0].HostPort -cne [string]$Profile.Port -or
        $published[0].HostIp -cne '127.0.0.1' -or $published[0].HostPort -cne [string]$Profile.Port) {
        throw "Container published port mismatch for $($Profile.Profile)."
    }
    $portKeys = @($container.HostConfig.PortBindings.PSObject.Properties.Name)
    if ($portKeys.Count -ne 1 -or $portKeys[0] -cne '5432/tcp') { throw 'Unexpected additional published container ports.' }
    $environment = @($container.Config.Env)
    if ($environment -cnotcontains "POSTGRES_DB=$($Profile.Database)" -or
        $environment -cnotcontains "POSTGRES_USER=$($Profile.User)") {
        throw "Container DB/user environment mismatch for $($Profile.Profile)."
    }
    $labels = $container.Config.Labels
    if ($labels.'com.gade.preexp.managed' -cne 'true' -or
        $labels.'com.gade.preexp.run_id' -cne $RunId -or
        $labels.'com.gade.preexp.profile' -cne $Profile.Profile) {
        throw "Container ownership labels mismatch for $($Profile.Profile)."
    }
    $mounts = @($container.Mounts | Where-Object { $_.Destination -ceq '/var/lib/postgresql/data' })
    if ($mounts.Count -ne 1 -or $mounts[0].Name -cne $Profile.Volume) {
        throw "Container data volume mismatch for $($Profile.Profile)."
    }
    $volumeResult = Invoke-Docker -Arguments @('volume','inspect',$Profile.Volume) -AllowFailure
    if ($volumeResult.ExitCode -ne 0) { throw "Expected named volume is missing for $($Profile.Profile)." }
    $volumeInfo = @($volumeResult.Stdout | ConvertFrom-Json -ErrorAction Stop)[0]
    if ($volumeInfo.Labels.'com.gade.preexp.managed' -cne 'true' -or
        $volumeInfo.Labels.'com.gade.preexp.run_id' -cne $RunId -or
        $volumeInfo.Labels.'com.gade.preexp.profile' -cne $Profile.Profile) {
        throw "Data volume ownership labels mismatch for $($Profile.Profile)."
    }
    $Profile | Add-Member -NotePropertyName ContainerId -NotePropertyValue $container.Id -Force
    return $container
}

function Invoke-ContainerPsql {
    param([Parameter(Mandatory = $true)]$Profile,
          [Parameter(Mandatory = $true)][string]$Sql,
          [switch]$TuplesOnly)
    $container = Assert-ContainerIdentity -Profile $Profile -ExpectedId $Profile.ContainerId -RequireRunning
    $arguments = @('exec','-i',$container.Id,'psql','-X','-v','ON_ERROR_STOP=1','-U',$Profile.User,'-d',$Profile.Database)
    if ($TuplesOnly) { $arguments += @('-A','-t','-q') }
    # SQL is sent over stdin to avoid shell parsing and preserve psql's exit code.
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $DockerExe
    $start.Arguments = (($arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($Sql)
        $process.StandardInput.Close()
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode=$process.ExitCode; Stdout=$stdoutTask.GetAwaiter().GetResult().Trim(); Stderr=$stderrTask.GetAwaiter().GetResult().Trim() }
    } finally { $process.Dispose() }
}

function Assert-DatabaseIdentity([Parameter(Mandatory = $true)]$Profile) {
    $sql = "SELECT json_build_object('database',current_database(),'user',current_user,'inet_server_port',inet_server_port(),'configured_port',current_setting('port'))::text;"
    $result = Invoke-ContainerPsql -Profile $Profile -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0) { throw "Read-only database identity query failed for $($Profile.Profile): $($result.Stderr)" }
    try { $identity = $result.Stdout | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Database identity output is invalid JSON for $($Profile.Profile)." }
    if ($identity.database -cne $Profile.Database -or $identity.user -cne $Profile.User -or
        $identity.configured_port -cne '5432' -or
        ($null -ne $identity.inet_server_port -and [int]$identity.inet_server_port -ne 5432)) {
        throw "Database identity mismatch for $($Profile.Profile)."
    }
    return $identity
}

function Assert-EmptyDatabase([Parameter(Mandatory = $true)]$Profile) {
    $sql = @'
SELECT
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')) || '|' ||
  (SELECT count(*) FROM pg_namespace
   WHERE nspname NOT IN ('pg_catalog','information_schema','public') AND nspname NOT LIKE 'pg_toast%') || '|' ||
  (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public') || '|' ||
  (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
   WHERE n.nspname='public' AND t.typtype IN ('d','e','r'));
'@
    $result = Invoke-ContainerPsql -Profile $Profile -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0 -or $result.Stdout -cne '0|0|0|0') {
        throw "Database $($Profile.Database) is not a fresh empty schema: $($result.Stdout) $($result.Stderr)"
    }
}

function Assert-ResourceNameUnused {
    param([Parameter(Mandatory = $true)][string]$Name,
          [Parameter(Mandatory = $true)][ValidateSet('container','volume')][string]$Kind)
    $arguments = if ($Kind -eq 'container') { @('inspect',$Name) } else { @('volume','inspect',$Name) }
    $result = Invoke-Docker -Arguments $arguments -AllowFailure
    if ($result.ExitCode -eq 0) { throw "Refusing to reuse existing $Kind named '$Name'. Choose a new RunId." }
    if ($result.Stderr -notmatch 'No such (object|container|volume)') {
        throw "Could not prove $Kind name '$Name' is unused: $($result.Stderr)"
    }
}

function Write-Plan {
    Write-Host "RUN_ID=$RunId"
    Write-Host 'MODE=PreflightOnly (read-only; no files, containers, databases, or volumes are created)'
    Write-Host 'DOCKER_ENGINE=PASS; postgres_image=postgres:16 (must already be present; no pull is performed)'
    Write-Host 'FORBIDDEN_TARGETS=m2a_pentest;host_port=15432;Compose resources;original m2a-migration-smoke container and volume'
    Write-Host 'PLANNED RESOURCES (created only after one exact confirmation):'
    foreach ($profile in $Portfolios) {
        Write-Host ("  container={0}; image=postgres:16; host=127.0.0.1:{1}->5432; database={2}; user={3}; new_volume={4}" -f
            $profile.ContainerName,$profile.Port,$profile.Database,$profile.User,$profile.Volume)
    }
    Write-Host "  run_directory=$RunDirectory"
    Write-Host "  host_migration_logs=$LogDirectory"
    Write-Host "  eventual_local_tag=$TagName (created only after migration/app/regression/build/Git gates pass; never pushed)"
    Write-Host 'CLEANUP=none; resources are retained if any stage fails or blocks; all created resources are listed above.'
    Write-Host "SOURCE_025_SHA256=$Patched025Hash"
    Write-Host "CURRENT_HEAD=$(Get-HeadSha)"
    Write-Host "SOURCE_MANIFEST_ENTRIES=$($script:SourceManifest.Count)"
    foreach ($entry in $script:SourceManifest) { Write-Host ("  sha256={0} path={1}" -f $entry.sha256,$entry.path) }
    Write-Host "GIT_SCOPE=PASS (only the allowlisted repair, runner, app smoke, and audit files may be committed)"
    Write-Host 'CONFIRMATION_PHRASE=RUN-GADE-PREEXP-VALIDATION'
}

function Test-HostPreflight {
    $dockerInfo = Invoke-CheckedProcess -FileName $DockerExe -Arguments @('info','--format','{{.ServerVersion}}') -Label 'Docker Engine preflight'
    if ([string]::IsNullOrWhiteSpace($dockerInfo.Stdout)) { throw 'Docker Engine returned no ServerVersion.' }
    $image = Invoke-Docker -Arguments @('image','inspect','postgres:16','--format','{{.Id}}')
    if ([string]::IsNullOrWhiteSpace($image.Stdout)) { throw 'postgres:16 image is not present locally; no image pull is attempted.' }
    foreach ($profile in $Portfolios) {
        if ($profile.Port -lt $PortMinimum -or $profile.Port -gt $PortMaximum -or $profile.Port -eq 15432) {
            throw "Port allowlist failure: $($profile.Port)"
        }
        if (-not (Test-PortAvailable -Port $profile.Port)) { throw "Host port $($profile.Port) is busy; choose a new RunId." }
        Assert-ResourceNameUnused -Name $profile.ContainerName -Kind container
        Assert-ResourceNameUnused -Name $profile.Volume -Kind volume
    }
    Assert-GitScope
    $dockerVersion = Invoke-CheckedProcess -FileName $DockerExe -Arguments @('version','--format','{{.Client.Version}}') -Label 'Docker CLI version'
    $pythonVersion = Invoke-CheckedProcess -FileName $Python -Arguments @('--version') -Label 'Python version'
    $npm = (Get-Command npm.cmd -ErrorAction Stop).Source
    $npmVersion = Invoke-CheckedProcess -FileName $npm -Arguments @('--version') -Label 'npm version'
    $node = (Get-Command node.exe -ErrorAction Stop).Source
    $nodeVersion = Invoke-CheckedProcess -FileName $node -Arguments @('--version') -Label 'Node version'
    Write-Host "DOCKER_SERVER_VERSION=$($dockerInfo.Stdout.Trim())"
    Write-Host "DOCKER_CLI_VERSION=$($dockerVersion.Stdout.Trim())"
    Write-Host "POSTGRES_IMAGE_ID=$($image.Stdout.Trim())"
    Write-Host "PYTHON_VERSION=$($pythonVersion.Stdout.Trim())"
    Write-Host "NPM_VERSION=$($npmVersion.Stdout.Trim())"
    Write-Host "NODE_VERSION=$($nodeVersion.Stdout.Trim())"
    return [pscustomobject]@{
        docker_server_version=$dockerInfo.Stdout.Trim(); docker_cli_version=$dockerVersion.Stdout.Trim()
        postgres_image_id=$image.Stdout.Trim(); python_version=$pythonVersion.Stdout.Trim()
        npm_version=$npmVersion.Stdout.Trim(); node_version=$nodeVersion.Stdout.Trim(); powershell_version=$PSVersionTable.PSVersion.ToString()
        host_os=[System.Environment]::OSVersion.VersionString
    }
}

function Save-ResourceProfile([Parameter(Mandatory = $true)]$Profile) {
    if ($null -eq $Checkpoint.resources) { $Checkpoint | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]@{}) }
    $containerId = ''
    if ($Profile.PSObject.Properties['ContainerId']) { $containerId = [string]$Profile.ContainerId }
    Set-CheckpointProperty -Object $Checkpoint.resources -Name $Profile.Profile -Value ([pscustomobject]@{
        container_name=$Profile.ContainerName; container_id=$containerId
        volume=$Profile.Volume; host_ip='127.0.0.1'; host_port=[int]$Profile.Port
        database=$Profile.Database; user=$Profile.User; profile=$Profile.Profile
    })
    Save-Checkpoint
}

function Create-OrVerifyResources {
    foreach ($profile in $Portfolios) {
        $existing = Get-ContainerJson $profile.ContainerName
        if ($null -ne $existing) {
            $saved = $Checkpoint.resources.PSObject.Properties[$profile.Profile]
            $expected = if ($null -ne $saved) { [string]$saved.Value.container_id } else { '' }
            if ($expected) { $profile | Add-Member -NotePropertyName ContainerId -NotePropertyValue $expected -Force }
            $validated = Assert-ContainerIdentity -Profile $profile -ExpectedId $expected -RequireRunning
            if (-not $expected) { Save-ResourceProfile $profile }
            continue
        }

        $volumeCheck = Invoke-Docker -Arguments @('volume','inspect',$profile.Volume) -AllowFailure
        if ($volumeCheck.ExitCode -eq 0) {
            $volumeRows = @($volumeCheck.Stdout | ConvertFrom-Json -ErrorAction Stop)
            $volumeLabels = $volumeRows[0].Labels
            if ($volumeLabels.'com.gade.preexp.managed' -cne 'true' -or
                $volumeLabels.'com.gade.preexp.run_id' -cne $RunId -or
                $volumeLabels.'com.gade.preexp.profile' -cne $profile.Profile) {
                throw "Existing volume ownership labels mismatch for $($profile.Profile)."
            }
        } else {
            Assert-ResourceNameUnused -Name $profile.Volume -Kind volume
            $createVolume = Invoke-Docker -Arguments @(
                'volume','create','--label','com.gade.preexp.managed=true',
                '--label',"com.gade.preexp.run_id=$RunId",'--label',"com.gade.preexp.profile=$($profile.Profile)",
                $profile.Volume
            )
            if ($createVolume.Stdout.Trim() -cne $profile.Volume) { throw "Docker did not create the expected volume $($profile.Volume)." }
            Write-RunRecord "RESOURCE_CREATED type=volume name=$($profile.Volume) run_id=$RunId profile=$($profile.Profile)"
        }
        Save-ResourceProfile $profile

        $random = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random) } finally { $rng.Dispose() }
        $password = [Convert]::ToBase64String($random)
        $environment = @{ POSTGRES_PASSWORD = $password }
        try {
            $start = Invoke-Process -FileName $DockerExe -Arguments @(
                'run','-d','--name',$profile.ContainerName,
                '--label','com.gade.preexp.managed=true',
                '--label',"com.gade.preexp.run_id=$RunId",'--label',"com.gade.preexp.profile=$($profile.Profile)",
                '--publish',"127.0.0.1:$($profile.Port):5432",
                '--mount',"type=volume,source=$($profile.Volume),target=/var/lib/postgresql/data",
                '--env',"POSTGRES_DB=$($profile.Database)",'--env',"POSTGRES_USER=$($profile.User)",
                '--env','POSTGRES_PASSWORD','postgres:16'
            ) -Environment $environment
        } finally {
            $password = $null
            [Array]::Clear($random,0,$random.Length)
            $environment.Clear()
        }
        if ($start.ExitCode -ne 0) { throw "Could not create $($profile.Profile) container: $($start.Stderr)" }
        $containerId = $start.Stdout.Trim()
        if ($containerId -notmatch '^[0-9a-fA-F]{64}$') { throw "Docker returned an invalid full container ID for $($profile.Profile)." }
        $profile | Add-Member -NotePropertyName ContainerId -NotePropertyValue $containerId.ToLowerInvariant() -Force
        Save-ResourceProfile $profile
        Write-RunRecord "RESOURCE_CREATED type=container name=$($profile.ContainerName) id=$($profile.ContainerId) image=postgres:16 host=127.0.0.1:$($profile.Port) database=$($profile.Database) volume=$($profile.Volume)"

        $ready = $false
        for ($attempt = 0; $attempt -lt 45; $attempt++) {
            $probe = Invoke-Docker -Arguments @('exec',$profile.ContainerId,'pg_isready','-U',$profile.User,'-d',$profile.Database) -AllowFailure
            if ($probe.ExitCode -eq 0) { $ready = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $ready) { throw "PostgreSQL did not become ready in $($profile.Profile); preserve this run's resources and log." }
        [void](Assert-ContainerIdentity -Profile $profile -ExpectedId $profile.ContainerId -RequireRunning)
        $identity = Assert-DatabaseIdentity $profile
        Assert-EmptyDatabase $profile
        Write-Host "DATABASE_PREFLIGHT=PASS profile=$($profile.Profile) database=$($identity.database) user=$($identity.user) configured_port=$($identity.configured_port) inet_server_port=$($identity.inet_server_port) schema=empty"
        Save-ResourceProfile $profile
    }
    return @($Portfolios | ForEach-Object { [pscustomobject]@{ profile=$_.Profile; container_id=$_.ContainerId; database=$_.Database; port=$_.Port; volume=$_.Volume } })
}

function Find-MigrationLog {
    param([Parameter(Mandatory = $true)]$Profile,
          [Parameter(Mandatory = $true)][string]$Mode,
          [Parameter(Mandatory = $true)][DateTime]$StartedAt)
    $files = @(Get-ChildItem -LiteralPath $LogDirectory -File -Filter '*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $StartedAt.AddSeconds(-2) } | Sort-Object LastWriteTime -Descending)
    foreach ($file in $files) {
        $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
        $expectedStart = "RUN_START mode=$Mode container=$($Profile.ContainerName) container_id=$($Profile.ContainerId) image=postgres:16 endpoint=127.0.0.1:$($Profile.Port) database=$($Profile.Database) user=$($Profile.User)"
        if ($content.Contains($expectedStart) -and $content.Contains("RUN_PASS mode=$Mode")) { return $file.FullName }
    }
    throw "Could not find a successful $Mode migration log for the exact container $($Profile.ContainerId)."
}

function Invoke-MigrationStage {
    param([Parameter(Mandatory = $true)]$Profile)
    $mode = $Profile.Mode
    $arguments = @{
        Mode=$mode; ExpectedContainerId=$Profile.ContainerId; ContainerName=$Profile.ContainerName
        HostPort=[int]$Profile.Port; DatabaseName=$Profile.Database; DatabaseUser=$Profile.User
    }
    Write-Host "RUNNER_PREFLIGHT profile=$($Profile.Profile) mode=$mode container_id=$($Profile.ContainerId)"
    & $Runner @arguments -PreflightOnly
    $startedAt = Get-Date
    Write-Host "RUNNER_APPLY profile=$($Profile.Profile) mode=$mode; orchestrator authorization already recorded"
    & $Runner @arguments -Apply
    $sourceLog = Find-MigrationLog -Profile $Profile -Mode $mode -StartedAt $startedAt
    $safeName = "migration-$($Profile.Profile).log"
    $destination = Join-Path $RunDirectory $safeName
    Copy-Item -LiteralPath $sourceLog -Destination $destination -Force
    $hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    $profileObject = [pscustomobject]@{ profile=$Profile.Profile; mode=$mode; container_id=$Profile.ContainerId; source_log=$sourceLog; saved_log=$destination; sha256=$hash }
    Set-CheckpointProperty -Object $Checkpoint.outputs -Name ("migration_{0}" -f $Profile.Profile) -Value $profileObject
    Save-Checkpoint
    return $profileObject
}

function Export-DatabaseSchema {
    $evidence = @()
    foreach ($profile in $Portfolios) {
        [void](Assert-ContainerIdentity -Profile $profile -ExpectedId $profile.ContainerId -RequireRunning)
        $identity = Assert-DatabaseIdentity $profile
        $schemaPath = Join-Path $RunDirectory ("schema-{0}.sql" -f $profile.Profile)
        $dump = Invoke-Docker -Arguments @('exec',$profile.ContainerId,'pg_dump','--schema-only','--no-owner','--no-privileges','-U',$profile.User,'-d',$profile.Database) -AllowFailure
        if ($dump.ExitCode -ne 0) { throw "Schema dump failed for $($profile.Profile): $($dump.Stderr)" }
        [System.IO.File]::WriteAllText($schemaPath,$dump.Stdout,(New-Object System.Text.UTF8Encoding($false)))
        $schemaHash = (Get-FileHash -LiteralPath $schemaPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $identityPath = Join-Path $RunDirectory ("identity-{0}.json" -f $profile.Profile)
        $identityRecord = [pscustomobject]@{
            run_id=$RunId; profile=$profile.Profile; container_name=$profile.ContainerName; container_id=$profile.ContainerId
            image='postgres:16'; host_ip='127.0.0.1'; host_port=[int]$profile.Port; database=$identity.database
            user=$identity.user; server_configured_port=$identity.configured_port; inet_server_port=$identity.inet_server_port
            schema_file=(Split-Path -Leaf $schemaPath); schema_sha256=$schemaHash; recorded_at=[DateTimeOffset]::Now.ToString('o')
        }
        [System.IO.File]::WriteAllText($identityPath,(ConvertTo-Json $identityRecord -Depth 10),(New-Object System.Text.UTF8Encoding($false)))
        $evidence += [pscustomobject]@{ profile=$profile.Profile; schema_file=$schemaPath; schema_sha256=$schemaHash; identity_file=$identityPath }
    }
    return ,$evidence
}

function Invoke-AppSmokeStage {
    $profile = Get-Profile 'fresh'
    $migration = $Checkpoint.outputs.PSObject.Properties['migration_fresh'].Value
    if ($null -eq $migration -or -not (Test-Path -LiteralPath $migration.saved_log -PathType Leaf)) { throw 'Fresh migration log is missing for application smoke.' }
    $started = Get-Date
    & $AppSmoke -ExpectedContainerId $profile.ContainerId -MigrationRunLog $migration.source_log `
        -ContainerName $profile.ContainerName -HostPort ([int]$profile.Port) -DatabaseName $profile.Database -DatabaseUser $profile.User
    $files = @(Get-ChildItem -LiteralPath $LogDirectory -File -Filter 'app-smoke-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $started.AddSeconds(-2) } | Sort-Object LastWriteTime -Descending)
    $successLog = $null
    foreach ($file in $files) {
        $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
        if ($content.Contains("RUN_START container=$($profile.ContainerName) container_id=$($profile.ContainerId)") -and $content.Contains('RUN_PASS')) {
            $successLog = $file; break
        }
    }
    if ($null -eq $successLog) { throw 'Could not find a successful application smoke log for the exact fresh container.' }
    $savedPath = Join-Path $RunDirectory 'application-smoke.log'
    Copy-Item -LiteralPath $successLog.FullName -Destination $savedPath -Force
    return [pscustomobject]@{ source_log=$successLog.FullName; saved_log=$savedPath; sha256=(Get-FileHash -LiteralPath $savedPath -Algorithm SHA256).Hash.ToLowerInvariant() }
}

function Invoke-BackendRegression {
    $profile = Get-Profile 'fresh'
    $container = Assert-ContainerIdentity -Profile $profile -ExpectedId $profile.ContainerId -RequireRunning
    $environmentRows = @($container.Config.Env | Where-Object { $_.StartsWith('POSTGRES_PASSWORD=',[StringComparison]::Ordinal) })
    if ($environmentRows.Count -ne 1) { throw 'Scratch password is missing or ambiguous; no regression was run.' }
    $password = $environmentRows[0].Substring('POSTGRES_PASSWORD='.Length)
    $escaped = [System.Uri]::EscapeDataString($password)
    $databaseUrl = "postgresql+asyncpg://$($profile.User):$escaped@127.0.0.1:$($profile.Port)/$($profile.Database)"
    $traceEnv = Join-Path $env:TEMP ('gade-postgres-trace-' + $RunId + '.env')
    $traceOutput = Join-Path $RunDirectory 'postgres-trace-evidence.json'
    $envText = "DATABASE_URL=$databaseUrl`n"
    [System.IO.File]::WriteAllText($traceEnv,$envText,(New-Object System.Text.UTF8Encoding($false)))
    $baseTemp = Join-Path $env:TEMP ('pytest-gade-' + $RunId)
    New-Item -ItemType Directory -Path $baseTemp -Force | Out-Null
    $environment = @{
        DATABASE_URL=$databaseUrl; GADE_TRACE_TEST_ENV_FILE=$traceEnv; GADE_TRACE_OUTPUT=$traceOutput
        PYTHONDONTWRITEBYTECODE='1'
    }
    $result = $null
    try {
        $result = Invoke-Process -FileName $Python -Arguments @('-m','pytest','-q','--basetemp',$baseTemp) -WorkingDirectory $RepoRoot -Environment $environment
    } finally {
        [System.IO.File]::WriteAllText($traceEnv,'DATABASE_URL=[REDACTED]' + "`n",(New-Object System.Text.UTF8Encoding($false)))
        Remove-Item -LiteralPath $traceEnv -Force -ErrorAction SilentlyContinue
        $password = $null; $databaseUrl = $null; $escaped = $null
        $environment.Clear()
    }
    $regressionLog = Join-Path $RunDirectory 'backend-regression.log'
    $joined = ($result.Stdout + "`r`n--- STDERR ---`r`n" + $result.Stderr).Trim()
    [System.IO.File]::WriteAllText($regressionLog,$joined,(New-Object System.Text.UTF8Encoding($false)))
    Write-Host $result.Stdout
    if ($result.ExitCode -ne 0) { throw "Backend regression failed (exit $($result.ExitCode)); see $regressionLog" }
    if (-not (Test-Path -LiteralPath $traceOutput -PathType Leaf)) { throw 'PostgreSQL transaction-local trace test did not emit its evidence JSON.' }
    $traceHash = (Get-FileHash -LiteralPath $traceOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    return [pscustomobject]@{
        log=$regressionLog; log_sha256=(Get-FileHash -LiteralPath $regressionLog -Algorithm SHA256).Hash.ToLowerInvariant()
        trace_evidence=$traceOutput; trace_sha256=$traceHash
    }
}

function Invoke-FrontendBuild {
    $npm = (Get-Command npm.cmd -ErrorAction Stop).Source
    $result = Invoke-Process -FileName $npm -Arguments @('--prefix','frontend','run','build') -WorkingDirectory $RepoRoot
    $logPath = Join-Path $RunDirectory 'frontend-build.log'
    $joined = ($result.Stdout + "`r`n--- STDERR ---`r`n" + $result.Stderr).Trim()
    [System.IO.File]::WriteAllText($logPath,$joined,(New-Object System.Text.UTF8Encoding($false)))
    Write-Host $result.Stdout
    if ($result.ExitCode -ne 0) { throw "Frontend production build failed (exit $($result.ExitCode)); see $logPath" }
    return [pscustomobject]@{ log=$logPath; sha256=(Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLowerInvariant() }
}

function Assert-HistoricalExperimentsUnchanged($Before) {
    $after = Get-HistoricalExperimentHashes
    if ((ConvertTo-Json -InputObject $Before -Depth 10 -Compress) -cne (ConvertTo-Json -InputObject $after -Depth 10 -Compress)) {
        throw 'Tracked historical experiment files changed during host validation.'
    }
    return $after
}

function New-BaselineCommitAndTag {
    Assert-GitScope
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $gitDiffCheck = Invoke-CheckedProcess -FileName $git -Arguments @('diff','--check') -Label 'git diff --check'
    $existingTag = Invoke-Process -FileName $git -Arguments @('rev-parse','-q','--verify',"refs/tags/$TagName")
    if ($existingTag.ExitCode -eq 0) { throw "Local tag $TagName already exists; refusing to replace it." }
    $before = [string]$Checkpoint.repository_head_before
    $headNow = (Invoke-CheckedProcess -FileName $git -Arguments @('rev-parse','HEAD') -Label 'current baseline SHA').Stdout.Trim()
    $status = Invoke-CheckedProcess -FileName $git -Arguments @('status','--porcelain=v1','--untracked-files=all') -Label 'post-commit git status'
    $commit = $null
    $actual = @()
    if ([string]::IsNullOrWhiteSpace($status.Stdout) -and $headNow -cne $before) {
        $parent = (Invoke-CheckedProcess -FileName $git -Arguments @('rev-parse','HEAD^') -Label 'baseline commit parent').Stdout.Trim()
        $subject = (Invoke-CheckedProcess -FileName $git -Arguments @('log','-1','--format=%s') -Label 'baseline commit subject').Stdout.Trim()
        if ($parent -cne $before -or $subject -cne 'fix(db): gate normalized data backfill by legacy schema') {
            throw 'Repository head changed unexpectedly before local baseline tag creation.'
        }
        $sha = $headNow
        $commit = [pscustomobject]@{ Stdout='Recovered previously created baseline commit after interruption.' }
    } else {
        $stagedPaths = @($AllowedGitPaths | Sort-Object -Unique)
        $addArgs = @('add','--') + $stagedPaths
        [void](Invoke-CheckedProcess -FileName $git -Arguments $addArgs -Label 'git add allowlisted files')
        [void](Invoke-CheckedProcess -FileName $git -Arguments @('diff','--cached','--check') -Label 'git diff --cached --check')
        $staged = Invoke-CheckedProcess -FileName $git -Arguments @('diff','--cached','--name-only') -Label 'git staged-path review'
        $actual = @($staged.Stdout -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $_ -replace '\\','/' })
        $unexpected = @($actual | Where-Object { $AllowedGitPaths -cnotcontains $_ })
        if ($unexpected.Count -gt 0) { throw "Unexpected staged paths; no commit created: $($unexpected -join ', ')" }
        if ($actual.Count -eq 0) { throw 'No authorized source files are staged; cannot create a new baseline.' }
        $commit = Invoke-CheckedProcess -FileName $git -Arguments @('commit','-m','fix(db): gate normalized data backfill by legacy schema') -Label 'baseline commit'
        $sha = (Invoke-CheckedProcess -FileName $git -Arguments @('rev-parse','HEAD') -Label 'new baseline SHA').Stdout.Trim()
        Set-CheckpointProperty -Object $Checkpoint -Name 'baseline' -Value ([pscustomobject]@{
            commit_sha=$sha; tag=$null; tag_commit_sha=$null; staged_paths=$actual; commit_output=$commit.Stdout.Trim()
        })
        Save-Checkpoint
    }
    $status = Invoke-CheckedProcess -FileName $git -Arguments @('status','--porcelain=v1','--untracked-files=all') -Label 'post-commit git status'
    if (-not [string]::IsNullOrWhiteSpace($status.Stdout)) { throw "Worktree is not clean after baseline commit: $($status.Stdout)" }
    [void](Invoke-CheckedProcess -FileName $git -Arguments @('tag','-a',$TagName,'-m',"GADE pre-experiment baseline $sha") -Label 'annotated local baseline tag')
    $tagSha = (Invoke-CheckedProcess -FileName $git -Arguments @('rev-parse',"refs/tags/$TagName^{commit}") -Label 'tag target check').Stdout.Trim()
    if ($tagSha -cne $sha) { throw "Annotated tag $TagName does not point to the new baseline commit." }
    $gitEvidence = [pscustomobject]@{ commit_sha=$sha; tag=$TagName; tag_commit_sha=$tagSha; staged_paths=$actual; commit_output=$commit.Stdout.Trim() }
    Set-CheckpointProperty -Object $Checkpoint -Name 'baseline' -Value $gitEvidence
    Save-Checkpoint
    $baselinePath = Join-Path $RunDirectory 'baseline.json'
    [System.IO.File]::WriteAllText($baselinePath,(ConvertTo-Json $gitEvidence -Depth 10),(New-Object System.Text.UTF8Encoding($false)))
    return $gitEvidence
}

function Write-BlockerPacket {
    param([string]$Observed,[string]$PhaseName=$CurrentPhase)
    $resumeSafety = 'NO_PARTIAL_DATABASE_WRITE_RECORDED'
    if ($null -ne $Checkpoint) {
        foreach ($stageProperty in $Checkpoint.stages.PSObject.Properties) {
            if ($stageProperty.Value.status -in @('RUNNING','FAIL') -and $stageProperty.Value.kind -in @('database','app-smoke')) {
                $resumeSafety = 'UNSAFE_TO_RESUME_PARTIAL_DATABASE_WRITE'
                break
            }
        }
    }
    return New-GadeBlockerPacket -Checkpoint $Checkpoint -RunId $RunId -PhaseName $PhaseName -Observed $Observed `
        -CheckpointPath (Join-Path $RunDirectory 'checkpoint.json') -Path (Join-Path $RunDirectory 'BLOCKER_PACKET.md') `
        -ResumeSafety $resumeSafety
}


try {
    if ($PreflightOnly -and $Resume) { throw 'PreflightOnly and Resume cannot be used together.' }
    if ($Resume -and -not $RunId) { throw 'Resume requires the exact 12-hex RunId printed by a previous run.' }
    if (-not $RunId) { $RunId = [Guid]::NewGuid().ToString('N').Substring(0,12).ToLowerInvariant() }
    if ($RunId -notmatch '^[0-9a-f]{12}$') { throw 'RunId must be exactly 12 lowercase hexadecimal characters.' }

    $CheckpointPath = Join-Path (Join-Path $RunRoot $RunId) 'checkpoint.json'
    if ($Resume) {
        if (-not (Test-Path -LiteralPath $CheckpointPath -PathType Leaf)) { throw "Checkpoint does not exist: $CheckpointPath" }
        $RunDirectory = Split-Path -Parent $CheckpointPath
        try { $loadedCheckpoint = Get-Content -LiteralPath $CheckpointPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Checkpoint JSON is corrupt or unreadable; refusing Resume without modifying it: $($_.Exception.Message)" }
        $Checkpoint = Assert-GadeHostCheckpointResumeSafe -Checkpoint $loadedCheckpoint -ExpectedRunId $RunId
        $Portfolios = @($Checkpoint.planned_resources | ForEach-Object {
            $saved = $_
            $mode = switch ($saved.profile) { 'fresh' { 'Migrations' } 'legacy025' { 'LegacyColumn' } 'legacy' { 'Legacy' } }
            $resource = $Checkpoint.resources.PSObject.Properties[[string]$saved.profile]
            $containerId = if ($null -ne $resource) { [string]$resource.Value.container_id } else { '' }
            [pscustomobject]@{
                Profile=[string]$saved.profile; Mode=$mode; ContainerName=[string]$saved.container_name
                ContainerId=$containerId; Port=[int]$saved.host_port
                Database=[string]$saved.database; User=[string]$saved.user; Volume=[string]$saved.volume; HostIp='127.0.0.1'
            }
        } | Sort-Object { @('legacy025','fresh','legacy').IndexOf($_.Profile) })
        if ($Portfolios.Count -ne 3) { throw 'Checkpoint does not contain exactly three independent test databases.' }
        $RunDirectory = Join-Path $RunRoot $RunId
        $script:SourceManifest = Get-SourceManifest
        $expectedFingerprint = ConvertTo-Json -InputObject $Checkpoint.source_manifest -Depth 10 -Compress
        $currentFingerprint = ConvertTo-Json -InputObject $script:SourceManifest -Depth 10 -Compress
        if ($expectedFingerprint -cne $currentFingerprint) {
            throw 'Source SHA-256 manifest changed since this checkpoint. Start a new RunId; previous evidence remains preserved.'
        }
        $resourceStage = $Checkpoint.stages.PSObject.Properties['Create and verify isolated PostgreSQL resources']
        if ($null -ne $resourceStage -and $resourceStage.Value.status -eq 'PASS') {
            foreach ($profile in $Portfolios) { [void](Assert-ContainerIdentity -Profile $profile -ExpectedId $profile.ContainerId -RequireRunning) }
        }
        Write-Host "RESUME=PASS run_id=$RunId checkpoint=$CheckpointPath; passed stages will be skipped."
    } else {
        if ($PreflightOnly -and -not $RunId) { throw 'Internal RunId generation failed.' }
        $RunDirectory = Join-Path $RunRoot $RunId
        if (Test-Path -LiteralPath $RunDirectory) { throw "Run directory already exists; use -Resume -RunId $RunId or select a new RunId." }
        $script:SourceManifest = Get-SourceManifest
        Assert-GitScope
        $head = Get-HeadSha
        $firstPort = $PortMinimum + ([Convert]::ToInt32($RunId.Substring(0,3),16) % 560)
        if (($firstPort + 2) -gt $PortMaximum) { throw 'Deterministic host port allocation exceeded the allowlist.' }
        $Portfolios = @(Get-RunProfiles -SelectedRunId $RunId -FirstPort $firstPort)
        $hostEnvironment = Test-HostPreflight
        if ($PreflightOnly) { Write-Plan; return }
        Write-Plan
        $confirmation = Read-Host 'Confirm the listed resources and complete host validation by typing exactly RUN-GADE-PREEXP-VALIDATION'
        if ($confirmation -cne 'RUN-GADE-PREEXP-VALIDATION') { Write-Host 'CANCELLED; no resource or database operation was performed.'; return }

        New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
        $scenarioCopy = Join-Path $RunDirectory 'boundary_scenarios_v1.json'
        Copy-Item -LiteralPath (Join-Path $RepoRoot 'experiments\data\boundary_scenarios_v1.json') -Destination $scenarioCopy
        $history = Get-HistoricalExperimentHashes
        $Checkpoint = [pscustomobject]@{
            schema_version=1; run_id=$RunId; status='RUNNING'; current_phase='PRE_RESOURCE_SETUP'
            created_at=[DateTimeOffset]::Now.ToString('o'); updated_at=[DateTimeOffset]::Now.ToString('o')
            repository_head_before=$head; source_manifest=$script:SourceManifest; host_environment=$hostEnvironment
            planned_resources=@($Portfolios | ForEach-Object { [pscustomobject]@{
                profile=$_.Profile; container_name=$_.ContainerName; host_port=[int]$_.Port
                database=$_.Database; user=$_.User; volume=$_.Volume
            } }); resources=[pscustomobject]@{}
            stages=[pscustomobject]@{}; outputs=[pscustomobject]@{}; historical_experiment_hashes=$history
            baseline=$null; blocker=$null
            experiment_inputs=[pscustomobject]@{
                scenario_dataset_path='experiments/data/boundary_scenarios_v1.json'
                scenario_dataset_sha256=(Get-FileHash -LiteralPath $scenarioCopy -Algorithm SHA256).Hash.ToLowerInvariant()
                code_manifest_sha256=(Get-StringSha256 (ConvertTo-Json -InputObject $script:SourceManifest -Depth 10 -Compress))
                oracle_version='boundary-scenarios-v1; readiness-validator-v1'
                migration_025_before='9797c8c0394fcc7504da4b65136028c72b458d8b2ed64129fa748b6377b88536'
                migration_025_after=$Patched025Hash
                authorization_policy_version='m2a-attack-depth-v1'
                provider_result='not_called_before_safe_harness_gate'
            }
            experiment_outputs=[pscustomobject]@{}
        }
        $CheckpointPath = Join-Path $RunDirectory 'checkpoint.json'
        foreach ($profile in $Portfolios) { Save-ResourceProfile $profile }
        Save-Checkpoint
        Write-RunRecord "HOST_VALIDATION_START run_id=$RunId repository_head=$head source_files=$($script:SourceManifest.Count)"
    }

    if ($Resume) {
        $failedDestructive = @($Checkpoint.stages.PSObject.Properties | Where-Object {
            $_.Value.status -in @('RUNNING','FAIL') -and $_.Value.kind -in @('database','app-smoke')
        })
        if ($failedDestructive.Count -gt 0) {
            throw "Checkpoint has an interrupted or failed database-writing stage '$($failedDestructive[0].Name)'. Preserve this run and use a new RunId for a fresh isolated database."
        }
    }

    [void](Invoke-CheckpointedStage -Name 'Create and verify isolated PostgreSQL resources' -Kind 'resource-create' -Action {
        Create-OrVerifyResources
    })

    [void](Invoke-CheckpointedStage -Name 'Migration 025 legacy-column compatibility' -Kind 'database' -Action {
        $p = Get-Profile 'legacy025'; Invoke-MigrationStage $p
    })
    [void](Invoke-CheckpointedStage -Name 'Fresh schema migrations 001-037' -Kind 'database' -Action {
        $p = Get-Profile 'fresh'; Invoke-MigrationStage $p
    })
    [void](Invoke-CheckpointedStage -Name 'Legacy 033-037 compatibility' -Kind 'database' -Action {
        $p = Get-Profile 'legacy'; Invoke-MigrationStage $p
    })
    [void](Invoke-CheckpointedStage -Name 'Schema constraints and ORM evidence' -Kind 'read-only' -Action {
        Export-DatabaseSchema
    })
    [void](Invoke-CheckpointedStage -Name 'Backend application smoke' -Kind 'app-smoke' -Action {
        Invoke-AppSmokeStage
    })
    [void](Invoke-CheckpointedStage -Name 'Backend regression with PostgreSQL trace integration' -Kind 'regression' -Action {
        Invoke-BackendRegression
    })
    [void](Invoke-CheckpointedStage -Name 'Frontend production build' -Kind 'build' -Action {
        Invoke-FrontendBuild
    })
    [void](Invoke-CheckpointedStage -Name 'Clean Git baseline and annotated local tag' -Kind 'git-baseline' -Action {
        $after = Assert-HistoricalExperimentsUnchanged -Before $Checkpoint.historical_experiment_hashes
        $historyPath = Join-Path $RunDirectory 'historical-experiment-hashes-after.json'
        [System.IO.File]::WriteAllText($historyPath,(ConvertTo-Json $after -Depth 10),(New-Object System.Text.UTF8Encoding($false)))
        New-BaselineCommitAndTag
    })

    Write-Host 'HOST_VALIDATION_STATUS=POSTGRESQL_BASELINE_READY; seven-level Worker and LLM experiments are outside this run.'
} catch {
    $originalRunError = $_
    $errorMessage = $_.Exception.Message
    if ($null -ne $Checkpoint -and $null -ne $RunDirectory -and (Test-Path -LiteralPath $RunDirectory -PathType Container)) {
        $resumeSafety = 'NO_PARTIAL_DATABASE_WRITE_RECORDED'
        try {
            foreach ($stageProperty in $Checkpoint.stages.PSObject.Properties) {
                if ($stageProperty.Value.status -in @('RUNNING','FAIL') -and $stageProperty.Value.kind -in @('database','app-smoke')) {
                    $resumeSafety = 'UNSAFE_TO_RESUME_PARTIAL_DATABASE_WRITE'
                    break
                }
            }
        } catch { $resumeSafety = 'NOT_ASSESSED_CHECKPOINT_SCHEMA_ERROR' }
        $failureArtifacts = Save-GadeHostFailureArtifacts -Checkpoint $Checkpoint -RunId $RunId `
            -PhaseName $CurrentPhase -Observed $originalRunError.ToString() -RunDirectory $RunDirectory `
            -CheckpointPath $CheckpointPath -ResumeSafety $resumeSafety
        if ($null -ne $failureArtifacts.packet) { Write-Host "BLOCKER_PACKET=$($failureArtifacts.packet.path)" }
        if ($failureArtifacts.write_failure) { Write-Host "CHECKPOINT_OR_BLOCKER_WRITE_FAILURE=$($failureArtifacts.write_failure)" }
        if ($failureArtifacts.fallback_path) { Write-Host "BLOCKER_FALLBACK=$($failureArtifacts.fallback_path)" }
        Write-Host "RESUME_CHECKPOINT=$CheckpointPath"
    }
    Write-Error -Message $errorMessage -ErrorAction Continue
    throw $originalRunError
}
