[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$MigrationRunner = Join-Path $PSScriptRoot 'Invoke-MigrationSmoke.ps1'
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$IntegrationTest = Join-Path $RepoRoot 'tests\test_learning_feedback_postgresql.py'
$EvidenceRoot = Join-Path $RepoRoot 'experiments\gade-seven-level-v1\real-worker-l1\local-only\learning-feedback'
$Docker = $null

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
        [hashtable]$Environment = @{}
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $FileName
    $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($key in $Environment.Keys) { $start.EnvironmentVariables[[string]$key] = [string]$Environment[$key] }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdoutTask.GetAwaiter().GetResult()
            Stderr = $stderrTask.GetAwaiter().GetResult()
        }
    } finally { $process.Dispose() }
}

function Invoke-DockerRead([string[]]$Arguments, [switch]$AllowFailure) {
    $result = Invoke-Process -FileName $Docker -Arguments $Arguments
    if (-not $AllowFailure -and $result.ExitCode -ne 0) {
        throw "docker $($Arguments[0]) failed (exit $($result.ExitCode)): $(($result.Stderr -replace '[\r\n]+',' ').Trim())"
    }
    return $result
}

function Test-LocalPortAvailable([int]$Port) {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
    try { $listener.Start(); return $true }
    catch { return $false }
    finally { try { $listener.Stop() } catch {} }
}

function Write-JsonAtomic([string]$Path, $Value) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backup = "$Path.$([guid]::NewGuid().ToString('N')).bak"
    $json = $Value | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($temporary, $json, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) {
        # File.Replace requires a valid backup path on Windows PowerShell/.NET Framework.
        # A unique sibling backup keeps the original checkpoint intact if replacement fails.
        [System.IO.File]::Replace($temporary, $Path, $backup, $false)
        if (Test-Path -LiteralPath $backup) { [System.IO.File]::Delete($backup) }
    } else {
        [System.IO.File]::Move($temporary, $Path)
    }
}

$RunId = [guid]::NewGuid().ToString('N').Substring(0,12)
$ContainerName = "gade-preexp-$RunId-fresh"
$VolumeName = "gade_lf_${RunId}_pgdata"
$Database = "gade_${RunId}_fresh"
$PortStart = 25436 + ([Convert]::ToInt32($RunId.Substring(8,4),16) % 564)
$HostPort = $null
$ContainerId = $null
$RunDirectory = Join-Path $EvidenceRoot $RunId
$LogPath = Join-Path $RunDirectory 'host-integration.log'
$CheckpointPath = Join-Path $RunDirectory 'checkpoint.json'
$BlockerPath = Join-Path $RunDirectory 'BLOCKER_PACKET.md'
$Password = $null
$DatabaseUrl = $null
$RunState = 'PREFLIGHT'

try {
    $Docker = (Get-Command docker.exe -ErrorAction Stop).Source
    if (-not (Test-Path -LiteralPath $MigrationRunner -PathType Leaf) -or
        -not (Test-Path -LiteralPath $IntegrationTest -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw 'Migration runner, integration test, or repository Python runtime is missing.'
    }

    $server = Invoke-DockerRead @('version','--format','{{.Server.Version}}')
    if ([string]::IsNullOrWhiteSpace($server.Stdout)) { throw 'Docker Engine Server version is unavailable.' }
    $image = Invoke-DockerRead @('image','inspect','postgres:16','--format','{{.Id}}')
    if ([string]::IsNullOrWhiteSpace($image.Stdout)) { throw 'postgres:16 must already exist locally; this runner will not pull images.' }
    $pythonVersion = Invoke-Process -FileName $Python -Arguments @('--version')
    if ($pythonVersion.ExitCode -ne 0) { throw 'Repository Python runtime preflight failed.' }

    $containerLookup = Invoke-DockerRead @('inspect','--type','container',$ContainerName) -AllowFailure
    if ($containerLookup.ExitCode -eq 0) { throw "Run-scoped container name unexpectedly exists: $ContainerName" }
    $volumeLookup = Invoke-DockerRead @('volume','inspect',$VolumeName) -AllowFailure
    if ($volumeLookup.ExitCode -eq 0) { throw "Run-scoped volume unexpectedly exists: $VolumeName" }
    for ($offset = 0; $offset -lt 564; $offset++) {
        $candidate = 25436 + (($PortStart - 25436 + $offset) % 564)
        if ($candidate -ne 15432 -and (Test-LocalPortAvailable $candidate)) { $HostPort = $candidate; break }
    }
    if ($null -eq $HostPort) { throw 'No free localhost port in the dedicated 25436-25999 test range.' }

    $migrations = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'initdb') -File |
        Where-Object { $_.Name -match '^\d{3}_.+\.sql$' } | Sort-Object Name)
    if ($migrations.Count -ne 37 -or $migrations[0].Name -notlike '001_*' -or $migrations[-1].Name -notlike '037_*') {
        throw "Expected the existing numbered migration chain 001-037; found $($migrations.Count) files."
    }

    New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null
    # Verify checkpoint replacement before asking for confirmation or creating Docker resources.
    $atomicProbe = Join-Path $RunDirectory 'atomic-writer-preflight.json'
    Write-JsonAtomic $atomicProbe ([ordered]@{probe='first'})
    Write-JsonAtomic $atomicProbe ([ordered]@{probe='second'; verified=$true})
    $atomicProbeValue = Get-Content -LiteralPath $atomicProbe -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($atomicProbeValue.probe -ne 'second' -or -not $atomicProbeValue.verified) { throw 'Atomic checkpoint writer preflight returned unexpected content.' }
    Remove-Item -LiteralPath $atomicProbe -Force
    $resources = [ordered]@{
        run_id=$RunId; container=$ContainerName; container_id='not-created'; image='postgres:16'
        image_id=$image.Stdout.Trim(); host='127.0.0.1'; port=$HostPort; volume=$VolumeName
        database=$Database; user=$Database; old_run='2e1a8bda7d8a (must remain untouched)'
        old_container='gade-preexp-2e1a8bda7d8a-fresh (must remain untouched)'
    }
    Write-Host "PREFLIGHT=PASS docker_server=$($server.Stdout.Trim()) python=$($pythonVersion.Stdout.Trim())"
    Write-Host 'PLAN=Create only the following new PostgreSQL 16 container and volume; apply existing SQL migrations 001-037 to its empty database; run focused PostgreSQL 16 feedback/governance tests; preserve logs and evidence. No Worker or L1 action will run.'
    Write-Host ($resources | ConvertTo-Json -Depth 5)
    $trackedSources = @(
        'app/models.py','worker/learning_engine.py','worker/learning_feedback.py',
        'worker/task_poller.py','worker/analysis_pipeline.py',
        'tests/test_learning_feedback.py','tests/test_task_poller_learning_feedback.py','tests/test_cve_pipeline.py',
        'docs/MVP_DEMO_SCRIPT.md','.gitignore',
        'tests/test_learning_feedback_postgresql.py','scripts/Invoke-LearningFeedbackPg16Integration.ps1','scripts/Test-LearningFeedbackPg16AtomicWriter.ps1'
    )
    $sourceHashes = [ordered]@{}
    foreach ($relative in $trackedSources) {
        $sourcePath = Join-Path $RepoRoot $relative
        if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
            $sourceHashes[$relative] = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $migrationHashes = [ordered]@{}
    foreach ($migration in $migrations) {
        $migrationHashes[$migration.Name] = (Get-FileHash -LiteralPath $migration.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $head = Invoke-Process -FileName (Get-Command git.exe -ErrorAction Stop).Source -Arguments @('rev-parse','HEAD')
    if ($head.ExitCode -ne 0) { throw 'Could not read repository Git HEAD.' }
    $manifest = [ordered]@{
        run_id=$RunId; captured_utc=[DateTimeOffset]::UtcNow.ToString('o')
        git_head=$head.Stdout.Trim(); branch=(Invoke-Process -FileName (Get-Command git.exe).Source -Arguments @('branch','--show-current')).Stdout.Trim()
        docker_server=$server.Stdout.Trim(); postgres_image_id=$image.Stdout.Trim(); python_version=$pythonVersion.Stdout.Trim()
        resources=$resources; source_sha256=$sourceHashes; migration_sha256=$migrationHashes
        execution_scope='Database integration only; no Worker dispatch, no real L1 action, no old Run access'
    }
    Write-JsonAtomic (Join-Path $RunDirectory 'manifest.json') $manifest
    Write-Host 'MIGRATIONS_TO_APPLY:'
    $migrations | ForEach-Object { Write-Host "  $($_.Name)" }
    $confirmation = Read-Host 'To create these isolated resources and run the database integration tests, type exactly CREATE-GADE-LF-PG16'
    if ($confirmation -cne 'CREATE-GADE-LF-PG16') { Write-Host 'CANCELLED; no resources were created.'; return }

    $RunState = 'CREATING_RESOURCES'
    Write-JsonAtomic $CheckpointPath ([ordered]@{run_id=$RunId; current_phase=$RunState; status='running'; resources=$resources; updated_utc=[DateTimeOffset]::UtcNow.ToString('o')})
    $labelArgs = @('--label','com.gade.learning-feedback-test=true','--label',"com.gade.learning-feedback-test.run_id=$RunId")
    $volumeResult = Invoke-DockerRead (@('volume','create') + $labelArgs + @($VolumeName))
    if ($volumeResult.Stdout.Trim() -cne $VolumeName) { throw 'Docker returned an unexpected test volume name.' }

    $random = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $Password = [Convert]::ToBase64String($random)
    [Array]::Clear($random,0,$random.Length)
    $dockerEnvironment = @{ POSTGRES_PASSWORD = $Password }
    $run = Invoke-Process -FileName $Docker -Arguments (@(
        'run','-d','--name',$ContainerName) + $labelArgs + @(
        '--publish',"127.0.0.1:$HostPort`:5432",
        '--mount',"type=volume,source=$VolumeName,target=/var/lib/postgresql/data",
        '--env',"POSTGRES_DB=$Database",'--env',"POSTGRES_USER=$Database",'--env','POSTGRES_PASSWORD','postgres:16'
    )) -Environment $dockerEnvironment
    $dockerEnvironment.Clear()
    if ($run.ExitCode -ne 0) { throw "Docker failed creating the run-scoped PostgreSQL container: $($run.Stderr.Trim())" }
    $ContainerId = $run.Stdout.Trim().ToLowerInvariant()
    if ($ContainerId -notmatch '^[0-9a-f]{64}$') { throw 'Docker did not return a complete 64-character container ID.' }
    $resources.container_id = $ContainerId
    $RunState = 'WAITING_FOR_POSTGRES'
    Write-JsonAtomic $CheckpointPath ([ordered]@{run_id=$RunId; current_phase=$RunState; status='running'; resources=$resources; updated_utc=[DateTimeOffset]::UtcNow.ToString('o')})
    $ready = $false
    for ($i=0; $i -lt 60; $i++) {
        $probe = Invoke-DockerRead @('exec',$ContainerId,'pg_isready','-U',$Database,'-d',$Database) -AllowFailure
        if ($probe.ExitCode -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Isolated PostgreSQL 16 did not become ready.' }

    $RunState = 'APPLYING_MIGRATIONS_001_037'
    Write-JsonAtomic $CheckpointPath ([ordered]@{run_id=$RunId; current_phase=$RunState; status='running'; resources=$resources; updated_utc=[DateTimeOffset]::UtcNow.ToString('o')})
    try {
        & $MigrationRunner -Mode Migrations -ExpectedContainerId $ContainerId -ContainerName $ContainerName `
            -HostPort $HostPort -DatabaseName $Database -DatabaseUser $Database -Apply *> $LogPath
    } catch { throw "Fresh isolated database migration stage failed: $($_.Exception.Message)" }
    if (-not (Select-String -LiteralPath $LogPath -SimpleMatch 'RUN_STATUS=PASS (migration smoke only; not formal experiment evidence)' -Quiet)) {
        throw "Migration runner did not record PASS; see $LogPath"
    }

    $RunState = 'POSTGRESQL_16_INTEGRATION_TESTS'
    Write-JsonAtomic $CheckpointPath ([ordered]@{run_id=$RunId; current_phase=$RunState; status='running'; resources=$resources; updated_utc=[DateTimeOffset]::UtcNow.ToString('o')})
    $escapedPassword = [Uri]::EscapeDataString($Password)
    $DatabaseUrl = "postgresql+asyncpg://$Database`:$escapedPassword@127.0.0.1`:$HostPort/$Database"
    $testOutput = Join-Path $RunDirectory 'postgresql-integration-evidence.json'
    $testEnvironment = @{
        DATABASE_URL=$DatabaseUrl
        GADE_LEARNING_FEEDBACK_TEST_DATABASE_URL=$DatabaseUrl
        GADE_LEARNING_FEEDBACK_TEST_OUTPUT=$testOutput
        PYTHONDONTWRITEBYTECODE='1'
    }
    $pytestLog = Join-Path $RunDirectory 'pytest.log'
    $test = Invoke-Process -FileName $Python -Arguments @('-m','pytest','-q',
        'tests/test_learning_feedback_postgresql.py','tests/test_learning_feedback.py',
        'tests/test_task_poller_learning_feedback.py','tests/test_execution_authorization.py') -Environment $testEnvironment
    $safeOutput = ($test.Stdout + "`r`n--- STDERR ---`r`n" + $test.Stderr).Replace($escapedPassword,'[REDACTED]')
    [System.IO.File]::WriteAllText($pytestLog,$safeOutput,(New-Object System.Text.UTF8Encoding($false)))
    $Password = $null; $DatabaseUrl = $null; $escapedPassword = $null; $testEnvironment.Clear()
    if ($test.ExitCode -ne 0) { throw "Focused PostgreSQL integration and regression tests failed (exit $($test.ExitCode)); see $pytestLog" }
    if (-not (Test-Path -LiteralPath $testOutput -PathType Leaf)) { throw 'PostgreSQL integration test did not create its evidence JSON.' }
    $testEvidence = Get-Content -LiteralPath $testOutput -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    foreach ($property in @('feedback_failure_preserved_result','feedback_retry_idempotent','trace_relations_resolved','single_use_grant_rejected','unauthorized_worker_dispatch_blocked')) {
        if (-not $testEvidence.$property) { throw "PostgreSQL evidence is missing PASS assertion '$property'." }
    }
    if ($testEvidence.worker_receipt_created) { throw 'The database integration test unexpectedly claims to have created a Worker receipt.' }
    $RunState = 'PASS'
    Write-JsonAtomic $CheckpointPath ([ordered]@{run_id=$RunId; current_phase=$RunState; status='PASS'; resources=$resources; evidence=$testOutput; updated_utc=[DateTimeOffset]::UtcNow.ToString('o')})

    # Hash the final PASS checkpoint, not its preceding in-progress version.
    $resultHashes = [ordered]@{}
    foreach ($path in @($testOutput,$pytestLog,$LogPath,$CheckpointPath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $resultHashes[[System.IO.Path]::GetFileName($path)] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    $manifest.result_sha256 = $resultHashes
    Write-JsonAtomic (Join-Path $RunDirectory 'manifest.json') $manifest
    Write-Host "POSTGRESQL_16_INTEGRATION=PASS run_id=$RunId evidence=$testOutput"
    Write-Host "RESOURCES_PRESERVED container=$ContainerName container_id=$ContainerId volume=$VolumeName"
    Write-Host 'REAL_WORKER_EXECUTION=NOT_TESTED (this run tests database persistence and governance guards only).'
} catch {
    $failedPhase = $RunState
    $RunState = 'FAIL'
    $originalError = $_.Exception.Message
    $checkpointError = $null
    $blockerError = $null
    try { New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null } catch {}
    try {
        Write-JsonAtomic $CheckpointPath ([ordered]@{run_id=$RunId; current_phase=$RunState; status='FAIL'; failed_phase=$failedPhase; error=$originalError; resources=[ordered]@{container=$ContainerName; container_id=$ContainerId; volume=$VolumeName; host_port=$HostPort; database=$Database}; updated_utc=[DateTimeOffset]::UtcNow.ToString('o')})
    } catch { $checkpointError = $_.Exception.Message }
    $packet = @"
# LearningFeedback PostgreSQL Integration Blocker

- Run ID: $RunId
- Failed phase: $failedPhase
- Original error: $originalError
- Checkpoint write error: $(if ($checkpointError) { $checkpointError } else { 'none' })
- Container: $ContainerName
- Container ID: $ContainerId
- Database: $Database
- Port: $HostPort
- Log: $LogPath
- Checkpoint: $CheckpointPath

Resources created by this run are preserved. No cleanup, L1 action, or Worker execution was performed by the failure handler.
"@
    try { [System.IO.File]::WriteAllText($BlockerPath,$packet,(New-Object System.Text.UTF8Encoding($false))) }
    catch { $blockerError = $_.Exception.Message }
    if ($checkpointError -or $blockerError) {
        $fallback = @(
            "Run ID: $RunId",
            "Original error: $originalError",
            "Checkpoint write error: $(if ($checkpointError) { $checkpointError } else { 'none' })",
            "Blocker packet write error: $(if ($blockerError) { $blockerError } else { 'none' })",
            "Container: $ContainerName; Container ID: $ContainerId; Volume: $VolumeName; Port: $HostPort; Database: $Database",
            "Run directory: $RunDirectory"
        ) -join [Environment]::NewLine
        try { [System.IO.File]::AppendAllText((Join-Path $RunDirectory 'fallback-diagnostic.txt'), $fallback + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false))) }
        catch { Write-Host "FAILURE_DIAGNOSTIC_FALLBACK original=[$originalError] checkpoint=[$checkpointError] blocker=[$blockerError] run_dir=[$RunDirectory]" }
    }
    throw "PostgreSQL LearningFeedback integration failed: $originalError; checkpoint_write_error=[$checkpointError]; blocker_write_error=[$blockerError]; preserve resources and inspect $RunDirectory"
} finally {
    $Password = $null; $DatabaseUrl = $null
}
