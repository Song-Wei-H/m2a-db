[CmdletBinding()]
param([switch]$PreflightOnly)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$baseline = 'gade-preexp-v1'
$branch = 'experiment/gade-seven-level-v1'
$target = '10.56.66.119'
$targetPort = 18080
$worker = 'http://10.56.64.121:8000'
$runId = [guid]::NewGuid().ToString('N').Substring(0,12)
$correlationId = [guid]::NewGuid().ToString('D').ToLowerInvariant()
$name = "gade-preexp-$runId-fresh" # required by the existing exact-identity migration runner
$database = "gade_${runId}_fresh"
$volume = "gade_l1_${runId}_pgdata"
$output = Join-Path $PSScriptRoot "local-only\$runId"
$migrationRunner = Join-Path $repo 'scripts\Invoke-MigrationSmoke.ps1'
$driver = Join-Path $PSScriptRoot 'run_l1_e2e.py'
$verifier = Join-Path $PSScriptRoot 'verify_legacy_l1_evidence.py'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$port = 0
$phase = 'READ_ONLY_PREFLIGHT'
$manifest = $null

function Assert-Ok([bool]$Condition, [string]$Reason) {
    if (-not $Condition) { throw $Reason }
}
function Run-Docker([string[]]$Arguments) {
    $outputText = & docker.exe @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "Docker command failed (exit $code): $($outputText -join ' ')" }
    return ($outputText -join "`n").Trim()
}
function Save-Json([string]$Path, $Object) {
    $Object | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $Path -Encoding utf8
}

try {
    Push-Location $repo
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $currentBranch = (& git branch --show-current).Trim()
    $head = (& git rev-parse HEAD).Trim()
    $tag = (& git rev-list -n 1 $baseline).Trim()
    Assert-Ok ($LASTEXITCODE -eq 0 -and $tag -match '^[0-9a-f]{40}$') 'Baseline tag missing.'
    Assert-Ok ($tag -ceq '9eaea6a355a07687031e8c43465c17bc5fce1145') 'Frozen baseline tag target changed.'
    Assert-Ok ($currentBranch -ceq $branch) "Wrong branch $currentBranch"
    Assert-Ok (@(& git status --porcelain).Count -eq 0) 'Experiment working tree is not clean.'
    Assert-Ok (Test-Path -LiteralPath $python) 'Repository .venv Python missing.'
    Assert-Ok (Test-Path -LiteralPath $migrationRunner) 'Migration runner missing.'
    $files = @(Get-ChildItem -LiteralPath (Join-Path $repo 'initdb') -Filter '*.sql' -File |
        Where-Object Name -Match '^\d{3}_.+\.sql$' | Sort-Object Name)
    Assert-Ok ($files.Count -eq 37) "Expected 37 numbered migrations, got $($files.Count)."
    for ($i=0; $i -lt 37; $i++) {
        Assert-Ok ($files[$i].Name.Substring(0,3) -ceq ('{0:D3}' -f ($i+1))) 'Migration order/gap detected.'
    }
    $dockerInfo = Run-Docker -Arguments @('info','--format','{{.ServerVersion}}')
    Assert-Ok (-not [string]::IsNullOrWhiteSpace($dockerInfo)) 'Docker Engine unavailable.'
    $lab = @( (Run-Docker -Arguments @('inspect','m2a-mode-b-target') | ConvertFrom-Json) )[0]
    Assert-Ok ($lab.Name -ceq '/m2a-mode-b-target' -and $lab.Config.Image -ceq 'docker/welcome-to-docker:latest' -and
        $lab.State.Running -and $lab.State.Health.Status -ceq 'healthy' -and
        @($lab.NetworkSettings.Networks.PSObject.Properties.Name) -ccontains 'm2a-mode-b-lab') 'Existing Lab container identity or health drift.'
    $bind = @($lab.NetworkSettings.Ports.'8080/tcp')
    Assert-Ok ($bind.Count -eq 1 -and $bind[0].HostIp -ceq $target -and
        $bind[0].HostPort -ceq [string]$targetPort) 'Existing Lab binding mismatch.'
    $localIp = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $target)
    Assert-Ok ($localIp.Count -eq 1) 'Expected Lab host IP is not assigned exactly once.'
    $labResponse = Invoke-WebRequest -Uri "http://${target}:${targetPort}/healthz" -UseBasicParsing -TimeoutSec 5
    Assert-Ok ($labResponse.StatusCode -eq 200 -and $labResponse.Content.Trim() -ceq 'mode-b-target-ready') 'Lab HTTP response drift.'
    $workerHealthResponse = Invoke-WebRequest -Uri "$worker/health" -UseBasicParsing -TimeoutSec 5
    $health = $workerHealthResponse.Content | ConvertFrom-Json
    Assert-Ok ($health.status -ceq 'ok' -and $health.version -ceq 'evidence-tools-v1' -and
        @($health.allowed_tools) -ccontains 'http_security_headers') 'Worker health or tool allowlist mismatch.'
    Assert-Ok (-not ($health.PSObject.Properties.Name -ccontains 'build_sha256')) 'Worker now exposes a build hash; stop and re-audit the API mode instead of assuming legacy behavior.'
    $openApi = Invoke-RestMethod -Uri "$worker/openapi.json" -TimeoutSec 5
    $executePathProperty = $openApi.paths.PSObject.Properties['/execute']
    Assert-Ok ($null -ne $executePathProperty) 'Worker OpenAPI does not expose /execute.'
    $executePost = $executePathProperty.Value.post
    Assert-Ok ($null -ne $executePost) 'Worker OpenAPI does not expose POST /execute.'
    $requestContent = $executePost.requestBody.content.PSObject.Properties['application/json']
    Assert-Ok ($null -ne $requestContent) 'Worker /execute JSON request schema unavailable.'
    $requestSchemaRef = [string]$requestContent.Value.schema.'$ref'
    Assert-Ok ($requestSchemaRef -match '^#/components/schemas/[^/]+$') 'Worker /execute request schema is not a known component.'
    $requestSchemaName = $requestSchemaRef.Split('/')[-1]
    $requestSchemaProperty = $openApi.components.schemas.PSObject.Properties[$requestSchemaName]
    Assert-Ok ($null -ne $requestSchemaProperty) 'Worker /execute request schema component missing.'
    $workerRequestProperties = @($requestSchemaProperty.Value.properties.PSObject.Properties.Name)
    $workerRequiredFields = @($requestSchemaProperty.Value.required)
    foreach ($field in @('tool','target','port','service')) {
        Assert-Ok ($workerRequestProperties -ccontains $field) "Legacy Worker API lacks required fixed field '$field'."
    }
    foreach ($field in $workerRequiredFields) {
        Assert-Ok (@('tool','target','port','service') -ccontains $field) "Legacy Worker API has unsupported required field '$field'."
    }
    foreach ($field in @('request_id','correlation_id','template_id','expected_worker_build_sha256')) {
        Assert-Ok (-not ($workerRequestProperties -ccontains $field)) "Worker API is no longer the observed legacy contract ('$field' is present). Stop for contract review."
    }
    $workerDate = $null
    $labDate = $null
    try { $workerDate = [DateTimeOffset]::Parse([string]$workerHealthResponse.Headers['Date']).ToUniversalTime() } catch { }
    try { $labDate = [DateTimeOffset]::Parse([string]$labResponse.Headers['Date']).ToUniversalTime() } catch { }
    $hostNow = [DateTimeOffset]::UtcNow
    $workerHostSkew = if ($null -ne $workerDate) { [math]::Round(($workerDate - $hostNow).TotalSeconds,3) } else { $null }
    $labHostSkew = if ($null -ne $labDate) { [math]::Round(($labDate - $hostNow).TotalSeconds,3) } else { $null }
    $workerLabSkew = if ($null -ne $workerDate -and $null -ne $labDate) { [math]::Round(($workerDate - $labDate).TotalSeconds,3) } else { $null }
    $targetLogsAvailable = $true
    $targetLogPreflightError = $null
    try { $null = Run-Docker -Arguments @('logs','--tail','1',$lab.Id) }
    catch { $targetLogsAvailable = $false; $targetLogPreflightError = $_.Exception.Message }
    for ($candidate = 25436; $candidate -le 25999; $candidate++) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'),$candidate)
            $listener.Start()
            $port = $candidate
            break
        } catch { } finally { if ($null -ne $listener) { $listener.Stop() } }
    }
    Assert-Ok ($port -ge 25436 -and $port -ne 15432) 'No allowed free scratch port.'
    # An absent object makes `docker inspect` exit nonzero and write stderr.
    # Windows PowerShell can promote that expected stderr to a terminating
    # NativeCommandError under ErrorActionPreference=Stop. List instead, then
    # compare exact returned names; every Docker command must itself succeed.
    $existingContainers = @(Run-Docker -Arguments @('container','ls','-a','--filter',"name=^/$name$",'--format','{{.Names}}') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-Ok ($existingContainers.Count -eq 0) 'Run-scoped container already exists.'
    $existingVolumes = @(Run-Docker -Arguments @('volume','ls','--filter',"name=^$volume$",'--format','{{.Name}}') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-Ok ($existingVolumes.Count -eq 0) 'Run-scoped volume already exists.'
    Write-Host "PREFLIGHT=PASS branch=$currentBranch head=$head baseline=$tag docker=$dockerInfo"
    Write-Host "RUN_ID=$runId EXPERIMENT_CORRELATION_ID=$correlationId"
    Write-Host "EXISTING_LAB=$($lab.Id) endpoint=${target}:${targetPort} healthy=true; WORKER=$worker health=ok version=$($health.version)"
    Write-Host "LEGACY_API=PASS request_fields=$($workerRequestProperties -join ',') native_request_correlation=unavailable native_receipt=unavailable"
    Write-Host "CLOCK_SKEW_SECONDS worker-host=$workerHostSkew lab-host=$labHostSkew worker-lab=$workerLabSkew"
    Write-Host "TARGET_ACCESS_LOGS_PRECHECK=$(if($targetLogsAvailable){'AVAILABLE'}else{'UNAVAILABLE'})"
    Write-Host "NEW_RESOURCE container=$name image=postgres:16 bind=127.0.0.1:${port}:5432 volume=$volume database=$database user=$database"
    Write-Host 'ACTION=http_security_headers.collect.v1 fixed HEAD / User-Agent=M2A-Worker/1; target=10.56.66.119/32 port=18080/TCP; exactly one new ToolTask ID will be executed.'
    Write-Host 'MIGRATIONS=001..037 on the new empty database only; no existing database, container, firewall rule, or batch dispatcher is changed.'
    Write-Host "MIGRATION_FILES=$($files.Name -join ',')"
    Write-Host 'LEGACY_ADAPTER=local-only; sends only tool,target,port,service after local GADE authorization; remote Worker will not be changed.'
    if ($PreflightOnly) {
        Save-Json (Join-Path $output 'preflight.json') ([ordered]@{
            run_id=$runId; experiment_correlation_id=$correlationId; status='PREFLIGHT_ONLY_PASS';
            branch=$currentBranch; head=$head; baseline_tag=$baseline; baseline_commit=$tag;
            container=$name; volume=$volume; database=$database; candidate_port=$port;
            target=$target; target_port=$targetPort; worker=$worker; worker_version=$health.version;
            worker_request_properties=$workerRequestProperties; target_access_logs_available=$targetLogsAvailable;
            clock_check=@{worker_host_skew_seconds=$workerHostSkew;lab_host_skew_seconds=$labHostSkew;worker_lab_skew_seconds=$workerLabSkew}
        })
        Write-Host "PREFLIGHT_ONLY=PASS EVIDENCE=$output"; return
    }
    $answer = Read-Host 'Type exactly RUN-GADE-L1-E2E to create these resources and execute one governed action'
    if ($answer -cne 'RUN-GADE-L1-E2E') { Write-Host 'CANCELLED; no resource created.'; return }

    $phase = 'CREATE_ISOLATED_POSTGRESQL'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $manifest = [ordered]@{run_id=$runId; started_utc=[DateTime]::UtcNow.ToString('o'); branch=$branch;
        experiment_commit=$head; baseline_tag=$baseline; baseline_commit=$tag;
        container=$name; volume=$volume; database=$database; port=$port;
        target=$target; target_port=$targetPort; authorized_scope='10.56.66.119/32'; worker=$worker;
        action='http_security_headers.collect.v1'; worker_version=$health.version;
        worker_api_mode='legacy'; worker_request_properties=$workerRequestProperties;
        worker_build_sha256='not_exposed_by_legacy_health';
        worker_source_sha256_last_readonly='9cc89630fb2af6e38307b3bf55fad5012a9fbfe25a3c2de75c7df3a8cfa4d0f9';
        worker_source_hash_currently_reverified=$false;
        experiment_correlation_id=$correlationId;
        target_access_logs_precheck=$targetLogsAvailable; target_access_log_precheck_error=$targetLogPreflightError;
        clock_check=@{worker_host_skew_seconds=$workerHostSkew;lab_host_skew_seconds=$labHostSkew;worker_lab_skew_seconds=$workerLabSkew};
        policy_version='m2a-attack-depth-v1';
        action_contract_sha256=(Get-FileHash (Join-Path $repo 'app\action_contracts.py') -Algorithm SHA256).Hash.ToLowerInvariant();
        migrations=@($files | ForEach-Object { @{file=$_.Name;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} });
        runner_sha256=(Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();
        driver_sha256=(Get-FileHash $driver -Algorithm SHA256).Hash.ToLowerInvariant();
        status='CREATING_RESOURCES'}
    Save-Json (Join-Path $output 'manifest.json') $manifest
    Run-Docker -Arguments @('volume','create','--label','com.gade.l1.managed=true','--label',"com.gade.l1.run_id=$runId",$volume) | Out-Null
    $password = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $priorPostgresPassword = [Environment]::GetEnvironmentVariable('POSTGRES_PASSWORD', 'Process')
    $env:POSTGRES_PASSWORD = $password
    try {
        $cid = Run-Docker -Arguments @('run','-d','--name',$name,'--label','com.gade.l1.managed=true',
            '--label',"com.gade.l1.run_id=$runId",'--publish',"127.0.0.1:${port}:5432",
            '--mount',"type=volume,source=$volume,target=/var/lib/postgresql/data",
            '--env',"POSTGRES_DB=$database",'--env',"POSTGRES_USER=$database",
            '--env','POSTGRES_PASSWORD','postgres:16')
    } finally { [Environment]::SetEnvironmentVariable('POSTGRES_PASSWORD', $priorPostgresPassword, 'Process') }
    Assert-Ok ($cid -match '^[0-9a-f]{64}$') 'Docker returned invalid full container ID.'
    $manifest['container_id'] = $cid
    Save-Json (Join-Path $output 'manifest.json') $manifest
    $ready = $false
    for ($attempt=0; $attempt -lt 45; $attempt++) {
        $probe = & docker.exe exec $cid pg_isready -U $database -d $database 2>$null
        if ($LASTEXITCODE -eq 0) { $ready=$true; break }
        Start-Sleep -Seconds 1
    }
    Assert-Ok $ready 'New PostgreSQL container did not become ready.'
    $phase = 'MIGRATE_001_037'
    $runnerParams = @{Mode='Migrations';ExpectedContainerId=$cid;ContainerName=$name;
        HostPort=$port;DatabaseName=$database;DatabaseUser=$database}
    & $migrationRunner @runnerParams -PreflightOnly *> (Join-Path $output 'migration-preflight.log')
    & $migrationRunner @runnerParams -HostOrchestratorRunId $runId -Apply *> (Join-Path $output 'migration-001-037.log')
    $migrationText = Get-Content -LiteralPath (Join-Path $output 'migration-001-037.log') -Raw
    Assert-Ok ($migrationText.Contains('RUN_STATUS=PASS')) 'Migration runner did not report PASS.'
    $manifest.status = 'MIGRATIONS_PASS'
    Save-Json (Join-Path $output 'manifest.json') $manifest

    $phase = 'SINGLE_TASK_GOVERNANCE_AND_WORKER'
    $keys = @('DATABASE_URL','ENFORCE_TARGET_SCOPE','ALLOWED_SCOPES','KALI_WORKER_URL',
        'GADE_L1_RUN_ID','GADE_L1_DB_PORT','GADE_L1_OUTPUT','GADE_L1_CORRELATION_ID','M2A_WORKER_API_MODE')
    $priorEnvironment = @{}
    foreach($key in $keys) { $priorEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process') }
    $env:DATABASE_URL = "postgresql+asyncpg://${database}:${password}@127.0.0.1:${port}/${database}"
    $env:ENFORCE_TARGET_SCOPE = 'true'
    $env:ALLOWED_SCOPES = '10.56.66.119/32'
    $env:KALI_WORKER_URL = $worker
    $env:GADE_L1_RUN_ID = $runId
    $env:GADE_L1_DB_PORT = [string]$port
    $env:GADE_L1_OUTPUT = $output
    $env:GADE_L1_CORRELATION_ID = $correlationId
    $env:M2A_WORKER_API_MODE = 'legacy'
    $driverExitCode = $null
    try {
        $driverStdout = Join-Path $output 'driver.stdout.log'
        $driverStderr = Join-Path $output 'driver.stderr.log'
        $driverLog = Join-Path $output 'driver.log'
        $driverProcess = Start-Process -FilePath $python -ArgumentList ('"' + $driver + '"') `
            -WorkingDirectory $repo -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $driverStdout -RedirectStandardError $driverStderr
        $stdoutText = if (Test-Path -LiteralPath $driverStdout) { Get-Content -LiteralPath $driverStdout -Raw } else { '' }
        $stderrText = if (Test-Path -LiteralPath $driverStderr) { Get-Content -LiteralPath $driverStderr -Raw } else { '' }
        @('=== PYTHON STDOUT ===', $stdoutText, '=== PYTHON STDERR / TRACEBACK ===', $stderrText) |
            Set-Content -LiteralPath $driverLog -Encoding utf8
        $driverExitCode = $driverProcess.ExitCode
        $manifest['driver_exit_code'] = $driverExitCode
    } finally {
        foreach($key in $keys) {
            [Environment]::SetEnvironmentVariable($key, $priorEnvironment[$key], 'Process')
        }
        $password = $null
    }
    $state = Get-Content -LiteralPath (Join-Path $output 'e2e-state.json') -Raw | ConvertFrom-Json
    $targetLogPath = Join-Path $output 'target-log-window.raw.log'
    $requestStart = [string]$state.worker_exchange.request_sent_at_utc
    if (-not [string]::IsNullOrWhiteSpace($requestStart)) {
        try {
            Run-Docker -Arguments @('logs','--timestamps','--since',$requestStart,$lab.Id) |
                Set-Content -LiteralPath $targetLogPath -Encoding utf8
        } catch {
            Set-Content -LiteralPath (Join-Path $output 'target-log-capture-error.txt') -Value $_.Exception.Message -Encoding utf8
            Set-Content -LiteralPath $targetLogPath -Value '' -Encoding utf8
        }
    } else {
        Set-Content -LiteralPath $targetLogPath -Value '' -Encoding utf8
    }
    $verifierStdout = Join-Path $output 'verifier.stdout.log'
    $verifierStderr = Join-Path $output 'verifier.stderr.log'
    $verifierLog = Join-Path $output 'verifier.log'
    $verifierArgs = '"' + $verifier + '" --evidence-dir "' + $output + '" --target-log "' + $targetLogPath + '"'
    $verifierProcess = Start-Process -FilePath $python -ArgumentList $verifierArgs -WorkingDirectory $repo `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $verifierStdout -RedirectStandardError $verifierStderr
    @('=== VERIFIER STDOUT ===',(Get-Content -LiteralPath $verifierStdout -Raw),
      '=== VERIFIER STDERR ===',(Get-Content -LiteralPath $verifierStderr -Raw)) |
        Set-Content -LiteralPath $verifierLog -Encoding utf8
    Assert-Ok ($verifierProcess.ExitCode -eq 0) 'Legacy evidence verifier failed; no result grade was assigned.'
    $verdict = Get-Content -LiteralPath (Join-Path $output 'final-verdict.json') -Raw | ConvertFrom-Json
    $manifest.status = $verdict.final_status
    $manifest.evidence_grade = $verdict.evidence_grade
    $manifest.trace_completeness = $verdict.trace_completeness
    $manifest['completed_utc'] = [DateTime]::UtcNow.ToString('o')
    $manifest['evidence_sha256'] = @{}
    foreach($file in Get-ChildItem -LiteralPath $output -File | Where-Object Name -ne 'manifest.json') {
        $manifest.evidence_sha256[$file.Name] = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Save-Json (Join-Path $output 'manifest.json') $manifest
    Write-Host "GOVERNANCE_AUTHORIZATION=$($state.decision.outcome) proposal=$($state.ids.proposal_id) decision=$($state.ids.decision_id) grant=$($state.ids.authorization_id) task=$($state.ids.tool_task_id)"
    Write-Host "WORKER_HTTP_RESULT=$($state.worker_exchange.http_status) app_status=$($state.worker_exchange.application_status) request_id=$($state.request_id) correlation_id=$($state.experiment_correlation_id)"
    Write-Host "NATIVE_WORKER_RECEIPT=$($state.worker_exchange.native_receipt_status) TOOL_RESULT_PERSISTED=$($null -ne $state.tool_result.id) TRACE_COMPLETENESS=$($state.trace.status)"
    Write-Host "FINAL_EVIDENCE_GRADE=$($verdict.evidence_grade) FINAL_STATUS=$($verdict.final_status) EVIDENCE=$output"
} catch {
    if (-not (Test-Path -LiteralPath $output)) { New-Item -ItemType Directory -Path $output -Force | Out-Null }
    if (Test-Path -LiteralPath $output) {
        $requestId = ''
        $statePath = Join-Path $output 'e2e-state.json'
        if (Test-Path -LiteralPath $statePath) {
            try {
                $failureState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                $requestId = [string]$failureState.request_id
                if ([string]::IsNullOrWhiteSpace($requestId) -and $null -ne $failureState.worker_request) {
                    $requestId = [string]$failureState.worker_request.request_id
                }
            } catch { $requestId = 'unavailable; see malformed e2e-state.json' }
        }
        $message = "REAL_WORKER_L1_E2E=FAIL`nRun ID: $runId`nFailed phase: $phase`nRequest ID: $requestId`nError: $($_.Exception.Message)`nResources are preserved; no cleanup or rerun on partial database.`n"
        $driverLogPath = Join-Path $output 'driver.log'
        if (Test-Path -LiteralPath $driverLogPath) {
            $message += "`n## Complete Python driver log`n`n````text`n" +
                (Get-Content -LiteralPath $driverLogPath -Raw) + "`n```` `n"
        }
        try {
            if ($null -eq $manifest) {
                $manifest = [ordered]@{ run_id=$runId; experiment_correlation_id=$correlationId;
                    started_utc=[DateTime]::UtcNow.ToString('o'); branch=$branch; baseline_tag=$baseline;
                    container=$name; volume=$volume; database=$database; candidate_port=$port;
                    target=$target; target_port=$targetPort; worker=$worker; action='http_security_headers.collect.v1' }
            }
            if ($null -ne $manifest) {
                $manifest['status'] = 'FAIL'
                $manifest['failed_phase'] = $phase
                $manifest['failed_utc'] = [DateTime]::UtcNow.ToString('o')
                Save-Json (Join-Path $output 'manifest.json') $manifest
            }
            Set-Content -LiteralPath (Join-Path $output 'preflight-failure.txt') -Value $message -Encoding utf8
            Set-Content -LiteralPath (Join-Path $output 'BLOCKER_PACKET.md') -Value $message -Encoding utf8
            Write-Host "BLOCKER_PACKET=$(Join-Path $output 'BLOCKER_PACKET.md')"
        } catch { Write-Host "BLOCKER_WRITE_FAILURE=$($_.Exception.Message); ORIGINAL_FAILURE=$message" }
    }
    throw
} finally { Pop-Location }
