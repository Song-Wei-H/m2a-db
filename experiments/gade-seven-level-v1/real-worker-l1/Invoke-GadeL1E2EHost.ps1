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
$name = "gade-preexp-$runId-fresh" # required by the existing exact-identity migration runner
$database = "gade_${runId}_fresh"
$volume = "gade_l1_${runId}_pgdata"
$output = Join-Path $PSScriptRoot "local-only\$runId"
$migrationRunner = Join-Path $repo 'scripts\Invoke-MigrationSmoke.ps1'
$driver = Join-Path $PSScriptRoot 'run_l1_e2e.py'
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
    $health = Invoke-RestMethod -Uri "$worker/health" -TimeoutSec 5
    Assert-Ok ($health.status -ceq 'ok' -and $health.version -ceq 'evidence-tools-v1' -and
        @($health.allowed_tools) -ccontains 'http_security_headers') 'Worker health or tool allowlist mismatch.'
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
    $existingContainer = & docker.exe inspect $name 2>$null
    Assert-Ok ($LASTEXITCODE -ne 0) 'Run-scoped container already exists.'
    $existingVolume = & docker.exe volume inspect $volume 2>$null
    Assert-Ok ($LASTEXITCODE -ne 0) 'Run-scoped volume already exists.'
    Write-Host "PREFLIGHT=PASS branch=$currentBranch head=$head baseline=$tag docker=$dockerInfo"
    Write-Host "EXISTING_LAB=$($lab.Id) endpoint=${target}:${targetPort} healthy=true; WORKER=$worker health=ok"
    Write-Host "NEW_RESOURCE container=$name image=postgres:16 bind=127.0.0.1:${port}:5432 volume=$volume database=$database user=$database"
    Write-Host 'ACTION=http_security_headers.collect.v1 fixed HEAD /; target=10.56.66.119/32 port=18080/TCP; exactly one new ToolTask ID will be executed.'
    Write-Host 'MIGRATIONS=001..037 on the new empty database only; no existing database, container, firewall rule, or batch dispatcher is changed.'
    if ($PreflightOnly) { Write-Host 'PREFLIGHT_ONLY=PASS'; return }
    $answer = Read-Host 'Type exactly RUN-GADE-L1-E2E to create these resources and execute one governed action'
    if ($answer -cne 'RUN-GADE-L1-E2E') { Write-Host 'CANCELLED; no resource created.'; return }

    $phase = 'CREATE_ISOLATED_POSTGRESQL'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $manifest = [ordered]@{run_id=$runId; started_utc=[DateTime]::UtcNow.ToString('o'); branch=$branch;
        experiment_commit=$head; baseline_tag=$baseline; baseline_commit=$tag;
        container=$name; volume=$volume; database=$database; port=$port;
        target=$target; target_port=$targetPort; authorized_scope='10.56.66.119/32'; worker=$worker;
        action='http_security_headers.collect.v1'; worker_version=$health.version;
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
    & $migrationRunner @runnerParams -Apply *> (Join-Path $output 'migration-001-037.log')
    $migrationText = Get-Content -LiteralPath (Join-Path $output 'migration-001-037.log') -Raw
    Assert-Ok ($migrationText.Contains('RUN_STATUS=PASS')) 'Migration runner did not report PASS.'
    $manifest.status = 'MIGRATIONS_PASS'
    Save-Json (Join-Path $output 'manifest.json') $manifest

    $phase = 'SINGLE_TASK_GOVERNANCE_AND_WORKER'
    $keys = @('DATABASE_URL','ENFORCE_TARGET_SCOPE','ALLOWED_SCOPES','KALI_WORKER_URL',
        'GADE_L1_RUN_ID','GADE_L1_DB_PORT','GADE_L1_OUTPUT')
    $priorEnvironment = @{}
    foreach($key in $keys) { $priorEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process') }
    $env:DATABASE_URL = "postgresql+asyncpg://${database}:${password}@127.0.0.1:${port}/${database}"
    $env:ENFORCE_TARGET_SCOPE = 'true'
    $env:ALLOWED_SCOPES = '10.56.66.119/32'
    $env:KALI_WORKER_URL = $worker
    $env:GADE_L1_RUN_ID = $runId
    $env:GADE_L1_DB_PORT = [string]$port
    $env:GADE_L1_OUTPUT = $output
    try {
        & $python $driver *> (Join-Path $output 'driver.log')
        Assert-Ok ($LASTEXITCODE -eq 0) 'L1 driver failed; inspect e2e-state.json and driver.log.'
    } finally {
        foreach($key in $keys) {
            [Environment]::SetEnvironmentVariable($key, $priorEnvironment[$key], 'Process')
        }
        $password = $null
    }
    $state = Get-Content -LiteralPath (Join-Path $output 'e2e-state.json') -Raw | ConvertFrom-Json
    Assert-Ok ($state.status -ceq 'REAL_WORKER_L1_E2E_PASS') 'Driver did not produce receipt-backed complete trace.'
    $manifest.status = 'REAL_WORKER_L1_E2E_PASS'
    $manifest['completed_utc'] = [DateTime]::UtcNow.ToString('o')
    $manifest['evidence_sha256'] = @{}
    foreach($file in Get-ChildItem -LiteralPath $output -File | Where-Object Name -ne 'manifest.json') {
        $manifest.evidence_sha256[$file.Name] = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Save-Json (Join-Path $output 'manifest.json') $manifest
    Write-Host "REAL_WORKER_L1_E2E=PASS EVIDENCE=$output"
} catch {
    if (Test-Path -LiteralPath $output) {
        $message = "REAL_WORKER_L1_E2E=FAIL`nRun ID: $runId`nFailed phase: $phase`nError: $($_.Exception.Message)`nResources are preserved; no cleanup or rerun on partial database.`n"
        try {
            if ($null -ne $manifest) {
                $manifest['status'] = 'FAIL'
                $manifest['failed_phase'] = $phase
                $manifest['failed_utc'] = [DateTime]::UtcNow.ToString('o')
                Save-Json (Join-Path $output 'manifest.json') $manifest
            }
            Set-Content -LiteralPath (Join-Path $output 'BLOCKER_PACKET.md') -Value $message -Encoding utf8
            Write-Host "BLOCKER_PACKET=$(Join-Path $output 'BLOCKER_PACKET.md')"
        } catch { Write-Host "BLOCKER_WRITE_FAILURE=$($_.Exception.Message); ORIGINAL_FAILURE=$message" }
    }
    throw
} finally { Pop-Location }
