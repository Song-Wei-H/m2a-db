[CmdletBinding()]
param(
    [ValidateSet('Migrations', 'Legacy', 'LegacyColumn')]
    [string]$Mode = 'Migrations',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedContainerId,

    [string]$ContainerName,

    [ValidateRange(25436, 25999)]
    [int]$HostPort,

    [string]$DatabaseName,

    [string]$DatabaseUser,

    [ValidatePattern('^[0-9a-f]{12}$')]
    [string]$HostOrchestratorRunId,

    [switch]$Apply,

    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This runner supports its historical scratch profiles and run-scoped GADE host
# profiles. It never runs docker compose or changes container/volume lifecycle;
# all SQL uses the inspected immutable container ID.
$Targets = @{
    Migrations = [pscustomobject]@{
        Name = 'm2a-migration-smoke'; HostIp = '127.0.0.1'; HostPort = '25432'
        Database = 'm2a_smoke'; User = 'm2a_smoke'; First = 1; Last = 37
    }
    Legacy = [pscustomobject]@{
        Name = 'm2a-legacy-smoke'; HostIp = '127.0.0.1'; HostPort = '25433'
        Database = 'm2a_legacy_smoke'; User = 'm2a_legacy_smoke'; First = 1; Last = 37
    }
    LegacyColumn = [pscustomobject]@{
        Name = 'm2a-025-backfill-smoke'; HostIp = '127.0.0.1'; HostPort = '25435'
        Database = 'm2a_025_backfill'; User = 'm2a_025_backfill'; First = 1; Last = 37
    }
}

$Target = $Targets[$Mode]
$customTargetKeys = @('ContainerName', 'HostPort', 'DatabaseName', 'DatabaseUser')
$customTargetProvided = @($customTargetKeys | Where-Object { $PSBoundParameters.ContainsKey($_) }).Count
if ($Apply -and $PreflightOnly) { throw '-Apply and -PreflightOnly cannot be combined.' }
if ($customTargetProvided -ne 0 -and $customTargetProvided -ne 4) {
    throw 'Custom host targets require ContainerName, HostPort, DatabaseName, and DatabaseUser together.'
}
if ($customTargetProvided -eq 4) {
    $match = [regex]::Match($ContainerName, '^gade-preexp-([0-9a-f]{12})-(fresh|legacy025|legacy)$')
    if (-not $match.Success) { throw 'Custom container is outside the gade-preexp run-scoped allowlist.' }
    $profile = $match.Groups[2].Value
    $requiredProfile = switch ($Mode) {
        'Migrations' { 'fresh' }
        'LegacyColumn' { 'legacy025' }
        'Legacy' { 'legacy' }
    }
    if ($profile -cne $requiredProfile) { throw "Target profile '$profile' does not match runner mode '$Mode'." }
    $expectedDb = 'gade_{0}_{1}' -f $match.Groups[1].Value, $profile
    if ($DatabaseName -cne $expectedDb -or $DatabaseUser -cne $expectedDb) {
        throw "Custom database and user must both equal the allowlisted identity '$expectedDb'."
    }
    if ($HostPort -lt 25436 -or $HostPort -gt 25999 -or $HostPort -eq 15432) {
        throw 'Custom host port is outside 25436-25999 or is a forbidden development port.'
    }
    $Target = [pscustomobject]@{
        Name = $ContainerName; HostIp = '127.0.0.1'; HostPort = [string]$HostPort
        Database = $DatabaseName; User = $DatabaseUser; First = 1; Last = 37
    }
}
if (-not [string]::IsNullOrWhiteSpace($HostOrchestratorRunId)) {
    if (-not $Apply -or $PreflightOnly -or $customTargetProvided -ne 4 -or $Mode -cne 'Migrations') {
        throw 'HostOrchestratorRunId is valid only for Apply on a run-scoped fresh Migrations target.'
    }
    if ($ContainerName -cne "gade-preexp-$HostOrchestratorRunId-fresh") {
        throw 'HostOrchestratorRunId does not match the exact fresh container identity.'
    }
}
if ($Target.Database -ceq 'm2a_pentest' -or $Target.HostPort -ceq '15432') {
    throw 'Refusing development database m2a_pentest or development host port 15432.'
}
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$InitDb = Join-Path $RepoRoot 'initdb'
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$RunId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$LogDirectory = Join-Path $env:LOCALAPPDATA 'M2A\MigrationSmoke'
$LogPath = Join-Path $LogDirectory ("{0}-{1}.log" -f $Mode.ToLowerInvariant(), $RunId)
. (Join-Path $PSScriptRoot 'GadeMigration037Oracle.ps1')

function Write-RunLog([string]$Message) {
    $line = '{0} {1}' -f ([DateTimeOffset]::Now.ToString('o')), $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Invoke-DockerRead([string[]]$Arguments) {
    $docker = (Get-Command docker.exe -ErrorAction Stop).Source
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $docker
    $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "docker $($Arguments -join ' ') failed (exit $($process.ExitCode)): $stderr" }
        return $stdout.Trim()
    } finally { $process.Dispose() }
}

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

function Invoke-DockerPsql([string]$ContainerId, [string]$Sql, [switch]$SingleTransaction, [switch]$TuplesOnly) {
    $arguments = @('exec', '-i', $ContainerId, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', $Target.User, '-d', $Target.Database)
    if ($SingleTransaction) { $arguments += '-1' }
    if ($TuplesOnly) { $arguments += @('-A', '-t', '-q') }

    $docker = (Get-Command docker.exe -ErrorAction Stop).Source
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $docker
    $start.Arguments = (($arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($Sql)
    $process.StandardInput.Close()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $result = [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout.Trim(); Stderr = $stderr.Trim() }
    $process.Dispose()
    return $result
}

function Get-NumberedMigrations {
    $files = @(Get-ChildItem -LiteralPath $InitDb -File | Where-Object { $_.Name -match '^(\d{3})_.+\.sql$' } | Sort-Object Name)
    $expected = @($Target.First..$Target.Last)
    $actual = @($files | ForEach-Object { [int]([regex]::Match($_.Name, '^(\d{3})_').Groups[1].Value) })
    if ($actual.Count -ne $expected.Count) { throw "Expected $($expected.Count) numbered migrations, found $($actual.Count)." }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ($actual[$index] -ne $expected[$index]) { throw "Migration sequence gap/order error at $($files[$index].Name)." }
    }
    return $files
}

function Get-ValidatedContainer {
    $inspection = Invoke-DockerRead @('inspect', $Target.Name) | ConvertFrom-Json
    if (@($inspection).Count -ne 1) { throw "Expected exactly one container named $($Target.Name)." }
    $container = @($inspection)[0]
    if ($container.Id -ne $ExpectedContainerId.ToLowerInvariant()) { throw 'Container ID does not match -ExpectedContainerId.' }
    if (($container.Name -replace '^/', '') -cne $Target.Name) { throw 'Container name mismatch.' }
    if ($container.Config.Image -cne 'postgres:16') { throw "Unexpected image: $($container.Config.Image). Expected postgres:16." }
    if (-not $container.State.Running) { throw 'Target container is not running.' }
    if ($null -eq $container.NetworkSettings.Ports.'5432/tcp' -or @($container.NetworkSettings.Ports.'5432/tcp').Count -ne 1) {
        throw 'Container must publish exactly one 5432/tcp binding.'
    }
    $binding = @($container.NetworkSettings.Ports.'5432/tcp')[0]
    if ($binding.HostIp -cne $Target.HostIp -or $binding.HostPort -cne $Target.HostPort) {
        throw "Port binding mismatch; expected $($Target.HostIp):$($Target.HostPort)->5432."
    }

    # A local Unix-socket connection makes inet_server_port() NULL. Never use
    # NULL-sensitive concatenation to build the database identity.
    $identitySql = "SELECT json_build_object('database',current_database(),'user',current_user,'inet_server_port',inet_server_port(),'configured_port',current_setting('port'))::text;"
    $identityRaw = Invoke-DockerRead @('exec', $container.Id, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', $Target.User, '-d', $Target.Database, '-A', '-t', '-q', '-c', $identitySql)
    if ([string]::IsNullOrWhiteSpace($identityRaw)) { throw 'psql identity query returned empty stdout with exit 0; run Diagnose-MigrationSmoke.ps1 and inspect stdout/stderr.' }
    try { $identity = $identityRaw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "psql identity output is not JSON: '$identityRaw'. Run Diagnose-MigrationSmoke.ps1." }
    if ($identity.database -cne $Target.Database -or $identity.user -cne $Target.User) {
        throw "Database identity mismatch: database='$($identity.database)' user='$($identity.user)' (expected '$($Target.Database)'/'$($Target.User)')."
    }
    if ($identity.configured_port -cne '5432' -or ($null -ne $identity.inet_server_port -and [int]$identity.inet_server_port -ne 5432)) {
        throw "PostgreSQL internal port mismatch: inet_server_port='$($identity.inet_server_port)' configured_port='$($identity.configured_port)' (expected 5432; NULL inet_server_port is valid for Unix socket)."
    }

    $stdinProbe = Invoke-DockerPsql -ContainerId $container.Id -Sql "SELECT 'STDIN_CAPTURE_OK';`n" -TuplesOnly
    if ($stdinProbe.ExitCode -ne 0 -or $stdinProbe.Stdout -cne 'STDIN_CAPTURE_OK') {
        throw "psql stdin/capture probe failed: exit=$($stdinProbe.ExitCode) stdout='$($stdinProbe.Stdout)' stderr='$($stdinProbe.Stderr)'. Run Diagnose-MigrationSmoke.ps1."
    }
    Write-Host ("DATABASE_IDENTITY=PASS; database={0}; user={1}; configured_port={2}; inet_server_port={3}; stdin_capture=PASS" -f $identity.database, $identity.user, $identity.configured_port, $(if ($null -eq $identity.inet_server_port) { 'NULL (Unix socket)' } else { $identity.inet_server_port }))
    return $container
}

function Assert-EmptyDatabase([string]$ContainerId) {
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
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0) { throw "Read-only empty-database preflight failed: $($result.Stderr)" }
    if ($result.Stdout.Trim() -cne '0|0|0|0') { throw "Database is not empty (relations|custom schemas|functions|domain-enum-range types = $($result.Stdout.Trim())). No SQL was run." }
}

function Invoke-Migration([string]$ContainerId, [System.IO.FileInfo]$File) {
    $sql = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8
    $hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $started = [DateTimeOffset]::Now
    Write-RunLog ("MIGRATION_START file={0} sha256={1}" -f $File.Name, $hash)
    Write-Host ("Applying {0} ..." -f $File.Name)
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -SingleTransaction
    $finished = [DateTimeOffset]::Now
    if ($result.Stdout) { Write-Host $result.Stdout }
    if ($result.Stderr) { Write-Host $result.Stderr }
    if ($result.ExitCode -ne 0) {
        Write-RunLog ("MIGRATION_FAIL file={0} started={1:o} finished={2:o} elapsed_ms={3} exit={4} stderr={5}" -f $File.Name, $started, $finished, ($finished-$started).TotalMilliseconds, $result.ExitCode, ($result.Stderr -replace '[\r\n]+',' '))
        throw "Migration $($File.Name) failed (psql exit $($result.ExitCode)); subsequent migrations were not run. See $LogPath"
    }
    Write-RunLog ("MIGRATION_PASS file={0} started={1:o} finished={2:o} elapsed_ms={3} exit=0" -f $File.Name, $started, $finished, ($finished-$started).TotalMilliseconds)
}

function Assert-PostMigrationSchema([string]$ContainerId) {
    $sql = @'
DO $$
DECLARE missing text;
BEGIN
  SELECT string_agg(format('%I.%I', r.tbl, r.col), ', ' ORDER BY r.tbl, r.col) INTO missing
  FROM (VALUES
    ('decision_proposals','decision_score_id'),('decision_proposals','raw_proposal'),('decision_proposals','evidence_refs'),('decision_proposals','input_hash'),
    ('tool_tasks','execution_request'),('tool_tasks','execution_request_hash'),('tool_tasks','execution_audit'),
    ('tool_results','execution_receipt'),('tool_results','output_hash'),
    ('authorization_decisions','proposal_id'),('authorization_decisions','authorization_id'),('authorization_decisions','outcome'),('authorization_decisions','record_hash'),
    ('targets','authorization_depth'),('targets','authorization_policy_version'),('targets','authorization_effective_from'),('targets','authorization_expires_at'),('targets','authorization_configured_by'),
    ('vulnerability_candidates','target_id'),('vulnerability_candidates','cve'),('vulnerability_candidates','candidate_key'),('vulnerability_candidates','required_action'),('vulnerability_candidates','required_attack_depth'),('vulnerability_candidates','status'),('vulnerability_candidates','validation_result'),('vulnerability_candidates','validation_coverage')
  ) AS r(tbl,col)
  WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns c WHERE c.table_schema='public' AND c.table_name=r.tbl AND c.column_name=r.col);
  IF missing IS NOT NULL THEN RAISE EXCEPTION 'Required 033-036 columns missing: %', missing; END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='targets'::regclass AND conname='targets_authorization_depth_range' AND contype='c')
    THEN RAISE EXCEPTION 'Missing authorization depth range constraint'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND conname='vulnerability_candidates_validation_coverage_values' AND contype='c')
    THEN RAISE EXCEPTION 'Missing validation coverage check constraint'; END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint c
    WHERE c.conrelid='tool_results'::regclass AND c.contype='f' AND c.confrelid='tool_tasks'::regclass
      AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid='tool_results'::regclass AND attname='tool_task_id')]::smallint[]
  ) THEN RAISE EXCEPTION 'Execution trace tool_results.tool_task_id -> tool_tasks.id FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='authorization_decisions'::regclass AND contype='f' AND confrelid='decision_proposals'::regclass)
    THEN RAISE EXCEPTION 'Authorization decision -> proposal FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='authorization_decisions'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%outcome%')
    THEN RAISE EXCEPTION 'Authorization decision outcome constraint missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND contype='f' AND confrelid='targets'::regclass)
    THEN RAISE EXCEPTION 'Vulnerability candidate -> target FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND contype='f' AND confrelid='tool_tasks'::regclass)
    THEN RAISE EXCEPTION 'Vulnerability candidate -> tool task FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND contype='f' AND confrelid='open_ports'::regclass)
    THEN RAISE EXCEPTION 'Vulnerability candidate -> open port FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND contype='f' AND confrelid='authorization_decisions'::regclass)
    THEN RAISE EXCEPTION 'Vulnerability candidate -> authorization decision FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND contype='f' AND confrelid='execution_authorizations'::regclass)
    THEN RAISE EXCEPTION 'Vulnerability candidate -> execution authorization FK missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='vulnerability_candidates'::regclass AND contype='u' AND conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid='vulnerability_candidates'::regclass AND attname='candidate_key')]::smallint[])
    THEN RAISE EXCEPTION 'Vulnerability candidate key uniqueness constraint missing'; END IF;
  IF (SELECT count(*) FROM pg_trigger WHERE tgname='protect_execution_trace_trigger' AND NOT tgisinternal)<>5
    THEN RAISE EXCEPTION 'Expected all five execution trace immutability triggers'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='idx_vulnerability_candidates_validation_coverage')
    THEN RAISE EXCEPTION 'Validation coverage index missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='vulnerability_candidates'::regclass AND attname='validation_coverage' AND attnotnull AND atttypid='character varying'::regtype)
    THEN RAISE EXCEPTION 'Validation coverage must be a NOT NULL varchar column'; END IF;
END $$;
SELECT 'SCHEMA_033_036=PASS';
'@
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0) { throw "033-036 schema/constraint validation failed: $($result.Stderr)" }
    Write-Host $result.Stdout
}

function Assert-OrmColumns([string]$ContainerId) {
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "Project Python environment not found at $Python; cannot validate ORM mappings." }
    $pythonCode = "from app.models import Base; [print(t+'|'+c.name) for t,table in Base.metadata.tables.items() for c in table.columns]"
    Push-Location $RepoRoot
    try { $modelRows = @(& $Python -c $pythonCode 2>&1); $pythonExitCode = $LASTEXITCODE }
    finally { Pop-Location }
    if ($pythonExitCode -ne 0) { throw "Could not load SQLAlchemy models: $($modelRows -join ' ')" }
    $expected = @($modelRows | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[a-z_]+\|[a-z_]+$' })
    if ($expected.Count -eq 0) { throw 'SQLAlchemy metadata returned no mapped columns.' }
    $schemaSql = "SELECT table_name || '|' || column_name FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,column_name;`n"
    $actualResult = Invoke-DockerPsql -ContainerId $ContainerId -Sql $schemaSql -TuplesOnly
    if ($actualResult.ExitCode -ne 0) { throw "Could not read PostgreSQL columns for ORM comparison: $($actualResult.Stderr)" }
    $actual = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($row in ($actualResult.Stdout -split "`r?`n")) { if ($row.Trim()) { [void]$actual.Add($row.Trim()) } }
    $missing = @($expected | Where-Object { -not $actual.Contains($_) } | Sort-Object -Unique)
    if ($missing.Count -gt 0) { throw "SQLAlchemy mapped columns absent from public schema: $($missing -join ', ')" }
    Write-Host ("SQLALCHEMY_MODEL_COLUMNS=PASS ({0} mapped columns across {1} tables are present)" -f $expected.Count, @($expected | ForEach-Object { ($_ -split '\|')[0] } | Sort-Object -Unique).Count)
}

function Assert-Migration037Schema([string]$ContainerId) {
    $sql = @'
DO $$
DECLARE bad text;
BEGIN
  WITH expected(tbl,col,typ,nullable,maxlen,default_kind) AS (VALUES
    ('evidence_confidence','id','integer',false,NULL::integer,'serial'),
    ('evidence_confidence','target_id','integer',true,NULL::integer,'none'),
    ('evidence_confidence','open_port_id','integer',true,NULL::integer,'none'),
    ('evidence_confidence','decision_score_id','integer',true,NULL::integer,'none'),
    ('evidence_confidence','tool_result_id','integer',true,NULL::integer,'none'),
    ('evidence_confidence','tool_name','character varying',true,100,'none'),
    ('evidence_confidence','evidence_type','character varying',true,100,'none'),
    ('evidence_confidence','confidence_score','double precision',true,NULL::integer,'none'),
    ('evidence_confidence','confidence_reason','text',true,NULL::integer,'none'),
    ('evidence_confidence','supporting_evidence','jsonb',true,NULL::integer,'none'),
    ('evidence_confidence','contradictory_evidence','jsonb',true,NULL::integer,'none'),
    ('evidence_confidence','created_at','timestamp without time zone',false,NULL::integer,'now'),
    ('llm_recommendations','id','integer',false,NULL::integer,'serial'),
    ('llm_recommendations','target_id','integer',true,NULL::integer,'none'),
    ('llm_recommendations','decision_score_id','integer',true,NULL::integer,'none'),
    ('llm_recommendations','evidence_confidence_id','integer',true,NULL::integer,'none'),
    ('llm_recommendations','recommended_action','character varying',true,50,'none'),
    ('llm_recommendations','recommended_tool','character varying',true,100,'none'),
    ('llm_recommendations','confidence','double precision',true,NULL::integer,'none'),
    ('llm_recommendations','reasoning','text',true,NULL::integer,'none'),
    ('llm_recommendations','raw_response','jsonb',true,NULL::integer,'none'),
    ('llm_recommendations','approved','boolean',false,NULL::integer,'false'),
    ('llm_recommendations','validator_status','character varying',true,50,'none'),
    ('llm_recommendations','validator_reason','text',true,NULL::integer,'none'),
    ('llm_recommendations','created_at','timestamp without time zone',false,NULL::integer,'now')
  ), actual AS (
    SELECT c.table_name,c.column_name,c.data_type,c.is_nullable,c.character_maximum_length,c.column_default
    FROM information_schema.columns c WHERE c.table_schema='public'
      AND c.table_name IN ('evidence_confidence','llm_recommendations')
  )
  SELECT string_agg(e.tbl||'.'||e.col, ', ' ORDER BY e.tbl,e.col) INTO bad
  FROM expected e LEFT JOIN actual a ON a.table_name=e.tbl AND a.column_name=e.col
  WHERE a.column_name IS NULL OR a.data_type<>e.typ
    OR a.is_nullable <> CASE WHEN e.nullable THEN 'YES' ELSE 'NO' END
    OR a.character_maximum_length IS DISTINCT FROM e.maxlen
    OR (e.default_kind='serial' AND COALESCE(a.column_default,'') NOT LIKE 'nextval(%')
    OR (e.default_kind='now' AND COALESCE(a.column_default,'') NOT LIKE 'now()%')
    OR (e.default_kind='false' AND COALESCE(a.column_default,'') NOT IN ('false','false::boolean'))
    OR (e.default_kind='none' AND a.column_default IS NOT NULL);
  IF bad IS NOT NULL THEN RAISE EXCEPTION 'Migration 037 column parity failure: %',bad; END IF;
  IF (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='evidence_confidence')<>12
    OR (SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='llm_recommendations')<>13 THEN
    RAISE EXCEPTION 'Migration 037 tables contain unexpected/missing columns';
  END IF;
  IF (SELECT count(*) FROM pg_constraint WHERE conrelid='public.evidence_confidence'::regclass AND contype='p')<>1
    OR (SELECT count(*) FROM pg_constraint WHERE conrelid='public.llm_recommendations'::regclass AND contype='p')<>1
    OR EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid IN
      ('public.evidence_confidence'::regclass,'public.llm_recommendations'::regclass) AND contype<>'p') THEN
    RAISE EXCEPTION 'Migration 037 primary-key/constraint shape differs from ORM declarations';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public'
      AND tablename IN ('evidence_confidence','llm_recommendations')
      AND indexname NOT IN ('evidence_confidence_pkey','llm_recommendations_pkey')) THEN
    RAISE EXCEPTION 'Migration 037 created an undeclared secondary index';
  END IF;
END $$;
SELECT 'MIGRATION_037_SCHEMA=PASS';
'@
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0 -or $result.Stdout -cne 'MIGRATION_037_SCHEMA=PASS') {
        throw "Migration 037 schema validation failed: exit=$($result.ExitCode) stdout=$($result.Stdout) stderr=$($result.Stderr)"
    }
    Write-Host $result.Stdout
}

function Assert-Migration037PreconditionFails([string]$ContainerId) {
    $container = Get-ValidatedContainer
    $runMatch = [regex]::Match($Target.Name,'^gade-preexp-([0-9a-f]{12})-legacy$')
    $targetPort = 0
    $portValid = [int]::TryParse([string]$Target.HostPort, [ref]$targetPort) -and
        $targetPort -ge 25436 -and $targetPort -le 25999 -and $targetPort -ne 15432
    $targetIdentityValid = $runMatch.Success -and
        $container.Id -ceq $ContainerId.ToLowerInvariant() -and
        $Target.HostIp -ceq '127.0.0.1' -and
        $portValid -and
        $Target.Database -ceq ('gade_{0}_legacy' -f $runMatch.Groups[1].Value) -and
        $Target.User -ceq $Target.Database
    if (-not $targetIdentityValid) {
        throw 'Migration 037 negative test target is not the exact run-scoped legacy PostgreSQL database.'
    }

    $migrationPath = Join-Path $InitDb '037_llm_evidence_tables.sql'
    $migrationSql = Get-Content -LiteralPath $migrationPath -Raw -Encoding UTF8
    $attempt = Invoke-DockerPsql -ContainerId $ContainerId -Sql $migrationSql -SingleTransaction
    $stateSql = @'
BEGIN READ ONLY;
SELECT COALESCE(to_regclass('public.evidence_confidence')::text,'NULL') || '|' ||
       COALESCE(to_regclass('public.llm_recommendations')::text,'NULL');
COMMIT;
'@
    $state = Invoke-DockerPsql -ContainerId $ContainerId -Sql $stateSql -TuplesOnly
    $decision = Test-GadeMigration037PreconditionOutcome -Attempt $attempt -SchemaCheck $state -TargetIdentityValid $targetIdentityValid
    if (-not $decision.Pass) {
        throw "Migration 037 pre-036 negative test failed oracle: reason=$($decision.Reason) exit=$($attempt.ExitCode) stdout=$($attempt.Stdout) stderr=$($attempt.Stderr) schema_exit=$($state.ExitCode) schema_stdout=$($state.Stdout) schema_stderr=$($state.Stderr)"
    }
    Write-RunLog ("MIGRATION_037_GUARD=PASS target={0} prerequisite=036_missing sql_exit={1} schema={2}" -f $Target.Database, $attempt.ExitCode, $state.Stdout)
    Write-Host 'MIGRATION_037_PRECONDITION=PASS missing_036 fails closed; no target tables created'
}

function Assert-Migration037PartialObjectRollback([string]$ContainerId) {
    $migrationPath = Join-Path $InitDb '037_llm_evidence_tables.sql'
    $migrationSql = Get-Content -LiteralPath $migrationPath -Raw -Encoding UTF8
    $probe = "CREATE TABLE public.evidence_confidence (id integer);`n" + $migrationSql
    $attempt = Invoke-DockerPsql -ContainerId $ContainerId -Sql $probe -SingleTransaction
    if ($attempt.ExitCode -eq 0 -or $attempt.Stderr -notmatch 'refuses pre-existing or partial public\.evidence_confidence') {
        throw "Migration 037 partial-object negative test did not fail closed as intended: exit=$($attempt.ExitCode) stderr=$($attempt.Stderr)"
    }
    $state = Invoke-DockerPsql -ContainerId $ContainerId -Sql "SELECT COALESCE(to_regclass('public.evidence_confidence')::text,'NULL') || '|' || COALESCE(to_regclass('public.llm_recommendations')::text,'NULL');`n" -TuplesOnly
    if ($state.ExitCode -ne 0 -or $state.Stdout -cne 'NULL|NULL') {
        throw "Migration 037 failed transaction did not roll back the test-created partial object: $($state.Stdout) $($state.Stderr)"
    }
    Write-RunLog 'MIGRATION_037_GUARD=PASS prerequisite=partial_target_relation created_objects_after_rollback=0'
    Write-Host 'MIGRATION_037_ATOMICITY=PASS partial-object rejection rolled back all transaction DDL'
}

function Invoke-LegacyFixture([string]$ContainerId, [string]$Stage) {
    if ($Stage -eq 'Before033') {
        $sql = @'
INSERT INTO targets(target,target_type,scope,status,created_at)
VALUES ('legacy-compatibility.invalid','domain','internal','completed',TIMESTAMP '2020-01-02 03:04:05')
RETURNING id \gset legacy_
INSERT INTO tool_tasks(target_id,tool_name,status,created_at)
VALUES (:legacy_id,'legacy_fixture_only','completed',TIMESTAMP '2020-01-02 03:05:00')
RETURNING id \gset task_
INSERT INTO tool_results(target_id,tool_task_id,tool_name,success,evidence,created_at)
VALUES (:legacy_id,:task_id,'legacy_fixture_only',FALSE,'controlled legacy fixture; no validation claim',TIMESTAMP '2020-01-02 03:06:00');
INSERT INTO vulnerabilities(target_id,cve,vuln_name,status,evidence,created_at)
VALUES (:legacy_id,'CVE-1900-0001','Controlled legacy fixture','unverified','fixture-only; not a finding',TIMESTAMP '2020-01-02 03:07:00');
'@
    } else {
        $sql = @'
INSERT INTO vulnerability_candidates(target_id,cve,candidate_key,status,validation_result,created_at,updated_at)
VALUES ((SELECT id FROM targets WHERE target='legacy-compatibility.invalid'),'CVE-1900-0001','legacy-compatibility-fixture','DISCOVERED',NULL,TIMESTAMP '2020-01-02 03:08:00',TIMESTAMP '2020-01-02 03:08:00');
'@
    }
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -SingleTransaction
    if ($result.ExitCode -ne 0) { throw "Legacy fixture insertion failed at ${Stage}: $($result.Stderr)" }
    Write-Host ("LEGACY_FIXTURE_{0}=INSERTED" -f $Stage.ToUpperInvariant())
}

function Assert-LegacyCompatibility([string]$ContainerId) {
    $sql = @'
DO $$
DECLARE bad_count bigint;
BEGIN
  SELECT count(*) INTO bad_count FROM targets
    WHERE target='legacy-compatibility.invalid'
      AND (authorization_depth<>1 OR authorization_policy_version<>'legacy-safe-default'
           OR authorization_configured_by<>'legacy-record' OR authorization_effective_from IS NULL);
  IF bad_count<>0 THEN RAISE EXCEPTION 'Legacy target authorization defaults were not preserved'; END IF;
  SELECT count(*) INTO bad_count FROM tool_results r JOIN targets t ON t.id=r.target_id
    WHERE t.target='legacy-compatibility.invalid'
      AND (r.execution_receipt IS NOT NULL OR r.output_hash IS NOT NULL);
  IF bad_count<>0 THEN RAISE EXCEPTION 'Migration fabricated execution trace evidence for legacy rows'; END IF;
  SELECT count(*) INTO bad_count FROM tool_tasks q JOIN targets t ON t.id=q.target_id
    WHERE t.target='legacy-compatibility.invalid'
      AND (q.execution_request IS NOT NULL OR q.execution_request_hash IS NOT NULL OR q.execution_audit IS NOT NULL);
  IF bad_count<>0 THEN RAISE EXCEPTION 'Migration fabricated execution request evidence for legacy rows'; END IF;
  SELECT count(*) INTO bad_count FROM vulnerabilities v JOIN targets t ON t.id=v.target_id
    WHERE t.target='legacy-compatibility.invalid' AND v.status<>'unverified';
  IF bad_count<>0 THEN RAISE EXCEPTION 'Legacy vulnerability status changed'; END IF;
  SELECT count(*) INTO bad_count FROM vulnerability_candidates c JOIN targets t ON t.id=c.target_id
    WHERE t.target='legacy-compatibility.invalid'
      AND (c.validation_coverage<>'NOT_EVALUATED' OR c.validation_result IS NOT NULL
           OR c.status<>'DISCOVERED' OR c.authorization_decision_id IS NOT NULL
           OR c.execution_authorization_id IS NOT NULL OR c.tool_task_id IS NOT NULL);
  IF bad_count<>0 THEN RAISE EXCEPTION 'Legacy queue row gained false coverage, validation, or authorization'; END IF;
END $$;
SELECT 'LEGACY_COMPATIBILITY=PASS; trace=NULL; depth=1/legacy-record; coverage=NOT_EVALUATED; status=DISCOVERED';
'@
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0) { throw "Legacy compatibility validation failed: $($result.Stderr)" }
    Write-Host $result.Stdout
}

function Add-LegacyNormalizedDataFixture([string]$ContainerId) {
    $sql = @'
DO $$
BEGIN
  IF (SELECT count(*) FROM normalized_results) <> 0 THEN
    RAISE EXCEPTION 'normalized_results must be empty before controlled legacy-column fixture';
  END IF;
END $$;
ALTER TABLE normalized_results ADD COLUMN normalized_data JSONB;
INSERT INTO normalized_results(tool_name,evidence_type,normalized_data,normalized_output)
VALUES
  ('gade_025_fixture_copy','controlled-fixture','{"case":"copy","value":25}'::jsonb,NULL),
  ('gade_025_fixture_preserve','controlled-fixture','{"case":"source"}'::jsonb,'{"case":"existing"}'::jsonb),
  ('gade_025_fixture_null','controlled-fixture',NULL,NULL);
'@
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -SingleTransaction
    if ($result.ExitCode -ne 0) { throw "Could not insert controlled normalized_data fixture: $($result.Stderr)" }
    Write-RunLog 'LEGACY_025_FIXTURE=INSERTED rows=3 source_column=normalized_data'
    Write-Host 'LEGACY_025_FIXTURE=INSERTED rows=3'
}

function Assert-LegacyNormalizedDataBackfill([string]$ContainerId) {
    $sql = @'
DO $$
DECLARE bad_count bigint;
BEGIN
  SELECT count(*) INTO bad_count FROM normalized_results;
  IF bad_count<>3 THEN RAISE EXCEPTION 'Fixture row count changed: %', bad_count; END IF;

  SELECT count(*) INTO bad_count FROM normalized_results
  WHERE tool_name='gade_025_fixture_copy'
    AND normalized_data='{"case":"copy","value":25}'::jsonb
    AND normalized_output=normalized_data;
  IF bad_count<>1 THEN RAISE EXCEPTION '025 did not copy the non-NULL legacy source into the NULL output exactly once'; END IF;

  SELECT count(*) INTO bad_count FROM normalized_results
  WHERE tool_name='gade_025_fixture_preserve'
    AND normalized_data='{"case":"source"}'::jsonb
    AND normalized_output='{"case":"existing"}'::jsonb;
  IF bad_count<>1 THEN RAISE EXCEPTION '025 overwrote the existing output or changed the legacy source'; END IF;

  SELECT count(*) INTO bad_count FROM normalized_results
  WHERE tool_name='gade_025_fixture_null'
    AND normalized_data IS NULL AND normalized_output IS NULL;
  IF bad_count<>1 THEN RAISE EXCEPTION '025 changed NULL source/output semantics'; END IF;

  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_schema='public' AND table_name='normalized_results'
                   AND column_name='normalized_data') THEN
    RAISE EXCEPTION '025 removed the legacy source column';
  END IF;
END $$;
SELECT 'LEGACY_025_BACKFILL=PASS';
'@
    $result = Invoke-DockerPsql -ContainerId $ContainerId -Sql $sql -TuplesOnly
    if ($result.ExitCode -ne 0 -or $result.Stdout -cne 'LEGACY_025_BACKFILL=PASS') {
        throw "Legacy-column 025 assertions failed: exit=$($result.ExitCode) stdout=$($result.Stdout) stderr=$($result.Stderr)"
    }
    Write-RunLog 'LEGACY_025_BACKFILL=PASS copy=1 preserved=1 null=1 source_retained=true'
    Write-Host $result.Stdout
}

try {
    if (-not (Get-Command docker.exe -ErrorAction SilentlyContinue)) { throw 'docker.exe is not available in PATH.' }
    $migrations = @(Get-NumberedMigrations)
    $nonVersioned = @(Get-ChildItem -LiteralPath $InitDb -File -Filter '*.sql' | Where-Object { $_.Name -notmatch '^\d{3}_.+\.sql$' } | Sort-Object Name)

    Write-Host "MODE=$Mode; TARGET=$($Target.Name); HOST=$($Target.HostIp):$($Target.HostPort); DATABASE=$($Target.Database); USER=$($Target.User)"
    Write-Host 'READ_ONLY_PREFLIGHT: verifying exact container name, immutable ID, image, state, published port, database identity, and empty schema...'
    $container = Get-ValidatedContainer
    Assert-EmptyDatabase $container.Id
    Write-Host 'PREFLIGHT=PASS (database is empty; migrations not yet executed)'
    Write-Host 'NUMBERED MIGRATIONS (lexical order; these alone are executed):'
    $migrations | ForEach-Object { Write-Host ('  {0}' -f $_.Name) }
    Write-Host 'OTHER initdb SQL (reported, never auto-executed):'
    $nonVersioned | ForEach-Object { Write-Host ('  EXCLUDED: {0}' -f $_.Name) }
    Write-Host 'SQL interpretation: 001 starts with DROP TABLE IF EXISTS ... CASCADE; blank-database preflight is mandatory.'
    if ($Mode -eq 'Legacy') { Write-Host 'LEGACY PLAN: apply 001-032, insert controlled historical rows, apply 033-035, add a pre-036 queue row, then apply 036-037 and assert no fabricated trace/authorization/coverage.' }
    elseif ($Mode -eq 'LegacyColumn') { Write-Host 'LEGACY-COLUMN PLAN: apply 001-024, add three controlled normalized_data fixtures, apply 025, assert copy/preserve/NULL semantics, apply 026-037, then validate schema/ORM.' }
    else { Write-Host 'SEED PLAN: numbered migrations contain their own seed/upsert statements (notably 028-032); no separate seed/helper SQL is run.' }

    if ($PreflightOnly) { Write-Host 'PREFLIGHT_ONLY=PASS; no migration SQL was executed.'; return }
    if (-not $Apply) {
        $requiredConfirmation = switch ($Mode) {
            'Legacy' { 'APPLY-LEGACY-001-037' }
            'LegacyColumn' { 'APPLY-LEGACY025-001-037' }
            default { 'APPLY-001-037' }
        }
        if ([string]::IsNullOrWhiteSpace($HostOrchestratorRunId)) {
            $confirmation = Read-Host "To execute against this empty scratch DB, type exactly $requiredConfirmation"
            if ($confirmation -cne $requiredConfirmation) { Write-Host 'CANCELLED; no migration SQL was executed.'; return }
        } else {
            Write-RunLog "HOST_ORCHESTRATOR_CONFIRMATION_ACCEPTED run_id=$HostOrchestratorRunId exact_container=$ContainerName"
        }
    } else {
        Write-Host 'APPLY=AUTHORIZED_BY_HOST_ORCHESTRATOR_CONFIRMATION'
    }

    # Close the gap between read-only preflight and explicit operator consent.
    $container = Get-ValidatedContainer
    Assert-EmptyDatabase $container.Id
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    Write-RunLog ("RUN_START mode={0} container={1} container_id={2} image=postgres:16 endpoint={3}:{4} database={5} user={6}" -f $Mode, $Target.Name, $container.Id, $Target.HostIp, $Target.HostPort, $Target.Database, $Target.User)
    Write-RunLog ('MIGRATION_MANIFEST ' + (($migrations | ForEach-Object { '{0}:{1}' -f $_.Name, (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }) -join ';'))

    if ($Mode -eq 'Legacy') {
        foreach ($file in ($migrations | Where-Object { [int]$_.Name.Substring(0,3) -le 32 })) { Invoke-Migration $container.Id $file }
        Invoke-LegacyFixture $container.Id 'Before033'
        foreach ($file in ($migrations | Where-Object { [int]$_.Name.Substring(0,3) -ge 33 -and [int]$_.Name.Substring(0,3) -le 35 })) { Invoke-Migration $container.Id $file }
        Invoke-LegacyFixture $container.Id 'Before036'
        Assert-Migration037PreconditionFails $container.Id
        Invoke-Migration $container.Id ($migrations | Where-Object { $_.Name -like '036_*' })
        Assert-Migration037PartialObjectRollback $container.Id
        Invoke-Migration $container.Id ($migrations | Where-Object { $_.Name -like '037_*' })
    } elseif ($Mode -eq 'LegacyColumn') {
        foreach ($file in ($migrations | Where-Object { [int]$_.Name.Substring(0,3) -le 24 })) { Invoke-Migration $container.Id $file }
        Add-LegacyNormalizedDataFixture $container.Id
        Invoke-Migration $container.Id ($migrations | Where-Object { $_.Name -like '025_*' })
        Assert-LegacyNormalizedDataBackfill $container.Id
        foreach ($file in ($migrations | Where-Object { [int]$_.Name.Substring(0,3) -ge 26 })) { Invoke-Migration $container.Id $file }
    } else {
        foreach ($file in $migrations) { Invoke-Migration $container.Id $file }
    }
    Assert-Migration037Schema $container.Id
    Assert-PostMigrationSchema $container.Id
    Assert-OrmColumns $container.Id
    if ($Mode -eq 'Legacy') { Assert-LegacyCompatibility $container.Id }
    Write-RunLog ("RUN_PASS mode={0} completed_at={1:o}" -f $Mode, [DateTimeOffset]::Now)
    Write-Host "RUN_STATUS=PASS (migration smoke only; not formal experiment evidence)"
    Write-Host "LOG=$LogPath"
} catch {
    if (Test-Path -LiteralPath $LogPath) { Write-RunLog ("RUN_FAIL mode={0} error={1}" -f $Mode, ($_.Exception.Message -replace '[\r\n]+',' ')) }
    throw
}
