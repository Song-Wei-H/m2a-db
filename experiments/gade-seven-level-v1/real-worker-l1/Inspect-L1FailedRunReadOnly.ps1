[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$runId = '2e1a8bda7d8a'
$expectedId = 'be6d4640d5d45489e2c08dbc7fcd16928f405a830530be50e85d4233473bd509'
$name = "gade-preexp-$runId-fresh"
$volume = "gade_l1_${runId}_pgdata"
$database = "gade_${runId}_fresh"
$port = '25436'
$root = Join-Path $PSScriptRoot "local-only\$runId"
$manifestPath = Join-Path $root 'manifest.json'
$evidenceDir = Join-Path $root ('read-only-audit-{0}-{1}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), [guid]::NewGuid().ToString('N'))
$evidencePath = Join-Path $evidenceDir 'audit.json'

function Quote-WindowsArgument([string]$Value) {
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

function Invoke-Process([string]$FileName, [string[]]$Arguments) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FileName
    $info.Arguments = (($Arguments | ForEach-Object { Quote-WindowsArgument ([string]$_) }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{exit_code=$process.ExitCode;stdout=$stdout.GetAwaiter().GetResult();stderr=$stderr.GetAwaiter().GetResult()}
    } finally { $process.Dispose() }
}

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Preserved run manifest missing; no Docker or SQL command issued.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.run_id -cne $runId -or $manifest.container_id -cne $expectedId -or
    $manifest.container -cne $name -or $manifest.volume -cne $volume -or
    $manifest.database -cne $database -or [string]$manifest.port -cne $port -or
    $manifest.status -cne 'FAIL') {
    throw 'Preserved manifest identity mismatch; no Docker or SQL command issued.'
}

New-Item -ItemType Directory -Path $evidenceDir -ErrorAction Stop | Out-Null
$record = [ordered]@{run_id=$runId;started_utc=[DateTimeOffset]::UtcNow.ToString('o');
    purpose='read-only persisted-state audit of failed L1 run'; expected_container_id=$expectedId;
    script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();
    manifest_sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();
    observed_identity=$null;identity_status='NOT_CHECKED';query_status='NOT_RUN';
    raw_stdout=$null;raw_stderr=$null;query_exit_code=$null;parsed_query=$null;error=$null}
try {
    $docker = (Get-Command docker.exe -ErrorAction Stop).Source
    $inspection = Invoke-Process $docker @('inspect',$expectedId)
    if ($inspection.exit_code -ne 0) { throw "docker inspect failed, exit $($inspection.exit_code): $($inspection.stderr)" }
    $containers = @(ConvertFrom-Json -InputObject $inspection.stdout -ErrorAction Stop)
    if ($containers.Count -ne 1) { throw 'Expected exactly one inspected container.' }
    $container = $containers[0]
    $bindings = @($container.NetworkSettings.Ports.'5432/tcp')
    $mounts = @($container.Mounts | Where-Object { $_.Destination -ceq '/var/lib/postgresql/data' })
    $configured = @($container.Config.Env)
    $observed = [ordered]@{id=$container.Id;name=$container.Name;image=$container.Config.Image;
        running=[bool]$container.State.Running;run_label=$container.Config.Labels.'com.gade.l1.run_id';
        managed_label=$container.Config.Labels.'com.gade.l1.managed';
        host_ip=if($bindings.Count -eq 1){$bindings[0].HostIp}else{$null};
        host_port=if($bindings.Count -eq 1){$bindings[0].HostPort}else{$null};
        volume=if($mounts.Count -eq 1){$mounts[0].Name}else{$null};
        database_configured=($configured -ccontains "POSTGRES_DB=$database");
        user_configured=($configured -ccontains "POSTGRES_USER=$database")}
    $record.observed_identity = $observed
    if ($observed.id -cne $expectedId -or $observed.name -cne "/$name" -or
        $observed.image -cne 'postgres:16' -or -not $observed.running -or
        $observed.run_label -cne $runId -or $observed.managed_label -cne 'true' -or
        $bindings.Count -ne 1 -or $observed.host_ip -cne '127.0.0.1' -or
        $observed.host_port -cne $port -or $observed.volume -cne $volume -or
        -not $observed.database_configured -or -not $observed.user_configured) {
        throw 'Container identity mismatch; no SQL command issued.'
    }
    $record.identity_status = 'PASS'

    $sql = @'
BEGIN TRANSACTION READ ONLY;
SELECT jsonb_build_object(
  'database', current_database(), 'user', current_user,
  'configured_port', current_setting('port'),
  'server_read_only', current_setting('transaction_read_only'),
  'observed_utc', (now() AT TIME ZONE 'UTC'),
  'columns', (SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY c.table_name,c.ordinal_position),'[]'::jsonb)
              FROM information_schema.columns c WHERE c.table_schema='public'
              AND c.table_name IN ('tool_tasks','execution_authorizations','authorization_decisions',
                                   'decision_proposals','tool_results','learning_feedback')),
  'target', (SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT * FROM targets WHERE id=1) t),
  'task', (SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb) FROM (SELECT * FROM tool_tasks WHERE id=1) t),
  'proposal', (SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb) FROM (SELECT * FROM decision_proposals WHERE id=1) p),
  'decision', (SELECT COALESCE(jsonb_agg(to_jsonb(d)),'[]'::jsonb) FROM (SELECT * FROM authorization_decisions WHERE id=1) d),
  'grant', (SELECT COALESCE(jsonb_agg(to_jsonb(a)),'[]'::jsonb) FROM (SELECT * FROM execution_authorizations WHERE id=1) a),
  'results', (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM (SELECT * FROM tool_results WHERE tool_task_id=1 OR id=1) r),
  'feedback', (SELECT COALESCE(jsonb_agg(to_jsonb(f) ORDER BY f.id),'[]'::jsonb) FROM (SELECT * FROM learning_feedback WHERE tool_result_id=1) f),
  'counts', jsonb_build_object(
      'all_tasks',(SELECT count(*) FROM tool_tasks),
      'all_results',(SELECT count(*) FROM tool_results),
      'all_feedback',(SELECT count(*) FROM learning_feedback))
)::text;
COMMIT;
'@
    $query = Invoke-Process $docker @('exec',$expectedId,'psql','-X','-q','-t','-A','-v','ON_ERROR_STOP=1','-U',$database,'-d',$database,'-c',$sql)
    $record.raw_stdout = $query.stdout
    $record.raw_stderr = $query.stderr
    $record.query_exit_code = $query.exit_code
    if ($query.exit_code -ne 0) { throw "read-only PostgreSQL query failed (exit $($query.exit_code))" }
    $lines = @($query.stdout -split '\r?\n' | Where-Object { $_.Trim().StartsWith('{') })
    if ($lines.Count -ne 1) { throw 'Expected exactly one JSON result row.' }
    $parsed = ConvertFrom-Json -InputObject $lines[0] -ErrorAction Stop
    if ($parsed.database -cne $database -or $parsed.user -cne $database -or
        [string]$parsed.configured_port -cne '5432' -or $parsed.server_read_only -cne 'on') {
        throw 'PostgreSQL database/user/read-only identity mismatch.'
    }
    $record.parsed_query = $parsed
    $record.query_status = 'PASS'
    Write-Host "READ_ONLY_AUDIT=PASS EVIDENCE=$evidencePath"
} catch {
    $record.error = $_.Exception.Message
    Write-Host "READ_ONLY_AUDIT=FAIL EVIDENCE=$evidencePath"
    throw
} finally {
    $record['completed_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
    if (Test-Path -LiteralPath $evidencePath) { throw 'Evidence collision; refusing overwrite.' }
    $record | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
}
