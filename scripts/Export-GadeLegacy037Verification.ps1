[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$RunId = 'f29fe50313b9'
$Expected = [pscustomobject]@{
    RunId = $RunId
    ContainerId = 'ec972a87427ad1a0dca848857bc916eb5555071a2cc9fea3aedcb5a760c441e2'
    ContainerName = 'gade-preexp-f29fe50313b9-legacy025'
    Image = 'postgres:16'
    Profile = 'legacy025'
    HostIp = '127.0.0.1'
    HostPort = '25957'
    Database = 'gade_f29fe50313b9_legacy025'
    User = 'gade_f29fe50313b9_legacy025'
    Volume = 'gade_preexp_f29fe50313b9_legacy025'
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

function Invoke-HostProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$StandardInput
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $FileName
    $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' ')
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($PSBoundParameters.ContainsKey('StandardInput')) { $start.RedirectStandardInput = $true }
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

function Get-ContainerEnvironmentValue {
    param([string[]]$Environment,[string]$Name)
    $matches = @($Environment | Where-Object { $_.StartsWith(($Name + '='),[StringComparison]::Ordinal) })
    if ($matches.Count -ne 1) { return $null }
    return $matches[0].Substring($Name.Length + 1)
}

$evidenceRoot = Join-Path $RepoRoot 'reports\local-only\host-verification\f29fe50313b9'
$evidenceId = '{0}-{1}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), [guid]::NewGuid().ToString('N')
$evidenceDirectory = Join-Path $evidenceRoot $evidenceId
$evidencePath = Join-Path $evidenceDirectory 'verification.json'
New-Item -ItemType Directory -Path $evidenceDirectory -ErrorAction Stop | Out-Null
if (Test-Path -LiteralPath $evidencePath) { throw "Evidence path collision; refusing overwrite: $evidencePath" }

$sql = @'
BEGIN READ ONLY;
SELECT 'IDENTITY|' || current_database() || '|' || current_user || '|' || current_setting('port');
SELECT 'TABLE|' || name || '|' || COALESCE(to_regclass(format('public.%I', name))::text, 'NULL')
  FROM (VALUES ('evidence_confidence'), ('llm_recommendations')) AS expected(name)
  ORDER BY name;
SELECT 'COLUMN|' || table_name || '|' || column_name
  FROM information_schema.columns
  WHERE table_schema = 'public'
    AND table_name IN ('evidence_confidence', 'llm_recommendations')
  ORDER BY table_name, ordinal_position;
COMMIT;
'@

$record = [ordered]@{
    schema_version = 1
    purpose = 'read-only live verification for Migration 037 gate'
    started_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    completed_at_utc = $null
    expected_identity = $Expected
    observed_identity = $null
    identity_status = 'NOT_CHECKED'
    query_status = 'NOT_RUN'
    query_sql = $sql
    query_exit_code = $null
    raw_stdout = $null
    raw_stderr = $null
    error = $null
}
$failure = $null

try {
    $docker = (Get-Command docker.exe -ErrorAction Stop).Source
    $inspect = Invoke-HostProcess -FileName $docker -Arguments @('inspect',$Expected.ContainerId)
    if ($inspect.ExitCode -ne 0) {
        $record.observed_identity = [pscustomobject]@{ inspect_exit_code=$inspect.ExitCode; inspect_stderr=$inspect.Stderr }
        throw "docker inspect failed (exit $($inspect.ExitCode)); no SQL was issued."
    }
    try { $container = @($inspect.Stdout | ConvertFrom-Json -ErrorAction Stop)[0] }
    catch { throw "docker inspect did not return valid JSON; no SQL was issued: $($_.Exception.Message)" }

    $bindings = @($container.NetworkSettings.Ports.'5432/tcp')
    $databaseEnv = Get-ContainerEnvironmentValue -Environment @($container.Config.Env) -Name 'POSTGRES_DB'
    $userEnv = Get-ContainerEnvironmentValue -Environment @($container.Config.Env) -Name 'POSTGRES_USER'
    $volumeMount = @($container.Mounts | Where-Object { $_.Destination -ceq '/var/lib/postgresql/data' })
    $observed = [ordered]@{
        container_id = [string]$container.Id
        container_name = ([string]$container.Name -replace '^/','')
        image = [string]$container.Config.Image
        running = [bool]$container.State.Running
        run_id_label = [string]$container.Config.Labels.'com.gade.preexp.run_id'
        profile_label = [string]$container.Config.Labels.'com.gade.preexp.profile'
        managed_label = [string]$container.Config.Labels.'com.gade.preexp.managed'
        published_bindings = @($bindings | ForEach-Object { [pscustomobject]@{ host_ip=$_.HostIp; host_port=$_.HostPort } })
        configured_database = $databaseEnv
        configured_user = $userEnv
        data_volume = if ($volumeMount.Count -eq 1) { [string]$volumeMount[0].Name } else { $null }
    }
    $record.observed_identity = [pscustomobject]$observed

    $identityMatches = $container.Id -ceq $Expected.ContainerId -and
        ($container.Name -replace '^/','') -ceq $Expected.ContainerName -and
        $container.Config.Image -ceq $Expected.Image -and
        [bool]$container.State.Running -and
        $container.Config.Labels.'com.gade.preexp.run_id' -ceq $Expected.RunId -and
        $container.Config.Labels.'com.gade.preexp.profile' -ceq $Expected.Profile -and
        $container.Config.Labels.'com.gade.preexp.managed' -ceq 'true' -and
        $bindings.Count -eq 1 -and $bindings[0].HostIp -ceq $Expected.HostIp -and
        $bindings[0].HostPort -ceq $Expected.HostPort -and
        $databaseEnv -ceq $Expected.Database -and $userEnv -ceq $Expected.User -and
        $volumeMount.Count -eq 1 -and $volumeMount[0].Name -ceq $Expected.Volume
    if (-not $identityMatches) {
        $record.identity_status = 'FAIL'
        throw 'Container identity mismatch; no SQL was issued.'
    }
    $record.identity_status = 'PASS'

    $query = Invoke-HostProcess -FileName $docker -Arguments @(
        'exec','-i',$Expected.ContainerId,'psql','-X','-v','ON_ERROR_STOP=1','-U',$Expected.User,'-d',$Expected.Database,'-A','-t','-q','-f','-'
    ) -StandardInput ($sql + "`n")
    $record.query_exit_code = $query.ExitCode
    $record.raw_stdout = $query.Stdout
    $record.raw_stderr = $query.Stderr
    if ($query.ExitCode -ne 0) {
        $record.query_status = 'FAIL'
        throw "Read-only SQL query failed (psql exit $($query.ExitCode))."
    }
    $identityLine = @($query.Stdout -split "`r?`n" | Where-Object { $_ -like 'IDENTITY|*' })
    $expectedIdentityLine = 'IDENTITY|{0}|{1}|5432' -f $Expected.Database,$Expected.User
    if ($identityLine.Count -ne 1 -or $identityLine[0] -cne $expectedIdentityLine) {
        $record.query_status = 'FAIL'
        throw 'Connected PostgreSQL database/user/port identity mismatch; query was read-only.'
    }
    $record.query_status = 'PASS'
} catch {
    $failure = $_.Exception.Message
    $record.error = $_.ToString()
} finally {
    $record.completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    $json = ConvertTo-Json -InputObject ([pscustomobject]$record) -Depth 20
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $stream = New-Object System.IO.FileStream($evidencePath,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}

Write-Host "LIVE_VERIFICATION_EVIDENCE=$evidencePath"
Write-Host "IDENTITY_STATUS=$($record.identity_status) QUERY_STATUS=$($record.query_status)"
if ($failure) { throw "HOST_VERIFICATION_FAILED=$failure; evidence saved at $evidencePath" }
Write-Host 'LIVE_VERIFICATION=PASS (read-only SQL completed; inspect raw_stdout in evidence JSON)'
