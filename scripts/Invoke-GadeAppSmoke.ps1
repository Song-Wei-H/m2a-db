[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedContainerId,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$MigrationRunLog,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^gade-preexp-[0-9a-f]{12}-fresh$')]
    [string]$ContainerName,

    [Parameter(Mandatory = $true)]
    [ValidateRange(25436, 25999)]
    [int]$HostPort,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^gade_[0-9a-f]{12}_fresh$')]
    [string]$DatabaseName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^gade_[0-9a-f]{12}_fresh$')]
    [string]$DatabaseUser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Run only in ordinary host PowerShell after a new clean 001-037 migration run.
# This wrapper operates only on the new isolated host-validation container.
$Name = $ContainerName
$Database = $DatabaseName
$DbUser = $DatabaseUser
$RepoRoot = 'C:\Users\p2166\m2a-db'
$Python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
$PythonHarness = Join-Path $PSScriptRoot 'gade_app_smoke.py'
$Patched025Hash = 'd088b88e230d20c7d5ab63a7a3039bb54c6e946d20b6ef36b2481c870d7f6bd3'
$ExpectedContainerId = $ExpectedContainerId.ToLowerInvariant()
$LogDirectory = Join-Path $env:LOCALAPPDATA 'M2A\MigrationSmoke'
$RunId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$AppLog = Join-Path $LogDirectory ("app-smoke-{0}.log" -f $RunId)

if ($Database -ceq 'm2a_pentest' -or $HostPort -eq 15432 -or $Database -cne $DbUser -or
    $Name -notmatch '^gade-preexp-([0-9a-f]{12})-fresh$' -or
    $Database -cne ('gade_{0}_fresh' -f $Matches[1])) {
    throw 'Target is outside the run-scoped isolated scratch allowlist.'
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw 'Repository .venv Python not found.' }
if (-not (Test-Path -LiteralPath $PythonHarness -PathType Leaf)) { throw 'Python app smoke harness not found.' }

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

function Invoke-DockerInspect {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = (Get-Command docker.exe -ErrorAction Stop).Source
    $start.Arguments = 'inspect ' + (ConvertTo-WindowsArgument $Name)
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
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "docker inspect failed (exit $($process.ExitCode)): $stderr" }
        return $stdoutTask.GetAwaiter().GetResult()
    } finally {
        $process.Dispose()
    }
}

function Get-ValidatedScratchPassword {
    $raw = Invoke-DockerInspect
    try { $containers = @(ConvertFrom-Json -InputObject $raw -ErrorAction Stop) }
    catch { throw 'Docker inspect returned invalid JSON; raw output was suppressed.' }
    $raw = $null
    if ($containers.Count -ne 1) { throw 'Expected exactly one scratch container.' }
    $container = $containers[0]
    if ($container.Id -cne $ExpectedContainerId -or
        $container.Name -cne "/$Name" -or
        $container.Config.Image -cne 'postgres:16' -or
        -not $container.State.Running) {
        throw 'Scratch container ID/name/image/running-state mismatch.'
    }
    $configured = @($container.HostConfig.PortBindings.'5432/tcp')
    $published = @($container.NetworkSettings.Ports.'5432/tcp')
    if ($configured.Count -ne 1 -or $published.Count -ne 1 -or
        $configured[0].HostIp -cne '127.0.0.1' -or $configured[0].HostPort -cne $HostPort -or
        $published[0].HostIp -cne '127.0.0.1' -or $published[0].HostPort -cne $HostPort) {
        throw "Scratch port binding mismatch; expected only 127.0.0.1:$HostPort->5432."
    }
    $envSet = @($container.Config.Env)
    if ($envSet -cnotcontains "POSTGRES_DB=$Database" -or $envSet -cnotcontains "POSTGRES_USER=$DbUser") {
        throw 'Scratch database/user environment mismatch.'
    }
    $prefix = 'POSTGRES_PASSWORD='
    $secretRows = @($envSet | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($secretRows.Count -ne 1 -or $secretRows[0].Length -le $prefix.Length) {
        throw 'Scratch POSTGRES_PASSWORD is missing or ambiguous; no raw environment was printed.'
    }
    Write-Host "CONTAINER=PASS name=$Name id=$ExpectedContainerId image=postgres:16 endpoint=127.0.0.1:$HostPort"
    return $secretRows[0].Substring($prefix.Length)
}

function Assert-CleanMigrationLog {
    $resolvedLog = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $MigrationRunLog).Path)
    $allowedDir = [System.IO.Path]::GetFullPath($LogDirectory).TrimEnd('\') + '\'
    if (-not $resolvedLog.StartsWith($allowedDir, [StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFileName($resolvedLog) -notmatch '^migrations-\d{8}-\d{6}-[0-9a-f]{8}\.log$') {
        throw 'Migration log must be an original migrations-*.log under LOCALAPPDATA\M2A\MigrationSmoke.'
    }
    $log = Get-Content -LiteralPath $resolvedLog -Raw -Encoding UTF8
    $start = "RUN_START mode=Migrations container=$Name container_id=$ExpectedContainerId image=postgres:16 endpoint=127.0.0.1:$HostPort database=$Database user=$DbUser"
    if (-not $log.Contains($start) -or -not $log.Contains('RUN_PASS mode=Migrations') -or
        $log.Contains('MIGRATION_FAIL ') -or $log.Contains('RUN_FAIL ')) {
        throw 'Migration log does not prove an error-free 001-037 run on this exact container.'
    }
    $files = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'initdb') -File |
        Where-Object { $_.Name -match '^\d{3}_.+\.sql$' } | Sort-Object Name)
    if ($files.Count -ne 37) { throw 'Expected exactly 37 numbered migration files.' }
    for ($i = 0; $i -lt 37; $i++) {
        $file = $files[$i]
        if ([int]$file.Name.Substring(0, 3) -ne ($i + 1)) { throw 'Numbered migration sequence is not contiguous.' }
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($file.Name -eq '025_normalized_results_schema_alignment.sql' -and $hash -cne $Patched025Hash) {
            throw 'Migration 025 hash differs from the scoped audited repair.'
        }
        if (-not $log.Contains("$($file.Name):$hash") -or
            ([regex]::Matches($log, '(?m)^\S+ MIGRATION_PASS file=' + [regex]::Escape($file.Name) + ' ')).Count -ne 1) {
            throw "Migration log has no unique matching PASS/manifest entry for $($file.Name)."
        }
    }
    Write-Host "MIGRATION_LOG=PASS path=$resolvedLog; passes=37; repaired_025_sha256=$Patched025Hash"
}

function Write-RunLog([string]$Message) {
    Add-Content -LiteralPath $AppLog -Value ('{0} {1}' -f [DateTimeOffset]::Now.ToString('o'), $Message) -Encoding UTF8
}

function Invoke-PythonSmoke([string]$Secret) {
    # ProcessStartInfo avoids Windows PowerShell 5.1's native-stderr ErrorRecord
    # behavior. The password is supplied only to this child process, never as
    # a command-line argument or a parent PowerShell environment variable.
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Python
    $start.Arguments = ConvertTo-WindowsArgument $PythonHarness
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['M2A_APP_SMOKE_PASSWORD'] = $Secret
    $start.EnvironmentVariables['M2A_APP_SMOKE_REPO'] = $RepoRoot
    $start.EnvironmentVariables['M2A_APP_SMOKE_CONTAINER_ID'] = $ExpectedContainerId
    $start.EnvironmentVariables['M2A_APP_SMOKE_HOST'] = '127.0.0.1'
    $start.EnvironmentVariables['M2A_APP_SMOKE_PORT'] = [string]$HostPort
    $start.EnvironmentVariables['M2A_APP_SMOKE_DATABASE'] = $Database
    $start.EnvironmentVariables['M2A_APP_SMOKE_USER'] = $DbUser
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
    } finally {
        $process.Dispose()
    }
}

$password = $null
try {
    Assert-CleanMigrationLog
    $password = Get-ValidatedScratchPassword
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    Write-RunLog "RUN_START container=$Name container_id=$ExpectedContainerId database=$Database port=$HostPort"
    $result = Invoke-PythonSmoke -Secret $password
    $encodedPassword = [System.Uri]::EscapeDataString($password)
    foreach ($line in (($result.Stdout + "`n" + $result.Stderr) -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $safeLine = [string]$line
        if ($password.Length -gt 0) { $safeLine = $safeLine.Replace($password, '[REDACTED]') }
        if ($encodedPassword.Length -gt 0) { $safeLine = $safeLine.Replace($encodedPassword, '[REDACTED]') }
        Write-Host $safeLine
        Write-RunLog $safeLine
    }
    $stdoutLines = @($result.Stdout -split "`r?`n")
    if ($result.ExitCode -ne 0 -or @($stdoutLines | Where-Object { $_ -ceq 'APP_SMOKE=PASS' }).Count -ne 1 -or
        @($stdoutLines | Where-Object { $_ -ceq 'CLEANUP=PASS' }).Count -ne 1) {
        throw "Application smoke failed (Python exit $($result.ExitCode)); see $AppLog."
    }
    Write-RunLog 'RUN_PASS'
    Write-Host 'APP_SMOKE_STATUS=PASS (isolated scratch DB only; no Worker execution)'
    Write-Host "LOG=$AppLog"
} catch {
    if (Test-Path -LiteralPath $AppLog) { Write-RunLog ("RUN_FAIL error={0}" -f ($_.Exception.GetType().Name)) }
    throw
} finally {
    $password = $null
}
