[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedContainerId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$name = 'm2a-migration-smoke'
$database = 'm2a_smoke'
$user = 'm2a_smoke'
$hostPort = '25432'

function Invoke-ReadOnlySql([string]$ContainerId, [string]$Sql, [string]$Label) {
    $inputPath = [IO.Path]::GetTempFileName()
    $outputPath = [IO.Path]::GetTempFileName()
    $errorPath = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($inputPath, $Sql + [Environment]::NewLine, [Text.Encoding]::ASCII)
        $arguments = @('exec', '-i', $ContainerId, 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
            '-U', $user, '-d', $database, '-A', '-t', '-F', '|', '-P', 'null=<NULL>')
        $process = Start-Process -FilePath (Get-Command docker.exe -ErrorAction Stop).Source `
            -ArgumentList $arguments -RedirectStandardInput $inputPath `
            -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath `
            -NoNewWindow -Wait -PassThru
        $stdout = [IO.File]::ReadAllText($outputPath)
        $stderr = [IO.File]::ReadAllText($errorPath)
        Write-Output ("{0}_EXIT={1}" -f $Label, $process.ExitCode)
        Write-Output ("{0}_STDOUT_JSON={1}" -f $Label, (ConvertTo-Json -InputObject $stdout -Compress))
        Write-Output ("{0}_STDERR_JSON={1}" -f $Label, (ConvertTo-Json -InputObject $stderr -Compress))
        if ($process.ExitCode -ne 0) { throw "$Label failed; see stderr above." }
    } finally {
        Remove-Item -LiteralPath $inputPath, $outputPath, $errorPath -Force -ErrorAction SilentlyContinue
    }
}

$inspectionText = @(& docker.exe inspect $name 2>&1)
$inspectionExit = $LASTEXITCODE
if ($inspectionExit -ne 0) { throw "docker inspect failed (exit $inspectionExit): $($inspectionText -join ' ')" }
$inspection = ($inspectionText -join [Environment]::NewLine) | ConvertFrom-Json
if (@($inspection).Count -ne 1) { throw 'Expected exactly one container.' }
$container = @($inspection)[0]
if ($container.Id -ne $ExpectedContainerId.ToLowerInvariant()) { throw 'Container ID mismatch.' }
if (($container.Name -replace '^/', '') -cne $name) { throw 'Container name mismatch.' }
if ($container.Config.Image -cne 'postgres:16') { throw 'Container image mismatch.' }
if (-not $container.State.Running) { throw 'Container is not running.' }
$bindings = @($container.NetworkSettings.Ports.'5432/tcp')
if ($null -eq $container.NetworkSettings.Ports.'5432/tcp' -or $bindings.Count -ne 1 -or
    $bindings[0].HostIp -cne '127.0.0.1' -or $bindings[0].HostPort -cne $hostPort) {
    throw 'Host binding mismatch; expected 127.0.0.1:25432->5432/tcp.'
}
Write-Output ("CONTAINER=PASS name={0} id={1} image=postgres:16 binding=127.0.0.1:{2}->5432" -f $name, $container.Id, $hostPort)

# These SELECTs do not write to PostgreSQL. NULL inet_server_port is expected
# for a Unix-socket connection and must be observed, not assumed.
Invoke-ReadOnlySql $container.Id 'SELECT current_database(), current_user, inet_server_port(), current_setting(''port'');' 'IDENTITY'
Invoke-ReadOnlySql $container.Id "SELECT 'STDIN_CAPTURE_OK';" 'STDIN_PROBE'
Write-Output 'DIAGNOSTIC_COMPLETE; no migration SQL was executed.'
