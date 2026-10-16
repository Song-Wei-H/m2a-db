[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeL3SshTransport.ps1')

$temp = Join-Path $env:TEMP ('gade-l3-ssh-transport-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $log = Join-Path $temp 'native-stderr.log'
    $arguments = '/c "<nul set /p =SCP_TEST_PROMPT: 1>&2 & echo. 1>&2 & echo SCP_TEST_DIAGNOSTIC 1>&2 & exit /b 255"'
    $result = Invoke-GadeInteractiveNativeProcess -FilePath $cmd -ArgumentList $arguments -StderrLogPath $log
    $captured = Get-Content -LiteralPath $log -Raw
    if ($result.ExitCode -ne 255) { throw "Expected preserved native exit 255, got $($result.ExitCode)." }
    if ($captured -notmatch 'SCP_TEST_PROMPT:' -or $captured -notmatch 'SCP_TEST_DIAGNOSTIC') {
        throw 'Native stderr prompt/diagnostic was not completely preserved.'
    }
    if ($captured -notmatch 'exit_code=255') { throw 'Native exit code was not recorded.' }
    Write-Output "SSH_TRANSPORT_CAPTURE_TEST=PASS exit=$($result.ExitCode) diagnostic_log=$log"

    $capturedResult = Invoke-GadeCapturedNativeProcess -FilePath $cmd `
        -ArgumentList '/c "echo DRIVER_TEST_STDOUT & echo Traceback (most recent call last): 1>&2 & echo DRIVER_TEST_FRAME 1>&2 & exit /b 1"'
    if ($capturedResult.ExitCode -ne 1) { throw "Expected captured-process exit 1, got $($capturedResult.ExitCode)." }
    if ($capturedResult.Stdout -notmatch 'DRIVER_TEST_STDOUT' -or
        $capturedResult.Stderr -notmatch 'Traceback \(most recent call last\):' -or
        $capturedResult.Stderr -notmatch 'DRIVER_TEST_FRAME') {
        throw 'Captured process did not preserve stdout and multi-line traceback text.'
    }
    Write-Output "NONINTERACTIVE_NATIVE_CAPTURE_TEST=PASS exit=$($capturedResult.ExitCode) stdout_and_stderr_preserved=true"
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
