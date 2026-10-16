[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'GadeCodexCli.ps1')
. (Join-Path $PSScriptRoot 'GadeL3SshTransport.ps1')

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('gade-codex-cli-' + [guid]::NewGuid().ToString('N'))
$pathRoot = Join-Path $testRoot 'path'
$installRoot = Join-Path $testRoot 'localappdata\OpenAI\Codex\bin'
New-Item -ItemType Directory -Path $pathRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $installRoot 'older') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $installRoot 'newer') -Force | Out-Null

try {
    $firstSessionArgs = @(Get-GadeCodexExecArgumentList -Model 'gpt-5.6-sol' -PersistentSession `
        -SchemaPath 'schema.json' -ResponsePath 'response.json' -AgentDirectory 'agent-scratch')
    if ($firstSessionArgs[0] -cne 'exec' -or $firstSessionArgs -notcontains '--color' -or
        $firstSessionArgs -notcontains 'never' -or $firstSessionArgs -notcontains '--sandbox' -or
        $firstSessionArgs -notcontains 'read-only' -or $firstSessionArgs -notcontains '--cd') {
        throw 'New Codex session arguments lost their supported color/sandbox/working-directory options.'
    }

    $sessionId = '01a142d2-f637-7401-812c-929f2ede76d4'
    $resumeArgs = @(Get-GadeCodexExecArgumentList -Model 'gpt-5.6-sol' -SessionId $sessionId -PersistentSession `
        -SchemaPath 'schema.json' -ResponsePath 'response.json' -AgentDirectory 'agent-scratch')
    if ($resumeArgs[0] -cne 'exec' -or $resumeArgs[1] -cne 'resume' -or $resumeArgs[2] -cne $sessionId -or
        $resumeArgs -contains '--color' -or $resumeArgs -contains '--sandbox' -or $resumeArgs -contains '--cd' -or
        $resumeArgs -notcontains '--model' -or $resumeArgs -notcontains '--json' -or
        $resumeArgs -notcontains '--output-schema' -or $resumeArgs -notcontains '--output-last-message') {
        throw 'Codex resume arguments contain unsupported first-turn options or omit required continuation options.'
    }

    $ephemeralArgs = @(Get-GadeCodexExecArgumentList -Model 'gpt-5.6-sol' -SchemaPath 'schema.json' `
        -ResponsePath 'response.json' -AgentDirectory 'agent-scratch')
    if ($ephemeralArgs -notcontains '--ephemeral') { throw 'Non-persistent first turn lost the ephemeral-session flag.' }

    $pathExe = Join-Path $pathRoot 'codex.exe'
    [IO.File]::WriteAllText($pathExe, 'path executable')
    $savedPath = $env:PATH
    try {
        $env:PATH = $pathRoot + [IO.Path]::PathSeparator + $savedPath
        $resolved = Resolve-GadeCodexCliExecutable -LocalAppDataPath (Join-Path $testRoot 'missing')
    } finally {
        $env:PATH = $savedPath
    }
    if ($resolved -cne (Get-Item -LiteralPath $pathExe).FullName) { throw 'PATH resolution did not prefer the supplied executable.' }

    Remove-Item -LiteralPath $pathExe -Force
    $olderExe = Join-Path $installRoot 'older\codex.exe'
    $newerExe = Join-Path $installRoot 'newer\codex.exe'
    [IO.File]::WriteAllText($olderExe, 'older bundled executable')
    Start-Sleep -Milliseconds 1100
    [IO.File]::WriteAllText($newerExe, 'newer bundled executable')
    $resolved = Resolve-GadeCodexCliExecutable -LocalAppDataPath (Join-Path $testRoot 'localappdata') -SkipPathLookup
    if ($resolved -cne (Get-Item -LiteralPath $newerExe).FullName) { throw 'Bundled-install fallback did not choose the newest executable.' }

    $missingRoot = Join-Path $testRoot 'absent'
    $missingMessage = $null
    try {
        Resolve-GadeCodexCliExecutable -PathExecutable (Join-Path $missingRoot 'codex.exe') -LocalAppDataPath $missingRoot -SkipPathLookup | Out-Null
    } catch {
        $missingMessage = $_.Exception.Message
    }
    if ($missingMessage -notmatch 'Codex CLI executable was not found') { throw 'Missing CLI did not fail with an explicit diagnostic.' }

    $actual = Resolve-GadeCodexCliExecutable -SkipPathLookup
    $version = Invoke-GadeCapturedNativeProcess -FilePath $actual -ArgumentList '--version'
    if ($version.ExitCode -ne 0 -or $version.Stdout -notmatch '^codex-cli\s+') { throw "Resolved installed CLI failed local --version verification (exit $($version.ExitCode)); $($version.Stderr)" }
    $resumeHelp = Invoke-GadeCapturedNativeProcess -FilePath $actual -ArgumentList 'exec resume --help'
    if ($resumeHelp.ExitCode -ne 0 -or (($resumeHelp.Stdout + $resumeHelp.Stderr) -match '(?m)^\s*--color\b')) {
        throw 'Codex resume help unexpectedly failed or lists --color; review the argument-builder compatibility test.'
    }
    $login = Invoke-GadeCapturedNativeProcess -FilePath $actual -ArgumentList 'login status'
    if (-not (Test-GadeCodexChatGPTLogin -ExitCode $login.ExitCode -Stdout $login.Stdout -Stderr $login.Stderr)) { throw "Resolved installed CLI failed read-only login status verification (exit $($login.ExitCode))." }
    $loginMessageChannel = if ($login.Stderr -match '(?m)^\s*Logged in using ChatGPT\s*$') { 'stderr' } elseif ($login.Stdout -match '(?m)^\s*Logged in using ChatGPT\s*$') { 'stdout' } else { 'unknown' }
    if ($loginMessageChannel -ceq 'unknown') { throw 'CLI login status was accepted without the expected message in either stream.' }
    if (Test-GadeCodexChatGPTLogin -ExitCode 0 -Stdout '' -Stderr 'WARNING: arbitrary warning only') { throw 'An arbitrary stderr warning was incorrectly accepted as authentication.' }
    if (Test-GadeCodexChatGPTLogin -ExitCode 1 -Stdout 'Logged in using ChatGPT' -Stderr '') { throw 'A successful-looking message with nonzero exit was incorrectly accepted.' }
    if (-not (Test-GadeCodexChatGPTLogin -ExitCode 0 -Stdout '' -Stderr 'Logged in using ChatGPT')) { throw 'A valid stderr authentication status was rejected.' }

    foreach ($scriptPath in @(
        (Join-Path $PSScriptRoot 'Invoke-GadeL3D7D1Host.ps1'),
        (Join-Path $PSScriptRoot 'GadeCodexCli.ps1'),
        $PSCommandPath
    )) {
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count -gt 0) {
            throw "PowerShell 5.1 parser errors in '$scriptPath': $($parseErrors.Message -join '; ')"
        }
    }

    Write-Output 'CODEX_CLI_PREFLIGHT_TEST=PASS path_precedence=PASS app_fallback=PASS missing_cli_fail_closed=PASS'
    Write-Output 'CODEX_EXEC_ARGUMENTS=PASS new_exec_keeps_color_and_read_only_sandbox resume_omits_unsupported_color_sandbox_cd ephemeral_preserved'
    Write-Output 'CODEX_RESUME_HELP=PASS --color_not_supported_by_installed_resume_command'
    Write-Output 'CHATGPT_LOGIN_CHANNEL_TEST=PASS stdout_or_stderr=accepted exit_code_required=true arbitrary_warning_rejected=true'
    Write-Output ("LIVE_LOGIN_MESSAGE_CHANNEL=" + $loginMessageChannel)
    Write-Output ("INSTALLED_CLI_VERSION=" + $version.Stdout.Trim())
    Write-Output 'LOGIN_STATUS=PASS (read-only; no LLM request sent)'
    Write-Output 'POWERSHELL_5_1_AST=PASS runner_helper_test=0_errors'
} finally {
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
