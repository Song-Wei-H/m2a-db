function Get-GadeCodexExecArgumentList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Model,
        [AllowEmptyString()][string]$SessionId = '',
        [switch]$PersistentSession,
        [Parameter(Mandatory=$true)][string]$SchemaPath,
        [Parameter(Mandatory=$true)][string]$ResponsePath,
        [Parameter(Mandatory=$true)][string]$AgentDirectory
    )

    $isResume = -not [string]::IsNullOrWhiteSpace($SessionId)
    $arguments = @('exec')
    if ($isResume) {
        $arguments += @('resume', $SessionId)
    } elseif (-not $PersistentSession) {
        $arguments += '--ephemeral'
    }

    $arguments += @('--model', $Model, '--json')
    # Codex CLI exposes --color on `exec`, but not on `exec resume`.
    if (-not $isResume) { $arguments += @('--color', 'never') }
    if (-not $isResume) { $arguments += @('--sandbox', 'read-only') }
    $arguments += @('--ignore-user-config', '--disable', 'shell_tool', '--disable', 'apps', '--disable', 'multi_agent', '--disable', 'remote_plugin',
        '-c', 'web_search="disabled"', '--skip-git-repo-check')
    if (-not $isResume) { $arguments += @('--cd', $AgentDirectory) }
    $arguments += @('--output-schema', $SchemaPath, '--output-last-message', $ResponsePath, '-')
    return $arguments
}

function Resolve-GadeCodexCliExecutable {
    [CmdletBinding()]
    param(
        [string]$PathExecutable,
        [string]$LocalAppDataPath,
        [switch]$SkipPathLookup
    )

    if ([string]::IsNullOrWhiteSpace($PathExecutable) -and -not $SkipPathLookup) {
        $pathCommand = Get-Command codex.exe -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $pathCommand -and -not [string]::IsNullOrWhiteSpace([string]$pathCommand.Source)) {
            $PathExecutable = [string]$pathCommand.Source
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PathExecutable) -and
        (Test-Path -LiteralPath $PathExecutable -PathType Leaf)) {
        return (Get-Item -LiteralPath $PathExecutable).FullName
    }

    if ([string]::IsNullOrWhiteSpace($LocalAppDataPath)) {
        $LocalAppDataPath = $env:LOCALAPPDATA
    }
    if ([string]::IsNullOrWhiteSpace($LocalAppDataPath)) {
        throw 'Codex CLI executable was not found on PATH, and LOCALAPPDATA is unavailable.'
    }

    $installRoot = Join-Path $LocalAppDataPath 'OpenAI\Codex\bin'
    if (Test-Path -LiteralPath $installRoot -PathType Container) {
        $candidates = @(
            Get-ChildItem -LiteralPath $installRoot -Directory -ErrorAction Stop |
                ForEach-Object {
                    $candidatePath = Join-Path $_.FullName 'codex.exe'
                    if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
                        Get-Item -LiteralPath $candidatePath
                    }
                } |
                Sort-Object -Property LastWriteTimeUtc -Descending
        )
        if ($candidates.Count -gt 0) {
            return $candidates[0].FullName
        }
    }

    throw "Codex CLI executable was not found. Checked PATH and the Codex Desktop install directory '$installRoot'."
}

function Test-GadeCodexChatGPTLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][int]$ExitCode,
        [string]$Stdout,
        [string]$Stderr
    )

    if ($ExitCode -ne 0) { return $false }
    $combinedOutput = ([string]$Stdout) + "`n" + ([string]$Stderr)
    return ($combinedOutput -match '(?m)^\s*Logged in using ChatGPT\s*$')
}
