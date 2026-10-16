#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$RunnerPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)

# Parse only: never dot-source or invoke the deployment runner.
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or
    $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Run this regression with Windows PowerShell 5.1 (powershell.exe).'
}
if ([string]::IsNullOrWhiteSpace($RunnerPath)) {
    $RunnerPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Invoke-GadeL2D7D1Host.ps1'
}

function Assert-RunnerEncodingAndSyntax([string]$Path, [switch]$CheckCanonicalPaths) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $bytes = [IO.File]::ReadAllBytes($resolved)
    if ($bytes.Length -lt 3 -or $bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191) {
        throw 'UTF8_BOM_REQUIRED: Windows PowerShell 5.1 must not infer the ANSI encoding.'
    }
    $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
    $decoded = $strictUtf8.GetString($bytes, 3, $bytes.Length - 3)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $resolved, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        $details = @($parseErrors | ForEach-Object {
            '{0}:{1}: {2}' -f $_.Extent.StartLineNumber, $_.ErrorId, $_.Message
        }) -join [Environment]::NewLine
        throw ('POWERSHELL_5_1_PARSE_FAILED: ' + $details)
    }
    $inputTokens = $null
    $inputErrors = $null
    [System.Management.Automation.Language.Parser]::ParseInput(
        $decoded, [ref]$inputTokens, [ref]$inputErrors) | Out-Null
    if ($inputErrors.Count -ne 0) { throw 'Decoded UTF-8 source has a syntax error.' }

    $topTry = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.TryStatementAst]
    })
    if ($topTry.Count -ne 1 -or $topTry[0].CatchClauses.Count -ne 1 -or $null -eq $topTry[0].Finally) {
        throw 'The deployment runner top-level Try/Catch/Finally structure is incomplete.'
    }

    $canonicalPaths = @()
    if ($CheckCanonicalPaths) {
        # ASCII base64 expectations keep the test independent of source decoding.
        $expectedBase64 = @(
            'QzpcVXNlcnNccDIxNjZcRG9jdW1lbnRzXENoYXRHUFRc57i96KaP5YmHXDAzIOWwiOahiO+8iFByb2plY3Rz77yJXE0yQSDlsIjmoYjvvIhNMkHvvIk=',
            'TTJBIOWft+ihjOaJi+WGiu+8iE0yQSBSdW5ib29r77yJLm1k',
            'TTJBIOW7uue9ruatt+WPsu+8iE0yQSBCdWlsZCBIaXN0b3J577yJLm1k',
            'TTJBIOW3suefpeWVj+mhjO+8iE0yQSBLbm93biBJc3N1ZXPvvIkubWQ=',
            '5aCx5ZGK77yITTJBIEdBREUgQm91bmRhcnkgRXhwZXJpbWVudCBEZXNpZ24gMjAyNjA4MjDvvIkubWQ='
        )
        $expectedStrings = @($expectedBase64 | ForEach-Object {
            $strictUtf8.GetString([Convert]::FromBase64String($_))
        })
        $literals = @($ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
        }, $true) | ForEach-Object Value)
        foreach ($expected in $expectedStrings) {
            $literalMatches = @($literals | Where-Object {
                [string]::Equals($_, $expected, [StringComparison]::Ordinal)
            })
            if ($literalMatches.Count -lt 1) { throw ('Canonical Unicode literal mismatch: ' + $expected) }
        }
        foreach ($leaf in $expectedStrings[1..4]) {
            $fullPath = Join-Path $expectedStrings[0] $leaf
            if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
                throw ('Canonical Obsidian file is missing: ' + $fullPath)
            }
            $canonicalPaths += $fullPath
        }
    }
    return [pscustomobject]@{
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition = $PSVersionTable.PSEdition
        RunnerPath = $resolved
        Encoding = 'UTF-8 BOM'
        StrictUtf8 = 'PASS'
        ParseErrors = $parseErrors.Count
        TryCatchFinally = 'PASS'
        CanonicalPaths = $canonicalPaths
        RunnerSha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

$result = Assert-RunnerEncodingAndSyntax -Path $RunnerPath -CheckCanonicalPaths
$fixture = [IO.Path]::GetTempFileName()
try {
    $runnerBytes = [IO.File]::ReadAllBytes($result.RunnerPath)
    $withoutBom = New-Object byte[] ($runnerBytes.Length - 3)
    [Array]::Copy($runnerBytes, 3, $withoutBom, 0, $withoutBom.Length)
    [IO.File]::WriteAllBytes($fixture, $withoutBom)
    $rejected = $false
    try {
        Assert-RunnerEncodingAndSyntax -Path $fixture | Out-Null
    } catch {
        if ($_.Exception.Message -notlike 'UTF8_BOM_REQUIRED:*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'The missing-BOM negative control was incorrectly accepted.' }
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Force }
}

$result | Add-Member -NotePropertyName MissingBomNegativeControl -NotePropertyValue 'PASS'
$result | Add-Member -NotePropertyName DeploymentOrExperimentExecuted -NotePropertyValue $false
$result | ConvertTo-Json -Depth 5
