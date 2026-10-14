$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$runner = Join-Path $PSScriptRoot 'Invoke-LearningFeedbackPg16Integration.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Runner parse failed: $($parseErrors[0].Message)" }
$functionAst = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-JsonAtomic' },$true)
if (-not $functionAst) { throw 'Write-JsonAtomic function not found.' }
. ([scriptblock]::Create($functionAst.Extent.Text))
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("gade-json-atomic-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $checkpoint = Join-Path $testRoot 'checkpoint.json'
    Write-JsonAtomic $checkpoint ([ordered]@{run_id='unit-test'; current_phase='FIRST'; status='running'})
    Write-JsonAtomic $checkpoint ([ordered]@{run_id='unit-test'; current_phase='SECOND'; status='running'; retained='yes'})
    $loaded = Get-Content -LiteralPath $checkpoint -Raw | ConvertFrom-Json
    if ($loaded.current_phase -ne 'SECOND' -or $loaded.retained -ne 'yes' -or $loaded.run_id -ne 'unit-test') {
        throw 'Atomic replacement did not preserve the latest complete checkpoint JSON.'
    }
    $leftovers = @(Get-ChildItem -LiteralPath $testRoot -File | Where-Object { $_.Extension -in @('.tmp','.bak') })
    if ($leftovers.Count -ne 0) { throw "Atomic writer left temporary artifacts after success: $($leftovers.Name -join ', ')" }
    'ATOMIC_JSON_WRITER=PASS initial-create=PASS replace-existing=PASS reload=PASS no-temp-or-backup=PASS'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}