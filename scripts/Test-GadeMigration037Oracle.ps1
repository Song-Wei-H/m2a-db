$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GadeMigration037Oracle.ps1')

$script:Passed = 0
$script:Failed = 0

function Assert-OracleCase([string]$Name,[bool]$Expected,[scriptblock]$Action) {
    try {
        $actual = & $Action
        if ([bool]$actual -ne $Expected) { throw "expected=$Expected actual=$actual" }
        $script:Passed++
        Write-Host "PASS $Name"
    } catch {
        $script:Failed++
        Write-Host "FAIL $Name :: $($_.Exception.Message)"
    }
}

$goodAttempt = [pscustomobject]@{
    ExitCode=3; Stdout='';
    Stderr="ERROR:  Migration 037 requires migration 036 validation_coverage varchar(24) NOT NULL`r`nCONTEXT: PL/pgSQL function inline_code_block line 18 at RAISE"
}
$cleanSchema = [pscustomobject]@{ ExitCode=0; Stdout="NULL|NULL`r`n"; Stderr='' }

Assert-OracleCase 'A: exit 3 plus expected prerequisite and no partial schema passes' $true {
    (Test-GadeMigration037PreconditionOutcome -Attempt $goodAttempt -SchemaCheck $cleanSchema -TargetIdentityValid $true).Pass
}
Assert-OracleCase 'B: exit 0 fails' $false {
    $attempt=[pscustomobject]@{ ExitCode=0; Stdout=''; Stderr='' }
    (Test-GadeMigration037PreconditionOutcome -Attempt $attempt -SchemaCheck $cleanSchema -TargetIdentityValid $true).Pass
}
Assert-OracleCase 'C: exit 3 with unrelated SQL error fails' $false {
    $attempt=[pscustomobject]@{ ExitCode=3; Stdout=''; Stderr='ERROR: permission denied for schema public' }
    (Test-GadeMigration037PreconditionOutcome -Attempt $attempt -SchemaCheck $cleanSchema -TargetIdentityValid $true).Pass
}
Assert-OracleCase 'D: Docker connection failure fails' $false {
    $attempt=[pscustomobject]@{ ExitCode=125; Stdout=''; Stderr='docker: error during connect: named pipe unavailable' }
    (Test-GadeMigration037PreconditionOutcome -Attempt $attempt -SchemaCheck $cleanSchema -TargetIdentityValid $true).Pass
}
Assert-OracleCase 'E: ErrorRecord and multiline diagnostics parse' $true {
    $exception = New-Object System.Exception("ERROR: Migration 037 requires migration 036 validation_coverage varchar(24) NOT NULL`r`nCONTEXT: inline block")
    $record = New-Object System.Management.Automation.ErrorRecord($exception,'psql.stderr',[System.Management.Automation.ErrorCategory]::NotSpecified,$null)
    $attempt=[pscustomobject]@{ ExitCode=3; Stdout=@(); Stderr=@($record,"CONTEXT: follow-up detail") }
    (Test-GadeMigration037PreconditionOutcome -Attempt $attempt -SchemaCheck $cleanSchema -TargetIdentityValid $true).Pass
}
Assert-OracleCase 'F: any leftover target schema fails' $false {
    $partial=[pscustomobject]@{ ExitCode=0; Stdout="evidence_confidence|NULL`n"; Stderr='' }
    (Test-GadeMigration037PreconditionOutcome -Attempt $goodAttempt -SchemaCheck $partial -TargetIdentityValid $true).Pass
}
Assert-OracleCase 'G: mismatched isolated target fails' $false {
    (Test-GadeMigration037PreconditionOutcome -Attempt $goodAttempt -SchemaCheck $cleanSchema -TargetIdentityValid $false).Pass
}

Write-Host "MIGRATION037_ORACLE_TEST_RESULTS passed=$script:Passed failed=$script:Failed"
if ($script:Failed -ne 0) { exit 1 }
