Set-StrictMode -Version Latest

function ConvertTo-GadeOracleText {
    param([AllowNull()]$Value)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @($Value)) {
        if ($null -eq $item) { continue }
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            if ($null -ne $item.Exception) { $parts.Add([string]$item.Exception.Message) }
            $parts.Add([string]$item.ToString())
        } else {
            $parts.Add([string]$item)
        }
    }
    return ($parts -join "`n")
}

function Get-GadeOracleField {
    param([AllowNull()]$Object,[Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-GadeOracleExitCode {
    param([AllowNull()]$Result)
    $raw = Get-GadeOracleField -Object $Result -Name 'ExitCode'
    $parsed = 0
    if ($null -eq $raw -or -not [int]::TryParse([string]$raw,[ref]$parsed)) { return $null }
    return $parsed
}

function Test-GadeMigration037PreconditionOutcome {
    [CmdletBinding()]
    param(
        [AllowNull()]$Attempt,
        [AllowNull()]$SchemaCheck,
        [Parameter(Mandatory = $true)][bool]$TargetIdentityValid
    )

    if (-not $TargetIdentityValid) {
        return [pscustomobject]@{ Pass=$false; Reason='target_identity_mismatch' }
    }

    $attemptExit = Get-GadeOracleExitCode -Result $Attempt
    if ($null -eq $attemptExit -or $attemptExit -ne 3) {
        return [pscustomobject]@{ Pass=$false; Reason="unexpected_sql_exit:$attemptExit" }
    }

    $attemptOutput = ConvertTo-GadeOracleText (Get-GadeOracleField $Attempt 'Stdout')
    $attemptError = ConvertTo-GadeOracleText (Get-GadeOracleField $Attempt 'Stderr')
    $diagnostic = $attemptOutput + "`n" + $attemptError
    $expectedReason = '(?is)\bMigration\s+037\s+requires\s+migration\s+036\s+validation_coverage\s+varchar\s*\(\s*24\s*\)\s+NOT\s+NULL\b'
    if (-not [regex]::IsMatch($diagnostic,$expectedReason)) {
        return [pscustomobject]@{ Pass=$false; Reason='expected_migration036_prerequisite_error_missing' }
    }

    $schemaExit = Get-GadeOracleExitCode -Result $SchemaCheck
    if ($null -eq $schemaExit -or $schemaExit -ne 0) {
        return [pscustomobject]@{ Pass=$false; Reason="schema_check_failed:$schemaExit" }
    }
    $schemaOutput = ConvertTo-GadeOracleText (Get-GadeOracleField $SchemaCheck 'Stdout')
    $rows = @($schemaOutput -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
    if ($rows.Count -ne 1 -or $rows[0] -cne 'NULL|NULL') {
        return [pscustomobject]@{ Pass=$false; Reason='partial_migration037_schema_detected' }
    }

    return [pscustomobject]@{ Pass=$true; Reason='expected_prerequisite_rejection_and_no_partial_schema' }
}
