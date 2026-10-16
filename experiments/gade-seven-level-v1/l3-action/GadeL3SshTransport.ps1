function Invoke-GadeInteractiveNativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$ArgumentList,
        [Parameter(Mandatory=$true)][string]$StderrLogPath
    )

    $logParent = Split-Path -Parent $StderrLogPath
    if (-not (Test-Path -LiteralPath $logParent -PathType Container)) {
        throw "SCP diagnostic log directory does not exist: $logParent"
    }

    $startedUtc = [DateTime]::UtcNow.ToString('o')
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = $FilePath
    $process.StartInfo.Arguments = $ArgumentList
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $false
    # Keep stdin and stdout attached to the interactive host so OpenSSH's
    # password prompt remains usable. Read stderr character-by-character so
    # its no-newline password prompt is both displayed and preserved.
    $process.StartInfo.RedirectStandardError = $true
    $writer = $null
    $exitCode = $null
    $failure = $null
    try {
        $writer = New-Object System.IO.StreamWriter($StderrLogPath, $false, (New-Object System.Text.UTF8Encoding($false)))
        $writer.AutoFlush = $true
        $writer.WriteLine("started_utc=$startedUtc")
        $writer.WriteLine("executable=$FilePath")
        $writer.WriteLine("arguments=$ArgumentList")
        $writer.WriteLine('--- native stderr begins ---')

        if (-not $process.Start()) { throw "Could not start native process: $FilePath" }
        while (($character = $process.StandardError.Read()) -ge 0) {
            $value = [char]$character
            [Console]::Error.Write($value)
            $writer.Write($value)
        }
        $process.WaitForExit()
        $exitCode = $process.ExitCode
    } catch {
        $failure = $_.Exception.Message
        if ($null -ne $writer) { $writer.WriteLine("runner_exception=$failure") }
        throw
    } finally {
        if ($null -ne $writer) {
            $writer.WriteLine('--- native stderr ends ---')
            $writer.WriteLine("completed_utc=$([DateTime]::UtcNow.ToString('o'))")
            $writer.WriteLine("exit_code=$exitCode")
            $writer.Dispose()
        }
        $process.Dispose()
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        StderrLogPath = $StderrLogPath
        StartedUtc = $startedUtc
        Failure = $failure
    }
}

function Invoke-GadeCapturedNativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string]$ArgumentList
    )

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName = $FilePath
    $process.StartInfo.Arguments = $ArgumentList
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $process.StartInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    try {
        if (-not $process.Start()) { throw "Could not start native process: $FilePath" }
        # Drain both streams concurrently. This avoids deadlock and avoids
        # PowerShell 5.1 promoting native stderr lines to NativeCommandError.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    } finally {
        $process.Dispose()
    }
}
