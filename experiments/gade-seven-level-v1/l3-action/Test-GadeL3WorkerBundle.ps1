[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RepositoryRoot,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw "This compatibility test must run under Windows PowerShell 5.1; found $($PSVersionTable.PSVersion)."
}
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$evidence = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$tar = (Get-Command tar.exe -ErrorAction Stop).Source
$id = [guid]::NewGuid().ToString('N')
$tempRoot = Join-Path $env:TEMP "gade-l3-tar-$id"
$bundle = Join-Path $tempRoot 'bundle'
$extract = Join-Path $tempRoot 'extract'
New-Item -ItemType Directory -Path (Join-Path $bundle 'app'), (Join-Path $bundle 'kali_worker'), $extract -Force | Out-Null
$relativeFiles = @('app/action_contracts.py','kali_worker/app.py')
try {
    foreach ($relative in $relativeFiles) {
        $source = Join-Path $root ($relative.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required bundle input missing: $relative" }
        $destination = Join-Path $bundle ($relative.Replace('/', '\'))
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $archive = Join-Path $tempRoot 'worker.tar.gz'
    $createOut = Join-Path $evidence 'local-tar-selftest-create.stdout.log'
    $createErr = Join-Path $evidence 'local-tar-selftest-create.stderr.log'
    $args = '-czf "' + $archive + '" -C "' + $bundle + '" ' + ($relativeFiles -join ' ')
    $created = Start-Process -FilePath $tar -ArgumentList $args -WorkingDirectory $bundle -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $createOut -RedirectStandardError $createErr
    if ($created.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw "tar create self-test failed exit=$($created.ExitCode). See $createErr"
    }
    $listOut = Join-Path $evidence 'local-tar-selftest-list.stdout.log'
    $listErr = Join-Path $evidence 'local-tar-selftest-list.stderr.log'
    $listed = Start-Process -FilePath $tar -ArgumentList ('-tzf "' + $archive + '"') -WorkingDirectory $bundle `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $listOut -RedirectStandardError $listErr
    if ($listed.ExitCode -ne 0) { throw "tar list self-test failed exit=$($listed.ExitCode). See $listErr" }
    $members = @([IO.File]::ReadAllLines($listOut) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    if ($members.Count -ne 2 -or $members[0] -cne $relativeFiles[0] -or $members[1] -cne $relativeFiles[1]) {
        throw 'tar self-test archive member set was not the exact two-source allowlist.'
    }
    $extractOut = Join-Path $evidence 'local-tar-selftest-extract.stdout.log'
    $extractErr = Join-Path $evidence 'local-tar-selftest-extract.stderr.log'
    $unpacked = Start-Process -FilePath $tar -ArgumentList ('-xzf "' + $archive + '" -C "' + $extract + '"') `
        -WorkingDirectory $bundle -NoNewWindow -Wait -PassThru -RedirectStandardOutput $extractOut -RedirectStandardError $extractErr
    if ($unpacked.ExitCode -ne 0) { throw "tar extract self-test failed exit=$($unpacked.ExitCode). See $extractErr" }
    $hashes = [ordered]@{}
    foreach ($relative in $relativeFiles) {
        $expected = (Get-FileHash -LiteralPath (Join-Path $bundle ($relative.Replace('/', '\'))) -Algorithm SHA256).Hash.ToLowerInvariant()
        $actualPath = Join-Path $extract ($relative.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $actualPath -PathType Leaf)) { throw "tar extraction omitted $relative" }
        $actual = (Get-FileHash -LiteralPath $actualPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $expected) { throw "tar extraction hash mismatch for $relative" }
        $hashes[$relative] = $actual
    }
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $record = [ordered]@{status='PASS';powershell=$PSVersionTable.PSVersion.ToString();tar_path=$tar;archive_sha256=$archiveHash;members=$members;files=$hashes;remote_side_effects=$false}
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'local-tar-selftest.json') -Encoding UTF8
    Write-Output "LOCAL_TAR_SELFTEST=PASS powershell=$($PSVersionTable.PSVersion) members=$($members.Count) archive_sha256=$archiveHash remote_side_effects=false"
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
