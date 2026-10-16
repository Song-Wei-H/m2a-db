[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$expectedBranch = 'experiment/gade-seven-level-v1'
$targetName = 'm2a-mode-b-target'
$sidecarName = 'm2a-mode-b-l2-auth'
$networkName = 'm2a-mode-b-lab'
$composeFile = Join-Path $repo 'compose.mode-b-target.yml'
$configFile = Join-Path $PSScriptRoot '.env.l2.local'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$validator = Join-Path $PSScriptRoot 'validate_l3_target.py'
$sidecarImage = 'm2a-mode-b-l2-auth:local'
$baseImage = 'python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4'
$targetAddress = '10.56.66.119'
$targetPort = '18080'
$runId = [guid]::NewGuid().ToString('N').Substring(0,12).ToLowerInvariant()
$output = Join-Path $repo "reports\experiments\gade-seven-level-v1\l3-target\local-only\$runId"
$rollbackTag = "m2a-mode-b-l2-auth:l3-rollback-$runId"
$priorSidecarImageId = $null
$sidecarWasRecreated = $false

function Write-JsonAtomic([string]$Path, $Value) {
    $temporary = "$Path.tmp"
    $json = ConvertTo-Json -InputObject $Value -Depth 24
    [System.IO.File]::WriteAllText($temporary, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Write-HashManifest {
    $hashRows=@()
    Get-ChildItem -LiteralPath $output -File | Where-Object { $_.Name -ne 'sha256-manifest.json' } | ForEach-Object {
        $hashRows += [pscustomobject]@{ path=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); bytes=$_.Length }
    }
    Write-JsonAtomic (Join-Path $output 'sha256-manifest.json') ([ordered]@{ self_hash_excluded=$true; files=$hashRows })
}

function Quote-NativeArgument([string]$Value) {
    if ($Value -match '[\s"]') { return '"' + $Value.Replace('"','\"') + '"' }
    return $Value
}

function Invoke-Native([string]$Executable, [string[]]$Arguments, [string]$Label) {
    $stdoutPath = Join-Path $output "$Label.stdout.log"
    $stderrPath = Join-Path $output "$Label.stderr.log"
    $argumentLine = (($Arguments | ForEach-Object { Quote-NativeArgument ([string]$_) }) -join ' ')
    $process = Start-Process -FilePath $Executable -ArgumentList $argumentLine -WorkingDirectory $repo `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
        Stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    }
}

function Invoke-Docker([string[]]$Arguments, [string]$Label) {
    $docker = (Get-Command docker.exe -ErrorAction Stop).Source
    $result = Invoke-Native $docker $Arguments $Label
    if ($result.ExitCode -ne 0) {
        $message = ([string]$result.Stderr).Trim()
        if ([string]::IsNullOrWhiteSpace($message)) { $message = ([string]$result.Stdout).Trim() }
        throw "docker $($Arguments[0]) failed exit=$($result.ExitCode): $message"
    }
    return $result
}

function Get-ContainerSafe([string]$Name, [string]$Label) {
    $format = '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{json .Config.Labels}}|{{json .NetworkSettings.Networks}}|{{json .NetworkSettings.Ports}}'
    $result = Invoke-Docker @('inspect','--format',$format,$Name) $Label
    $parts = ([string]$result.Stdout).Trim() -split '\|', 7
    if ($parts.Count -ne 7) { throw "Could not parse safe Docker identity for $Name." }
    $labels = if ($parts[4] -and $parts[4] -ne '<nil>') { $parts[4] | ConvertFrom-Json } else { $null }
    $networks = if ($parts[5] -and $parts[5] -ne '<nil>') { $parts[5] | ConvertFrom-Json } else { $null }
    $ports = if ($parts[6] -and $parts[6] -ne '<nil>') { $parts[6] | ConvertFrom-Json } else { $null }
    return [pscustomobject]@{ Id=$parts[0]; Name=$parts[1].TrimStart('/'); Image=$parts[2]; State=$parts[3]; Labels=$labels; Networks=$networks; Ports=$ports }
}

function Assert-ContainerIdentity($Container, [string]$Name, [string]$Service) {
    if ($Container.Name -cne $Name -or $Container.State -cne 'running') { throw "Expected running container identity mismatch: $Name." }
    if ($null -eq $Container.Labels -or $Container.Labels.'com.docker.compose.service' -cne $Service) {
        throw "Compose service label mismatch for $Name."
    }
    if ($null -eq $Container.Networks -or $null -eq $Container.Networks.PSObject.Properties[$networkName]) {
        throw "Expected lab network is not attached to $Name."
    }
}

function Get-ImageIdentity([string]$Reference, [string]$Label) {
    $format = '{{.Id}}|{{json .RepoDigests}}'
    $result = Invoke-Docker @('image','inspect','--format',$format,$Reference) $Label
    $parts = ([string]$result.Stdout).Trim() -split '\|', 2
    if ($parts.Count -ne 2) { throw "Could not parse image identity for $Reference." }
    return [pscustomobject]@{ Id=$parts[0]; RepoDigests=($parts[1] | ConvertFrom-Json) }
}

function Assert-LabPort($Container) {
    $property = $Container.Ports.PSObject.Properties['8080/tcp']
    if ($null -eq $property -or $null -eq $property.Value -or $property.Value.Count -ne 1) {
        throw 'Target published port mapping is missing or ambiguous.'
    }
    $binding = $property.Value[0]
    if ($binding.HostIp -cne $targetAddress -or $binding.HostPort -cne $targetPort) {
        throw 'Target published address differs from the authorized isolated lab endpoint.'
    }
}

New-Item -ItemType Directory -Path $output -Force | Out-Null
$manifest = [ordered]@{
    run_id=$runId; started_utc=[DateTime]::UtcNow.ToString('o'); phase='PREFLIGHT'
    branch=$null; target_name=$targetName; target_container_id_before=$null
    sidecar_name=$sidecarName; sidecar_container_id_before=$null
    network=$networkName; scope="$targetAddress/32:$targetPort/tcp"
    operations=@('Build only existing mode-b-l2-auth service from local digest-pinned Python base image with pull disabled',
                 'Back up existing sidecar image tag for rollback',
                 'Force-recreate only m2a-mode-b-l2-auth; do not recreate m2a-mode-b-target',
                 'Run isolated L3 target validation including reset, session rejection, marker inspection, and L1/L2 regression')
    result='PREFLIGHT'
}

try {
    $git = (Get-Command git.exe -ErrorAction Stop).Source
    $branchResult = Invoke-Native $git @('-C',$repo,'rev-parse','--abbrev-ref','HEAD') 'git-branch'
    if ($branchResult.ExitCode -ne 0) { throw 'Could not read Git branch.' }
    $branch = ([string]$branchResult.Stdout).Trim()
    if ($branch -cne $expectedBranch) { throw "Branch guard failed: expected $expectedBranch, found $branch." }
    $manifest.branch = $branch

    foreach ($requiredPath in @($composeFile,$configFile,$python,$validator,(Join-Path $PSScriptRoot 'l2_auth.py'),(Join-Path $PSScriptRoot 'l3_execution_task.py'),(Join-Path $PSScriptRoot 'Dockerfile.l2-auth'),(Join-Path $PSScriptRoot '.dockerignore'))) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) { throw "Required L3 target file is missing: $requiredPath" }
    }

    $docker = (Get-Command docker.exe -ErrorAction Stop).Source
    $target = Get-ContainerSafe $targetName 'target-container-before'
    $sidecar = Get-ContainerSafe $sidecarName 'sidecar-container-before'
    Assert-ContainerIdentity $target $targetName 'mode-b-target'
    Assert-ContainerIdentity $sidecar $sidecarName 'mode-b-l2-auth'
    Assert-LabPort $target
    if ($sidecar.Image -cne $sidecarImage) { throw "Sidecar image reference mismatch: $($sidecar.Image)" }
    $priorImage = Get-ImageIdentity $sidecarImage 'prior-sidecar-image'
    $base = Get-ImageIdentity $baseImage 'base-image-preflight'
    $manifest.target_container_id_before = $target.Id
    $manifest.sidecar_container_id_before = $sidecar.Id
    $manifest.prior_sidecar_image_id = $priorImage.Id
    $manifest.prior_sidecar_image_content_id = $sidecar.Image
    $manifest.base_image_id = $base.Id
    $manifest.base_image_repo_digests = @($base.RepoDigests)
    $manifest.source_sha256 = [ordered]@{
        'lab/mode-b-target/l2_auth.py'=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'l2_auth.py') -Algorithm SHA256).Hash.ToLowerInvariant()
        'lab/mode-b-target/l3_execution_task.py'=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'l3_execution_task.py') -Algorithm SHA256).Hash.ToLowerInvariant()
        'lab/mode-b-target/validate_l3_target.py'=(Get-FileHash -LiteralPath $validator -Algorithm SHA256).Hash.ToLowerInvariant()
        'lab/mode-b-target/Dockerfile.l2-auth'=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Dockerfile.l2-auth') -Algorithm SHA256).Hash.ToLowerInvariant()
        'lab/mode-b-target/.dockerignore'=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot '.dockerignore') -Algorithm SHA256).Hash.ToLowerInvariant()
        'lab/mode-b-target/Invoke-GadeL3TargetHost.ps1'=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Invoke-GadeL3TargetHost.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
        'compose.mode-b-target.yml'=(Get-FileHash -LiteralPath $composeFile -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest.phase='PREFLIGHT_PASS'
    $manifest.result='AWAITING_CONFIRMATION'
    Write-JsonAtomic (Join-Path $output 'run-manifest.json') $manifest

    Write-Output "L3_TARGET_PREFLIGHT=PASS run_id=$runId branch=$branch"
    Write-Output "TARGET=$targetName container_id=$($target.Id) endpoint=http://${targetAddress}:${targetPort} network=$networkName"
    Write-Output "L2_SIDECAR=$sidecarName container_id=$($sidecar.Id) image=$($sidecar.Image) network=$networkName"
    Write-Output "BASE_IMAGE=$baseImage local_image_id=$($base.Id) (no pull permitted)"
    Write-Output 'PLANNED=build only mode-b-l2-auth; backup old sidecar image; recreate only that sidecar; leave Nginx target container ID unchanged; run target reset/session/execute/marker/expiry/L1-L2 checks; save evidence.'
    Write-Output "EVIDENCE=$output"
    $confirmation = Read-Host 'Type exactly DEPLOY-GADE-L3-TARGET to update only the existing L2/L3 target sidecar and run verification'
    if ($confirmation -cne 'DEPLOY-GADE-L3-TARGET') {
        $manifest.result='CANCELLED'; $manifest.completed_utc=[DateTime]::UtcNow.ToString('o')
        Write-JsonAtomic (Join-Path $output 'run-manifest.json') $manifest
        Write-HashManifest
        Write-Output 'CANCELLED; no Docker build, service restart, or target request was made.'
        exit 2
    }

    $manifest.phase='BACKUP_OLD_IMAGE'
    $priorSidecarImageId = $priorImage.Id
    Invoke-Docker @('image','tag',$priorSidecarImageId,$rollbackTag) 'backup-sidecar-image' | Out-Null
    $manifest.rollback_tag=$rollbackTag

    $manifest.phase='BUILD_SIDECAR'
    $build = Invoke-Docker @('compose','-f',$composeFile,'build','--pull=false','mode-b-l2-auth') 'docker-build-sidecar'
    $manifest.build_exit_code=$build.ExitCode
    $newImage = Get-ImageIdentity $sidecarImage 'new-sidecar-image'
    $manifest.new_image_id=$newImage.Id
    $manifest.new_image_repo_digests=@($newImage.RepoDigests)

    $manifest.phase='RECREATE_SIDECAR_ONLY'
    $sidecarWasRecreated=$true
    Invoke-Docker @('compose','-f',$composeFile,'up','-d','--no-deps','--force-recreate','mode-b-l2-auth') 'recreate-l2-sidecar' | Out-Null
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    $health='starting'
    while ([DateTime]::UtcNow -lt $deadline) {
        $healthResult=Invoke-Docker @('inspect','--format','{{.State.Health.Status}}',$sidecarName) 'sidecar-health-poll'
        $health=([string]$healthResult.Stdout).Trim()
        if ($health -ceq 'healthy') { break }
        if ($health -ceq 'unhealthy') { throw 'L2/L3 sidecar reported unhealthy.' }
        Start-Sleep -Seconds 2
    }
    if ($health -cne 'healthy') { throw 'L2/L3 sidecar did not become healthy within 90 seconds.' }
    $newSidecar=Get-ContainerSafe $sidecarName 'sidecar-container-after'
    $targetAfter=Get-ContainerSafe $targetName 'target-container-after'
    Assert-ContainerIdentity $newSidecar $sidecarName 'mode-b-l2-auth'
    Assert-ContainerIdentity $targetAfter $targetName 'mode-b-target'
    Assert-LabPort $targetAfter
    if ($targetAfter.Id -cne $target.Id) { throw 'Target Nginx container changed; refusing to proceed.' }
    $manifest.sidecar_container_id_after=$newSidecar.Id
    $manifest.target_container_id_after=$targetAfter.Id
    $manifest.sidecar_health=$health

    $manifest.phase='LIVE_TARGET_VALIDATION'
    $validation=Invoke-Native $python @('-B',$validator,'--target',"http://${targetAddress}:${targetPort}",'--run-id',$runId,'--config',$configFile,'--output',(Join-Path $output 'l3-target-validation.json')) 'live-target-validation'
    $manifest.validation_exit_code=$validation.ExitCode
    if ($validation.ExitCode -ne 0) { throw "Live L3 target validation failed (exit $($validation.ExitCode)); see live-target-validation.stderr.log." }
    $manifest.validation_stdout=([string]$validation.Stdout).Trim()

    $logs=Invoke-Docker @('logs',$sidecarName) 'l2-sidecar-logs'
    $correlated=@($logs.Stdout -split "`r?`n" | Where-Object { $_ -match [regex]::Escape($runId) })
    [System.IO.File]::WriteAllLines((Join-Path $output 'target-correlated-audit-events.jsonl'),$correlated,(New-Object System.Text.UTF8Encoding($false)))
    $manifest.correlated_audit_line_count=$correlated.Count
    if ($correlated.Count -lt 2) { throw 'Expected target-side audit events correlated to this Run ID were not present in sidecar logs.' }

    $targetFinal=Get-ContainerSafe $targetName 'target-container-final'
    if ($targetFinal.Id -cne $target.Id) { throw 'Target Nginx container identity changed during verification.' }
    $manifest.phase='COMPLETE'
    $manifest.result='PASS'
    $manifest.completed_utc=[DateTime]::UtcNow.ToString('o')
    Write-JsonAtomic (Join-Path $output 'run-manifest.json') $manifest

    Write-HashManifest
    Write-Output "L3_TARGET_VALIDATION=PASS run_id=$runId target_container_unchanged=$($target.Id) sidecar_container=$($newSidecar.Id) image_id=$($newImage.Id) audit_lines=$($correlated.Count) evidence=$output"
}
catch {
    $manifest.result='FAIL'
    $manifest.failure_type=$_.Exception.GetType().FullName
    $manifest.failure=$_.Exception.Message
    $manifest.completed_utc=[DateTime]::UtcNow.ToString('o')
    if ($sidecarWasRecreated -and $priorSidecarImageId) {
        try {
            Invoke-Docker @('image','tag',$priorSidecarImageId,$sidecarImage) 'rollback-restore-image-tag' | Out-Null
            Invoke-Docker @('compose','-f',$composeFile,'up','-d','--no-deps','--force-recreate','mode-b-l2-auth') 'rollback-recreate-sidecar' | Out-Null
            $manifest.rollback_status='attempted_old_image_restored_sidecar_only'
        } catch {
            $manifest.rollback_status='FAILED'
            $manifest.rollback_error=$_.Exception.Message
        }
    }
    try { Write-JsonAtomic (Join-Path $output 'run-manifest.json') $manifest } catch { }
    try { Write-HashManifest } catch { }
    Write-Error "L3 target validation failed phase=$($manifest.phase); evidence=$output; error=$($manifest.failure)"
    exit 1
}
