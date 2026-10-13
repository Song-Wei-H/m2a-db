param(
    [string]$Repository = 'C:\Users\p2166\m2a-db'
)

$ErrorActionPreference = 'Stop'
$expectedBranch = 'experiment/gade-seven-level-v1'
$labName = 'm2a-mode-b-target'
$labIp = '10.56.66.119'
$labPort = 18080
$workerIp = '10.56.64.121'
$workerPort = 8000
$evidenceRoot = Join-Path $Repository 'experiments\gade-seven-level-v1\real-worker-l1\local-only'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$outDir = Join-Path $evidenceRoot $runId
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Record-Step([string]$Name, [scriptblock]$Block) {
    $started = [DateTime]::UtcNow.ToString('o')
    try {
        $value = & $Block
        return @{ name=$Name; status='OBSERVED'; started_utc=$started; value=$value }
    } catch {
        return @{ name=$Name; status='ERROR'; started_utc=$started; error=$_.Exception.Message }
    }
}

$results = [ordered]@{
    run_id = $runId
    mode = 'READ_ONLY_PREFLIGHT'
    expected_lab = @{ name=$labName; ip=$labIp; port=$labPort }
    expected_worker = @{ ip=$workerIp; port=$workerPort }
    steps = @()
    worker_to_lab_reachability = 'NOT_VERIFIED_NO_REMOTE_EXECUTION'
    real_l1_execution = 'NOT_STARTED'
}

$results.steps += Record-Step 'git_identity' {
    $branch = (& git -C $Repository branch --show-current).Trim()
    $head = (& git -C $Repository rev-parse HEAD).Trim()
    $status = @(& git -C $Repository status --porcelain)
    if ($branch -cne $expectedBranch) { throw "Wrong branch: $branch" }
    @{ branch=$branch; head=$head; worktree_clean=($status.Count -eq 0) }
}
$results.steps += Record-Step 'host_lab_ip' {
    $rows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object IPAddress -eq $labIp |
        Select-Object IPAddress,InterfaceAlias,PrefixLength,AddressState)
    @{ exact_ip_present=($rows.Count -gt 0); records=$rows }
}
$results.steps += Record-Step 'lab_container' {
    $raw = & docker inspect $labName 2>&1
    if ($LASTEXITCODE -ne 0) { throw "docker inspect failed: $($raw -join ' ')" }
    $items = @(($raw -join "`n") | ConvertFrom-Json)
    if ($items.Count -ne 1 -or $items[0].Name -cne "/$labName") { throw 'Lab container identity mismatch' }
    $c = $items[0]
    $binding = @($c.NetworkSettings.Ports.'8080/tcp')
    @{ id=$c.Id; name=$c.Name; image=$c.Config.Image; running=$c.State.Running;
       health=$c.State.Health.Status; bindings=$binding; networks=@($c.NetworkSettings.Networks.PSObject.Properties.Name) }
}
$results.steps += Record-Step 'lab_http' {
    $response = Invoke-WebRequest -Uri "http://${labIp}:${labPort}/healthz" -UseBasicParsing -TimeoutSec 5
    @{ status_code=[int]$response.StatusCode; uri=$response.BaseResponse.ResponseUri.AbsoluteUri }
}
$results.steps += Record-Step 'worker_health' {
    $response = Invoke-RestMethod -Uri "http://${workerIp}:${workerPort}/health" -TimeoutSec 5
    @{ status=$response.status; version=$response.version; allowed_tools=@($response.allowed_tools);
       scope_enforced_by_worker=$response.scope_enforced_by_worker }
}
$results.steps += Record-Step 'firewall_profiles' {
    @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction)
}
$results.steps += Record-Step 'firewall_matching_allow_rules' {
    $rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    $matching = foreach ($rule in $rules) {
        $port = $rule | Get-NetFirewallPortFilter
        $address = $rule | Get-NetFirewallAddressFilter
        if ($port.Protocol -eq 'TCP' -and [string]$port.LocalPort -eq [string]$labPort) {
            @{ name=$rule.DisplayName; profile=[string]$rule.Profile; local_port=$port.LocalPort;
               local_address=$address.LocalAddress; remote_address=$address.RemoteAddress }
        }
    }
    @($matching)
}

$path = Join-Path $outDir 'preflight.json'
$results | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding utf8
Write-Output "READ_ONLY_PREFLIGHT_EVIDENCE=$path"
Write-Output 'No Docker, database, firewall, Worker execution, or target configuration was changed.'
