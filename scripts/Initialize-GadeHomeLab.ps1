[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$TargetHost,
    [Parameter(Mandatory=$true)][string]$WorkerHost,
    [Parameter(Mandatory=$true)][string]$IngressSubnet,
    [Parameter(Mandatory=$true)][string]$IngressGateway,
    [Parameter(Mandatory=$true)][string]$ImageName,
    [Parameter(Mandatory=$true)][string]$TargetEnvFile,
    [Parameter(Mandatory=$true)][string]$BlueEnvFile,
    [Parameter(Mandatory=$true)][string]$ComponentEnvFile,
    [string]$ComposeProject = 'gade-a-d7-home'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertTo-GadeIPv4 {
    param([Parameter(Mandatory=$true)][string]$Value,[Parameter(Mandatory=$true)][string]$Name)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Name must be an IPv4 address."
    }
    $octets = $Value.Split('.') | ForEach-Object { [int]$_ }
    if ($octets[0] -eq 0 -or $octets[0] -eq 127 -or $octets[0] -ge 224 -or
        ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 0 -and $octets[2] -eq 2) -or
        ($octets[0] -eq 198 -and $octets[1] -eq 51 -and $octets[2] -eq 100) -or
        ($octets[0] -eq 203 -and $octets[1] -eq 0 -and $octets[2] -eq 113)) {
        throw "$Name must be a real, locally assigned lab IPv4 address; documentation/reserved addresses are rejected."
    }
    return $parsed
}

function Test-GadeIPv4InCidr {
    param([Parameter(Mandatory=$true)][Net.IPAddress]$Address,[Parameter(Mandatory=$true)][string]$Cidr)
    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $network = $null
    $prefix = 0
    if (-not [Net.IPAddress]::TryParse($parts[0],[ref]$network) -or
        $network.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        -not [int]::TryParse($parts[1],[ref]$prefix) -or $prefix -lt 16 -or $prefix -gt 28) { return $false }
    $addressBytes = $Address.GetAddressBytes()
    $networkBytes = $network.GetAddressBytes()
    for ($i=0; $i -lt 4; $i++) {
        $bits = [Math]::Min(8,[Math]::Max(0,$prefix - ($i * 8)))
        if ($bits -eq 0) { continue }
        $mask = (0xff -shl (8 - $bits)) -band 0xff
        if (($addressBytes[$i] -band $mask) -ne ($networkBytes[$i] -band $mask)) { return $false }
    }
    return $true
}

if ($ComposeProject -notmatch '^[a-z0-9][a-z0-9_-]{2,40}$') { throw 'ComposeProject must be a short lowercase Compose project label.' }
if ($ImageName -notmatch '^[a-z0-9][a-z0-9._:/-]{2,120}$') { throw 'ImageName contains unsupported characters.' }

$targetAddress = ConvertTo-GadeIPv4 -Value $TargetHost -Name 'TargetHost'
$workerAddress = ConvertTo-GadeIPv4 -Value $WorkerHost -Name 'WorkerHost'
$gatewayAddress = ConvertTo-GadeIPv4 -Value $IngressGateway -Name 'IngressGateway'
if (-not (Test-GadeIPv4InCidr -Address $gatewayAddress -Cidr $IngressSubnet)) {
    throw 'IngressGateway must be inside IngressSubnet.'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$hostAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { $_.IPAddress })
if ($TargetHost -notin $hostAddresses) { throw 'TargetHost must be assigned to this workstation before generating the Host-only published binding.' }

$targetEnv = [IO.Path]::GetFullPath($TargetEnvFile)
$blueEnv = [IO.Path]::GetFullPath($BlueEnvFile)
$componentEnv = [IO.Path]::GetFullPath($ComponentEnvFile)
foreach ($path in @($targetEnv,$blueEnv,$componentEnv)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required private local environment file is missing: $path" }
    if ($path -notlike "$repo*") { throw 'Private environment files must remain inside this local repository folder and ignored by Git.' }
}

$outputs = @(
    (Join-Path $repo 'compose.gade-a-d7.yml'),
    (Join-Path $repo 'lab\mode-b-target\nginx.gade-a-d7.conf'),
    (Join-Path $repo 'lab\mode-b-target\nuclei-target-truth-v1.json')
)
foreach ($path in $outputs) {
    if (Test-Path -LiteralPath $path) { throw "Refusing to overwrite existing local lab configuration: $path" }
}

$composeTemplate = [IO.File]::ReadAllText((Join-Path $repo 'compose.gade-a-d7.template.yml'))
$nginxTemplate = [IO.File]::ReadAllText((Join-Path $repo 'lab\mode-b-target\nginx.gade-a-d7.conf.template'))
$truthTemplate = [IO.File]::ReadAllText((Join-Path $repo 'lab\mode-b-target\nuclei-target-truth-v1.template.json'))
$nginx = $nginxTemplate.Replace('__GADE_A_D7_HOST_SOURCE_IP__',$TargetHost).Replace('__GADE_A_D7_WORKER_SOURCE_IP__',$WorkerHost).Replace('__GADE_A_D7_INGRESS_GATEWAY__',$IngressGateway)
$truth = $truthTemplate.Replace('__GADE_SCENARIO_B_TARGET_HOST__',$TargetHost).Replace('__GADE_SCENARIO_B_SCOPE__',"$TargetHost/32")
$truthObject = $truth | ConvertFrom-Json -ErrorAction Stop
if ($truthObject.target -cne "$TargetHost`:18080" -or $truthObject.scope -cne "$TargetHost/32") {
    throw 'Rendered Scenario B truth contract differs from the selected exact target scope.'
}
$hashProvider = [Security.Cryptography.SHA256]::Create()
try { $truthHash = -join ($hashProvider.ComputeHash([Text.Encoding]::UTF8.GetBytes($truth)) | ForEach-Object { $_.ToString('x2') }) }
finally { $hashProvider.Dispose() }
if ($nginx.Contains('__GADE_') -or $truth.Contains('__GADE_')) {
    throw 'A generated template still contains an unresolved placeholder or office-specific address.'
}

[IO.File]::WriteAllText($outputs[0],$composeTemplate,(New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText($outputs[1],$nginx,(New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText($outputs[2],$truth,(New-Object Text.UTF8Encoding($false)))

$env:GADE_A_D7_HOST_BIND_IP = $TargetHost
$env:GADE_A_D7_HOST_PORT = '18081'
$env:GADE_A_D7_INGRESS_SUBNET = $IngressSubnet
$env:GADE_A_D7_INGRESS_GATEWAY = $IngressGateway
$env:GADE_A_D7_IMAGE = $ImageName
$env:GADE_A_D7_COMPOSE_PROJECT = $ComposeProject
$env:GADE_A_D7_TARGET_ENV_FILE = $targetEnv
$env:GADE_A_D7_BLUE_ENV_FILE = $blueEnv
$env:GADE_A_D7_COMPONENT_ENV_FILE = $componentEnv
$env:GADE_A_D7_COMPOSE_FILE = $outputs[0]
$env:GADE_OFFICE_DOCKER_LAB = '1'
$env:GADE_OFFICE_DOCKER_LAB_TARGET = $TargetHost
$env:GADE_OFFICE_DOCKER_LAB_PORT = '18081'
$env:GADE_LAB_TARGET_HOST = $TargetHost
$env:GADE_LAB_TARGET_PORT = '18081'
$env:GADE_LAB_TARGET_SCOPE = "$TargetHost/32"
$env:GADE_SCENARIO_B_TARGET_HOST = $TargetHost
$env:GADE_SCENARIO_B_TARGET_TRUTH_SHA256 = $truthHash
$env:GADE_KALI_WORKER_HOST = $WorkerHost
$env:GADE_L3_EXPECTED_WORKER_URL = "http://${WorkerHost}:8001"

Write-Output 'HOME_LAB_CONFIGURATION=GENERATED; no credentials were read or created.'
Write-Output "COMPOSE=$($outputs[0])"
Write-Output "NGINX_CONFIG=$($outputs[1])"
Write-Output "SCENARIO_B_TRUTH=$($outputs[2])"
Write-Output "SCENARIO_B_TRUTH_SHA256=$truthHash"
Write-Output 'NEXT: inspect local files and Docker Compose config; do not run Pilot until source/runtime compatibility is frozen.'
