$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$runnerPath = Join-Path $PSScriptRoot '..\experiments\gade-seven-level-v1\l3-action\Invoke-GadeL3D7D1Host.ps1'
$runnerPath = [IO.Path]::GetFullPath($runnerPath)
$tokens = $null
$parseErrors = $null
$runnerAst = [System.Management.Automation.Language.Parser]::ParseFile($runnerPath,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "Runner AST parse failed: $($parseErrors[0].Message)" }
$runnerText = Get-Content -LiteralPath $runnerPath -Raw

$script:assertions = 0
$script:functionAsts = @{}
function Assert-True([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:assertions++
}
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $thrown = $false
    try { & $Action | Out-Null } catch { $thrown = $true }
    Assert-True $thrown $Message
}
Assert-True ($runnerText.Contains('$officeComposeProject = $env:GADE_A_D7_COMPOSE_PROJECT') -and
    $runnerText.Contains('$targetSidecar = if ($OfficeAD7Synthetic) { "$officeComposeProject-gade-a-d7-target-1"') -and
    $runnerText.Contains('$targetSidecar=[string]$sidecarRecord[0].id')) 'Office Runner must use the explicitly selected local Compose project and inspected Target container ID.'

foreach ($name in @('ConvertFrom-GadeDockerContainerIdOutput','ConvertFrom-GadeOfficeDockerInspectOutput','Get-OfficeDockerTopology','Invoke-Docker')) {
    $functionAst = $runnerAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name },$true)
    if ($null -eq $functionAst) { throw "Runner function '$name' is missing." }
    . ([scriptblock]::Create($functionAst.Extent.Text))
    $script:functionAsts[$name] = $functionAst
}

$ids = @()
foreach ($letter in @('a','b','c','d','e','f')) { $ids += ($letter * 64) }
$newline = [string][char]13 + [string][char]10
$crlfIds = ($ids -join $newline) + $newline
$parsedIds = @(ConvertFrom-GadeDockerContainerIdOutput -Output $crlfIds -ExitCode 0)
Assert-True ($parsedIds.Count -eq 6 -and [string]::Join(',', $parsedIds) -ceq [string]::Join(',', $ids)) 'CRLF and multiple project-scoped full IDs must parse in order.'
Assert-Throws { ConvertFrom-GadeDockerContainerIdOutput -Output '' -ExitCode 0 } 'Empty container output must fail closed.'
Assert-Throws { ConvertFrom-GadeDockerContainerIdOutput -Output (($ids[0] + $newline) + 'garbage') -ExitCode 0 } 'Partial/non-canonical container ID output must fail closed.'
$nonAsciiId = -join @([char]0x7532,[char]0x4E59,[char]0x4E19)
Assert-Throws { ConvertFrom-GadeDockerContainerIdOutput -Output (($ids[0] + $newline) + ($nonAsciiId * 24)) -ExitCode 0 } 'Non-ASCII container IDs must fail closed.'
Assert-Throws { ConvertFrom-GadeDockerContainerIdOutput -Output (($ids[0] + $newline) + ('A' * 64)) -ExitCode 0 } 'Non-canonical uppercase container IDs must fail closed.'
Assert-Throws { ConvertFrom-GadeDockerContainerIdOutput -Output (($ids[0] + $newline) + $ids[0]) -ExitCode 0 } 'Duplicate container IDs must fail closed.'
Assert-Throws { ConvertFrom-GadeDockerContainerIdOutput -Output $crlfIds -ExitCode 1 } 'A nonzero Docker list exit code must fail closed even when output is present.'

$serviceNames = @('blue-observer','gade-a-d7-target','node-alpha','node-beta','receiver','target-gateway')
$nonAsciiText = -join @([char]0x5F15,[char]0x865F,[char]0x6A19,[char]0x8A18)
$fixtureCommand = 'print("' + $nonAsciiText + ' ""quoted"" marker")'
$fixtures = @()
for ($i = 0; $i -lt 6; $i++) {
    $fixtures += [pscustomobject]@{
        Id = $ids[$i]
        Config = [pscustomobject]@{
            Cmd = @('python3','-c',$fixtureCommand)
            Labels = [pscustomobject]@{
                'com.docker.compose.service' = $serviceNames[$i]
                'com.docker.compose.project' = 'gade-a-d7-home'
                'com.docker.compose.project.config_files' = 'C:/reviewed/compose.gade-a-d7.yml'
            }
        }
        State = [pscustomobject]@{ Running = $true; Status = 'running'; Health = [pscustomobject]@{ Status = 'healthy' } }
        Image = 'sha256:' + ('1' * 64)
        NetworkSettings = [pscustomobject]@{ Networks = [pscustomobject]@{ 'gade_internal' = [pscustomobject]@{ NetworkID = 'net' } }; Ports = [pscustomobject]@{} }
    }
}
$fixtures[5].NetworkSettings.Ports = [pscustomobject]@{ '8080/tcp' = @([pscustomobject]@{ HostIp = '192.0.2.119'; HostPort = '18081' }) }
$json = (ConvertTo-Json -InputObject $fixtures -Depth 20 -Compress) + $newline
$roundTrip = @(ConvertFrom-GadeOfficeDockerInspectOutput -Output $json -ExitCode 0 -ExpectedIds $ids)
Assert-True ($roundTrip.Count -eq 6) 'A six-container inspect array must parse as six structured objects.'
Assert-True ($roundTrip[0].Config.Cmd[2] -ceq $fixtureCommand) 'Non-ASCII and quoted command content must survive JSON parsing without being used for identity.'
Assert-True ($roundTrip[5].NetworkSettings.Ports.'8080/tcp'[0].HostPort -ceq '18081') 'Structured PortBindings must survive inspect parsing.'

$reordered = @($fixtures[5],$fixtures[2],$fixtures[0],$fixtures[4],$fixtures[1],$fixtures[3])
$reorderedJson = ConvertTo-Json -InputObject $reordered -Depth 20 -Compress
$reorderedRows = @(ConvertFrom-GadeOfficeDockerInspectOutput -Output $reorderedJson -ExitCode 0 -ExpectedIds $ids)
Assert-True ($reorderedRows.Count -eq 6) 'Inspect ordering must not be relied on when verifying the complete container identity set.'
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output '' -ExitCode 0 -ExpectedIds $ids } 'Empty inspect output must fail closed.'
$malformedJson = [string][char]123 + [char]34 + 'Command' + [char]34 + ':' + [char]34 + 'unterminated' + [char]125
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output $malformedJson -ExitCode 0 -ExpectedIds $ids } 'Malformed quoted JSON must fail closed rather than be stripped or ignored.'
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output $json -ExitCode 1 -ExpectedIds $ids } 'A nonzero inspect exit code must fail closed even when JSON is present.'
$partialJson = ConvertTo-Json -InputObject @($fixtures | Select-Object -First 5) -Depth 20 -Compress
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output $partialJson -ExitCode 0 -ExpectedIds $ids } 'Partial inspect data must fail closed.'
$wrongIdentity = @($fixtures | ForEach-Object { $_ | Select-Object * })
$wrongIdentity[0].Id = '9' * 64
$wrongJson = ConvertTo-Json -InputObject $wrongIdentity -Depth 20 -Compress
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output $wrongJson -ExitCode 0 -ExpectedIds $ids } 'Inspect identity mismatch must fail closed.'
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output $json -ExitCode 0 -ExpectedIds @() } 'Inspect without an explicit project-scoped ID allowlist must fail closed.'

$networkParserAst=$runnerAst.Find({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'ConvertFrom-GadeOfficeDockerNetworkInspectOutput'},$true)
if($null -eq $networkParserAst){throw 'Network inspect parser function is missing.'}
. ([scriptblock]::Create($networkParserAst.Extent.Text))
$internalMembers=[ordered]@{}
foreach($id in $ids){$internalMembers[$id]=[pscustomobject]@{Name=('/'+$id)}}
$internalFixture=[pscustomobject]@{Name='gade-a-d7-home_gade-a-d7-internal';Internal=$true;Containers=[pscustomobject]$internalMembers}
$internalJson=ConvertTo-Json -InputObject @($internalFixture) -Depth 20 -Compress
$internalParsed=ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $internalJson -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids
Assert-True ($internalParsed.Internal -eq $true -and $internalParsed.ContainerIds.Count -eq 6) 'Internal network JSON array must preserve all six container IDs in PowerShell 5.1.'
$gatewayMembers=[ordered]@{}
$gatewayMembers[$ids[5]]=[pscustomobject]@{Name='/target-gateway'}
$ingressFixture=[pscustomobject]@{Name='gade-a-d7-home_gade-a-d7-ingress';Internal=$false;Containers=[pscustomobject]$gatewayMembers}
$ingressJson=ConvertTo-Json -InputObject @($ingressFixture) -Depth 20 -Compress
$ingressParsed=ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $ingressJson -ExitCode 0 -ExpectedName $ingressFixture.Name -ExpectedInternal $false -ExpectedContainerIds @($ids[5])
Assert-True ($ingressParsed.Internal -eq $false -and $ingressParsed.ContainerIds.Count -eq 1 -and $ingressParsed.ContainerIds[0] -ceq $ids[5]) 'Ingress network must contain only the reviewed gateway ID.'
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output '' -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Empty network inspect output must fail closed.'
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $internalJson -ExitCode 1 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'A nonzero network inspect exit code must fail closed.'
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $malformedJson -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Malformed network JSON must fail closed.'
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $internalJson -ExitCode 0 -ExpectedName 'wrong-network' -ExpectedInternal $true -ExpectedContainerIds $ids } 'Wrong network identity must fail closed.'
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $internalJson -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $false -ExpectedContainerIds $ids } 'Wrong internal-network flag must fail closed.'
$partialNetwork=[pscustomobject]@{Name=$internalFixture.Name;Internal=$true;Containers=[pscustomobject]@{}}
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output (ConvertTo-Json -InputObject @($partialNetwork) -Depth 10 -Compress) -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Missing network membership must fail closed.'
$unexpectedMembers=[ordered]@{}
foreach($id in $ids){$unexpectedMembers[$id]=[pscustomobject]@{Name=('/'+$id)}}
$unexpectedMembers[('9' * 64)]=[pscustomobject]@{Name='/unexpected'}
$unexpectedNetwork=[pscustomobject]@{Name=$internalFixture.Name;Internal=$true;Containers=[pscustomobject]$unexpectedMembers}
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output (ConvertTo-Json -InputObject @($unexpectedNetwork) -Depth 10 -Compress) -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Unreviewed network members must fail closed.'
$multipleNetworks=ConvertTo-Json -InputObject @($internalFixture,$ingressFixture) -Depth 10 -Compress
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output $multipleNetworks -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Multiple network objects must fail closed when one exact network was requested.'
$upperInspectIdentity = @($fixtures | ForEach-Object { $_ | Select-Object * })
$upperInspectIdentity[0].Id = $ids[0].ToUpperInvariant()
Assert-Throws { ConvertFrom-GadeOfficeDockerInspectOutput -Output (ConvertTo-Json -InputObject $upperInspectIdentity -Depth 20 -Compress) -ExitCode 0 -ExpectedIds $ids } 'Inspect IDs with non-canonical uppercase characters must fail closed.'
$upperNetworkMembers=[ordered]@{}
$upperNetworkMembers[$ids[0].ToUpperInvariant()]=[pscustomobject]@{Name='/uppercase'}
foreach($id in @($ids | Select-Object -Skip 1)){$upperNetworkMembers[$id]=[pscustomobject]@{Name=('/'+$id)}}
$upperNetwork=[pscustomobject]@{Name=$internalFixture.Name;Internal=$true;Containers=[pscustomobject]$upperNetworkMembers}
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output (ConvertTo-Json -InputObject @($upperNetwork) -Depth 10 -Compress) -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Network membership with a non-canonical uppercase ID must fail closed.'
$missingInternal=[pscustomobject]@{Name=$internalFixture.Name;Containers=[pscustomobject]$internalMembers}
Assert-Throws { ConvertFrom-GadeOfficeDockerNetworkInspectOutput -Output (ConvertTo-Json -InputObject @($missingInternal) -Depth 10 -Compress) -ExitCode 0 -ExpectedName $internalFixture.Name -ExpectedInternal $true -ExpectedContainerIds $ids } 'Missing internal-state metadata must fail closed.'
$networkTopologyText=$script:functionAsts['Get-OfficeDockerTopology'].Extent.Text
Assert-True ($networkTopologyText.Contains('ConvertFrom-GadeOfficeDockerNetworkInspectOutput') -and $networkTopologyText.Contains('NetworkSettings.Networks.PSObject.Properties | ForEach-Object')) 'Topology must parse and enumerate structured network membership explicitly.'
$topologyText = $script:functionAsts['Get-OfficeDockerTopology'].Extent.Text
Assert-True ($topologyText.Contains("'--no-trunc'") -and $topologyText.Contains("'--quiet'") -and $topologyText.Contains("'--filter'")) 'Topology must query only the reviewed Compose project using full IDs, without display JSON.'
Assert-True ($topologyText.Contains("'inspect'") -and $topologyText.Contains('ConvertFrom-GadeOfficeDockerInspectOutput') -and $topologyText.Contains('ConvertFrom-GadeDockerContainerIdOutput')) 'Topology must use docker inspect and both strict parsers.'
Assert-True ($topologyText.Contains('project.config_files') -and $topologyText.Contains('State.Health.Status') -and $topologyText.Contains('NetworkSettings.Networks') -and $topologyText.Contains('NetworkSettings.Ports')) 'Compose identity, Health, Networks, and PortBindings checks must remain present.'
Assert-True ($topologyText.Contains('HostIp') -and $topologyText.Contains('HostPort') -and $topologyText.Contains('internal.Internal') -and $topologyText.Contains('ingress.ContainerIds')) 'Gateway binding and isolated-network membership checks must remain present.'
Assert-True (-not $topologyText.Contains('{{json .}}') -and -not $topologyText.Contains('.Command')) 'Topology must not depend on docker ps display Command or line-formatted JSON.'
$dockerInvokerText = $script:functionAsts['Invoke-Docker'].Extent.Text
Assert-True ($dockerInvokerText.Contains('[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)') -and $dockerInvokerText.Contains('$LASTEXITCODE')) 'Docker native output decoding must be explicitly UTF-8 and preserve the native exit code.'

Write-Output "GADE_OFFICE_DOCKER_JSON_TEST=PASS assertions=$script:assertions powershell=$($PSVersionTable.PSVersion)"
