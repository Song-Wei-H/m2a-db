[CmdletBinding()]
param([string]$FinalizeExistingRunId)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$branchExpected = 'experiment/gade-seven-level-v1'
$baselineTag = 'gade-preexp-v1'
$baselineExpected = '9eaea6a355a07687031e8c43465c17bc5fce1145'
$workerHost = '10.56.64.121'
$workerUrl = "http://${workerHost}:8001"
$sharedWorkerUrl = "http://${workerHost}:8000"
$target = '10.56.66.119'
$targetPort = 18080
$scope = '10.56.66.119/32'
$targetSidecar = 'm2a-mode-b-l2-auth'
$targetContainer = 'm2a-mode-b-target'
$workerRoot = '/home/user2/gade-worker'
$expectedOldWorkerSha = '7ef5c3cce2c6f1d3393c9b64490f19e3190e9c8a26349120486da2da45693856'
$expectedWorkerSha = (Get-FileHash -LiteralPath (Join-Path $repo 'kali_worker\app.py') -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedActionSha = (Get-FileHash -LiteralPath (Join-Path $repo 'app\action_contracts.py') -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedAction = 'lab.valid_account_access.v1'
$expectedTool = 'lab_valid_account_access'
$expectedTemplate = 'lab_valid_account_access_v1'
$runId = [guid]::NewGuid().ToString('N').Substring(0,12).ToLowerInvariant()
$output = Join-Path $PSScriptRoot "local-only\$runId"
$migrationRunner = Join-Path $repo 'scripts\Invoke-MigrationSmoke.ps1'
$driver = Join-Path $PSScriptRoot 'run_l2_d7_d1.py'
$python = Join-Path $repo '.venv\Scripts\python.exe'
$secretConfig = Join-Path $repo 'lab\mode-b-target\.env.l2.local'
$phase = 'PREFLIGHT'
$containerId = $null
$volumeName = "gade_l2_${runId}_pgdata"
$containerName = "gade-preexp-$runId-fresh"
$database = "gade_${runId}_fresh"
$dbPassword = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$dbPort = 0
$script:SensitiveValues = @()
. (Join-Path $PSScriptRoot 'GadeL2ResetGate.ps1')

function Assert-Ok([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Invoke-Docker([string[]]$Arguments) {
    # Windows PowerShell 5.1 can promote native stderr records to terminating
    # errors when ErrorActionPreference is Stop. Docker logs legitimately
    # forwards container stderr, so capture both streams under Continue and
    # read the native exit code before restoring the caller's preference.
    $priorErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& docker.exe @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $priorErrorActionPreference
    }
    $output = ($lines | ForEach-Object { [string]$_ }) -join "`n"
    if ($code -ne 0) {
        throw "docker $($Arguments[0]) failed exit=${code}; output: $($output.Trim())"
    }
    return $output.Trim()
}

function Invoke-Docker-Captured([string[]]$Arguments, [string]$OutPath, [string]$ErrPath) {
    $exe = (Get-Command docker.exe -ErrorAction Stop).Source
    $quoted = foreach ($a in $Arguments) { if ($a -match '[\s"]') { '"' + $a.Replace('"','\"') + '"' } else { $a } }
    $p = Start-Process -FilePath $exe -ArgumentList ($quoted -join ' ') -WorkingDirectory $repo `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $OutPath -RedirectStandardError $ErrPath
    return [pscustomobject]@{
        ExitCode=$p.ExitCode
        Stdout=$(if (Test-Path -LiteralPath $OutPath) { Get-Content -LiteralPath $OutPath -Raw } else { '' })
        Stderr=$(if (Test-Path -LiteralPath $ErrPath) { Get-Content -LiteralPath $ErrPath -Raw } else { '' })
    }
}

function Save-Json([string]$Path, $Object) {
    $Object | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Sanitize-Text([string]$Value) {
    $safe = [string]$Value
    foreach ($secret in $script:SensitiveValues) {
        if (-not [string]::IsNullOrEmpty([string]$secret)) {
            $safe = $safe.Replace([string]$secret, '[REDACTED]')
        }
    }
    return $safe
}

function Read-DotEnvValue([string]$Path, [string]$Name) {
    $line = Get-Content -LiteralPath $Path | Where-Object { $_ -match "^\s*(?:export\s+)?$([regex]::Escape($Name))=" } | Select-Object -Last 1
    if ($null -eq $line) { throw "Required local lab setting $Name is missing." }
    $value = ([string]$line).Substring(([string]$line).IndexOf('=') + 1).Trim()
    if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    if ([string]::IsNullOrWhiteSpace($value)) { throw "Required local lab setting $Name is empty." }
    return $value
}

function Invoke-WorkerDeployOverSsh([string]$Username, [string]$Password) {
    $ssh = (Get-Command ssh.exe -ErrorAction Stop).Source
    $scp = (Get-Command scp.exe -ErrorAction Stop).Source
    $tar = (Get-Command tar.exe -ErrorAction Stop).Source
    $temp = Join-Path $env:TEMP "gade-l2-$runId"
    $packageRoot = Join-Path $temp 'bundle'
    New-Item -ItemType Directory -Path (Join-Path $packageRoot 'app'), (Join-Path $packageRoot 'kali_worker') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $repo 'app\action_contracts.py') -Destination (Join-Path $packageRoot 'app\action_contracts.py')
    Copy-Item -LiteralPath (Join-Path $repo 'kali_worker\app.py') -Destination (Join-Path $packageRoot 'kali_worker\app.py')
    $archivePath = Join-Path $temp 'worker-update.tar.gz'
    $tarStdout = Join-Path $output 'worker-bundle-tar-create.stdout.log'
    $tarStderr = Join-Path $output 'worker-bundle-tar-create.stderr.log'
    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
    $tarArguments = '-czf "' + $archivePath + '" -C "' + $packageRoot + '" app/action_contracts.py kali_worker/app.py'
    $tarProcess = Start-Process -FilePath $tar -ArgumentList $tarArguments -WorkingDirectory $packageRoot `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $output 'worker-bundle-tar-create.stdout.log') `
        -RedirectStandardError (Join-Path $output 'worker-bundle-tar-create.stderr.log')
    if ($tarProcess.ExitCode -ne 0) {
        $tarError = if (Test-Path -LiteralPath $tarStderr) { Get-Content -LiteralPath $tarStderr -Raw } else { '' }
        throw "Windows tar.exe failed to create Worker bundle (exit $($tarProcess.ExitCode)): $tarError"
    }
    Assert-Ok (Test-Path -LiteralPath $archivePath -PathType Leaf) 'Windows tar.exe produced no Worker bundle.'
    $listOut = Join-Path $output 'worker-bundle-tar-list.stdout.log'
    $listErr = Join-Path $output 'worker-bundle-tar-list.stderr.log'
    $listArguments = '-tzf "' + $archivePath + '"'
    $listProcess = Start-Process -FilePath $tar -ArgumentList $listArguments -WorkingDirectory $packageRoot `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $listOut -RedirectStandardError $listErr
    if ($listProcess.ExitCode -ne 0) {
        $listError = if (Test-Path -LiteralPath $listErr) { Get-Content -LiteralPath $listErr -Raw } else { '' }
        throw "Windows tar.exe failed to list Worker bundle (exit $($listProcess.ExitCode)): $listError"
    }
    $tarEntries = @([IO.File]::ReadAllLines($listOut) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    Assert-Ok ($tarEntries.Count -eq 2 -and $tarEntries[0] -ceq 'app/action_contracts.py' -and
        $tarEntries[1] -ceq 'kali_worker/app.py') 'Worker tar.gz paths do not match the exact two-file deployment contract.'
    $archiveSha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $evidenceArchive = Join-Path $output 'worker-update.tar.gz'
    Copy-Item -LiteralPath $archivePath -Destination $evidenceArchive -Force
    Set-Content -LiteralPath (Join-Path $output 'worker-update.tar.gz.sha256') -Value "$archiveSha  worker-update.tar.gz" -Encoding ASCII
    Save-Json (Join-Path $output 'worker-bundle-manifest.json') ([ordered]@{
        run_id=$runId; created_utc=[DateTime]::UtcNow.ToString('o'); archive='worker-update.tar.gz'; archive_sha256=$archiveSha
        files=@(@{path='app/action_contracts.py';sha256=(Get-FileHash (Join-Path $packageRoot 'app\action_contracts.py') -Algorithm SHA256).Hash.ToLowerInvariant()},
            @{path='kali_worker/app.py';sha256=(Get-FileHash (Join-Path $packageRoot 'kali_worker\app.py') -Algorithm SHA256).Hash.ToLowerInvariant()})
        archive_members=$tarEntries
    })
    $secretB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{username=$Username;password=$Password} | ConvertTo-Json -Compress)))

    $remote = @'
import base64, hashlib, json, os, pathlib, re, shutil, signal, socket, subprocess, sys, tarfile, tempfile, time, urllib.request
ROOT = pathlib.Path('/home/user2/gade-worker')
RUN = '__RUN__'
WORKER_HOST = '__WORKER_HOST__'
EXPECTED = '__EXPECTED__'
EXPECTED_ACTION = '__ACTION__'
ARCHIVE = ROOT / ('.gade-l2-update-' + RUN + '.tar.gz')
EXPECTED_ARCHIVE_SHA = '__ARCHIVE_SHA__'
SECRETS = json.loads(base64.b64decode('__SECRETS__').decode('utf-8'))
EXPECTED_OLD = '__OLD__'
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def health(port):
    # Probe the exact host interface used by the preflight-verified Worker URL.
    # The dedicated service may bind only to its LAN address, and urllib must
    # not route this private health check through an inherited proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f'http://{WORKER_HOST}:{port}/health', timeout=8) as r:
        return json.loads(r.read().decode('utf-8'))
def listeners(port):
    out = subprocess.check_output(['ss','-ltnpH',f'sport = :{port}'], text=True, stderr=subprocess.STDOUT)
    return sorted(set(int(x) for x in re.findall(r'pid=(\d+)', out)))
def proc(pid):
    p = pathlib.Path('/proc') / str(pid)
    status = (p/'status').read_text()
    ppid = int(re.search(r'^PPid:\s+(\d+)', status, re.M).group(1))
    cgroup = (p/'cgroup').read_text()
    return {'pid':pid,'ppid':ppid,'uid':p.stat().st_uid,'cwd':os.readlink(p/'cwd'),
            'cgroup':cgroup,
            'argv':[x.decode() for x in (p/'cmdline').read_bytes().split(b'\0') if x],
            'env':dict(x.decode(errors='replace').split('=',1) for x in (p/'environ').read_bytes().split(b'\0') if b'=' in x)}
def fail(msg): raise RuntimeError(msg)
if os.getuid() != 1004 or pathlib.Path.home() != pathlib.Path('/home/user2'):
    fail('Expected unprivileged user2 UID 1004.')
if not ROOT.is_dir() or ROOT.resolve() != pathlib.Path('/home/user2/gade-worker'):
    fail('Dedicated Worker root identity mismatch.')
if not ARCHIVE.is_file() or ARCHIVE.is_symlink(): fail('Transferred tar.gz is missing or is not a regular file.')
checksum = subprocess.run(['sha256sum',str(ARCHIVE)],cwd=str(ROOT),capture_output=True,text=True)
if checksum.returncode: fail('Kali sha256sum could not read the transferred tar.gz: '+checksum.stderr[-500:])
archive_sha_verified = checksum.stdout.split()[0] if checksum.stdout.split() else ''
if archive_sha_verified != EXPECTED_ARCHIVE_SHA: fail('Kali sha256sum did not match the Windows tar.gz SHA-256.')
listing = subprocess.run(['tar','-tzf',str(ARCHIVE)],cwd=str(ROOT),capture_output=True,text=True)
if listing.returncode: fail('Kali tar could not list the transferred archive: '+listing.stderr[-500:])
archive_members = sorted(line for line in listing.stdout.splitlines() if line)
if archive_members != ['app/action_contracts.py','kali_worker/app.py']:
    fail('Transferred tar.gz file set differs from the exact two-file deployment contract.')
with tarfile.open(ARCHIVE,'r:gz') as bundle:
    members = bundle.getmembers()
    if sorted(member.name for member in members) != archive_members or any(not member.isfile() for member in members):
        fail('Transferred tar.gz contains an unexpected path or non-regular member.')
before = health(8001)
shared_pids = listeners(8000)
if len(shared_pids) != 1: fail(f'Expected one existing shared :8000 listener, got {shared_pids!r}.')
shared = proc(shared_pids[0])
if shared['uid'] != 1004 or shared['cwd'] != '/home/user2/kali-worker': fail('Shared :8000 listener identity differs from the recorded shared Worker; refusing deployment.')
if before.get('build_sha256') == EXPECTED:
    if sha(ROOT/'app/action_contracts.py') != EXPECTED_ACTION: fail('Already-deployed Action Contract file hash mismatch.')
    if 'lab_valid_account_access' not in before.get('allowed_tools',[]) or before.get('allowed_scopes') != ['10.56.66.119/32']:
        fail('Already-deployed Worker has unexpected Action/Scope state.')
    ARCHIVE.unlink()
    print(json.dumps({'status':'ALREADY_DEPLOYED','worker_build_sha256':before['build_sha256'],'action_contract_sha256':sha(ROOT/'app/action_contracts.py'),
        'allowed_tools':before['allowed_tools'],'scope':before['allowed_scopes'],'archive_sha256_verified':True,'archive_sha256':archive_sha_verified,
        'archive_members':archive_members,'transfer_archive_removed':not ARCHIVE.exists(),'shared_worker_pid':shared['pid'],'shared_worker_cwd':shared['cwd']}))
    sys.exit(0)
if before.get('build_sha256') != EXPECTED_OLD or 'lab_valid_account_access' in before.get('allowed_tools',[]):
    fail('Live :8001 Worker differs from the known old build; refusing automatic replacement.')
pids = listeners(8001)
if len(pids) != 1: fail(f'Expected exactly one :8001 listener, got {pids!r}.')
old = proc(pids[0])
if old['uid'] != 1004 or old['cwd'] != str(ROOT) or 'uvicorn' not in ' '.join(old['argv']) or 'kali_worker.app:app' not in old['argv']:
    fail('The :8001 PID is not the expected user2 dedicated Uvicorn process.')
if not re.search(r'user-1004\.slice/session-\d+\.scope', old['cgroup']):
    fail('The dedicated :8001 process is not in the recorded user2 session scope; refusing to race a service manager.')
if '--port' not in old['argv'] or old['argv'][old['argv'].index('--port')+1] != '8001' or '8000' in old['argv']:
    fail('The :8001 process command does not bind exactly the dedicated port.')
env = old['env']
if env.get('KALI_WORKER_PROFILE') != 'gade-experiment' or env.get('KALI_WORKER_ENFORCE_TARGET_SCOPE','').lower() != 'true' or env.get('KALI_WORKER_ALLOWED_SCOPES') != '10.56.66.119/32':
    fail('Existing Worker profile/scope is not exactly the approved isolated configuration.')
if not SECRETS.get('username') or len(SECRETS.get('password','')) < 24: fail('Worker-local L2 credentials invalid.')
start = ROOT/'start-gade-worker.sh'
if not start.is_file(): fail('Dedicated start-gade-worker.sh is missing.')
start_text = start.read_text()
if 'ROOT=' not in start_text or 'exec ' not in start_text: fail('Dedicated start script structure is unknown; refusing to patch.')
marker = '# GADE_L2_LOCAL_CREDENTIALS'
updated_start = start_text
if marker not in updated_start:
    snippet = '\n'+marker+'\nif [ -r "$ROOT/.gade-l2.env" ]; then set -a; . "$ROOT/.gade-l2.env"; set +a; fi\n'
    idx = updated_start.find('exec ')
    updated_start = updated_start[:idx] + snippet + updated_start[idx:]
envfile = ROOT/'.gade-l2.env'
had_env = envfile.exists()
if had_env:
    if envfile.is_symlink() or envfile.stat().st_uid != 1004 or (envfile.stat().st_mode & 0o077):
        fail('Existing private L2 credential file has unexpected owner, type, or permissions.')
staging = pathlib.Path(tempfile.mkdtemp(prefix='.gade-l2-'+RUN+'-', dir=str(ROOT)))
backup = ROOT/'.gade-l2-backups'/RUN
backup_complete = False
try:
    extract = staging/'extract'; extract.mkdir(mode=0o700)
    unpack = subprocess.run(['tar','-xzf',str(ARCHIVE),'-C',str(extract),'--no-same-owner','--no-same-permissions'],cwd=str(ROOT),capture_output=True,text=True)
    if unpack.returncode: fail('Kali tar extraction failed: '+unpack.stderr[-500:])
    for rel in ('app/action_contracts.py','kali_worker/app.py'):
        if not (extract/rel).is_file(): fail('Worker package omitted a required source file.')
    actual = hashlib.sha256((extract/'kali_worker/app.py').read_bytes()).hexdigest()
    if actual != EXPECTED: fail('Transferred Worker source hash mismatch.')
    if hashlib.sha256((extract/'app/action_contracts.py').read_bytes()).hexdigest() != EXPECTED_ACTION: fail('Transferred Action Contract hash mismatch.')
    py = ROOT/'.venv/bin/python'
    if not py.is_file() or not os.access(py,os.X_OK): fail('Existing user2 Python venv is unavailable.')
    check = subprocess.run([str(py),'-m','py_compile',str(extract/'kali_worker/app.py'),str(extract/'app/action_contracts.py')],cwd=str(ROOT),capture_output=True,text=True)
    if check.returncode: fail('Worker Python compile failed: '+check.stderr[-1000:])
    imports = subprocess.run([str(py),'-c','import fastapi, pydantic; import app.action_contracts; import kali_worker.app'],cwd=str(ROOT),capture_output=True,text=True)
    if imports.returncode: fail('Existing user2 venv is missing a required Worker Python dependency: '+imports.stderr[-1000:])
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(ROOT/'kali_worker/app.py', backup/'worker-app.py')
    shutil.copy2(ROOT/'app/action_contracts.py', backup/'action-contracts.py')
    shutil.copy2(start, backup/'start-gade-worker.sh')
    if had_env: shutil.copy2(envfile, backup/'.gade-l2.env')
    backup_complete = True
    # Install the persistent, private credential file without printing values.
    import shlex
    temp_env = staging/'.gade-l2.env'
    temp_env.write_text('export GADE_L2_TEST_USERNAME='+shlex.quote(SECRETS['username'])+'\nexport GADE_L2_TEST_PASSWORD='+shlex.quote(SECRETS['password'])+'\n',encoding='utf-8')
    os.chmod(temp_env,0o600)
    shutil.copyfile(temp_env,envfile); os.chmod(envfile,0o600)
    # Source a private credential file on future dedicated-worker starts only.
    start.write_text(updated_start,encoding='utf-8'); os.chmod(start,0o700)
    for rel in ('app/action_contracts.py','kali_worker/app.py'):
        dest = ROOT/rel; staged = extract/rel
        tmp = dest.with_name(dest.name+'.gade-'+RUN+'.tmp')
        shutil.copyfile(staged,tmp); os.chmod(tmp,0o600); os.replace(tmp,dest)
    if sha(ROOT/'kali_worker/app.py') != EXPECTED: fail('Installed Worker source hash mismatch.')
    if sha(ROOT/'app/action_contracts.py') != EXPECTED_ACTION: fail('Installed Action Contract hash mismatch.')
    os.kill(old['pid'],signal.SIGTERM)
    for _ in range(100):
        if not pathlib.Path('/proc/'+str(old['pid'])).exists(): break
        time.sleep(.1)
    else: fail('Old dedicated :8001 process did not stop after SIGTERM.')
    if listeners(8001): fail('Port 8001 remains bound after stopping the dedicated Worker.')
    env.update({'GADE_L2_TEST_USERNAME':SECRETS['username'],'GADE_L2_TEST_PASSWORD':SECRETS['password'],
                'KALI_WORKER_PROFILE':'gade-experiment','KALI_WORKER_ENFORCE_TARGET_SCOPE':'true',
                'KALI_WORKER_ALLOWED_SCOPES':'10.56.66.119/32','GADE_NUCLEI_ACTION_ENABLED':'false'})
    log = open(ROOT/'worker.log','ab',buffering=0)
    child = subprocess.Popen(old['argv'],cwd=old['cwd'],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)
    for _ in range(100):
        if child.poll() is not None: fail(f'New dedicated Worker exited immediately ({child.returncode}).')
        try:
            after = health(8001)
            if after.get('build_sha256') == EXPECTED: break
        except Exception: pass
        time.sleep(.2)
    else: fail('Updated Worker did not become healthy with expected build hash.')
    if 'lab_valid_account_access' not in after.get('allowed_tools',[]): fail('Updated Worker did not load the L2 Action.')
    if after.get('scope_enforced_by_worker') is not True or after.get('allowed_scopes') != ['10.56.66.119/32']:
        fail('Updated Worker scope enforcement mismatch.')
    if listeners(8000) != shared_pids: fail('Shared Worker :8000 PID changed during deployment.')
    shared_after = proc(shared_pids[0])
    if shared_after['cwd'] != shared['cwd'] or shared_after['argv'] != shared['argv'] or shared_after['uid'] != shared['uid']:
        fail('Shared Worker :8000 process identity changed during deployment.')
    ARCHIVE.unlink()
    print(json.dumps({'status':'DEPLOYED','old_pid':old['pid'],'new_pid':child.pid,'worker_build_sha256':after['build_sha256'],
        'action_loaded':'lab_valid_account_access' in after.get('allowed_tools',[]),'allowed_tools':after['allowed_tools'],
        'scope_enforced':after.get('scope_enforced_by_worker'),'scope':after.get('allowed_scopes'),
        'action_contract_sha256':sha(ROOT/'app/action_contracts.py'),'backup':str(backup),'credential_file_mode':'0600',
        'archive_sha256_verified':archive_sha_verified == EXPECTED_ARCHIVE_SHA,'archive_sha256':archive_sha_verified,
        'archive_members':archive_members,'transfer_archive_removed':not ARCHIVE.exists(),
        'shared_worker_pid':shared['pid'],'shared_worker_cwd':shared['cwd']}))
except Exception:
    if not backup_complete: raise
    # Restore only the dedicated :8001 sources/process from the exact captured state.
    try:
        current = listeners(8001)
        for pid in current:
            if pathlib.Path('/proc/'+str(pid)).exists() and proc(pid)['uid'] == 1004 and proc(pid)['cwd'] == str(ROOT):
                os.kill(pid,signal.SIGTERM)
        for _ in range(60):
            if not listeners(8001): break
            time.sleep(.1)
        for rel, saved in (('kali_worker/app.py',backup/'worker-app.py'),('app/action_contracts.py',backup/'action-contracts.py'),('start-gade-worker.sh',backup/'start-gade-worker.sh')):
            shutil.copy2(saved,ROOT/rel)
        if had_env:
            shutil.copy2(backup/'.gade-l2.env', envfile); os.chmod(envfile,0o600)
        else:
            envfile.unlink(missing_ok=True)
        subprocess.Popen(old['argv'],cwd=old['cwd'],env=old['env'],stdin=subprocess.DEVNULL,stdout=open(ROOT/'worker.log','ab',buffering=0),stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)
    except Exception as restore_error:
        print(json.dumps({'rollback':'FAILED','rollback_error':type(restore_error).__name__}),file=sys.stderr)
    raise
finally:
    shutil.rmtree(staging,ignore_errors=True)
'@
    $remote = $remote.Replace('__RUN__', $runId).Replace('__WORKER_HOST__', $workerHost).Replace('__EXPECTED__', $expectedWorkerSha).Replace('__ACTION__', $expectedActionSha).Replace('__ARCHIVE_SHA__', $archiveSha)
    $remote = $remote.Replace('__SECRETS__', $secretB64).Replace('__OLD__', $expectedOldWorkerSha)

    try {
        $remoteArchive = ".gade-l2-update-$runId.tar.gz"
        $scpPsi = New-Object System.Diagnostics.ProcessStartInfo
        $scpPsi.FileName = $scp
        $scpPsi.Arguments = '-o StrictHostKeyChecking=yes -o ConnectTimeout=10 "' + $archivePath + '" user2@10.56.64.121:/home/user2/gade-worker/' + $remoteArchive
        $scpPsi.UseShellExecute = $false
        $scpPsi.CreateNoWindow = $false
        $scpProc = New-Object System.Diagnostics.Process
        $scpProc.StartInfo = $scpPsi
        Assert-Ok $scpProc.Start() 'Could not start Windows OpenSSH scp.exe for the dedicated Worker bundle.'
        $scpProc.WaitForExit()
        Assert-Ok ($scpProc.ExitCode -eq 0) "SCP Worker bundle transfer failed with exit $($scpProc.ExitCode). Local archive SHA-256: $archiveSha"

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ssh
        $psi.Arguments = '-T -o StrictHostKeyChecking=yes -o ConnectTimeout=10 user2@10.56.64.121 "python3 -"'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $false # SSH password prompt stays on the host console if needed.
        $psi.CreateNoWindow = $false
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        Assert-Ok $proc.Start() 'Could not start Windows OpenSSH for the dedicated Worker.'
        $proc.StandardInput.Write($remote)
        $proc.StandardInput.Close()
        $stdout = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) { throw "SSH deployment failed exit=$($proc.ExitCode). Output: $stdout" }
        $rows = @($stdout -split "`r?`n" | Where-Object { $_.Trim().StartsWith('{') } | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-Ok ($rows.Count -ge 1) 'Remote deployment returned no structured status.'
        $result = $rows[-1]
        Assert-Ok ($result.status -in @('DEPLOYED','ALREADY_DEPLOYED') -and $result.worker_build_sha256 -ceq $expectedWorkerSha -and
            $result.action_contract_sha256 -ceq $expectedActionSha -and
            $result.action_loaded -ne $false -and $result.scope_enforced -ne $false -and
            $result.archive_sha256_verified -eq $true -and $result.archive_sha256 -ceq $archiveSha -and
            @($result.archive_members).Count -eq 2 -and $result.transfer_archive_removed -eq $true) 'Remote Worker did not verify the expected tar.gz deployment and L2 scope.'
        return $result
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Reset-Lab([string]$Key, [string]$CaseId, [string]$RequestId) {
    $body = @{ reset_key=$Key; test_case_id=$CaseId } | ConvertTo-Json -Compress
    $headers = @{ 'X-Request-ID'=$RequestId; 'X-Test-Case-ID'=$CaseId }
    $response = Invoke-RestMethod -Method Post -Uri "http://${target}:${targetPort}/lab/admin/reset" `
        -ContentType 'application/json' -Headers $headers -Body $body -TimeoutSec 8
    return $response
}

function Get-TargetEvents([string]$LogPath, [string]$ContainerIdentity = 'm2a-mode-b-l2-auth') {
    $raw = Invoke-Docker @('logs',$ContainerIdentity)
    Set-Content -LiteralPath $LogPath -Value $raw -Encoding UTF8
    $events = @()
    foreach ($line in ($raw -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $events += ($line | ConvertFrom-Json -ErrorAction Stop) } catch { }
    }
    return ,$events
}

function Get-EventPropertyValue($Event, [string]$Name) {
    if ($null -eq $Event) { return $null }
    $property = $Event.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Finalize-ExistingTargetEvidence([string]$ExistingRunId) {
    Assert-Ok ($ExistingRunId -match '^[0-9a-f]{12}$') 'FinalizeExistingRunId must be the exact 12-character lowercase Run ID.'
    $evidenceDir = Join-Path $PSScriptRoot "local-only\$ExistingRunId"
    Assert-Ok (Test-Path -LiteralPath $evidenceDir -PathType Container) 'Existing Run evidence directory is missing.'
    foreach ($name in @('manifest.json','run-state.json','d7-evidence.json','d1-evidence.json')) {
        Assert-Ok (Test-Path -LiteralPath (Join-Path $evidenceDir $name) -PathType Leaf) "Required preserved evidence is missing: $name"
    }
    $manifest = Get-Content -LiteralPath (Join-Path $evidenceDir 'manifest.json') -Raw | ConvertFrom-Json
    $state = Get-Content -LiteralPath (Join-Path $evidenceDir 'run-state.json') -Raw | ConvertFrom-Json
    $d7 = Get-Content -LiteralPath (Join-Path $evidenceDir 'd7-evidence.json') -Raw | ConvertFrom-Json
    $d1 = Get-Content -LiteralPath (Join-Path $evidenceDir 'd1-evidence.json') -Raw | ConvertFrom-Json
    Assert-Ok ($manifest.run_id -ceq $ExistingRunId -and $state.run_id -ceq $ExistingRunId) 'Run ID does not match preserved evidence identity.'
    Assert-Ok ($manifest.target -ceq '10.56.66.119:18080' -and $manifest.target_sidecar_id -match '^[0-9a-f]{64}$') 'Preserved target identity is incomplete or unexpected.'
    Assert-Ok ($state.status -ceq 'D7_PASS_D1_DENY_PASS' -and $state.d7_status -ceq 'D7_REAL_EXECUTION_PASS' -and
        $state.d1_status -ceq 'D1_GOVERNANCE_DENIAL_PASS' -and $state.formal_sample -eq $false) 'Existing run does not contain the expected completed engineering D7/D1 evidence.'
    $requestId = [string]$d7.worker_receipt.request_id
    $corr7 = [string]$d7.correlation_id
    $corr1 = [string]$d1.correlation_id
    Assert-Ok ($d7.status -ceq 'D7_REAL_EXECUTION_PASS' -and $d7.tool_task.status -ceq 'completed' -and
        $d7.tool_result.success -eq $true -and $d7.worker_receipt.action_success -eq $true -and
        $requestId -match '^[0-9a-f-]{36}$' -and $corr7 -ceq "GADE-L2-D7-$ExistingRunId") 'Preserved D7 ToolTask/ToolResult/Receipt evidence failed integrity checks.'
    Assert-Ok ($d1.status -ceq 'D1_GOVERNANCE_DENIAL_PASS' -and $d1.authorization_decision.outcome -ceq 'DENY' -and
        $d1.reason_code -ceq 'ATTACK_DEPTH_EXCEEDED' -and $d1.tool_task_created -eq $false -and
        $null -eq $d1.execution_authorization -and $corr1 -ceq "GADE-L2-D1-$ExistingRunId") 'Preserved D1 denial evidence failed integrity checks.'
    $inspect = @( (Invoke-Docker @('inspect',[string]$manifest.target_sidecar_id) | ConvertFrom-Json) )[0]
    Assert-Ok ($inspect.Id -ceq $manifest.target_sidecar_id -and $inspect.Name -ceq '/m2a-mode-b-l2-auth' -and
        $inspect.Config.Image -ceq 'm2a-mode-b-l2-auth:local' -and $inspect.State.Running) 'Existing target sidecar identity/state mismatch; refusing to read logs.'
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $rawPath = Join-Path $evidenceDir "target-events-recovery-$stamp.jsonl"
    $events = Get-TargetEvents -LogPath $rawPath -ContainerIdentity ([string]$manifest.target_sidecar_id)
    $d7Events = @($events | Where-Object { (Get-EventPropertyValue $_ 'request_id') -ceq $requestId -and (Get-EventPropertyValue $_ 'test_case_id') -ceq $corr7 })
    foreach ($eventName in @('login_succeeded','session_created','protected_access_granted')) {
        Assert-Ok (@($d7Events | Where-Object { (Get-EventPropertyValue $_ 'event') -ceq $eventName }).Count -ge 1) "Read-only target log recovery did not find D7 event '$eventName'. Raw logs preserved at $rawPath"
    }
    $d1Events = @($events | Where-Object { (Get-EventPropertyValue $_ 'test_case_id') -ceq $corr1 })
    Assert-Ok ($d1Events.Count -eq 0) "Read-only target log recovery found a D1 target event; raw logs preserved at $rawPath"
    $resetBetweenCases = $false
    $resetD1Path = Join-Path $evidenceDir 'lab-reset-d1.json'
    if (Test-Path -LiteralPath $resetD1Path -PathType Leaf) {
        $resetD1 = Get-Content -LiteralPath $resetD1Path -Raw | ConvertFrom-Json
        $resetBetweenCases = ($resetD1.status -ceq 'reset' -and $resetD1.active_sessions -eq 0 -and $resetD1.case_id -ceq "GADE-L2-D1-$ExistingRunId-RESET")
    }
    $recovery = [ordered]@{
        run_id=$ExistingRunId; recovered_utc=[DateTime]::UtcNow.ToString('o'); mode='READ_ONLY_TARGET_LOG_FINALIZATION'
        target_sidecar_id=$manifest.target_sidecar_id; target_log_path=[IO.Path]::GetFileName($rawPath)
        worker_request_id=$requestId; d7_correlation_id=$corr7; d1_correlation_id=$corr1
        d7_events=$d7Events; d1_events=$d1Events; d7_target_events_verified=$true; d1_target_events_absent=$true
        reset_between_cases_verified=$resetBetweenCases
        status=$(if ($resetBetweenCases) { 'TARGET_CORRELATION_PASS' } else { 'TARGET_CORRELATION_VERIFIED_PAIRING_PARTIAL_D1_RESET_NOT_PERFORMED' })
        actions_replayed=$false; database_touched=$false; lab_reset_performed=$false; formal_sample=$false
    }
    $recoveryPath = Join-Path $evidenceDir "target-side-recovery-$stamp.json"
    Save-Json $recoveryPath $recovery
    $hashes = [ordered]@{
        target_log_sha256=(Get-FileHash -LiteralPath $rawPath -Algorithm SHA256).Hash.ToLowerInvariant()
        recovery_json_sha256=(Get-FileHash -LiteralPath $recoveryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Save-Json (Join-Path $evidenceDir "target-side-recovery-$stamp.sha256.json") $hashes
    Write-Host "TARGET_LOG_RECOVERY=$($recovery.status) run_id=$ExistingRunId d7_events=$($d7Events.Count) d1_events=$($d1Events.Count) reset_between_cases=$resetBetweenCases"
    Write-Host "RECOVERY_EVIDENCE=$recoveryPath"
    Write-Host "RAW_TARGET_LOGS=$rawPath"
}

function Find-FreePort {
    for ($candidate=25436; $candidate -le 25999; $candidate++) {
        $listener=$null
        try {
            $listener=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'),$candidate)
            $listener.Start(); return $candidate
        } catch { } finally { if ($null -ne $listener) { $listener.Stop() } }
    }
    throw 'No unused scratch port in the migration runner allowlist.'
}

if (-not [string]::IsNullOrWhiteSpace($FinalizeExistingRunId)) {
    Finalize-ExistingTargetEvidence $FinalizeExistingRunId
    return
}

try {
    Push-Location $repo
    $branchLines = @(& git branch --show-current 2>&1)
    $branchExit = $LASTEXITCODE
    $branch = [string]($branchLines -join '').Trim()
    Assert-Ok ($branchExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($branch)) 'Could not read Git branch.'
    Assert-Ok ($branch -ceq $branchExpected) 'Wrong experiment branch.'
    $headLines = @(& git rev-parse HEAD 2>&1)
    $headExit = $LASTEXITCODE
    $head = [string]($headLines -join '').Trim()
    Assert-Ok ($headExit -eq 0 -and $head -match '^[0-9a-f]{40}$') 'Could not read Git HEAD.'
    $baselineLines = @(& git rev-list -n 1 $baselineTag 2>&1)
    $baselineExit = $LASTEXITCODE
    $baseline = [string]($baselineLines -join '').Trim()
    Assert-Ok ($baselineExit -eq 0 -and $baseline -ceq $baselineExpected) 'Frozen baseline tag target changed.'
    Assert-Ok (Test-Path -LiteralPath $python) 'Repository Python venv is missing.'
    Assert-Ok (Test-Path -LiteralPath $migrationRunner) 'Existing migration runner is missing.'
    Assert-Ok (Test-Path -LiteralPath $driver) 'L2 D7/D1 driver is missing.'
    Assert-Ok (Test-Path -LiteralPath $secretConfig) 'Local-only L2 lab credential config is missing.'
    $username = Read-DotEnvValue $secretConfig 'GADE_L2_TEST_USERNAME'
    $password = Read-DotEnvValue $secretConfig 'GADE_L2_TEST_PASSWORD'
    $resetKey = Read-DotEnvValue $secretConfig 'GADE_L2_RESET_KEY'
    $script:SensitiveValues = @($username,$password,$resetKey,$dbPassword)
    Assert-Ok ($password.Length -ge 24 -and $resetKey.Length -ge 24) 'Local L2 secret length validation failed.'
    $files = @(Get-ChildItem -LiteralPath (Join-Path $repo 'initdb') -Filter '*.sql' -File | Where-Object Name -Match '^\d{3}_.+\.sql$' | Sort-Object Name)
    Assert-Ok ($files.Count -eq 37) "Expected 001-037; found $($files.Count)."
    for($i=0;$i -lt 37;$i++){Assert-Ok ($files[$i].Name.Substring(0,3) -ceq ('{0:D3}' -f ($i+1))) 'Migration chain has a gap.'}
    Assert-Ok ((Get-FileHash (Join-Path $repo 'kali_worker\app.py') -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $expectedWorkerSha) 'Local Worker SHA changed during preflight.'
    $dockerVersion = Invoke-Docker @('info','--format','{{.ServerVersion}}')
    Assert-Ok (-not [string]::IsNullOrWhiteSpace($dockerVersion)) 'Docker Engine is not available in the Host environment.'
    $image = Invoke-Docker @('image','inspect','--format','{{.Id}}','postgres:16')
    Assert-Ok ($image -match '^sha256:[0-9a-f]{64}$') 'postgres:16 is not present locally; runner will not pull an image.'
    $lab = @( (Invoke-Docker @('inspect',$targetContainer) | ConvertFrom-Json) )[0]
    $sidecar = @( (Invoke-Docker @('inspect',$targetSidecar) | ConvertFrom-Json) )[0]
    Assert-Ok ($lab.State.Running -and $lab.Config.Image -ceq 'docker/welcome-to-docker:latest') 'Existing isolated lab identity/state mismatch.'
    Assert-Ok ($sidecar.State.Running -and $sidecar.Config.Image -ceq 'm2a-mode-b-l2-auth:local') "Existing L2 auth sidecar identity/state mismatch (expected running image m2a-mode-b-l2-auth:local; found state=$($sidecar.State.Status) running=$($sidecar.State.Running) image=$($sidecar.Config.Image))."
    $binding = @($lab.NetworkSettings.Ports.'8080/tcp')
    Assert-Ok ($binding.Count -eq 1 -and $binding[0].HostIp -ceq $target -and $binding[0].HostPort -ceq [string]$targetPort) 'Lab endpoint binding drift.'
    $targetHealth = Invoke-WebRequest -Uri "http://${target}:${targetPort}/lab/healthz" -UseBasicParsing -TimeoutSec 8
    Assert-Ok ($targetHealth.StatusCode -eq 200) 'L2 target health failed.'
    $workerHealth = Invoke-RestMethod -Uri "$workerUrl/health" -TimeoutSec 8
    $sharedBefore = Invoke-RestMethod -Uri "$sharedWorkerUrl/health" -TimeoutSec 8
    Assert-Ok ($sharedBefore.status -ceq 'ok') 'Shared Worker :8000 health preflight failed.'
    $needsDeploy = $workerHealth.build_sha256 -cne $expectedWorkerSha
    if ($needsDeploy) {
        Assert-Ok ($workerHealth.build_sha256 -ceq $expectedOldWorkerSha -and @($workerHealth.allowed_tools) -notcontains $expectedTool) 'Dedicated Worker is neither the known old nor the already-updated expected build.'
    } else {
        Assert-Ok (@($workerHealth.allowed_tools) -contains $expectedTool -and $workerHealth.scope_enforced_by_worker -eq $true -and @($workerHealth.allowed_scopes).Count -eq 1 -and @($workerHealth.allowed_scopes)[0] -ceq $scope) 'Already deployed L2 Worker has action/scope drift.'
    }
    $dbPort = Find-FreePort
    $port = $dbPort
    $existing = @(Invoke-Docker @('container','ls','-a','--filter',"name=^/$containerName$",'--format','{{.Names}}') | Where-Object { $_ })
    $volumes = @(Invoke-Docker @('volume','ls','--filter',"name=^$volumeName$",'--format','{{.Name}}') | Where-Object { $_ })
    Assert-Ok ($existing.Count -eq 0 -and $volumes.Count -eq 0) 'Run-scoped PostgreSQL resource collision.'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $gitStatus = @(& git status --porcelain --untracked-files=all)
    Assert-Ok ($LASTEXITCODE -eq 0) 'Could not capture source state.'
    Set-Content -LiteralPath (Join-Path $output 'git-status.txt') -Value $(if($gitStatus.Count){$gitStatus -join "`n"}else{'(clean)'}) -Encoding UTF8
    $manifest = [ordered]@{
        run_id=$runId; status='PREFLIGHT_PASS'; branch=$branchExpected; head=$head; baseline_tag=$baselineTag; baseline_commit=$baseline
        started_utc=[DateTime]::UtcNow.ToString('o'); source_state=$(if($gitStatus.Count){'DIRTY_STAGE_VALIDATION'}else{'CLEAN'})
        worker_url=$workerUrl; worker_before_sha256=$workerHealth.build_sha256; worker_expected_sha256=$expectedWorkerSha
        worker_action=$expectedAction; action_contract_sha256=$expectedActionSha
        shared_worker_source_sha256_recorded='9cc89630fb2af6e38307b3bf55fad5012a9fbfe25a3c2de75c7df3a8cfa4d0f9'
        shared_worker_health_before=$sharedBefore
        target="${target}:${targetPort}"; target_container_id=$lab.Id; target_sidecar_id=$sidecar.Id; scope=$scope
        postgres_image_id=$image; postgres_container=$containerName; postgres_volume=$volumeName; database=$database; db_port=$port
        migrations=@($files | ForEach-Object {@{name=$_.Name;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
        formal_sample=$false; status_detail='No database or target state has been changed yet.'
    }
    Save-Json (Join-Path $output 'manifest.json') $manifest
    Write-Host "PREFLIGHT=PASS run_id=$runId branch=$branchExpected head=$head worker_before=$($workerHealth.build_sha256) worker_expected=$expectedWorkerSha"
    Write-Host "TARGET=$target`:$targetPort target_container_id=$($lab.Id) l2_sidecar_id=$($sidecar.Id) scope=$scope"
    Write-Host "PLANNED_REMOTE=back up only $workerRoot; install 2 Worker source files and private L2 credentials; restart only :8001 PID as user2; :8000 is read-only checked."
    Write-Host "PLANNED_LOCAL=one new postgres:16 container=$containerName volume=$volumeName bind=127.0.0.1:${port}:5432 database=$database; apply 001-037; register one isolated Action; execute one D7 task; persist one D1 denial; two authenticated Lab resets."
    Write-Host "EVIDENCE=$output"
    $confirmation = Read-Host 'Type exactly RUN-GADE-L2-D7-D1 to deploy :8001 and run the isolated D7/D1 validation'
    if ($confirmation -cne 'RUN-GADE-L2-D7-D1') { Write-Host 'CANCELLED; no deployment, resource creation, Lab reset, or action request was performed.'; return }

    if ($needsDeploy) {
        $phase='DEPLOY_DEDICATED_WORKER_8001'
        $deployment = Invoke-WorkerDeployOverSsh -Username $username -Password $password
        $manifest.worker_deployment=$deployment
        $manifest.status='WORKER_8001_DEPLOYED'
        Save-Json (Join-Path $output 'manifest.json') $manifest
    } else { $manifest.worker_deployment=@{status='ALREADY_DEPLOYED';worker_build_sha256=$expectedWorkerSha;action_loaded=$true;scope_enforced=$true} }
    $workerAfter = Invoke-RestMethod -Uri "$workerUrl/health" -TimeoutSec 8
    Assert-Ok ($workerAfter.build_sha256 -ceq $expectedWorkerSha -and @($workerAfter.allowed_tools) -contains $expectedTool -and
        $workerAfter.scope_enforced_by_worker -eq $true -and @($workerAfter.allowed_scopes).Count -eq 1 -and @($workerAfter.allowed_scopes)[0] -ceq $scope) 'Dedicated Worker post-deploy acceptance failed.'
    $sharedAfter = Invoke-RestMethod -Uri "$sharedWorkerUrl/health" -TimeoutSec 8
    $sharedBeforeCanonical=($sharedBefore | ConvertTo-Json -Depth 12 -Compress)
    $sharedAfterCanonical=($sharedAfter | ConvertTo-Json -Depth 12 -Compress)
    Assert-Ok ($sharedAfterCanonical -ceq $sharedBeforeCanonical) 'Shared Worker :8000 health identity changed during dedicated deployment.'
    Assert-Ok ($null -eq $manifest.worker_deployment.shared_worker_pid -or $manifest.worker_deployment.shared_worker_pid -gt 0) 'Remote report did not preserve the shared Worker PID.'
    $manifest.shared_worker_unchanged=$true; $manifest.shared_worker_health_after=$sharedAfter; $manifest.worker_after_sha256=$workerAfter.build_sha256
    Save-Json (Join-Path $output 'manifest.json') $manifest

    $phase='CREATE_ISOLATED_POSTGRESQL'
    $volumeResult = Invoke-Docker @('volume','create','--label','com.gade.l2.managed=true','--label',"com.gade.l2.run_id=$runId",$volumeName)
    Assert-Ok ($volumeResult -ceq $volumeName) 'Docker returned a different volume name.'
    $oldPgPass=[Environment]::GetEnvironmentVariable('POSTGRES_PASSWORD','Process')
    [Environment]::SetEnvironmentVariable('POSTGRES_PASSWORD',$dbPassword,'Process')
    try {
        $containerId=Invoke-Docker @('run','-d','--name',$containerName,'--label','com.gade.l2.managed=true','--label',"com.gade.l2.run_id=$runId",
            '--publish',"127.0.0.1:${port}:5432",'--mount',"type=volume,source=$volumeName,target=/var/lib/postgresql/data",
            '--env',"POSTGRES_DB=$database",'--env',"POSTGRES_USER=$database",'--env','POSTGRES_PASSWORD','postgres:16')
    } finally { [Environment]::SetEnvironmentVariable('POSTGRES_PASSWORD',$oldPgPass,'Process') }
    Assert-Ok ($containerId -match '^[0-9a-f]{64}$') 'Invalid full PostgreSQL container ID.'
    $manifest.container_id=$containerId; $manifest.status='POSTGRESQL_CREATED'; Save-Json (Join-Path $output 'manifest.json') $manifest
    $ready=$false
    for($i=0;$i -lt 45;$i++){ & docker.exe exec $containerId pg_isready -U $database -d $database *> $null; if($LASTEXITCODE -eq 0){$ready=$true;break}; Start-Sleep -Seconds 1 }
    Assert-Ok $ready 'Isolated PostgreSQL 16 did not become ready.'
    $runnerParams=@{Mode='Migrations';ExpectedContainerId=$containerId;ContainerName=$containerName;HostPort=$port;DatabaseName=$database;DatabaseUser=$database}
    & $migrationRunner @runnerParams -PreflightOnly *> (Join-Path $output 'migration-preflight.log')
    if(-not (Select-String -LiteralPath (Join-Path $output 'migration-preflight.log') -Pattern 'PREFLIGHT_ONLY=PASS' -Quiet)){
        throw 'Migration preflight failed; SQL was not applied.'
    }
    & $migrationRunner @runnerParams -HostOrchestratorRunId $runId -Apply *> (Join-Path $output 'migration-001-037.log')
    if($LASTEXITCODE -ne 0 -or -not (Select-String -LiteralPath (Join-Path $output 'migration-001-037.log') -Pattern 'RUN_STATUS=PASS' -Quiet)){
        throw 'Isolated 001-037 migration chain failed; preserve the run-scoped DB and log.'
    }
    $manifest.status='MIGRATIONS_001_037_PASS'; Save-Json (Join-Path $output 'manifest.json') $manifest

    $keys=@('DATABASE_URL','ENFORCE_TARGET_SCOPE','ALLOWED_SCOPES','ALLOWED_TOOLS','KALI_WORKER_URL','M2A_WORKER_API_MODE',
        'GADE_L2_RUN_ID','GADE_L2_DB_PORT','GADE_L2_OUTPUT','GADE_L2_EXPECTED_WORKER_SHA256','GADE_L2_TEST_PASSWORD','GADE_L1_CORRELATION_ID')
    $prior=@{}; foreach($k in $keys){$prior[$k]=[Environment]::GetEnvironmentVariable($k,'Process')}
    $encodedPass=[Uri]::EscapeDataString($dbPassword)
    $env:DATABASE_URL="postgresql+asyncpg://${database}:${encodedPass}@127.0.0.1:${port}/${database}"
    $env:ENFORCE_TARGET_SCOPE='true'; $env:ALLOWED_SCOPES=$scope; $env:ALLOWED_TOOLS=$expectedTool
    $env:KALI_WORKER_URL=$workerUrl; $env:M2A_WORKER_API_MODE='native'
    $env:GADE_L2_RUN_ID=$runId; $env:GADE_L2_DB_PORT=[string]$port; $env:GADE_L2_OUTPUT=$output
    $env:GADE_L2_EXPECTED_WORKER_SHA256=$expectedWorkerSha; $env:GADE_L2_TEST_PASSWORD=$password
    $d7Error=$null
    try {
        $phase='RESET_GATE_D7'
        $caseIdD7="GADE-L2-D7-$runId-RESET"
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $caseIdD7 -RequestId "$caseIdD7-request" `
            -EvidencePath (Join-Path $output 'lab-reset-d7.json') `
            -ResetRequest { param($caseId,$requestId) Reset-Lab $resetKey $caseId $requestId } `
            -CaseAction {
                & $python $driver --case D7 *> (Join-Path $output 'driver-d7.log')
                if($LASTEXITCODE -ne 0){throw "D7 case driver failed with exit $LASTEXITCODE."}
            } | Out-Null
        if(-not (Test-Path -LiteralPath (Join-Path $output 'd7-evidence.json') -PathType Leaf)) {
            throw 'D7 case returned without its evidence file.'
        }
        $phase='VERIFY_D7_TARGET_EVENTS'
        $d7=Get-Content -LiteralPath (Join-Path $output 'd7-evidence.json') -Raw | ConvertFrom-Json
        $requestId=[string]$d7.worker_receipt.request_id
        $corr7=[string]$d7.correlation_id
        Assert-Ok ($requestId -match '^[0-9a-f-]{36}$' -and $corr7) 'D7 correlation metadata missing or invalid.'
        $eventsAfterD7=Get-TargetEvents (Join-Path $output 'target-events-after-d7.jsonl')
        $d7Events=@($eventsAfterD7 | Where-Object {(Get-EventPropertyValue $_ 'request_id') -ceq $requestId -and (Get-EventPropertyValue $_ 'test_case_id') -ceq $corr7})
        foreach($eventName in @('login_succeeded','session_created','protected_access_granted')){
            Assert-Ok (@($d7Events | Where-Object {(Get-EventPropertyValue $_ 'event') -ceq $eventName}).Count -ge 1) "Target-side D7 event '$eventName' missing for the Worker request ID."
        }

        $phase='RESET_GATE_D1'
        $caseIdD1="GADE-L2-D1-$runId-RESET"
        Invoke-GadeResetGatedCase -RunId $runId -CaseId $caseIdD1 -RequestId "$caseIdD1-request" `
            -EvidencePath (Join-Path $output 'lab-reset-d1.json') `
            -ResetRequest { param($caseId,$requestId) Reset-Lab $resetKey $caseId $requestId } `
            -CaseAction {
                & $python $driver --case D1 *> (Join-Path $output 'driver-d1.log')
                if($LASTEXITCODE -ne 0){throw "D1 case driver failed with exit $LASTEXITCODE."}
            } | Out-Null
    } catch { $d7Error=$_.Exception.Message }
    finally { foreach($k in $keys){[Environment]::SetEnvironmentVariable($k,$prior[$k],'Process')} }
    foreach($driverLogName in @('driver-d7.log','driver-d1.log')){
        $driverLogPath=Join-Path $output $driverLogName
        if(Test-Path -LiteralPath $driverLogPath){
            $driverLog=Get-Content -LiteralPath $driverLogPath -Raw
            Set-Content -LiteralPath $driverLogPath -Value (Sanitize-Text $driverLog) -Encoding UTF8
        }
    }
    if($d7Error){throw (Sanitize-Text $d7Error)}

    $phase='TARGET_SIDE_CORRELATION'
    $d1=Get-Content -LiteralPath (Join-Path $output 'd1-evidence.json') -Raw | ConvertFrom-Json
    $corr1=[string]$d1.correlation_id
    Assert-Ok ($corr1 -and $corr7 -and $corr7 -cne $corr1) 'D7/D1 correlation metadata missing or invalid.'
    $eventsAfterD1=Get-TargetEvents (Join-Path $output 'target-events-after-d1.jsonl')
    $d1Events=@($eventsAfterD1 | Where-Object {(Get-EventPropertyValue $_ 'test_case_id') -ceq $corr1})
    Assert-Ok ($d1Events.Count -eq 0) 'A target-side request correlated to D1 occurred; D1 is not a clean governance-only denial.'
    $targetEvidence=[ordered]@{run_id=$runId;worker_request_id=$requestId;d7_correlation_id=$corr7;d1_correlation_id=$corr1;
        d7_events=$d7Events;d1_events=$d1Events;d7_target_events_verified=$true;d1_target_events_absent=$true;
        reset_before_each_case=$true;reset_evidence=@('lab-reset-d7.json','lab-reset-d1.json');
        source='read-only docker logs from existing m2a-mode-b-l2-auth sidecar'}
    Save-Json (Join-Path $output 'target-side-evidence.json') $targetEvidence
    $manifest.status='D7_REAL_EXECUTION_PASS_D1_GOVERNANCE_DENIAL_PASS'; $manifest.completed_utc=[DateTime]::UtcNow.ToString('o')
    $manifest.target_side_evidence='target-side-evidence.json'; $manifest.formal_sample=$false
    Save-Json (Join-Path $output 'manifest.json') $manifest
    $hashes=@{}
    Get-ChildItem -LiteralPath $output -File | Where-Object Name -ne 'sha256-manifest.json' | Sort-Object Name | ForEach-Object {
        $hashes[$_.Name]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Save-Json (Join-Path $output 'sha256-manifest.json') ([ordered]@{run_id=$runId;files=$hashes})
    $status="`n## 2026-10-15 — L2 D7/D1 isolated engineering validation $runId`n`n- Status: D7 real Worker execution and D1 governance denial validated in a new isolated PostgreSQL run. This is engineering evidence, not a formal A/B/C sample. Action: lab.valid_account_access.v1 / T1078, fixed target 10.56.66.119:18080, scope 10.56.66.119/32. D7 used a Tier 3 operator approval, one-use 300-second Grant and one exact ToolTask; Worker receipt and target-side login/session/protected-resource events were correlated by request and case IDs. D1 used the same fixed contract at authorized depth 1; GADE returned ATTACK_DEPTH_EXCEEDED with no Grant/ToolTask and the target log contains no D1 case ID.`n- Evidence: $output (manifest status: D7_REAL_EXECUTION_PASS_D1_GOVERNANCE_DENIAL_PASS); SHA-256 list: $output\sha256-manifest.json. Dedicated Worker :8001 source SHA: $expectedWorkerSha. Shared Worker :8000 health identity remained unchanged.`n"
    $vault='C:\Users\p2166\Documents\ChatGPT\總規則\03 專案（Projects）\M2A 專案（M2A）'
    $noteTargets=@(
        (Join-Path $vault 'M2A 執行手冊（M2A Runbook）.md'),
        (Join-Path $vault 'M2A 建置歷史（M2A Build History）.md'),
        (Join-Path $vault 'M2A 已知問題（M2A Known Issues）.md'),
        (Join-Path $vault '報告（M2A GADE Boundary Experiment Design 20260820）.md')
    )
    foreach($note in $noteTargets){
        if(Test-Path -LiteralPath $note){
            $content=Get-Content -LiteralPath $note -Raw
            if(-not $content.Contains("L2 D7/D1 isolated engineering validation $runId")){
                Add-Content -LiteralPath $note -Value $status -Encoding UTF8
            }
        }
    }
    Write-Host "L2_D7_D1=PASS run_id=$runId evidence=$output"
    Write-Host "WORKER_8001_SHA256=$expectedWorkerSha ACTION=$expectedAction TARGET_SIDE_EVENTS=PASS D1_GRANT=NONE D1_TASK=NONE"
    Write-Host "SHARED_WORKER_8000_UNCHANGED=health_snapshot_and_remote_pid_verified"
    Write-Host 'FORMAL_EXPERIMENT_SAMPLE=NO (isolated engineering validation only)'
} catch {
    if(Test-Path -LiteralPath $output){
        $blocker=[ordered]@{run_id=$runId;phase=$phase;status='BLOCKED_OR_FAIL';error_type=$_.Exception.GetType().FullName;
            error=(Sanitize-Text $_.Exception.Message);script_stack_trace=(Sanitize-Text $_.ScriptStackTrace);utc=[DateTime]::UtcNow.ToString('o');
            container=$containerName;container_id=$containerId;volume=$volumeName;database=$database;db_port=$dbPort;shared_worker_touched=$false}
        Save-Json (Join-Path $output 'blocker-packet.json') $blocker
    }
    throw
} finally {
    Pop-Location
}
