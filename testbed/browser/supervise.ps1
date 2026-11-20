# localhost:18888 브라우저 입구(server.cjs) 감시 실행기.
# server.cjs가 종료되면(ERP·게이트웨이·시험 단말 재시작으로 연결이 끊긴 경우 등) 3초 뒤 다시 실행한다.
# 한 PC에서 하나만 실행된다. 종료는 stop.ps1. OS 환경변수·프록시·방화벽 설정을 바꾸지 않는다.
$ErrorActionPreference = 'Stop'
$mutex = New-Object System.Threading.Mutex($false, 'Local\capstone-erp-ui-supervisor')
if (-not $mutex.WaitOne(0)) { Write-Output '이미 실행 중입니다(감시 실행기 1개만 허용).'; exit 0 }

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) { $env:DOCKER_BIN = $dockerCmd.Source }
else {
    $candidate = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'
    if (-not (Test-Path -LiteralPath $candidate)) { throw 'Docker CLI를 찾을 수 없습니다.' }
    $env:DOCKER_BIN = $candidate
}
$node = (Get-Command node -ErrorAction Stop).Source
$server = Join-Path $PSScriptRoot 'server.cjs'
$stateDir = Join-Path $env:LOCALAPPDATA 'capstone-erp-ui'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$log = Join-Path $stateDir 'supervisor.log'
$stopFlag = Join-Path $stateDir 'stop.flag'
Remove-Item -LiteralPath $stopFlag -ErrorAction SilentlyContinue
function Log($m) { Add-Content -LiteralPath $log -Value ("{0:u} {1}" -f (Get-Date).ToUniversalTime(), $m) -Encoding utf8 }
# 로그는 시작/종료 코드만 남긴다(인증값·요청 내용 없음). 1MB 넘으면 새로 시작.
if ((Test-Path $log) -and (Get-Item $log).Length -gt 1MB) { Remove-Item -LiteralPath $log }

Log "supervisor start pid=$PID"
try {
    while (-not (Test-Path -LiteralPath $stopFlag)) {
        $p = Start-Process -FilePath $node -ArgumentList "`"$server`"" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
        Log "server start pid=$($p.Id)"
        $p.WaitForExit()
        Log "server exit code=$($p.ExitCode)"
        if (Test-Path -LiteralPath $stopFlag) { break }
        Start-Sleep -Seconds 3
    }
} finally {
    Log 'supervisor stop'
    $mutex.ReleaseMutex()
}
