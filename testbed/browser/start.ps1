# 현재 PowerShell 프로세스에서만 도구 경로를 찾는다. OS 환경변수/프록시 설정을 바꾸지 않는다.
#   .\testbed\browser\start.ps1              # 이 창에서 실행(창을 닫으면 종료)
#   .\testbed\browser\start.ps1 -Background  # 창 없이 실행 + 꺼지면 자동 재시작 (정지: stop.ps1)
param([switch]$Background)
$ErrorActionPreference = 'Stop'
if ($Background) {
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'supervise.ps1')
    Write-Output '백그라운드로 실행했습니다: http://localhost:18888  (정지: .\testbed\browser\stop.ps1)'
    exit 0
}
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if ($dockerCmd) { $env:DOCKER_BIN = $dockerCmd.Source }
else {
    $candidate = Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe'
    if (-not (Test-Path -LiteralPath $candidate)) { throw 'Docker CLI를 PATH에서 찾을 수 없습니다.' }
    $env:DOCKER_BIN = $candidate
}
$nodeCmd = Get-Command node -ErrorAction Stop
& $nodeCmd.Source (Join-Path $PSScriptRoot 'server.cjs')
exit $LASTEXITCODE