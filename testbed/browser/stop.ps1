# 브라우저 입구 정지: 감시 실행기와 이 저장소의 server.cjs만 종료하고 중계 컨테이너만 내린다.
# ERP·DB·로그 볼륨은 건드리지 않는다. 다른 node 프로세스는 명령행을 확인해 제외한다.
$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $env:LOCALAPPDATA 'capstone-erp-ui'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
Set-Content -LiteralPath (Join-Path $stateDir 'stop.flag') -Value 'stop' -Encoding utf8

$here = $PSScriptRoot
$targets = Get-CimInstance Win32_Process | Where-Object {
    ($_.Name -eq 'powershell.exe' -and $_.CommandLine -like "*$here*supervise.ps1*") -or
    ($_.Name -eq 'node.exe' -and $_.CommandLine -like "*$here*server.cjs*")
}
foreach ($t in $targets) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue; Write-Output "종료: $($t.Name) pid=$($t.ProcessId)" }

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
$docker = if ($dockerCmd) { $dockerCmd.Source } else { Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\resources\bin\docker.exe' }
$ErrorActionPreference = 'Continue'   # docker는 진행 메시지를 stderr로 쓰므로 오류로 취급하지 않는다
& $docker compose -f (Join-Path $here 'compose.json') down *> $null
Write-Output '브라우저 입구 정지 완료(중계 컨테이너만 내림).'
