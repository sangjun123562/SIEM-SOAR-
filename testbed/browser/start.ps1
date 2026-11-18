# 현재 PowerShell 프로세스에서만 도구 경로를 찾는다. OS 환경변수/프록시 설정을 바꾸지 않는다.
$ErrorActionPreference = 'Stop'
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