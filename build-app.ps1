# Builds the all-in-one Windows app: dist\Backhaul.exe
# (WebView2 UI + exit node + client + embedded wstunnel and Wintun).
#
#   powershell -ExecutionPolicy Bypass -File .\build-app.ps1
#
# Requires Go 1.26+ on PATH (or in %USERPROFILE%\sdk\go) and internet access
# for the first run (pinned, checksum-verified downloads).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    $sdk = Join-Path $env:USERPROFILE 'sdk\go\bin'
    if (Test-Path (Join-Path $sdk 'go.exe')) { $env:Path = "$sdk;$env:Path" }
    else { throw 'Go is not installed (https://go.dev/dl/).' }
}

Write-Host '1/3  Fetching bundled components (wstunnel, Wintun) and drawing the icon...'
go run ./cmd/backhaul-app/gen
if ($LASTEXITCODE) { throw 'asset generation failed' }

Write-Host '2/3  Embedding icon, version info and administrator manifest...'
go run github.com/tc-hib/go-winres@v0.3.3 make --in cmd/backhaul-app/winres/winres.json --out cmd/backhaul-app/rsrc --arch amd64
if ($LASTEXITCODE) { throw 'resource generation failed' }

Write-Host '3/3  Building dist\Backhaul.exe...'
New-Item -ItemType Directory -Force dist | Out-Null
go build -trimpath -ldflags '-s -w -H=windowsgui' -o dist\Backhaul.exe ./cmd/backhaul-app
if ($LASTEXITCODE) { throw 'build failed' }

$size = [math]::Round((Get-Item dist\Backhaul.exe).Length / 1MB, 1)
Write-Host "Done: dist\Backhaul.exe ($size MB)"
