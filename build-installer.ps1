# Builds the Windows installer: dist\Backhaul-Setup-<version>.exe
#
#   powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
#   powershell -ExecutionPolicy Bypass -File .\build-installer.ps1 -Version 0.5.0
#
# Steps:
#   1. Build dist\Backhaul.exe with the version stamped in (build-app.ps1).
#   2. Compile installer\backhaul.iss with Inno Setup's ISCC.exe.
#   3. Produce dist\Backhaul-Setup-<version>.exe and its SHA-256.
#
# The in-app updater downloads this setup .exe from GitHub releases, so the
# file name (Backhaul-Setup-<version>.exe) and a checksums.txt listing it must
# both be uploaded to the release. publish-checksums below prints the line to
# add to checksums.txt.
#
# Requires: Go (see build-app.ps1) and Inno Setup 6 (https://jrsoftware.org/isdl.php).
param(
    [string]$Version,
    [switch]$SkipApp   # reuse an already-built dist\Backhaul.exe
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $Version) {
    if (Test-Path VERSION) { $Version = (Get-Content VERSION -Raw).Trim() }
    if (-not $Version) { throw 'No version: pass -Version or create a VERSION file.' }
}

# 1. App binary (stamped with the same version the updater will compare).
if (-not $SkipApp) {
    & "$PSScriptRoot\build-app.ps1" -Version $Version
    if ($LASTEXITCODE) { throw 'app build failed' }
}
if (-not (Test-Path dist\Backhaul.exe)) { throw 'dist\Backhaul.exe not found (run without -SkipApp).' }

# 2. Locate ISCC.exe (Inno Setup compiler).
$iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($iscc) { $iscc = $iscc.Source }
else {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"  # winget per-user install
    )
    $iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) {
    throw 'Inno Setup (ISCC.exe) not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php'
}

# 3. Compile the installer.
Write-Host "Compiling installer for version $Version..."
& $iscc "/DMyAppVersion=$Version" "installer\backhaul.iss"
if ($LASTEXITCODE) { throw 'ISCC failed' }

$setup = "dist\Backhaul-Setup-$Version.exe"
if (-not (Test-Path $setup)) { throw "expected $setup was not produced" }

$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
$size = [math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host "Done: $setup ($size MB)"
Write-Host ''
Write-Host 'Add this line to the release checksums.txt (the updater verifies it):'
Write-Host "$hash  Backhaul-Setup-$Version.exe"
