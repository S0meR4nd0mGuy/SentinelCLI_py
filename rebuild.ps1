$ErrorActionPreference = "Stop"

$EntryScript = "sentinelcli.py"
$MainName    = "sentinelcli"
$AliasName   = "sentinelclipy"
$ReleaseDir  = "release"
$Python      = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $EntryScript)) {
    Write-Host "ERROR: Could not find $EntryScript" -ForegroundColor Red
    Write-Host "Run this script from the project root (the folder containing 'sentinelcli.py')." -ForegroundColor Red
    exit 1
}

$pyinstaller = if (Test-Path $Python) { $Python } else { (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $pyinstaller) {
    Write-Host "Python not found. Install Python or create .venv first." -ForegroundColor Red
    exit 1
}

& $pyinstaller -m PyInstaller --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller not found. Installing it now..." -ForegroundColor Yellow
    & $pyinstaller -m pip install pyinstaller
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install PyInstaller." -ForegroundColor Red
        exit 1
    }
}

Write-Host "Stopping any running SentinelCliPy processes..." -ForegroundColor Cyan
Get-Process -Name $MainName, $AliasName -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Cleaning old build/dist folders..." -ForegroundColor Cyan
Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "dist" -ErrorAction SilentlyContinue
Remove-Item -Force "$AliasName.spec" -ErrorAction SilentlyContinue

Write-Host "`nBuilding $MainName.exe..." -ForegroundColor Cyan
& $pyinstaller -m PyInstaller --clean --noconfirm "$MainName.spec"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed for $MainName.exe." -ForegroundColor Red
    exit 1
}

Write-Host "`nCopying final executable into .\$ReleaseDir ..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
Copy-Item "dist\$MainName.exe" -Destination $ReleaseDir -Force

if (Test-Path "dist\$AliasName.exe") {
    Copy-Item "dist\$AliasName.exe" -Destination $ReleaseDir -Force
}

Write-Host "`nSigning executable(s)..." -ForegroundColor Cyan
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object { $_.Subject -eq "CN=SentinelCLI Local Dev" } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "WARNING: Signing certificate not found - binary will be unsigned." -ForegroundColor Yellow
} else {
    Get-ChildItem $ReleaseDir -Filter "*.exe" | ForEach-Object {
        Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -TimestampServer "http://timestamp.digicert.com" | Out-Null
        Write-Host "Signed: $($_.Name)" -ForegroundColor Green
    }
}

Write-Host "`nDone. The executable is in .\$ReleaseDir" -ForegroundColor Green
Get-ChildItem $ReleaseDir | Format-Table Name, Length, LastWriteTime