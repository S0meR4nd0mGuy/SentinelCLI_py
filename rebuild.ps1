$ErrorActionPreference = "Stop"

$EntryScript = "sentinelcli.py"
$MainName    = "sentinelcli"
$AliasName   = "sentinelclipy"
$ReleaseDir  = "release"

if (-not (Test-Path $EntryScript)) {
    Write-Host "ERROR: Could not find $EntryScript" -ForegroundColor Red
    Write-Host "Run this script from the project root (the folder containing 'sentinelcli.py')." -ForegroundColor Red
    exit 1
}

$pyinstaller = Get-Command pyinstaller -ErrorAction SilentlyContinue
if (-not $pyinstaller) {
    Write-Host "PyInstaller not found. Installing it now..." -ForegroundColor Yellow
    python -m pip install pyinstaller
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
Remove-Item -Force "$MainName.spec", "$AliasName.spec" -ErrorAction SilentlyContinue

Write-Host "`nBuilding $MainName.exe..." -ForegroundColor Cyan
pyinstaller --onefile --name $MainName $EntryScript
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

Write-Host "`nDone. The executable is in .\$ReleaseDir" -ForegroundColor Green
Get-ChildItem $ReleaseDir | Format-Table Name, Length, LastWriteTime