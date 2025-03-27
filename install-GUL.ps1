# Ensure we're running as admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script needs to be run as Administrator. Restarting with elevated privileges..."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Path for PowerShell 7
$ps7Path = "C:\Program Files\PowerShell\7\pwsh.exe"

# Install/Update LocalUsers module
if (Get-Module -ListAvailable -Name LocalUsers) {
    Write-Host "LocalUsers module is already installed. Checking for updates..." -ForegroundColor Green
    
    $currentModule = Get-Module -ListAvailable -Name LocalUsers | Sort-Object Version -Descending | Select-Object -First 1
    $onlineModule = Find-Module -Name LocalUsers -Repository PSGallery
    
    if ($onlineModule.Version -gt $currentModule.Version) {
        Write-Host "Updating LocalUsers module from version $($currentModule.Version) to $($onlineModule.Version)..." -ForegroundColor Yellow
        Update-Module -Name LocalUsers -Force
        Write-Host "LocalUsers module has been updated to version $($onlineModule.Version)." -ForegroundColor Green
    } else {
        Write-Host "LocalUsers module is already at the latest version ($($currentModule.Version))." -ForegroundColor Green
    }
} else {
    Write-Host "Installing LocalUsers module from PSGallery..." -ForegroundColor Yellow
    Install-Module -Name LocalUsers -Repository PSGallery -Force -Scope AllUsers
    
    if (Get-Module -ListAvailable -Name LocalUsers) {
        $installedModule = Get-Module -ListAvailable -Name LocalUsers | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host "LocalUsers module has been successfully installed (Version: $($installedModule.Version))." -ForegroundColor Green
    } else {
        Write-Host "Failed to install LocalUsers module. Please install manually." -ForegroundColor Red
    }
}

# Create GUL Roaming Folder and Wrapper Script
$gulRoamingFolder = Join-Path $env:APPDATA "GUL"
New-Item -ItemType Directory -Force -Path $gulRoamingFolder | Out-Null

# Download icon
$iconUrl = "https://github.com/HumanAgainstMachine/LocalUsers/releases/latest/download/GUL.ico"
$iconPath = Join-Path $gulRoamingFolder "GUL.ico"

try {
    Invoke-WebRequest -Uri $iconUrl -OutFile $iconPath
    Write-Host "Icon downloaded successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to download icon." -ForegroundColor Red
    $iconPath = "$ps7Path,0"  # Fallback to PowerShell icon
}

$gulWrapperScript = @"
Start-Process pwsh.exe -Verb RunAs -ArgumentList '-Command "irm https://github.com/HumanAgainstMachine/LocalUsers/releases/latest/download/GUL.ps1 | iex"'
"@

$gulWrapperScriptPath = Join-Path $gulRoamingFolder "LaunchGUL.ps1"
Set-Content -Path $gulWrapperScriptPath -Value $gulWrapperScript

# Create desktop shortcut for GUL
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "GUL.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath = $ps7Path
$Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$gulWrapperScriptPath`""
$Shortcut.IconLocation = $iconPath
$Shortcut.Description = "Launch GUL"
$Shortcut.Save()

# Add "Run as administrator" to the shortcut
$bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($shortcutPath, $bytes)

Write-Host "Installation completed successfully!" -ForegroundColor Green