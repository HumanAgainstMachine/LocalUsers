<#
.SYNOPSIS
    GUL app installation script
.DESCRIPTION
    GUL is a PowerShell 7.1+ app composed by LocalUsers module and a separate GUI script.
#>

# Create GUL Roaming Folder
$gulRoamingFolder = Join-Path $env:APPDATA "GUL"
New-Item -ItemType Directory -Force -Path $gulRoamingFolder | Out-Null

$baseUrl = "https://github.com/HumanAgainstMachine/LocalUsers/releases/latest/download/"

# Run as admin test
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "GUL needs to be installed as Administrator. Restarting with elevated privileges..."

    # This script download
    $myselfUrl = $baseUrl + "install-GUL.ps1"
    $myselfPath = Join-Path $gulRoamingFolder "install-GUL.ps1"

    try {
        Invoke-WebRequest -Uri $myselfUrl -OutFile $myselfPath
        Start-Process pwsh.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$myselfPath`"" -Verb RunAs
        Write-Host "`nRelaunch success" -ForegroundColor Green
    }
    catch {
        Write-Host "`nRelaunch failed" -ForegroundColor Red
    }
    finally {
        Write-Host "`nPress any key to close..."
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null        
        exit
    }
}

# Path for PowerShell 7
$ps7Path = "C:\Program Files\PowerShell\7\pwsh.exe"

# Install/Update LocalUsers module
if ($lUsers = Get-Module -ListAvailable -Name LocalUsers) {
    Write-Host "LocalUsers module is already installed. Checking for updates..." -ForegroundColor Green
    
    $currentModule = $lUsers | Sort-Object Version -Descending | Select-Object -First 1
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
    
    if ($lUsers = Get-Module -ListAvailable -Name LocalUsers) {
        $installedModule = $lUsers | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host "LocalUsers module has been successfully installed (Version: $($installedModule.Version))." -ForegroundColor Green
    } else {
        Write-Host "Failed to install LocalUsers module. Please install manually." -ForegroundColor Red
    }
}

$gulAppUrl = $baseUrl + "GUL.ps1"

# Create a script that the shortcut links to in order to prevent the shortcut from being flagged as a virus.
$gulLaunchps1 = @"
Start-Process pwsh.exe -Verb RunAs -ArgumentList '-Command "irm $gulAppUrl | iex"'
"@

$gulLaunchps1Path = Join-Path $gulRoamingFolder "LaunchGUL.ps1"
Set-Content -Path $gulLaunchps1Path -Value $gulLaunchps1


# Download icon
$iconUrl = $baseUrl + "GUL.ico"
$iconPath = Join-Path $gulRoamingFolder "GUL.ico"

try {
    Invoke-WebRequest -Uri $iconUrl -OutFile $iconPath
    Write-Host "Icon downloaded successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to download icon." -ForegroundColor Red
    $iconPath = "$ps7Path,0"  # Fallback to PowerShell icon
}

# Create desktop shortcut for GUL
$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "GUL.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath = $ps7Path
$Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$gulLaunchps1Path`""
$Shortcut.IconLocation = $iconPath
$Shortcut.Description = "Launch GUL"
$Shortcut.Save()

# Add "Run as administrator" to the shortcut
$bytes = [System.IO.File]::ReadAllBytes($shortcutPath)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($shortcutPath, $bytes)

Write-Host "Installation completed successfully!" -ForegroundColor Green

# Pause before closing
Write-Host "`nPress any key to close..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null