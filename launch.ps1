# Script to install the LocalUsers module if not present and call Show-User

# Check if the LocalUsers module is already installed
if (-not (Get-Module -ListAvailable -Name LocalUsers)) {
    Write-Host "LocalUsers module not found. Installing from PSGallery..."
    
    # Check if PSGallery is registered and trusted
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Default
    }
    
    # Set PSGallery as trusted if not already
    $galleryInfo = Get-PSRepository -Name PSGallery
    if ($galleryInfo.InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    
    # Install the LocalUsers module
    Install-Module -Name LocalUsers -Repository PSGallery -Force -Scope CurrentUser
    
    Write-Host "LocalUsers module installed successfully."
} else {
    Write-Host "LocalUsers module is already installed."
}

# Import the module
Import-Module LocalUsers

# Call the Show-User method
Write-Host "Calling Show-User method..."
Show-User