<#S
.SYNOPSIS
    Powerful local users management
#>

<#
### Summary Table of Permanent Built-in System Accounts:

| **Account Name**        | **SID**                 | **Purpose**                                  | **Status**           | **Displayed using the command** |
|-------------------------|-------------------------|----------------------------------------------|----------------------|---------------------------------|
| `Administrator`         | `S-1-5-21-<domain>-500` | Admin tasks and troubleshooting.             | Disabled by default. | Get-LocalUser |
| `Guest`                 | `S-1-5-21-<domain>-501` | Limited, temporary access.                   | Disabled by default. | Get-LocalUser |
| `DefaultAccount`        | `S-1-5-21-<domain>-503` | UWP app support.                             | Disabled, hidden.    | Get-LocalUser |
| `WDAGUtilityAccount`    | `S-1-5-21-<domain>-504` | Application Guard virtualization support.    | Disabled by default. | Get-LocalUser |
| `LocalSystem`           | `S-1-5-18`              | Critical system services.                    | Always active.       | Get-CimInstance -ClassName win32_userprofile -filter "Special=True" |
| `SYSTEM`                | `S-1-5-18`              | Internal system reference for `LocalSystem`. | Always active.       | Get-CimInstance -ClassName win32_userprofile -filter "Special=True" |
| `LocalService`          | `S-1-5-19`              | Low-privileged local service tasks.          | Always active.       | Get-CimInstance -ClassName win32_userprofile -filter "Special=True" |
| `NetworkService`        | `S-1-5-20`              | Network-enabled service tasks.               | Always active.       | Get-CimInstance -ClassName win32_userprofile -filter "Special=True" |

These accounts are foundational to Windows and shouldn’t be altered or deleted to maintain system stability and security.
#>

#Requires -RunAsAdministrator
$DebugPreference = 'Continue'

# -- Module vars --

[array]$users = @()

# -- End --

function Read-Quser {
    <# Inner function

    Parses the text output of the quser command, creating and returning an array of
    PowerShell custom objects representing user information.
    #>

$quserOutput = quser

<#
    Define columns start positions from the English header text line, should work for many languages, consider these real quser layouts
     1                     23                 42  46      54         65
     ↓                     ↓                  ↓   ↓       ↓          ↓
    ·USERNAME··············SESSIONNAME········ID··STATE···IDLE TIME··LOGON TIME     (English)
    ·NOMEUTENTE············NOMESESSIONE·······ID··STATO···INATTIVITÀ·ACCESSO        (Italian)
    ·UTILISATEUR···········SESSION············ID··ÉTAT····TEMPS INACT·TEMPS SESSION (French)
    ·NOMBRE·USUARIO········NOMBRE·SESIÓN······ID.·ESTADO··TIEMPO IN.·TIEMPO SESIÓN  (Spanish)
    ·BENUTZERNAME··········SITZUNGSNAME·······ID··STATUS··LEERLAUF···ANMELDEZEIT    (German)

    as you can see column spacing for those different languages does not affect the parsing of quser output
#>

# Language support check
$headerLine = $quserOutput[0].Trim()

$supportedLanguages = @(
    "USERNAME",         # EN
    "NOMEUTENTE",       # IT
    "UTILISATEUR",      # FR
    "NOMBRE USUARIO",   # ES
    "BENUTZERNAME"      # DE
)

if (($supportedLanguages | ForEach-Object { $headerLine.StartsWith($_) }) -notContains $true) {
    throw "Your Windows display language is not supported, read the docs to learn more."
}

$p0 = 1  # $headerLine.IndexOf("USERNAME")
$p1 = 23 # $headerLine.IndexOf("SESSIONNAME")
$p2 = 42 # $headerLine.IndexOf("ID")
$p3 = 46 # $headerLine.IndexOf("STATE")
$p4 = 54 # $headerLine.IndexOf("IDLE TIME")
$p5 = 65 # $headerLine.IndexOf("LOGON TIME")
$p6 = 200 # $headerLine.Length

# Get columns start and width
$columns = @{
    USERNAME      = @{ Start = $p0; Width = $p1 - $p0}
    SESSIONNAME   = @{ Start = $p1; Width = $p2 - $p1} # (not used here)
    ID            = @{ Start = $p2; Width = $p3 - $p2}
    STATE         = @{ Start = $p3; Width = $p4 - $p3} # ([Active|Disc], Active are logged in users, Disc are disconnected users
    IDLETIME      = @{ Start = $p4; Width = $p5 - $p4}
    LOGONTIME     = @{ Start = $p5; Width = $p6 - $p5}
}

$dataLines = $quserOutput | Select-Object -Skip 1

# Parse each data line into a custom object
$parsedData = foreach ($line in $dataLines) {
    $columns.LOGONTIME.Width = $line.Length - $p5 # Set last col width based on data line length
    [PSCustomObject]@{
        USERNAME     = $line.Substring($columns.USERNAME.Start, $columns.USERNAME.Width).Trim()
        SESSIONNAME  = $line.Substring($columns.SESSIONNAME.Start, $columns.SESSIONNAME.Width).Trim()
        ID           = $line.Substring($columns.ID.Start, $columns.ID.Width).Trim()
        STATE        = $line.Substring($columns.STATE.Start, $columns.STATE.Width).Trim()
        IDLETIME     = $line.Substring($columns.IDLETIME.Start, $columns.IDLETIME.Width).Trim()
        LOGONTIME    = $line.Substring($columns.LOGONTIME.Start, $columns.LOGONTIME.Width).Trim()
    }
}

Write-Output $parsedData
}

function Update-UserData {
    <# Inner function

    Collects local user data from various sources and updates the $users module variable.

    Data sources:
     - SID:                from Get-LocalUser
     - Username:           Name from Get-LocalUser
     - AccountSource:      PrincipalSource from Get-LocalUser
     - LocalPath:          from Get-CimInstance
     - isAdmin:            true or false determined by Get-LocalGroupMember
     - PasswordLastSet:    from Get-LocalUser
     - LastLogin:          from Get-LocalUser
     - LastLogout:         LastUseTime from Get-CimInstance or '-' if session is running
     - SessionID:          ID from quser
     - IdleSessionTime:    IDLE TIME from quser
     - SessionStart:       LOGON TIME from quser
    #>

    # Get user accounts, built-in not included
    $Script:users = Get-LocalUser | Where-Object { $_.SID -notmatch '(-500|-501|-503|-504)$' }
    | Select-Object SID, Name, PrincipalSource, LocalPath, isAdmin, PasswordLastSet, LastLogon, LastLogout, SessionID, SessionState, IdleSessionTime, SessionStart

    # Get user profiles, special not included
    $userprofiles = Get-CimInstance -ClassName win32_userprofile -Filter "Special=False" | Select-Object SID, LocalPath, LastUseTime

    # Add profile data to user accounts
    foreach ($user in $Script:users) {
        $user.SID = $user.SID.Value # Set SID as its value, actually it is an object
        foreach ($profile in $userprofiles) {
            if ($user.SID -eq $profile.SID) {
                $user.LocalPath = $profile.LocalPath
                $user.LastLogout = $profile.LastUseTime
                break
            }
        }
    }

    # Add isAdmin=[$true|$false] to user accounts
    $Administrators = Get-LocalGroupMember -Name Administrators | Select-Object -ExpandProperty Name
    foreach ($user in $Script:users) {
        $user.isAdmin = $Administrators -Contains "$env:COMPUTERNAME\$($user.name)"
    }

    # Add running sessions data to user accounts
    $sessions = Read-Quser
    foreach ($user in $Script:users) {
        foreach ($session in $sessions) {
            if ($session.USERNAME -eq $user.Name) {
                $user.SessionState = ($session.STATE.ToLower() -in 'active', 'attivo', 'aktiv', 'actif', 'activo') ? 'Active':$null
                $user.LastLogout = $null # overwrite LastUseTime that returns current time for running sessions
                $user.SessionID = $session.ID
                $user.IdleSessionTime = ($user.SessionState -eq 'Active') ? $($null):(($session.IDLETIME -ne '.') ? $session.IDLETIME:'0')
                $user.SessionStart = $session.LOGONTIME
                break
            }
        }
    }

    <#
    Add NoName users, which are user profiles lacking a username.
    User profiles without a name happens as far as I know in two cases:
    1. users removed with Remove-LocalUser, command that does not delete profile directories and registry entries associated with the account
    2. users manually removed without deleting their associated data, a feature allowed in older versions of Windows
    #>
    [array]$noNameUsers = @()
    $noNameUsers = foreach ($profile in $userprofiles) {
        if ($profile.SID -notin $users.SID) {
            [PSCustomObject]@{
                SID = $profile.SID
                Name = $null
                PrincipalSource = $null
                LocalPath = $profile.LocalPath
                isAdmin = $null
                PasswordLastSet = $null
                LastLogon = $null
                LastLogout = $profile.LastUseTime
                SessionID = $null
                IdleSessionTime = $null
                SessionStart = $null
            }
        }
    }
    $Script:users += $noNameUsers
}

function Stop-Session {
    <# Inner function

    Terminates the session specified by $SessionID.
    WARNING: This command may log out the currently logged-in user (terminate session)
    if the specified $SessionID belongs to the current session.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$SessionID
    )
    logoff $SessionID
}

function Backup-UserProfile {
    <# Inner function

    Backs up the user profile associated with the specified SID.
    - Excludes symbolic links.
    - Saves the backup with timestamp to the current user's desktop.
    - Called by Remove-User cmdlet only if a user-name exists.
    #>
    param (
        [Parameter(Mandatory=$True)]
        [string]$SID
    )

    $Name = ($users | Where-Object {$_.SID -eq $SID.Trim()} | Select-Object NAME).NAME

    $userLocalPath = (Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $SID }).LocalPath
    if ($userLocalPath) {
        $backupDir = (Split-Path -Qualifier $env:windir) + "\UsersApp\backups"
        $BackupPath = Join-Path $backupDir "$($Name)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

        # Create the backup directory if it doesn't exist
        if (-Not (Test-Path -Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath | Out-Null
        }

        # List of folders to backup
        $foldersToBackup = @("Desktop", "Documents", "Downloads", "Links", "Pictures", "Music", "Videos", "Saved games")

        Write-Host "Backing up user profile: $Name..."
        foreach ($folder in $foldersToBackup) {
            $sourcePath = Join-Path $userLocalPath $folder
            $destPath = Join-Path $BackupPath $folder

            & robocopy $sourcePath $destPath /E /COPY:DAT /XJ /R:1 /W:1 /IF /NP /NFL | Out-Null

            $successfulBackup = $true
            # Check robocopy exit code (0-7 are considered successful)
            if ($LASTEXITCODE -gt 7) {$successfulBackup = $false}            
            Write-Progress -Activity "Backing up $Name" -Status "Copying $folder..." -PercentComplete (($foldersToBackup.IndexOf($folder) / $foldersToBackup.Count) * 100)
        }

        if ($successfulBackup) {
            Write-Host "$Name Backup successful: user profile saved on this computer." -ForegroundColor Green
        }
        else {
            Write-Warning "$Name Backup failed: error copying files from user profile."
        }
    }
    else {
        Write-Warning "$Name User profile not found. Backup operation skipped."
    }
}

function Get-User {
    <#
    .SYNOPSIS
        Displays local user account data, excluding built-in and system accounts.

    .DESCRIPTION
        This cmdlet retrieves detailed information about local user accounts on the system.
        Data is collected from the sources: Get-LocalUser, Get-CimInstance, Get-LocalGroupMember, and quser.

    .OUTPUTS
        Object containing the following properties:
            SID:              Security ID of the user account.
            Username:         Specifies the account name.
            AccountSource:    Specifies the account type (e.g., Local, Active Directory, Microsoft Entra Group, or Microsoft Account).
            LocalPath:        Local path to the user's profile folder.
            isAdmin:          Indicates whether the user is an administrator.
            PasswordLastSet:  The date and time the user's password was last set.
            LastLogin:        The date and time of the user's most recent entry of credentials (last login).
            LastLogout:       The date and time the user's current session terminated (last logout).
            SessionID:        The current session ID of the user.
            IdleSessionTime:  The duration formatted as Days+HH:mm of user inactivity in the current session (disconnected while leaving session running).
            SessionStart:     The date and time the user's current session started.
    #>

    param ([Switch]$Activity)
    if ($Activity) {
        $columns = @(
            @{n='Username'; e={$_.Name ? $_.Name:'-'}},
            @{n='PasswordLastSet'; e={$_.PasswordLastSet ? $_.PasswordLastSet:'-'}},
            @{n='LastLogin';e={$_.LastLogon ? $_.LastLogon:'-'}},
            @{n='LastLogout';e={$_.LastLogout ? $_.LastLogout:'-'}},
            @{n='IdleSessionTime';e={$_.IdleSessionTime ? $_.IdleSessionTime:'-'}},
            @{n='SessionStart';e={$_.SessionStart ? $_.SessionStart:'-'}}
        )
    }
    else {
        $columns = @(
            @{n='Username'; e={$_.Name ? $_.Name:'-'}},
            'SID',
            @{n='AccountSource';e={$_.PrincipalSource ? ($_.PrincipalSource -as [string]):'-'}},
            @{n='LocalPath';e={$_.LocalPath ? $_.LocalPath:'-'}},
            @{n='isAdmin';e={($null -ne $_.isAdmin) ? $_.isAdmin:'-'}}
        )
    }
    Update-UserData
    Write-Output $users | Select-Object $columns
}

function New-User {
    <#
    .SYNOPSIS
        Creates a local user account with no expiration and a blank password.
        If the -isAdmin switch is provided, the account will have administrator
        privileges; otherwise, it will be a standard user.

    .DESCRIPTION
        Creates a local account with a blank password. The newly created
        user must log in to set a password if desired.
        #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$True)]
        [string]$Name,
        [switch]$isAdmin
    )

    $blankPassword = [securestring]::new()

    try {
        New-LocalUser -Name $Name -Password $blankPassword -PasswordNeverExpires -AccountNeverExpires -ErrorAction Stop | Out-Null
    }
    catch [Microsoft.PowerShell.Commands.UserExistsException] {
        # Re-throw the exception to propagate it up and hiding New-LocalUser origin
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
    catch [System.Management.Automation.ParameterBindingException] {
        throw "Username exceeds the maximum length. Please limit it to 20 characters or fewer."
    }

    if ($isAdmin) {
        Add-LocalGroupMember -Group Administrators -Member $Name
        Write-Host "$Name administrator account created" -ForegroundColor Green
    }
    else {
        Add-LocalGroupMember -Group Users -Member $Name
        Write-Host "$Name standard account created" -ForegroundColor Green
    }
}

function Remove-User {
    <#
    .SYNOPSIS
        Removes the specified local user account along with its profile folder and associated registry entries.

    .DESCRIPTION
        Removes the specified account using the provided -SID or -Name parameter.

    .PARAMETER SID
        The Security Identifier (SID) of the user account to remove.

    .PARAMETER Name
        The username of the user account to remove.

    .PARAMETER Backup
        Switch parameter. if provided, backs up the user profile while:
        - Excluding symbolic links.
        - Saving the backup with a timestamp to the current user's desktop.

    .NOTES
        Inspiration: https://adamtheautomator.com/powershell-delete-user-profile/
    #>

    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Set0')]
    param (
        [Parameter(ParameterSetName = 'Set0', Mandatory = $true)]
        [string]$SID,
        [Parameter(ParameterSetName = 'Set1', Mandatory = $true)]
        [string]$Name,
        [switch]$Backup
    )

    Update-UserData
    if ($PSCmdlet.ParameterSetName -eq 'Set1') {
        $SID    = ($users | Where-Object {$_.Name -eq $Name.Trim()} | Select-Object SID).SID
    } else {
        $Name = ($users | Where-Object {$_.SID -eq $SID.Trim()} | Select-Object NAME).NAME
    }
    $SessionID      = ($users | Where-Object {$_.SID -eq $SID.Trim()} | Select-Object SessionID).SessionID
    $SessionState   = ($users | Where-Object {$_.SID -eq $SID.Trim()} | Select-Object SessionState).SessionState

    if ($SessionState -eq 'Active') {
        Write-Warning "You can't remove yourself while operating!"
        Return
    }
    if (-Not $SID) {
        Write-Warning "User account not found."
        Return
    }
    if ($SessionID) {
        Stop-Session -SessionID $SessionID
    }
    else {
        <#
        When the admin runs `Remove-User -SID <SID>`, it is likely intended for a NoName user.
        If a NoName user's session is running, its session ID in the `$users` array will be `$null`
        due to the absence of a username. The following code identifies and terminates such sessions.
        #>
        $sessions = Read-Quser
        foreach ($session in $sessions) {
            if ($session.USERNAME -notin $users.Name) {
                Stop-Session -SessionID $session.ID
            }
        }
    }
    if ($Backup) {
        Backup-UserProfile -SID $SID
    }

    try {
        Write-Host "Removing user profile and registry data for: $Name..."
        # Remove CIM instance if exist (%USERPROFILE% folder and registry entry)
        $profileCimInstance = Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $SID }
        if ($null -ne $profileCimInstance) {
            Remove-CimInstance -InputObject $profileCimInstance -ErrorAction Stop
            Write-Host "Profile data and registry entries successfully removed" -ForegroundColor green
        }
        else {
            Write-Warning "Profile not found"
        }

        # Remove the sign-in entry in Windows
        Remove-LocalUser -SID $SID -ErrorAction Stop
        Write-Host "Account entry removed" -ForegroundColor Green
    }
    catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
        Write-Warning "Account entry not found"
    }
    catch {
        $_.exception.GetType().fullname
    }
}