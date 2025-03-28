
# LocalUsers PowerShell Module

## Overview
**LocalUser** helps maintain Windows stability and efficiency, providing enhanced user-centric cmdlets for local user management:

- `Get-User`
    1. Focuses only on real accounts (excludes built-in system accounts).
    2. Retrieves lost accounts (profiles lacking a name).
    3. Provides session activity details.

-  `Remove-User`
    1. Completely removes users, including profiles and registry entries.
    2. Optionally backs up user profiles before removal.

-  `New-User`
    1. Enables fast user creation with a blank password.

## Compatibility and Limitations
The **LocalUser** module parses the output of the `quser` command, which is language-dependent. The module has been tested with `quser` outputs in English, Italian, German, French, and Spanish. Based on available information, no other language outputs are possible, so the module is expected to function universally.

If a "Language not supported" exception is thrown, please contact me for assistance.


---

## Installation

Install **LocalUsers** from the [PowerShell Gallery](https://www.powershellgallery.com/packages/LocalUsers/):

```powershell
Install-Module -Name LocalUsers
```

---

## Cmdlet Reference

### `Get-User`

#### Synopsis
Displays detailed local user account information, excluding built-in and system accounts.

#### Syntax
```powershell
Get-User [-Activity]
```

#### Parameters
- `-Activity`: Displays user activity, including login/logout timestamps and session-related details.

#### Examples
```powershell
# Display all user accounts
Get-User | Format-table

# Display user activity details
Get-User -Activity | Format-table
```

#### Output Properties
| Property Name      | Description                                                                    | Requires `-Activity` |
|--------------------|--------------------------------------------------------------------------------|----------------------|
| `SID`              | Security ID of the user account                                                | No                   |
| `Username`         | Account name                                                                   | No                   |
| `AccountSource`    | Source of the account (Local, Microsoft Account, etc.)                         | No                   |
| `LocalPath`        | Path to the user's profile folder                                              | No                   |
| `isAdmin`          | Indicates if the account has administrative privileges                         | No                   |
| `PasswordLastSet`  | Date the password was last updated                                             | Yes                  |
| `LastLogin`        | Date of the user's last successful login                                       | Yes                  |
| `LastLogout`       | Date of the user's last logout (session terminated)                            | Yes                  |
| `SessionID`        | Current session ID                                                             | Yes                  |
| `IdleSessionTime`  | Inactivity duration in `Days+HH:mm` format (session running while disconnected)| Yes                  |
| `SessionStart`     | Date the current session began                                                 | Yes                  |

---

### `New-User`

#### Synopsis
Creates a new local user account with no expiration and a blank password.

#### Syntax
```powershell
New-User -Name <String> [-isAdmin]
```

#### Parameters
- `-Name`: Specifies the username for the new account.
- `-isAdmin`: Assigns administrative privileges to the user if specified.

#### Examples
```powershell
# Create a standard user
New-User -Name "JohnDoe"

# Create an administrator user
New-User -Name "AdminUser" -isAdmin
```

---

### `Remove-User`

#### Synopsis
Removes a specified local user account along with its profile and registry entries.

#### Syntax
```powershell
Remove-User [-SID <String>] [-Name <String>] [-Backup]
```

#### Parameters
- `-SID`: Specifies the SID of the user to be removed.
- `-Name`: Specifies the name of the user to be removed.
- `-Backup`: Saves the user's profile to the current user’s desktop before removal.

#### Examples
```powershell
# Remove a user by SID
Remove-User -SID "S-1-5-21-1234567890-1234567890-1234567890-1001"

# Remove a user by name and back up their profile
Remove-User -Name "JohnDoe" -Backup
```

---

## System Requirements

- **Operating System:** Windows 10 or later
- **PowerShell Version:** 7.1 or later
- **Privileges:** Requires administrative permissions

---

## Contribution

We welcome contributions! Submit issues or feature requests through the repository, or create a pull request.

---

## License

This module is licensed under the [MIT License](LICENSE).
