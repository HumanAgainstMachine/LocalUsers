<#
.SYNOPSIS
    Launch the GUI for LocalUsers module

#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Local User Management'
$form.Size = New-Object System.Drawing.Size(800,600)
$form.StartPosition = 'CenterScreen'

# Create DataGridView
$userGrid = New-Object System.Windows.Forms.DataGridView
$userGrid.Size = New-Object System.Drawing.Size(700,400)
$userGrid.Location = New-Object System.Drawing.Point(50,30)
$userGrid.AllowUserToAddRows = $false
$userGrid.AllowUserToDeleteRows = $false
$userGrid.MultiSelect = $true
$userGrid.SelectionMode = 'FullRowSelect'
$userGrid.RowHeadersVisible = $false
$userGrid.EnableHeadersVisualStyles = $false
$userGrid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $userGrid.ColumnHeadersDefaultCellStyle.BackColor

# Create columns
$userGrid.Columns.Add("Username", "Username") | Out-Null
$userGrid.Columns.Add("SID", "SID") | Out-Null
$userGrid.Columns.Add("AccountSource", "AccountSource") | Out-Null
$userGrid.Columns.Add("LocalPath", "LocalPath") | Out-Null
$userGrid.Columns.Add("isAdmin", "isAdmin") | Out-Null

# Set column widths
$userGrid.Columns["Username"].Width = 130
$userGrid.Columns["SID"].Width = 250
$userGrid.Columns["AccountSource"].Width = 100
$userGrid.Columns["LocalPath"].Width = 150
$userGrid.Columns["isAdmin"].Width = 70

# Create progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(50,440)
$progressBar.Size = New-Object System.Drawing.Size(700,12)
$progressBar.Style = 'Continuous'

# Create Remove button and Backup checkbox with larger sizes
$removeButton = New-Object System.Windows.Forms.Button
$removeButton.Location = New-Object System.Drawing.Point(50,460)
$removeButton.Size = New-Object System.Drawing.Size(120,23)  # Increased width
$removeButton.Text = 'Remove selected'

$backupCheckbox = New-Object System.Windows.Forms.CheckBox
$backupCheckbox.Location = New-Object System.Drawing.Point(180,463)
$backupCheckbox.Size = New-Object System.Drawing.Size(100,23)  # Increased width
$backupCheckbox.Text = "and Backup"

# Create horizontal separator line
$separator = New-Object System.Windows.Forms.Label
$separator.Location = New-Object System.Drawing.Point(50,490)
$separator.Size = New-Object System.Drawing.Size(700,2)
$separator.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D

# Create new user controls
$usernameLabel = New-Object System.Windows.Forms.Label
$usernameLabel.Location = New-Object System.Drawing.Point(50,505)  # Moved down slightly
$usernameLabel.Size = New-Object System.Drawing.Size(70,20)
$usernameLabel.Text = 'Username:'

$usernameTextBox = New-Object System.Windows.Forms.TextBox
$usernameTextBox.Location = New-Object System.Drawing.Point(120,505)  # Moved down slightly
$usernameTextBox.Size = New-Object System.Drawing.Size(150,20)

$isAdminCheckbox = New-Object System.Windows.Forms.CheckBox
$isAdminCheckbox.Location = New-Object System.Drawing.Point(280,505)  # Moved down slightly
$isAdminCheckbox.Size = New-Object System.Drawing.Size(90,20)  # Increased width
$isAdminCheckbox.Text = 'isAdmin'

# Moved Create button and increased size
$createButton = New-Object System.Windows.Forms.Button
$createButton.Location = New-Object System.Drawing.Point(380,503)  # Moved down slightly
$createButton.Size = New-Object System.Drawing.Size(100,23)
$createButton.Text = 'Create User'

# Function to populate the grid
function Update-UserGrid {
    $userGrid.Rows.Clear()
    $users = Get-User
    foreach ($user in $users) {
        $rowIndex = $userGrid.Rows.Add(
            $user.Username,
            $user.SID,
            $user.AccountSource,
            $user.LocalPath,
            $(if ($user.isAdmin) { "Yes" } else { "No" })
        )
        $userGrid.Rows[$rowIndex].Tag = $user
    }
    # Reset progress bar
    $progressBar.Value = 0
}

# Add click handlers
$removeButton.Add_Click({
    if ($userGrid.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No users selected.", "Warning")
        return
    }

    $progressBar.Maximum = $userGrid.SelectedRows.Count
    $progressBar.Value = 0

    foreach ($row in $userGrid.SelectedRows) {
        $user = $row.Tag
        $params = @{
            SID = $user.SID
        }
        if ($backupCheckbox.Checked) {
            $params.Add('Backup', $true)
        }

        Remove-User @params

        $progressBar.Value += 1
        $progressBar.Refresh()
        [System.Windows.Forms.Application]::DoEvents()
    }

    Update-UserGrid
})

$createButton.Add_Click({
    if ($usernameTextBox.Text) {
        $params = @{
            Name = $usernameTextBox.Text
        }
        if ($isAdminCheckbox.Checked) {
            $params.Add('isAdmin', $true)
        }

        New-User @params
        Update-UserGrid

        $usernameTextBox.Text = ''
        $isAdminCheckbox.Checked = $false
    }
})

# Add all controls to the form
$form.Controls.AddRange(@(
    $userGrid,
    $progressBar,
    $removeButton,
    $backupCheckbox,
    $separator,
    $usernameLabel,
    $usernameTextBox,
    $isAdminCheckbox,
    $createButton
))

# Initial population of the grid
Update-UserGrid

# Show the form
$form.ShowDialog()