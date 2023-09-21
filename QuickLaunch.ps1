function Choice-Loop {
    Write-Host "What do you want to do?"
    Write-Host "1. Senior Review"
    Write-Host "2. Backup Data"
    Write-Host "3. Verify Data"
    Write-Host "4. Restore Data"
    Write-Host "5. Run Actions"
    Write-Host "6. Exit"

    [int] $choice = Read-Host -Prompt "Enter your choice"
    switch ($choice) {
        1 { \\main\shares\fa\its_ds_general\utilities\Multi-Tool.ps1 -review }
        2 { \\main\shares\fa\its_ds_general\utilities\Backup-Data.ps1 -networkShares}
        3 { \\main\shares\fa\its_ds_general\utilities\Verify-Data.ps1 }
        4 { \\main\shares\fa\its_ds_general\utilities\Multi-Tool.ps1 -restore -networkShares}
        5 { \\main\shares\fa\its_ds_general\utilities\Multi-Tool.ps1 -Actions }
        6 { exit 0 }
        7 { \\main\shares\fa\its_ds_general\utilities\Backup-Data.ps1 -sourceDir (Read-Host "Enter the root directory (Ex. F:\)")}
        Default {cls}
    }
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb "RunAs" -ArgumentList "-File \\main\shares\fa\its_ds_general\utilities\quicklaunch.ps1 -NoExit"
    exit 0
}

cls

while($true) {
    Choice-Loop
}