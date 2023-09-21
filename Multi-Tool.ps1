[cmdletbinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Restore,
    [Parameter(Mandatory = $false)]
    [switch]$PostImageSetup,
    [Parameter(Mandatory = $false)]
    [switch]$Review,
    [Parameter(Mandatory = $false)]
    [switch]$Actions,
    [switch]$networkShares #TODO: TEMP
)

Begin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        write-host "This script needs to be run as admin..." -ForegroundColor red
        exit 1
    }

    function Start-UpdateInstallation {
        Begin {
            $AppEvalState0 = "0"
            $AppEvalState1 = "1"
        }
        Process {
            $Application = (Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate | Where-Object { $_.EvaluationState -like "*$($AppEvalState0)*" -or $_.EvaluationState -like "*$($AppEvalState1)*" })
            Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (, $Application) -Namespace root\ccm\clientsdk | Out-Null
        }
        End {}
    }
 
    function Get-InstalledPrograms {
        $Installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName) + (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName)
        return $Installed
    }

    function Install-Program {
        param(
            [Parameter(Mandatory = $true)]
            [string]$ProgramName,
            [Parameter(Mandatory = $true)]
            [string]$ProgramPath
        )
        if ($ProgramPath -like "*.ps1") {
            Write-Host "Installing $ProgramName"
            & $ProgramPath -DeploymentType Install -DeployMode NonInteractive | Out-Null
        }
        else {
            Start-Process -FilePath $ProgramPath -Wait
        }
    }

    function Get-LatestVersion {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path,
            [Parameter(Mandatory = $true)]
            [string]$Splitter
        )
        $folders = Get-ChildItem -Path $Path.split($Splitter)[0] | Where-Object { $_.PSIsContainer -eq $true }
        $latest = ($folders | Sort-Object -Descending -Property { $_.Name -as [version] } | Select-Object -First 1)
        return $latest
    }

    function Start-Actions {
        Write-Host "Running actions..." -ForegroundColor Yellow
        # Run actions: 
        $actions = "{00000000-0000-0000-0000-000000000113}", "{00000000-0000-0000-0000-000000000114}", "{00000000-0000-0000-0000-000000000021}"
        foreach ($action in $actions) {
            Invoke-WmiMethod -Namespace root\ccm -Class sms_client -Name TriggerSchedule $action
            Write-Host "Triggered action $action"
        }
    }

    function Install-AllPrograms {
        param(
            [Parameter(Mandatory = $true)]
            [hashtable]$Programs
        )
        foreach ($prog in $Programs.Keys) {
            if ($Installed -match $prog) {
                Write-Host "$prog found" -ForegroundColor Green
            }
            else {
                $failout = "$prog not found, installing..."
                $failoutLength = $failout.Length
                Write-Host $failout -ForegroundColor Yellow -NoNewline
                Install-Program -ProgramName $prog -ProgramPath $Programs[$prog]
                while ($true) {
                    if (Get-InstalledPrograms -match $prog) {
                        $successout = "`r$prog installed"
                        $successoutLength = $successout.Length
                        Write-Host ($successout + (" " * (1 + ($failoutLength - $successoutLength)))) -ForegroundColor Green
                        break
                    }
                    else {
                        Start-Sleep -Seconds 3
                    }
                }
            }
        }

    }

    function Install-DriverUpdates {
        $dcuService = Get-Service -Name "Dell Client Management Service"
        if ($dcuService.Status -eq "Stopped") {
            # TODO: enabled if disabled, set autostart if not set
            Set-Service $dcuService -StartupType Automatic
            Start-Service -Name "Dell Client Management Service"
            Write-Host "Started DCU service" -ForegroundColor Green
        }
        # Run DCU updates while waiting for SCCM update to finish pulling
        Start-Job -Name "DCU Updates" -ScriptBlock {
            $dcu = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
            Start-Process $dcu -ArgumentList "/configure -silent -autoSuspendBitLocker=enable -userConsent=disable" -Wait | Out-Null
            Start-Process $dcu -ArgumentList "/scan -silent" -Wait | Out-Null
            Start-Process $dcu -ArgumentList "/applyUpdates -reboot=disable" -Wait | Out-Null
        }
    }

    function Get-MalfunctioningDevices {
        $devices = Get-WmiObject Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | Where-Object { $_.Name -notmatch "Cisco Anyconnect" }
        if ($devices) {
            Write-Host "WARNING: Malfunctioning drivers in device manager" -ForegroundColor RED
            ForEach-Object -InputObject $devices {
                Write-Host "$($_.Name)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "No malfunctioning drivers detected" -ForegroundColor Green
        }
    }

    function Copy-Custom {
        # robocopy cannot have trailing slashes it seems
        param(
            [Parameter(Mandatory = $true)]
            [string]$SourcePath,
            [Parameter(Mandatory = $true)]
            [string]$DestPath,
            [Parameter(Mandatory = $false)]
            [string]$Excludes
        )
        begin {
            $threads = (([int](WMIC CPU Get NumberOfLogicalProcessors)[2]) * 2)
            # /NP /NS /NC /NFL /NDL to silence
            $robocopyargs = "*.* /MT:$threads /E /COPY:DAT /R:0 /W:0 /V /NFL /LOG+:robocopy.log /xd $Excludes /xf `".DS_Store`" `"NTUSER*`""
        }
        process {
            $output = "Copying $sourcePath to $destPath"
            Write-Host $output -NoNewline -ForegroundColor Yellow
            & robocopy "`"$sourcePath`"" "`"$destPath`"" $robocopyargs.split() | out-null
        }
        end {
            if ($LASTEXITCODE -gt 7) {
                Write-Host "`r$(' '*$output.Length)" -NoNewline
                Write-Host "`rRobocopy encountered an error while copying $sourcePath" -ForegroundColor Red
            }
            else {
                Write-Host "`r$(' '*$output.Length)" -NoNewline
                Write-Host "`rSuccessfully copied $sourcePath" -ForegroundColor Green
            }
            # return $LASTEXITCODE
        }
    }

    function Add-DomainProfile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$username
        )
        if ($username) {
            #Call Windows API using some C# code to get access to CreateProfile from userenv.dll
            if (-not ([System.Management.Automation.PSTypeName]'UserEnv').Type) {
                Add-Type @"
            using System;
            using System.Text;
            using System.Runtime.InteropServices;
            public static class UserEnv {
                [DllImport(`"userenv.dll`")]
                public static extern int CreateProfile([MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,`
                [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,
                [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath, uint cchProfilePath);}
"@
            }
            $capacity = 260
            $sb = new-object System.Text.StringBuilder($capacity)

            #Get Domain User SID and run CreateProfile with UserEnv Method
            $SID = ((Get-WmiObject Win32_UserAccount -Filter "Name='$username' and Domain='$env:USERDOMAIN'").SID)
            if ($null -eq $SID) {
                Write-Output "$username cannot be found in domain: $env:USERDOMAIN"
                break
            }
            else {
                try {
                    $result = [UserEnv]::CreateProfile($SID, $username, $sb, $capacity) 
                    if ($result -eq 0) {
                        Write-Host "Profile has been created for $($username)" -ForegroundColor Green
                    }
                    elseif ($result -eq '-2147024713') {
                        Write-Host "Profile already exists for $($username)" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "Profile creation failed for $username with error code: $($result)" -ForegroundColor Red
                    }
                }
                catch {
                    Write-Error $_.Exception.Message
                    Read-Host '[UserEnvh]::CreateProfile failed to run'
                    Write-Host "Profile creation failed for $username with an unkown error" -ForegroundColor Red
                    break
                }
            }
        }
    }

    function Remove-RccAccounts {
        $accounts = Get-LocalUser | Where-Object { $_.Name -match "rcc" }
        if ($accounts) {
            ForEach-Object -InputObject $accounts {
                Remove-LocalUser -Name $_.Name -Force
            }
        }
    }


    $Installed = Get-InstalledPrograms

} # End Begin

Process {
    $Serial = (wmic bios get serialnumber)[2]
    $Programs = @{} # Format is $Programs["Program Name"] = "Program Path"
    # Should find the latest version folder and use that
    # Can split on {} and use the first part of the split
    # to list the versioned folders, then use the highest number
    $splitter = "{}"
    $Programs["Jump Client"] = "\\main\dml\apps\BeyondTrust\Remote Support Jump Client\Windows\$($splitter)\x64\Files\bomgar-scc-w0eec305fy1e6d81y71gj5e5if7hdheyi7x61xyc40hc90.exe"
    $Programs["Sentinel Agent"] = "\\main\dml\apps\SentinelOne\Sentinel Agent\Windows\$($splitter)\Deploy-Application.ps1"
    $Programs["7-Zip"] = "\\main\dml\apps\7-Zip\Windows\$($splitter)\x64\SCCM_Install.cmd" # Needs to use Start-Process -FilePath $Path -Wait
    $Programs["Java"] = "\\main\dml\apps\Oracle\Java Runtime Environment\Windows\$($splitter)\Deploy-Application-CLIENT-USER-LOGGED-ON.ps1"
    $Programs["Chrome"] = "\\main\dml\apps\Google\Chrome\Windows\$($splitter)\Deploy-Application.ps1"
    $Programs["Spirion"] = "\\main\dml\apps\Spirion\Windows\$($splitter)\SCCM_Install.cmd"
    $Programs["Acrobat Reader"] = "\\main\dml\apps\Adobe\Acrobat Reader DC\Windows\$($splitter)\SCCM_Install.cmd"
    $Programs["Office"] = "\\main\dml\Apps\Microsoft\Office\2016\Windows\x86\SCCM_Install.cmd"
    $Programs["Firefox"] = "\\main\dml\Apps\Mozilla\Firefox\Windows\$($splitter)\SCCM_Install.cmd"
    $Programs["Insight Agent"] = "\\main\dml\Apps\Rapid7\Insight Agent\Windows\$($splitter)\SCCM_Install.cmd"
    [System.Collections.ArrayList]$keys = $Programs.Keys
    foreach ($program in $keys) {
        $Programs[$program] = $Programs[$program] -replace $splitter, (Get-LatestVersion -Path $Programs[$program] -Splitter $splitter)
    }

    if ($Actions) { Start-Actions }
    # POST IMAGE SETUP
    if ($PostImageSetup) {
        # gpupdate before running actions to pull the actions because sometimes they don't pull after an image
        Start-Job -Name "GPUpdate" -ScriptBlock { gpupdate /force } | Out-Null
        
        Start-Actions
        
        Install-AllPrograms -Programs $Programs

        
        # Driver Updates
        Install-DriverUpdates

        # Install updates
        Start-UpdateInstallation

        Get-NetAdapter -Physical | Select-Object Name, InterfaceDescription, MacAddress | Format-Table -AutoSize
        Write-Host "Serial number: $($Serial)" -ForegroundColor green
    }

    # SENIOR REVIEW
    if ($review) {
        Write-Host "Starting Senior Review" -ForegroundColor Green
        $formFactor = (Get-ComputerInfo).CsPCSystemTypeEx
        Write-Host "Trying to kick off update installation (if they're already downloaded)..." -ForegroundColor Yellow
        Start-UpdateInstallation
        # Install default programs if not found
        Install-AllPrograms -Programs $Programs
        # Check if bound on AD
        if ( (Get-ComputerInfo).CsDomain -eq "ad.rit.edu") {
            Write-Host "Bound to AD" -ForegroundColor Green
        }
        else {
            Write-Host "Not bound to AD" -ForegroundColor Red
            $AD = Read-Host("Enter Y to bind to AD: ")
        }

        if (!(Test-Path C:\ITS)) {
            Write-Host "C:\ITS doesn't exist... Creating." -ForegroundColor Yellow
            New-Item -Path C:\ITS -ItemType Directory
        }

        Get-MalfunctioningDevices

        if ($formFactor -match "Mobile") {
            Start-Process microsoft.windows.camera:
            Start-Sleep -Seconds 3
            Get-Process | Where-Object { $_.Name -Match "WindowsCamera" } | Stop-Process
        }
        # Test sound
        $sound = Get-WmiObject Win32_SoundDevice | Where-Object { $_.Status -ne "OK" }
        if ($sound) {
            Write-Host "WARNING: Malfunctioning sound device" -ForegroundColor RED
            Write-Host "$($sound.Name)" -Foregroundcolor Yellow
        }
        else {
            Write-Host "Sound devices ok, playing sound" -Foregroundcolor Yellow
            [console]::beep(500, 300)
        }
        Write-Host "Checking update history..." -foregroundcolor yellow
        $lastMonth = (Get-Date).AddDays(-30)
        $updates = Get-HotFix | Where-Object { $_.InstalledOn -gt $lastMonth } | Sort-Object installedon -desc
        if ($updates.Count -lt 3) {
            Write-Host "Updates don't seem to be installed, here are the ones that are installed:" -ForegroundColor Red
            $updates | Select-Object HotFixID , Description , InstalledOn | Format-Table -AutoSize
        }

        Write-Host "Computer OU:" -ForegroundColor green
        $Computer = Get-WmiObject -Namespace 'root\directory\ldap' -Query "Select DS_distinguishedName from DS_computer where DS_cn = '$env:COMPUTERNAME'"
        $OU = $Computer.DS_distinguishedName.Substring($Computer.DS_distinguishedName.IndexOf('OU='))
        Write-Host $OU -foregroundcolor yellow
        Write-Host "Installed adapters:" -ForegroundColor green
        $adapters = Get-NetAdapter -Physical | Select-Object Name, InterfaceDescription, MacAddress
        $adapters | Format-Table -AutoSize
        Write-Host "Serial: $($Serial)" -ForegroundColor green
        Write-Host "Reminder: Check claws!" -ForegroundColor Yellow
        switch ($AD) {
            "y" { 
                $domain = "ad.rit.edu"
                Add-Computer -DomainName $domain -Restart -Force -OUPath $OU
            }
        }
    }


    # RESTORE

    if ($restore) {
        # Validate Path
        $sourceDataPrePath = Read-Host "Please enter the name of the folder on endpoints/userbackups: "
        $sourceDataPrePath = $sourceDataPrePath -replace '^\\\\main\\endpoints\\userbackups\\', ''
        $sourceDataPath = "\\main\endpoints\userbackups\$sourceDataPrePath"
        if (($sourceDataPrePath.split("-").Length -eq 2) -and (Test-Path -Type Container $sourceDataPath)) {
            Write-Host "Validated path $($sourceDataPath)" -ForegroundColor Green
        }
        else {
            Write-Host "Invalid path" -ForegroundColor Red
            exit 1
        }

        # Check if user folder is a child-item to that path
        # If user is a valid domain user, the folder will be
        # placed in C:\Users\ after the domain profile is created
        # overwriting what it needs to overwrite
        Join-path -Path $sourceDataPath -ChildPath "Users"
        $usersFolderListing = (Get-ChildItem -Path (Join-path -Path $sourceDataPath -ChildPath "Users") | Where-Object { $_.PSIsContainer -eq $true }).Name
        $profilesToCreate = @()
        # Get domain SID to check if user exists
        foreach ($folderName in $usersFolderListing) {
            if ($null -eq (Get-WmiObject Win32_UserAccount -Filter "Name='$($folderName)' and Domain='$env:USERDOMAIN'").SID) {
                Write-Output "$($folderName) cannot be found in domain: $env:USERDOMAIN"
            }
            else {
                $profilesToCreate += $folderName
            }
        }
        Write-Host "Restoring profiles: $($profilesToCreate)" -ForegroundColor Green
        foreach ($profile in $profilesToCreate) {
            Add-DomainProfile -username $profile

            if ($networkShares -and (Test-Path -Path "$sourceDataPath\Users\$profile\NetworkKeyBackup.reg")) {
                # Restore the Network key from registry
                Write-Host "Restoring registry Network key for user $profile" -ForegroundColor Yellow
            
                # Fetch the SID for the user
                $sid = (Get-WmiObject -Class Win32_UserAccount -Filter "Name='$profile'").SID
            
                # Determine the path to NTUSER.DAT
                $ntuserPath = "C:\Users\$profile\NTUSER.DAT"
                Write-Host "Downloading Network Share Registry locally for $profile to C:\ITS" -ForegroundColor Yellow
                $importPath = "C:\ITS\$profile`NetworkKeyBackup.reg"
                Copy-Item -Path "$sourceDataPath\Users\$profile\NetworkKeyBackup.reg" -Destination $importPath -Force
            
                $loggedInUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
            
                # Check if the user is logged in
                if ($loggedInUsers -notcontains "DOMAIN\$profile") {
                    # If not logged in, load the hive using SID
                    & reg.exe load "HKU\$sid" $ntuserPath
                }
            
                # Import the Network key
                & reg.exe import $importPath
            
                # If the user was not logged in, unload the hive
                if ($loggedInUsers -notcontains "DOMAIN\$profile") {
                    & reg.exe unload "HKU\$sid"
                }
            }
        }
        # Restore data
        function Copy-Custom {
            # robocopy cannot have trailing slashes it seems
            param(
                [Parameter(Mandatory = $true)]
                [string]$SourcePath,
                [Parameter(Mandatory = $true)]
                [string]$DestPath,
                [Parameter(Mandatory = $false)]
                [string]$Excludes
            )
            begin {
                $threads = (([int](WMIC CPU Get NumberOfLogicalProcessors)[2]) * 2)
                # /NP /NS /NC /NFL /NDL to silence
                $robocopyargs = "*.* /MT:$threads /E /COPY:DAT /R:0 /W:0 /V /NFL /LOG+:robocopy.log /xd $Excludes /xf `".DS_Store`" `"NTUSER*`""
            }
            process {
                $output = "Copying $sourcePath to $destPath"
                Write-Host $output -NoNewline -ForegroundColor Yellow
                & robocopy "`"$sourcePath`"" "`"$destPath`"" $robocopyargs.split() | Out-Null
            }
            end {
                if ($LASTEXITCODE -gt 7) {
                    Write-Host "`r$(' '*$output.Length)" -NoNewline
                    Write-Host "`rRobocopy encountered an error while copying $sourcePath" -ForegroundColor Red
                }
                else {
                    Write-Host "`r$(' '*$output.Length)" -NoNewline
                    Write-Host "`rSuccessfully copied $sourcePath" -ForegroundColor Green
                }
                # return $LASTEXITCODE
            }
        }
        Copy-Custom -SourcePath ($sourceDataPath) -DestPath "C:\\"
    }
}

End {
    Write-Host "Script complete" -ForegroundColor Green
    Write-Host "Press any key to exit" -ForegroundColor Green
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}