param(
    # Get customer first name, last name, and ticket numbers as parameters. If not included in parameters, prompt for them.
    [string]$firstName,
    [string]$lastName,
    [string]$ticketNumber,
    [string[]]$Users,
    #boolean hidden flag
    [switch]$hidden,
    [switch]$networkShares,
    [string]$sourceDir
)

# Make sure the script is running with admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as an Administrator!" -ForegroundColor Red
    exit
}

#If first name, last name, or ticket number are not provided as parameters, prompt for them
if (!$firstName) {
    $firstName = Read-Host -Prompt 'Enter the customer first name'
}
if (!$lastName) {
    $lastName = Read-Host -Prompt 'Enter the customer last name'
}
if (!$ticketNumber) {
    $ticketNumber = Read-Host -Prompt 'Enter the ticket number'
}
if (!$Users) {
    $Users = Read-Host -Prompt 'Enter the Users to backup (separated by a comma)'
}
if (!$sourceDir) {
    Write-Host "Backing up from C:\"
    $sourceDir = 'C:\'
}

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Host "Starting new PowerShell process with admin privileges to run the script..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$($MyInvocation.MyCommand.Path)`" -firstName `"$firstName`" -lastName `"$lastName`" -ticketNumber `"$ticketNumber`" -Users `"$Users`" -sourceDir `"$sourceDir`" -networkShares"
    exit
}

#print the customer name and ticket number
Write-Host "Customer Name and Ticket: $firstName $lastName - $ticketNumber" -ForegroundColor Green
Write-Host "Number of threads for transfer: $(([int](WMIC CPU Get NumberOfLogicalProcessors)[2]) * 2)"

if ($test) {
    exit
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
        try {
            & robocopy "`"$sourcePath`"" "`"$destPath`"" $robocopyargs.split()
        }
        catch {
            
            $errorMessage = "Potential issue with backing up path: $sourcePath "
            Write-Host $errorMessage -ForegroundColor Yellow
        }
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
# Format of backup directory: \\main\Endpoints\UserBackups\FirstName LastName - TicketNumber
$backupDir = "\\main\Endpoints\UserBackups\${firstName} ${lastName} `- ${ticketNumber}"

#Create a new directory given the $backupDir if it doesnt exist
if (-NOT (Test-Path -Path $backupDir)) {
    New-Item -ItemType Directory -Force -Path $backupDir
    # test that directory created successfully
    if (Test-Path -Path $backupDir) {
        # print directory created successfully
        Write-Host "Successfully created directory $backupDir" -ForegroundColor Green
        #else print error and exit
    }
    else {
        Write-Host "Failed to create directory $backupDir" -ForegroundColor Red
        exit
    }
}
else {
    # print directory already exists
    Write-Host "Directory $backupDir already exists" -ForegroundColor Yellow
}

#create an array of users splitting on comma and dropping any spaces included
$userArray = $Users.Split(',') | ForEach-Object { $_.Trim() }
Write-Host "Users to backup: $userArray" -ForegroundColor Green

# Define directories to exclude
$excludeDirs = 'APPDIR', 'ITS', 'Intel', 'PerfLogs', 'Program Files', 'Program Files (x86)', 
'Windows', 'MSOCache', 'ProgramData', 'Dell', 'temp', 'Users', 'temp', 'Oracle', 'HashiCorp', 'Anaconda3', 'AMD', 'tmp', 'IExp0.tmp', 'IExp1.tmp', 'log', 'ProgramFilesFolder', 'RAPID', 'ScanAgent', 'sdklogx'

# Check if each user in $userArray exists as a directory in $sourceDir
$userArray | ForEach-Object {
    $userDir = Join-Path -Path (Join-Path -Path $sourceDir -ChildPath "Users") -ChildPath $_
    if (-not (Test-Path -Path $userDir -PathType Container)) {
        Write-Host "User $_ does not exist" -ForegroundColor Red
    }
}

# Backup the root of C:, excluding certain directories
Get-ChildItem -Path $sourceDir -Directory | ForEach-Object {
    if ($_.Name -notin $excludeDirs -and $_.Name -notmatch '^\$') {
        try {
            #if in test mode, simply print the directory that would be backed up and the dest directory
            Write-Host "Backing up directory $_.FullName ..." -NoNewline -ForegroundColor Yellow
            Copy-Custom -SourcePath $_.FullName -DestPath $backupDir
            Write-Host "`r                                                  `r" -NoNewline
            Write-Host "Successfully backed up directory $($_.FullName)" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to back up directory $($_.FullName)" -ForegroundColor Red
        }
    }
}

# Explicitly backup $sourceDir`SAS if it exists

if (Test-Path -Path '$sourceDir`SAS') {
    try {
        #if in test mode, simply print the directory that would be backed up and the dest directory
        Write-Host "Backing up directory $sourceDir`SAS ..." -NoNewline -ForegroundColor Yellow
        Copy-Item -Path '$sourceDir`SAS' -Destination $backupDir -Recurse -Force
        Write-Host "`r                                                  `r" -NoNewline
        Write-Host "Successfully backed up directory $sourceDir`SAS" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to back up directory $sourceDir`SAS" -ForegroundColor Red
    }
}
        
# Define directories to backup from each user profile
# $userDirs = 
# 'Contacts',
# 'Desktop',
# 'Documents',
# 'Downloads',
# 'Favorites',
# 'Music',
# 'Pictures',
# 'Saved Games',
# 'Videos',
# 'Work Folders'

$appDataDirs = 'AppData\Local\Microsoft\Outlook\Offline Address Books',
'AppData\Local\Microsoft\Edge\User Data\Default',
'AppData\Local\Mozilla\Firefox\Profiles',
'AppData\Roaming\Microsoft\Templates',
'AppData\Roaming\Microsoft\Signatures',
'AppData\Roaming\Microsoft\Proof',
'AppData\Roaming\Microsoft\UProof',
'AppData\Roaming\Mozilla\Firefox\Profiles',
'AppData\Local\Google\Chrome\User Data\Default'

foreach ($user in $userArray) {
    # iterate through users and backup each folder in the root of their user directory, excluding appdata
    Write-Host "Backing up user $user" -ForegroundColor Yellow
    $userBackupDir = Join-Path -Path $backupDir -ChildPath "Users\"
    $TargetUserDirectory = Join-Path -Path $userBackupDir -ChildPath $user
    if (!(Test-Path $TargetUserDirectory -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $TargetUserDirectory
    }
    Copy-Custom -SourcePath "$sourceDir`Users\$user" -DestPath $TargetUserDirectory -Excludes "`"$sourceDir`Users\$user\AppData`" `"$sourceDir`Users\$user\Local Settings`" `"$sourceDir`Users\$user\Application Data`""

    # Backup folders from AppData
    foreach ($appDataDir in $appDataDirs) {
        $targetAppDataPath = Join-Path -Path $TargetUserDirectory -ChildPath $appDataDir
        if(Test-Path $sourceDir`Users\$user\$appDataDir){
            Copy-Custom -SourcePath "$sourceDir`Users\$user\$appDataDir" -DestPath $targetAppDataPath -Excludes "`"$sourceDir`Users\$user\$appDataDir\cache`" `"$sourceDir`Users\$user\$appDataDir\Code Cache`" `"$sourceDir`Users\$user\$appDataDir\Service Worker`""
        }
    }

    if ($networkShares) {
        # Backup the Network key from registry
        Write-Host "Backing up registry Network key for user $user" -ForegroundColor Yellow
    
        $sid = (Get-WmiObject -Class Win32_UserAccount -Filter "Name='$user'").SID
        $ntuserPath = "$sourceDir`Users\$user\NTUSER.DAT"
        $exportPath = "$TargetUserDirectory\NetworkKeyBackup.reg"
    
        $loggedInUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
    
        # Check if the user is logged in
        Write-Host "$loggedInUsers"
        if ($loggedInUsers -notcontains "MAIN\$user") {
            # If not logged in, load the hive using SID
            Write-Host "User $user is not logged in. Loading hive using SID" -ForegroundColor Yellow
            & reg.exe load "HKU\$sid" $ntuserPath
        }
    
        # Export the Network key
        # If the user was not logged in, unload the hive
        if ($loggedInUsers -notcontains "MAIN\$user") {
            & reg.exe unload "HKU\$sid"
        }

        # Export the Network key using HKCU if the user is the user running the script
        if ($user -eq $env:USERNAME) {
            & reg.exe export "HKCU\Network" $exportPath
        }
        else {
            & reg.exe export "HKU\$sid\Network" $exportPath
        }

        # If the user was not logged in, unload the hive
        if ($loggedInUsers -notcontains "MAIN\$user") {
            & reg.exe unload "HKU\$sid"
        }
    }
    #make a path to target profiles.ini location
    $targetINIPath = Join-Path -Path $TargetUserDirectory -ChildPath  "\AppData\Roaming\Mozilla\Firefox\Profiles.ini"
    if ((Test-Path "$sourceDir`Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles.ini" -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $targetINIPath
        Copy-Item "$sourceDir`Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles.ini" -Destination $targetINIPath  -Force
    }
}

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("Backup completed!", "Backup Status", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
