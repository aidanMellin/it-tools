<# 
# Data Verification Script
# Verifies Data according to the Data Backup Sheet (April 2023)
# 4/20/2023
# By: Aidan Mellin (atmrcc)
#>

#Static Variables
$consoleWidth = $Host.UI.RawUI.BufferSize.Width
$hostname = hostname
$currentUser = $env:USERNAME

#Other Variables
$userPath = ""
$sourcePath = ""
$userPath = ""
$destPath = ""
$destUserPath = ""

#Welcome Screen
Write-Host 
"***********************************************************************"
"*                   ITS DESKTOP SUPPORT TECH  CENTER                   *"
"*                       Manual Data Verification Script               *"
"*                           Version: 0.0.5                             *"
"*                       Last Updated: 6/13/2023                        *"
"***********************************************************************"
#Output Machine Info
"Computer Information"
Write-Host ("-" * $consoleWidth)
"Hostname: $hostname" + "`n"
"Current User: $currentUser"
Write-Host ("-" * $consoleWidth)

#function a while loop to take a string parameter to display as input, and loop until the user enters a valid directory, then return that directory.
Function Get-ValidDirectory ($inputString) {
    do {
        #Get User Input
        $tempCheckDrive = Read-Host $inputString

        #Check if Directory exists
        if (Test-Path -Path $tempCheckDrive) {
            Write-Host "["$tempCheckDrive"] is a valid directory.`n" -ForegroundColor Green
            $isValid = $true
        }#if
        else {
            Write-Host "["$tempCheckDrive"] is not a valid directory. Did you include the colon? `n" -ForegroundColor Red
            $isValid = $false
        }#else
    } while (!$isValid)#dowhile
    return $tempCheckDrive
}

# Get all user directories in the specified drive or directory
$userDirectories = Get-ChildItem -Path "$driveToCheck\Users" -Directory

$userDirs = 
'Contacts',
'Desktop',
'Documents',
'Downloads',
'Favorites',
'Music',
'Pictures',
'Saved Games',
'Videos',
'Work Folders'

$appDataDirs = 'AppData\Local\Microsoft\Outlook\Offline Address Books',
'AppData\Local\Microsoft\Edge\User Data\Default',
'AppData\Local\Mozilla\Firefox\Profiles',
'AppData\Roaming\Microsoft\Templates',
'AppData\Roaming\Microsoft\Signatures',
'AppData\Roaming\Microsoft\Proof',
'AppData\Roaming\Microsoft\UProof',
'AppData\Roaming\Mozilla\Firefox\Profiles',
'AppData\Roaming\Mozilla\Firefox\Profiles.ini'

$excludeDirs = 'APPDIR', 'ITS', 'Intel', 'PerfLogs', 'Program Files', 'Program Files (x86)', 
'Windows', 'MSOCache', 'ProgramData', 'Dell', 'temp', 'Users', 'temp', 'AMD'

#Get all non standard folders not in the $driveToCheck and $excludeDirs that do not start with $ and folder is not a standard windows file
# $nonStandardDirs = Get-ChildItem -Path $driveToCheck -Directory | Where-Object {($_.Name -notin $excludeDirs) -and ($_.Name -notmatch '^\$')}


#Function to count files and directories
Function CountFilesAndDirs ($path) {

    $dirs = Get-ChildItem -Path $path -Directory -Recurse
    $files = Get-ChildItem -Path $path -File -Recurse

    return @{"dirs" = $dirs.Count; "files" = $files.Count}
}

#Function to compare source and destination
Function Compare-Dirs ($sourcePath, $destPath) {
    Write-Host "Checking directory: $sourcePath against $destPath" -NoNewline -ForegroundColor Yellow
    $sourceCount = CountFilesAndDirs $sourcePath
    $destCount = CountFilesAndDirs $destPath

    #Compare the number of files and directories, write error if source has more files or directories
    if ($sourceCount["dirs"] -gt $destCount["dirs"] -or $sourceCount["files"] -gt $destCount["files"]) {
        Write-Host "`rMismatch in file or directory count in path: $sourcePath" -ForegroundColor Red
        Write-Host "Source Dirs: $($sourceCount["dirs"]), Files: $($sourceCount["files"])" -ForegroundColor Red
        Write-Host "Destination Dirs: $($destCount["dirs"]), Files: $($destCount["files"])" -ForegroundColor Red
        return
    }else{
        Write-Host "`rMatch in file and directory count in path: $sourcePath and $destPath" -ForegroundColor Green
    }
}

#Function to foreach to take in  dirToCheck, sourcePath, and destPath
Function Check-Dirs ($dirToCheck, $sourcePath, $destPath) {
    foreach($dir in $dirToCheck) {
        $sourceDirPath = $sourcePath + "\" + $dir
        $destDirPath = $destPath + "\" + $dir
        if ((Test-Path -Path $sourceDirPath) -and (Test-Path -Path $destDirPath)) {
            Compare-Dirs $sourceDirPath $destDirPath
        }else{
            #if the directory does not exist on both the source and destination, dont write anything
            if ((Test-Path -Path $sourceDirPath) -and !(Test-Path -Path $destDirPath)) {
                Write-Host "Directory: $sourceDirPath or $destDirPath does not exist" -ForegroundColor Red
            }
        }
    }
}

# make $driveToCheck use Get-ValidDirectory
$driveToCheck = Get-ValidDirectory "Please enter the drive (e.g. C:) or directory you want to check against: "

#make $destPath use Get-ValidDirectory
$destPath = Get-ValidDirectory "Please enter the filepath of remote location to check against: "

# $nonStandardDirs = Get-Item -Path $driveToCheck -Directory | Where-Object {($_.Name -notin $excludeDirs -and $_.Name -notmatch '^\$')}

# get names of top directories in c:\ drive that are not in the exclude list and dont match -notmatch '^\$
$nonStandardDirs = Get-ChildItem -Path $driveToCheck -Directory | Where-Object {($_.Name -notin $excludeDirs) -and ($_.Name -notmatch '^\$')}


foreach($userDir in $userDirectories){
    $username = $userDir.Name
    $userPath = $userDir.FullName
    $destUserPath = $destPath +"\Users\"+ $username

    if (Test-Path -Path $destUserPath) {
        Write-Host "Verifying backup for user: $username" -ForegroundColor Green

        # Call Compare-Dirs function for each directory of interest under the user's directory
        Check-Dirs $userDirs $userPath $destUserPath
        Check-Dirs $appDataDirs $userPath $destUserPath
        Check-Dirs $nonStandardDirs $driveToCheck $destUserPath

        Write-Host "Verification of $username Completed.`n" -ForegroundColor Green

    } else {
        Write-Host "No backup found for user: $username." -ForegroundColor Red
    }
}

#Keep machine awake while running
$wshell = New-Object -ComObject Wscript.Shell

# Write-Host "Verification of AppData\Local Completed.`n" -ForegroundColor Yellow
#AppData Local Completed

#Inform user to double check
Write-Host "NOTICE: PLEASE CHECK FOR ANY EXTRA FOLDERS & FILES in the C:\ DIRECTORY & USER DIRECTORY `n" -ForegroundColor Yellow

Write-Host ("-" * $consoleWidth)
#Exit Prompt
Read-Host -Prompt "`nPress Enter to exit"
# Stop-Process -ID $pid