# QuickLaunch

All you have to do is run Quicklaunch as a script. It will try to self elevate and make sure that is is run in a regular ps window (there are some weird bugs when running in ps7, but I kept as ps for compatibility's sake given some of the computers that we work on in here)

There are a number of options available to you when running QuickLaunch.ps1:

## Senior Review
    This will check the standard settings, updates, drivers, and firmware to make sure that the Window's side (especially the managed aspect of it) is sound
## Backup Data
    This will prompt whoever is running the script for a number of paramters (which can also be included at runtime if executed as a standalone script). 
    This includes
        - First name
        - Last name
        - Ticket Number
        - A comma separated list of usernames (as designated by the User Folder)
        - whether the window is hidden or not
        - Whether the script should use the specific user hives to back up mapped shared drives (I'm really proud of this one)
        - The source directory for the backup (if backing up from external media)

    It executes the script in parallel and leverages robocopy, where it has been able to back up an entire computer in ~ 18 seconds with a Gigabit connection to our server
## Verify Data
    This will check the contents of a user's drive (given the specific backup policies we follow at RIT) and count folders, files, and sizes. Very handy for checking manual data backups and confirming that the Backup Data script didn't miss anything (somehow)

## Restore Data
    This will again ask for a series of parameters and restore the data from ITS servers onto a user's computer, including adding their domain profile to ensure that there is a seamless transition between their old and new computers

## Run Actions
    Run SCCM associated actions from Configuration Manager automatically.
