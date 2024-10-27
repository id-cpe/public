#Requires -RunAsAdministrator

# If we are on Windows we have to make sure we don't mark the module as a virus :-)
# Since we are running this on clean machines each time, this is a bit difficult
# (it also works on machines which have real-time protection disabled in the boot.ps1)

# If you are using an ide that imports modules to detect its effects, and you have not
# whitelisted it in your antivirus, it will probably be killed by your real-time antimalware

if ($IsLinux -ne $True -and $IsMacOS -ne $True) {
    # Create a folder which we are going to whitelist in a bit
    New-Item -Path $env:TEMP -Name PowerShellTemp -ItemType Directory
    $tempPath = $env:TEMP + "\PowerShellTemp\"

    # Whitelist the temporary folder
    Add-MpPreference -ExclusionPath "$tempPath"
    # And also whitelist the final location 
    Add-MpPreference -ExclusionPath "C:\Program Files\WindowsPowerShell\Modules\AADInternals"
    # Set it to the env variable that is used by Install-Module
    $env:TMP = $tempPath
    $env:TEMP = $tempPath

    # We temporarily make sure we don't block powershell from running
    Add-MpPreference -ExclusionProcess "powershell.exe"
    # Make sure to remove powershell from the antivirus whitelist when exiting, we can leave the other exclusions
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -SupportEvent -Action {
        Remove-MpPreference -ExclusionProcess "powershell.exe"
    }
}

$isInstalled = (Get-Module -ListAvailable -Name AADInternals).Count
if ($isInstalled -eq 0) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AADInternals -RequiredVersion 0.9.3 -Force -Scope AllUsers
}

Import-Module AADInternals -Force