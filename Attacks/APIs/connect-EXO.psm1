# Used for importing necessary modules in Excange Online

$isInstalled = (Get-Module -ListAvailable -Name ExchangeOnlineManagement).Count
if ($isInstalled -eq 0) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module ExchangeOnlineManagement -RequiredVersion 3.4.0 -Force
}

Import-Module ExchangeOnlineManagement