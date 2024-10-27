<#
.SYNOPSIS
Connect to Graph API and list all mailbox folders

.DESCRIPTION
TA0001: Initial Access
T1078.004: Cloud Accounts
2nd attack method
#>

# For plain SMTP (no TLS), we could have used telnet
# This would be the easiest for an attacker to implement themselves but Microsoft also no longer allows unencrypted SMTP
##Requires -RunAsAdministrator
#pkgmgr /iu:"TelnetClient"

$previousDirectory = $PWD
Set-Location $PSScriptRoot

# MaskInput is ignored on old versions of PowerShell
$upn = Read-Host "UPN (user must have SMTP authentication enabled)"
$password = Read-Host -MaskInput "Password for $upn" 

$upn_bytes = [System.Text.Encoding]::UTF8.GetBytes($upn)
$upn_base64 = [Convert]::ToBase64String($upn_bytes)
$password_bytes = [System.Text.Encoding]::UTF8.GetBytes($password)
$password_base64 = [Convert]::ToBase64String($password_bytes)

$date = Get-Date -UFormat "%a, %d %b %Y %H:%M:%S %Z00"

# Create the VBS file that we will be using to connect
$newvars = @{
    "%FROMNAME%" = $upn.Split("@")[0];
    "%USERNAME%" = $upn;
    "%USERNAMEBASE64%" = $upn_base64;
    "%PASSWORDBASE64%" = $password_base64;
    "%DATE%" = $date;
}

$template = "./smtpsim.vbs.template"
$destination_file = "./smtpsim.vbs"
$data = @()
foreach($line in Get-Content $template) {
    foreach($key in $newvars.Keys) {
        if ($line -match $key) {
            $line = $line -replace $key, $newvars[$key]
        }
    }
    $data += $line
}

$data | Out-File $destination_file

# We use SMTPConsole.exe (https://download.socketlabs.com/smtpconsole.zip)
cscript.exe //NoLogo ./smtpsim.vbs

Set-Location $previousDirectory