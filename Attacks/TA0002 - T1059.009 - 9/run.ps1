<#
.SYNOPSIS
Connect to Exchange Online REST API and create a subfolder of the inbox

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
9th attack method
#>

Get-Module | Where-Object name -eq connect-exo | Remove-Module -Verbose
Import-Module ../APIs/connect-EXO.psm1
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "exops.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "https://outlook.office.com/Exchange.Manage"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:EXOPS_DELEGATE_REDIRECT_URI }

Connect-ExchangeOnline -accessToken $accessToken -Organization $env:TENANT_ID
$folderName = "TA0002 - T1059.009 - 9 - $(Get-Random -Minimum 1000 -Maximum 9999)"

$folders = Get-MailboxFolder -GetChildren

# We cannot list emails here
# This is not supported by the exo powershell module
$inbox = ($folders | where-object { $_.Name -eq "Postvak IN" -or $_.Name -eq "Inbox" })[0]
$newFolder = New-MailboxFolder -Parent $inbox.Identity -Name $folderName

# Exchange Online PowerShell cannot remove the mailbox folder, but the previous entry is logged