<#
.SYNOPSIS
Connect to Exchange Online PowerShell, and create mailbox with a cloud user attached

.DESCRIPTION
TA0003: Persistence
T1136.003: Cloud Account
2nd attack method
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

$rand = Get-Random -Minimum 1000 -Maximum 9999
New-Mailbox -MicrosoftOnlineServicesID "ta0003-t1136.003-2-$rand@$env:TENANT_ID" -Alias "ta0003-t1136.003-2-$rand" -Name "TA0003 - T1136.003 - 2 - $rand"

# We cannot delete the account immediately, because propagation takes a long time