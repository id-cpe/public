<#
.SYNOPSIS
Connect to Exchange Online PowerShell module as an administrator and permanently delete a mailbox

.DESCRIPTION
TA0005: Defense evasion
T1564.008: Email Hiding Rules
2nd attack method
#>

Get-Module | Where-Object name -eq connect-exo | Remove-Module -Verbose
Import-Module ../APIs/connect-EXO.psm1
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1

# import wait-keyortimeout
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "exops.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1

$scopeEXO = "https://outlook.office.com/Exchange.Manage"
$scopeGraph = "User.ReadWrite.All"

$scope = "$scopeEXO $scopeGraph"

if ($null -eq $refreshToken) { $global:refreshToken = Get-DelegatedAccessToken -refreshToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:EXOPS_DELEGATE_REDIRECT_URI }

$accessTokenEXO = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scopeEXO
$accessTokenGraph = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scopeGraph

Connect-ExchangeOnline -accessToken $accessTokenEXO -Organization $env:TENANT_ID

$rand = Get-Random -Minimum 1000 -Maximum 9999
# First we create the mailbox we will be deleting later
New-Mailbox -MicrosoftOnlineServicesID "ta0040-t1485-1-$rand@$env:TENANT_ID" -Alias "ta0040-t1485-1-$rand" -Name "TA0040 - T1485 - 1 - $rand"

Wait-KeyOrTimeOut -Timeout 30000

#Remove-Mailbox "ta0040-t1485-1-$rand@$env:TENANT_ID"

# Get the user's ID in AAD
$url = "https://graph.microsoft.com/v1.0/users/ta0040-t1485-1-$rand@$env:TENANT_ID"
$response = Invoke-RestMethod -Method Get -Headers @{"Authorization"="Bearer $accessTokenGraph"} -Uri $url
$userId = $response.id

# Delete the user in AAD
$url = "https://graph.microsoft.com/v1.0/users/$userId"
Invoke-RestMethod -Method Delete -Headers @{"Authorization"="Bearer $accessTokenGraph"} -Uri $url

# Permanently delete the AAD object
$url = "https://graph.microsoft.com/v1.0/directory/deletedItems/$userId"
Invoke-RestMethod -Method Delete -Headers @{"Authorization"="Bearer $accessTokenGraph"} -Uri $url

# This will then delete the mailbox
Set-User -PermanentlyClearPreviousMailboxInfo "ta0040-t1485-1-$rand@$env:TENANT_ID"

