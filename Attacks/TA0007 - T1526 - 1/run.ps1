<#
.SYNOPSIS
Connect to Graph API and obtain a list of licenses to decide what services a user has access to

.DESCRIPTION
TA0007: Discovery
T1526: Cloud Service Discovery
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "User.Read"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Obtain a list of all users, we need the UserPrincipalName attribute
$url = "https://graph.microsoft.com/beta/me/licenseDetails"
$licenses = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}

Write-Host ($licenses.value.servicePlans | Where-Object { $_.appliesTo -eq "User" -and $_.provisioningStatus -eq "Success" }).servicePlanName