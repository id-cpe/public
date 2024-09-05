<#
.SYNOPSIS
Connect to Graph API and obtain a list of enterprise applications that are available and to what users these are available

.DESCRIPTION
TA0007: Discovery
T1526: Cloud Service Discovery
2nd attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "Application.Read.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Obtain a list of all users, we need the UserPrincipalName attribute
$url = 'https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignedTo&$select=appRoleAssignedTo,appRoleAssignmentRequired,servicePrincipalNames,replyUrls,info,id,appId,appDisplayName'
$apps = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}

$apps.value | Select-Object appId,appDisplayName,appRoleAssignmentRequired,{$_.appRoleAssignedTo.principalDisplayName},replyUrls