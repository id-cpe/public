<#
.SYNOPSIS
Connect to Graph API, print all groups including its members

.DESCRIPTION
TA0007: Discovery
T1069.003: Groups Discovery: Cloud Groups
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
$scope = "Group.Read.All" #According to the documentation GroupMember.Read.All suffices, but this is not the case
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Obtain a list of all users, we need the UserPrincipalName attribute
$url = 'https://graph.microsoft.com/v1.0/groups?$expand=members&$select=id,displayName,members'
$groups = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}

$groups.value | Select-Object id,displayName,{$_.members.UserPrincipalName}