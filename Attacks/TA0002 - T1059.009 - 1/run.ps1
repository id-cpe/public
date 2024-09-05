<#
.SYNOPSIS
Connect to Graph API and list all mailbox folders

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
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
$scope = "Mail.ReadBasic"
$accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI

# We perform the list request
$url = "https://graph.microsoft.com/v1.0/me/mailFolders"
$response = Invoke-WebRequest $url -Headers @{"Authorization"="Bearer $accessToken"}
$folders = ($response.Content | ConvertFrom-Json).Value

$folders