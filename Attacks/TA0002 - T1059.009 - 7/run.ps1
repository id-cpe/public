<#
.SYNOPSIS
Connect to Graph API, create a subfolder of the inbox and delete it again

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
7th attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "Mail.ReadWrite"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

$folderName = "TA0002 - T1059.009 - 7 - $(Get-Random -Minimum 1000 -Maximum 9999)"

# We perform the list request
$url = "https://graph.microsoft.com/v1.0/me/mailFolders"
$response = Invoke-WebRequest $url -Headers @{"Authorization"="Bearer $accessToken"}
$folders = ($response.Content | ConvertFrom-Json).Value

$inbox = ($folders | where-object { $_.displayName -eq "Postvak IN" -or $_.displayName -eq "Inbox" })[0]

# $url = "https://graph.microsoft.com/v1.0/me/mailFolders/" + $inbox.id + "/messages"
# $response = Invoke-WebRequest $url -Headers @{"Authorization"="Bearer $accessToken"}
# $messages = ($response.Content | ConvertFrom-Json).Value
# $messages

$url = "https://graph.microsoft.com/v1.0/me/mailFolders/" + $inbox.id + "/childfolders"
$newFolder = @{
    "displayName" = $folderName
} | ConvertTo-Json
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newFolder

# While a delete is also possible on the item itself, it is less comparable to the user interaction
$moveToDeleted = @{
    "destinationId" = "deleteditems";
} | ConvertTo-Json
$url = "https://graph.microsoft.com/v1.0/me/mailFolders/" + $response.id + "/move"
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $moveToDeleted
