<#
.SYNOPSIS
Connect to SharePoint Online REST v2 API, create a folder and (after a timeout) delete it again

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
6th attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "sporest.env"
$tenantName = $env:TENANT_ID.Split(".")[0]

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "https://$tenantName.sharepoint.com/AllSites.Manage"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:SPOREST_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:SPOREST_DELEGATE_REDIRECT_URI }

$folderName = "TA0002 - T1059.009 - 6 - $(Get-Random -Minimum 1000 -Maximum 9999)"

# Look for drives in the root site
$url = "https://$tenantName.sharepoint.com/_api/v2.0/sites/root/drives"
$response = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}
$drives = $response.value
$driveId = $null
foreach ($drive in $drives) {
  if ($drive.driveType -eq "documentLibrary" -and $drive.name -eq "Documents") { $driveId = $drive.id }
}
if ($null -eq $driveId) {
  Write-Error "Could not find site 'Documents'"
  exit 1
}

$url = "https://$tenantName.sharepoint.com/_api/v2.0/drives/$driveId/root/children"
$newFolder = @{
  "name" = $folderName;
  "folder" = @{};
  "@microsoft.graph.conflictBehavior" = "fail";
}
$newFolder = ConvertTo-Json $newFolder #Pipeline breaks empty array
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newFolder
$itemId = $response.id

# After creating, we also delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://$tenantName.sharepoint.com/_api/v2.0/drives/$driveId/items/$itemId"
Invoke-RestMethod $url -Method Delete -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"}