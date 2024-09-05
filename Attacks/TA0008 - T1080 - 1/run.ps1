<#
.SYNOPSIS
Connect to Graph API, look for the default document library and upload a virus test file to the default document library

.DESCRIPTION
TA0008: Lateral Movement
T1080: Taint Shared Content
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1


# We use the graph environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "Sites.Read.All Files.ReadWrite.All User.ReadBasic.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Look for drives in the root site
$url = "https://graph.microsoft.com/v1.0/sites/root/drives"
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

# We create a folder for our test
$url = "https://graph.microsoft.com/v1.0/drives/$driveId/root/children"
$rand = Get-Random -Minimum 1000 -Maximum 9999
$newFolder = @{
  "name" ="TA0008 - T1080 - 1 - $rand";
  "folder" = @{};
  "@microsoft.graph.conflictBehavior" = "fail";
}
$newFolder = ConvertTo-Json $newFolder #Pipeline breaks empty array
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newFolder

$folderId = $response.id
if ($null -eq $folderId) {
  Write-Error "Could not create folder"
  exit 1
}

# Upload the test file to the newly created folder
$url = "https://graph.microsoft.com/v1.0/drives/$driveId/items/$($folderId):/eicar.txt:/content"
$flag = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$response = Invoke-RestMethod $url -Method Put -ContentType "text/plain" -Headers @{"Authorization"="Bearer $accessToken"} -Body $flag

# This download will not trigger malware scanning
# $downloadUrl = $response.'@microsoft.graph.downloadUrl'
# Invoke-WebRequest $downloadUrl

# Wait 10 minutes for malware scanning
Wait-KeyOrTimeOut -Timeout 600000

# Do an attempt at downloading the file so that it does trigger malware scanning
# Should be available in v1.0 but the following works in beta:
$itemId = $response.ids
$url = "https://graph.microsoft.com/beta/drives/$driveId/items/$($itemId)?`$select=id,@microsoft.graph.downloadUrl,malware"
$response = Invoke-RestMethod $url -Method Get -Headers @{"Authorization"="Bearer $accessToken"}
$downloadUrl = $response.'@microsoft.graph.downloadUrl'
$download = Invoke-WebRequest $downloadUrl


# Delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://graph.microsoft.com/v1.0/drives/$driveId/items/$folderId"
$response = Invoke-RestMethod $url -Method Delete -Headers @{"Authorization"="Bearer $accessToken"}
