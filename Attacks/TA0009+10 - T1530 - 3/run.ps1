<#
.SYNOPSIS
Connect to Graph API, upload a lot of files and subsequently download a lot of files to the default document library in the default site.

.DESCRIPTION
TA0009/10: Collection & Exfiltration
T1530: Data from Cloud Storage
3rd attack method
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
  "name" ="TAZZ00 - T1530 - 1 - $rand";
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

# Create 100 files in this folder
$noFiles = 100
$i = 0
# $fileIds = New-Object string[] $noFiles
while ($i -lt $noFiles) {
  $url = "https://graph.microsoft.com/v1.0/drives/$driveId/items/$($folderId):/$i.txt:/content"
  $content = "It does not really matter what the content of the file is $i"
  $response = Invoke-RestMethod $url -Method Put -ContentType "text/plain" -Headers @{"Authorization"="Bearer $accessToken"} -Body $content
  # $fileIds[$i] = $response.id
  # Write-Host $response.id
  $i += 1
  Start-Sleep -Milliseconds 100
}

# This download will not trigger malware scanning
# $downloadUrl = $response.'@microsoft.graph.downloadUrl'
# Invoke-WebRequest $downloadUrl

# Wait 10 minutes to make sure that search works
Wait-KeyOrTimeOut -Timeout (15 * 60 * 1000)

# We search for 0.txt which we know exists
$url = "https://graph.microsoft.com/beta/drives/$driveId/search(q='0.txt')"
$response = Invoke-WebRequest $url -Method Get -Headers @{"Authorization"="Bearer $accessToken"}
$items = ($response.Content | ConvertFrom-Json).value

$found = $null
foreach ($item in $items) {
  if ($item.parentReference.id -eq $folderId) {
    $found = $item.id
  }
}
if ($null -eq $found) {
  Write-Error "No file found"
  exit 1
}

$url = "https://graph.microsoft.com/beta/drives/$driveId/items/$found"
$response = Invoke-RestMethod $url -Method Get -Headers @{"Authorization"="Bearer $accessToken"}
$downloadUrl = $response.'@microsoft.graph.downloadUrl'
Invoke-WebRequest $downloadUrl | Out-Null

# Delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://graph.microsoft.com/v1.0/drives/$driveId/items/$folderId"
$response = Invoke-RestMethod $url -Method Delete -Headers @{"Authorization"="Bearer $accessToken"}
