<#
.SYNOPSIS
Connect to SharePoint v1 API, look for the default document library and upload a virus test file to that library

.DESCRIPTION
TA0008: Lateral Movement
T1080: Taint Shared Content
3rd attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the SPO v1/listdata environment variables
Import-Environment "spolistdata.env"
$tenantName = $env:TENANT_ID.Split(".")[0]

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1

# We do not need FullControl, but we do need .Manage to be able to upload files
$scope = "https://$tenantName.sharepoint.com/AllSites.Manage"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:SPOLD_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:SPOLD_DELEGATE_REDIRECT_URI }

# We create a folder for our test
$folderName = "TA0008 - T1080 - 3 - $(Get-Random -Minimum 1000 -Maximum 9999)"
$newFolder = @{
    "__metadata" = @{
      "type" = "SP.Folder";
    };
    "ServerRelativeUrl" = "/Shared Documents/$folderName";
}
$newFolder = ConvertTo-Json $newFolder
$url = "https://$tenantName.sharepoint.com/_api/web/folders"
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata=verbose" -Headers @{"Authorization"="Bearer $accessToken"; "Accept" = "application/json";} -Body $newFolder
$folderURL = $response.'odata.id'

# Upload the test file to the newly created folder
$url = "$folderURL/Files/Add(url='eicar.txt', overwrite=false)"
$flag = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$fileResponse = Invoke-RestMethod $url -Method Post -ContentType "text/plain" -Headers @{"Authorization"="Bearer $accessToken"; "Accept" = "application/json;odata=verbose"} -Body $flag
$fileURL = $fileResponse.d.__metadata.uri
$fileId = $fileResponse.d.ServerRelativeUrl

Wait-KeyOrTimeOut -Timeout 300000

# Pretend we are doing an interactive download, so we will trigger malware scanning
# $downloadUrl = "$fileURL/OpenBinaryStream"
$downloadUrl = "https://pietersdevtenant.sharepoint.com/_api/web/GetFileByServerRelativePath(DecodedUrl=@a1)/OpenBinaryStream?@a1=" + [URI]::EscapeDataString("'" + $fileId + "'")
$response = Invoke-WebRequest $downloadUrl -Headers @{"Authorization"="Bearer $accessToken"}

# After creating, we also delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$response = Invoke-RestMethod $folderURL -Method Delete -ContentType "application/json;odata=verbose" -Headers @{"Authorization"="Bearer $accessToken"; "Accept" = "application/json";}

