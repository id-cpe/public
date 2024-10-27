<#
.SYNOPSIS
Connect to SharePoint Online REST v1 API, create a folder and (after a timeout) delete it again

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
5th attack method
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
$scope = "https://$tenantName.sharepoint.com/AllSites.FullControl"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:SPOLD_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:SPOLD_DELEGATE_REDIRECT_URI }

$folderName = "TA0002 - T1059.009 - 5 - $(Get-Random -Minimum 1000 -Maximum 9999)"
$newFolder = @{
    "__metadata" = @{
      "type" = "SP.Folder";
    };
    "ServerRelativeUrl" = "/Shared Documents/$folderName";
}
$newFolder = ConvertTo-Json $newFolder
$url = "https://$tenantName.sharepoint.com/_api/web/folders"
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata=verbose" -Headers @{"Authorization"="Bearer $accessToken"; "Accept" = "application/json";} -Body $newFolder

# After creating, we also delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = $response.'odata.id'
$response = Invoke-RestMethod $url -Method Delete -ContentType "application/json;odata=verbose" -Headers @{"Authorization"="Bearer $accessToken"; "Accept" = "application/json";}
