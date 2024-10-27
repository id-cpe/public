<#
.SYNOPSIS
Connect to SharePoint Online listdata.svc API, create a folder and (after a timeout) delete it again

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
10th attack method
#>

Get-Module | Where-Object name -eq connect-spold | Remove-Module -Verbose
Import-Module ../APIs/connect-SPOld.psm1
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "spolistdata.env"
$tenantName = $env:TENANT_ID.Split(".")[0]

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "https://$tenantName.sharepoint.com/AllSites.FullControl"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:SPOLD_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:SPOLD_DELEGATE_REDIRECT_URI }

$folderName = "TA0002 - T1059.009 - 10 - $(Get-Random -Minimum 1000 -Maximum 9999)"
$newFolder = @{
    "ContentTypeID" = "0x01200093331D3790C54144AC10D65D164227C0";
    "ContentType" = "Folder";
    "Title" = $folderName;
    "Path" = "/Shared Documents/";      
}
$slug = "/Shared Documents/$folderName|0x01200093331D3790C54144AC10D65D164227C0";
$newFolder = ConvertTo-Json $newFolder
$url = "https://$tenantName.sharepoint.com/_vti_bin/Listdata.svc/Documents"
$response = Invoke-WebRequest $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"; "Slug" = $slug;} -Body $newFolder

# After creating, we also delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$xml = [xml]$response
$url = $xml.GetElementsByTagName("id")[0].InnerText
$response = Invoke-WebRequest $url -Method Delete -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken";}
