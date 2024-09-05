<#
.SYNOPSIS
Connect to Graph API, create a sharepoint site, create a folder and share this folder with a specific user without sending an email

.DESCRIPTION
TA0003: Persistence
T1222: File and Directory Permissions Modification
4th attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1


# We use the SPO v1 environment variables
Import-Environment "sporest1.env"
$tenantName = $env:TENANT_ID.Split(".")[0]

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scopeGraph = "Sites.Read.All Files.ReadWrite.All User.ReadBasic.All"
$scopeSPOv1 = "https://$tenantName.sharepoint.com/AllSites.FullControl"

$scope = "$scopeGraph $scopeSPOv1"
if ($null -eq $refreshToken) { $refreshToken = Get-DelegatedAccessToken -refreshToken -tenantId $env:TENANT_ID -clientId $env:SPOREST1_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:SPOREST1_DELEGATE_REDIRECT_URI }

$accessTokenSPO = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:SPOREST1_DELEGATE_CLIENT_ID -scope $scopeSPOv1
$accessTokenGraph = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:SPOREST1_DELEGATE_CLIENT_ID -scope $scopeGraph

$rand = Get-Random -Minimum 1000 -Maximum 9999
# Create a new site
$url = "https://$tenantName.sharepoint.com/_api/SPSiteManager/create"
$newSite = @{
  "request" = @{
    "Title" = "TA0003 - T1222 - 4 - $rand";
    "Url" = "https://$tenantName.sharepoint.com/sites/ta0003-t1222-4-$rand";
    "Lcid" = 1033;  # English
    "ShareByEmailEnabled" = $False;
    "Description" = "TA0003 - T1222 - 4 - $rand";
    "WebTemplate" = "STS#3"; # Team site not associated with a group
    "SiteDesignId" = "f6cc5403-0d63-442e-96c0-285923709ffc"; #Blank site design
    "WebTemplateExtensionId" = "00000000-0000-0000-0000-000000000000";
  };
};
$newSite = ConvertTo-Json -Depth 99 $newSite
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json";} -Body $newSite
$siteId = $response.SiteId;

# Look for drives in the newly created site
$url = "https://graph.microsoft.com/v1.0/sites/$siteId/drives"
$response = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessTokenGraph"}
$drives = $response.value
$driveId = $null
foreach ($drive in $drives) {
  if ($drive.driveType -eq "documentLibrary" -and $drive.name -eq "Documents") { $driveId = $drive.id }
}
if ($null -eq $driveId) {
  Write-Error "Could not find site 'Documents'"
  exit 1
}

# We create a folder that we will be sharing
$url = "https://graph.microsoft.com/v1.0/drives/$driveId/root/children"
$newFolder = @{
  "name" ="TA0003 - T1222 - 4 - $rand";
  "folder" = @{};
  "@microsoft.graph.conflictBehavior" = "fail";
}
$newFolder = ConvertTo-Json $newFolder #Pipeline breaks empty array
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessTokenGraph"} -Body $newFolder

$itemId = $response.id

# Obtain object id of user to share folder with
$shareWith = Read-Host -Prompt "Share with (UPN)"
$url = "https://graph.microsoft.com/v1.0/users/$shareWith"
$response = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessTokenGraph"} 
$shareWith = $response.id

# Invite new user
$url = "https://graph.microsoft.com/v1.0/drives/$driveId/items/$itemId/invite"
$newPermissions = @{
  "recipients" = @(
    @{
      "objectId" = $shareWith;
    };
  );
  "message" = "Example message TA0003 - T1222 - 4 - $rand";
  "requireSignIn" = $True;
  "sendInvitation" = $False;
  "retainInheritedPermissions" = $True;
  "roles" = @("write");
}
$newPermissions = ConvertTo-Json -Depth 99 $newPermissions
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessTokenGraph"} -Body $newPermissions

# Delete the site again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://$tenantName.sharepoint.com/_api/SPSiteManager/delete"
$deleteSite = @{
  "siteId" = $siteId;
};
$deleteSite = ConvertTo-Json -Depth 99 $deleteSite
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json";} -Body $deleteSite
