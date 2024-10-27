<#
.SYNOPSIS
This is the script that the admin uses to prepare the environment which is then later abused by the attacker. This is not the script that the attacker runs.
Connect to SharePoint REST API v1 and the Graph API, create a sharepoint site

.DESCRIPTION
TA0009/10: Collection & Exfiltration
T1213.002:  Data from Information Repositories: Sharepoint 
Preparation for attack method 1
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
$scopeGraph = "Sites.Read.All User.ReadBasic.All"
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
    "Title" = "TA0009 - T1213.002 - 1 - $rand";
    "Url" = "https://$tenantName.sharepoint.com/sites/ta0009-t1213.002-1-$rand";
    "Lcid" = 1033;  # English
    "ShareByEmailEnabled" = $False;
    "Description" = "TA0009 - T1213.002 - 1 - $rand";
    "WebTemplate" = "STS#3"; # Team site not associated with a group
    "SiteDesignId" = "f6cc5403-0d63-442e-96c0-285923709ffc"; #Blank site design
    "WebTemplateExtensionId" = "00000000-0000-0000-0000-000000000000";
  };
};
$newSite = ConvertTo-Json -Depth 99 $newSite
$siteresp = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json";} -Body $newSite
$siteId = $siteresp.SiteId;
$siteUrl = $siteresp.SiteUrl
$siteUrlRelative = $siteresp.SiteUrl.Split("/",4)[3]

# Get the object id of the compromised user account
$shareWith = Read-Host -Prompt "Share with (UPN)"
$url = "https://graph.microsoft.com/v1.0/users/$shareWith"
$shareWith = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessTokenGraph"} 

# Share the newly created site with the 'compromised' user account
# $url = "https://graph.microsoft.com/v1.0/sites/$tenantName.sharepoint.com:/${siteUrlRelative}:/permissions"
# $newPermission = @{
#   "roles" = @("write");
#   "grantedToIdentitiesV2" = @(
#       @{
#       "user" = @{
#         "id" = $shareWith;
#         "displayName" = $shareWith;
#       };
#     };
#   );
# };
# $newPermission = ConvertTo-Json $newPermission -Depth 99
# write-Host $newPermission

# Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessTokenGraph"; "Accept" = "application/json";} -Body $newPermission

# Share the newly created site using existing groups
$user = @(
  @{
    "Key" = $shareWith.userPrincipalName;
    "IsResolved" = $False;
    "EntityData" = @{
      "ObjectId" = $shareWith.id;
    };
    "PeopleType"=  "Person";
    "PeopleSubtype" = "OrganizationUser";
  };
);
$user = ConvertTo-Json $user -Depth 99
$newPermission = @{
  "url" = $siteUrl;
  "peoplePickerInput" = $user;
  "roleValue" = "group:4"; #View
  "sendEmail" = $False;
  "emailBody" = "";
  "includeAnonymousLinkInEmail" = $False;
  "useSimplifiedRoles" = $True; #We use the groups and not the numeric IDs for the permissions
};
$newPermission = ConvertTo-Json $newPermission -Depth 99
$url = "$siteUrl/_api/SP.Web.ShareObject"
$null = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json;odata=verbose";} -Body $newPermission

# Create a new page
# See https://www.codesharepoint.com/rest-api/create-wiki-page-in-sharepoint-using-rest-api
# $newPage = "newPage3.aspx";
# $templateFileType = 0;
# $documentLibrary = "SitePages"
# $newPageUrl = "/$siteUrlRelative/$documentLibrary/$newPage"
# $url = "$siteUrl/_api/web/GetFolderByServerRelativeUrl('$documentLibrary')/Files/AddTemplateFile(urlOfFile='$newPageUrl',templateFileType=$templateFileType)"
# $response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json;odata=verbose";}

# Obtain a list of all the pages so we can publish it
# $url = "$siteUrl/_api/sitepages/Pages"
# $response = Invoke-RestMethod $url -Method Get -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json;odata=verbose";}

# Create a new modern page
$pageBody = @(
  @{
    "position" = @{
      "layoutIndex" = 1;
      "zoneIndex" = 1;
      "zoneId" = "e8975608-b178-469b-ae5f-a59d02abf94f";
      "sectionIndex" = 1;
      "sectionFactor" = 12;
      "controlIndex" = 1;
    };
    "id" = "778cf1f6-1ebe-4514-95aa-fc11d04dabfc";
    "controlType" = 4;
    "addedFromPersistedData" = $True;
    "isFromSectionTemplate" = $False;
    "innerHTML" = "<p>The secret number is 42</p>";
  };
  # {
  #   "controlType" = 0;
  #   "pageSettingsSlice": {
  #     "isDefaultDescription": true,
  #     "isDefaultThumbnail": true,
  #     "isSpellCheckEnabled": true,
  #     "globalRichTextStylingVersion": 0,
  #     "rtePageSettings": {
  #       "contentVersion": 4
  #     },
  #     "isEmailReady": false
  #   }
  # }
);
$pageBody = ConvertTo-Json $pageBody -Depth 99

$url = "$siteUrl/_api/sitepages/pages"
$pageData = @{
  "PageLayoutType" = "Article";
  "Title" = "$rand - Page with org secrets";
  "CanvasContent1" = $pageBody;
};
$pageData = ConvertTo-Json $pageData -Depth 99
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json;odata=verbose";} -Body $pageData

# Save the contents of the new page
$pageId = $response.d.Id
$url = "$siteUrl/_api/sitepages/pages($pageId)/Publish"
Invoke-RestMethod $url -Method Post -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json;odata=verbose";}


# $url = "$siteUrl/_api/web/GetFileByServerRelativeUrl('$newPageUrl')/Publish()"
# Invoke-RestMethod $url -Method Post -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json;odata=verbose";}

# Delete the site again
Write-Warning "Now run attacker script run.ps1 from the attacker's machine..."
$confirm = $null
while ($confirm -ne "Y") {
  $confirm = Read-Host -Prompt "Type Y when done to delete site"
}

$url = "https://$tenantName.sharepoint.com/_api/SPSiteManager/delete"
$deleteSite = @{
  "siteId" = $siteId;
};
$deleteSite = ConvertTo-Json -Depth 99 $deleteSite
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json;odata.metadata=none" -Headers @{"Authorization"="Bearer $accessTokenSPO"; "Accept" = "application/json";} -Body $deleteSite
