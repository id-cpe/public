<#
.SYNOPSIS
Connect to Graph API, create a folder in the signed-in user's personal OneDrive and share this folder with a specific user

.DESCRIPTION
TA0003: Persistence
T1222: File and Directory Permissions Modification
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
$scope = "Files.ReadWrite User.ReadBasic.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# We create a folder that we will be sharing
$url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
$rand = Get-Random -Minimum 1000 -Maximum 9999
$newFolder = @{
  "name" ="TA0003 - T1222 - 3 - $rand";
  "folder" = @{};
  "@microsoft.graph.conflictBehavior" = "fail";
}
$newFolder = ConvertTo-Json $newFolder #Pipeline breaks empty array
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newFolder

$itemId = $response.id

# Obtain object id of user to share folder with
$shareWith = Read-Host -Prompt "Share with (UPN)"
$url = "https://graph.microsoft.com/v1.0/users/$shareWith"
$response = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"} 
$shareWith = $response.id

# Invite new user
$url = "https://graph.microsoft.com/v1.0/me/drive/items/$itemId/invite"
$newPermissions = @{
  "recipients" = @(
    @{
      "objectId" = $shareWith;
    };
  );
  "message" = "Example message TA0003 - T1222 - 3 - $rand";
  "requireSignIn" = $True;
  "sendInvitation" = $True;
  "retainInheritedPermissions" = $True;
  "roles" = @("write");
}
$newPermissions = ConvertTo-Json -Depth 99 $newPermissions
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newPermissions

# Delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://graph.microsoft.com/v1.0/me/drive/items/$itemId"
$response = Invoke-RestMethod $url -Method Delete -Headers @{"Authorization"="Bearer $accessToken"}
