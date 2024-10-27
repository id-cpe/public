<#
.SYNOPSIS
Connect to Graph API and send an internal spearphishing email (which is subsequently read outside of this script)

.DESCRIPTION
TA0008: Lateral Movement
T1534: Internal Spearphishing
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
$scope = "Mail.Send"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

$recipient = Read-Host "Recipient (UPN)"

# Send an email
$url = "https://graph.microsoft.com/v1.0/me/sendMail"
$rand = Get-Random -Minimum 1000 -Maximum 9999

$emailMessage = @{
    "message" = @{
      "subject" = "TA0008 - T1534 - 1 - $rand";
      "body" = @{
        "contentType" = "Text";
        "content" = "Dear recipient, click this phishing link:";
      };
      "toRecipients" = @(
        @{
          "emailAddress" = @{
            "address" = $recipient;
          };
        };
      );
    };
    "saveToSentItems" = $True;
}
$emailMessage = ConvertTo-Json -Depth 99 $emailMessage
Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $emailMessage
