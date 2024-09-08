<#
.SYNOPSIS
Connect to Graph API with a user with/without MFA and send an email

.DESCRIPTION
TA0003: Persistence
T1556.006: Multi-Factor Authentication
1st attack method & 1st comparison method
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

# Send an email
$url = "https://graph.microsoft.com/v1.0/me/sendMail"
$rand = Get-Random -Minimum 1000 -Maximum 9999

$emailMessage = @{
    "message" = @{
      "subject" = "TA0003 - T1557.006 - 1 - $rand";
      "body" = @{
        "contentType" = "Text";
        "content" = "This is an example email with(out) MFA enabled.";
      };
      "toRecipients" = @(
        @{
          "emailAddress" = @{
            "address" = "example@$env:TENANT_ID";
          };
        };
      );
    };
    "saveToSentItems" = $False;
}
$emailMessage = ConvertTo-Json -Depth 99 $emailMessage
Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $emailMessage
