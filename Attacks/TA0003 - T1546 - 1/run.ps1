<#
.SYNOPSIS
Connect to Power Automate Web API, create a flow that is triggered when an email is received and delete the flow

.DESCRIPTION
TA0003: Persistence
T1546: Event Triggered Execution
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1
Get-Module | Where-Object name -eq connect-PowerAutomate | Remove-Module
Import-Module ../APIs/connect-PowerAutomate.psm1

# We use the ews environment variables
Import-Environment "powerautomate.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1

# We need access on the discovery endpoint and to manage all flows on the user's behalf
$scope = Get-PowerAutomateScopes
if ($null -eq $refreshToken) { $refreshToken = Get-DelegatedAccessToken -refreshToken -tenantId $env:TENANT_ID -clientId $env:PWRAU_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:PWRAU_DELEGATE_REDIRECT_URI }

Connect-PowerAutomate -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:PWRAU_DELEGATE_CLIENT_ID

Write-Host "Current flows: " -NoNewline
$currentFlows = Invoke-PowerAutomateFlowRequest -url "/flows?api-version=2016-11-01"
Write-Host $currentFlows.value

$connectorType = "shared_office365"
$sendmailconnector = Add-PowerAutomateConnector -connectorType $connectorType

# Define the new flow according to https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-workflow-definition-language
$flowName = "TA0003 - T1546 - 1 - $(Get-Random -Minimum 1000 -Maximum 9999)"
$newFlow = @{
    "properties" = @{
        "displayName" = $flowName;
        "environment" = @{
            "name" = "$(Get-PowerAutomateEnvironmentId)";
        };
        "connectionReferences" = @{
            "$connectorType" = @{
                "id" = "/providers/Microsoft.PowerApps/apis/$connectorType";
                "connectionName" = $sendmailconnector.name;
            };
        };
        "definition" = @{
            "`$schema" = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#";
            "contentVersion" = "undefined";
            "triggers" = @{
                "When_a_new_email_arrives_(V3)" = @{
                    "type" = "OpenApiConnectionNotification";
                    "inputs" = @{
                        "host" = @{
                            "apiId" = "/providers/Microsoft.PowerApps/apis/$connectorType";
                            "operationId" = "OnNewEmailV3";
                            "connectionName" = $connectorType;
                        };
                    };
                    "splitOn" = "@triggerOutputs()?['body/value']";
                };
            };
            "actions" = @{
                "Terminate" = @{
                    "type" = "Terminate";
                    "inputs" = @{
                        "runStatus" = "Succeeded";
                    };
                    "runAfter" = @{};
                };
            };
            "parameters" = @{
                "`$authentication" = @{
                    "defaultValue" = @{};
                    "type" = "SecureObject";
                };
                "`$connections" = @{
                    "defaultValue" = @{};
                    "type" = "Object";
                };
            };
        };
    };
}
$createdFlow = Invoke-PowerAutomateFlowRequest -url "/flows?api-version=2016-11-01" -Method POST -Body $newFlow
Write-Host "Created " + $createdFlow.name

# Once we have crated the flow, we need to wait for a few seconds before we can run it. 
# Unknown what is causing this delay, but this shold not be relevant for the output
# This linking seems similar to connectionReferences during creation, but this step is necessary
Write-Host "Linking flow to connector... " -NoNewline
$body = @{
    "connectionReferences" = @{
        "$connectorType" = @{
            "id" = "/providers/Microsoft.PowerApps/apis/$connectorType";
            "connectionName" = $sendmailconnector.name;
            "displayName" = "Office 365 Outlook";
        };
    }
};
Invoke-PowerAutomateFlowRequest -url "/flows/$($createdFlow.name)/install?api-version=2016-11-01" -Method POST -Body $body
Write-Host "done"

# We can wait a while and then delete the flow again
Wait-KeyOrTimeOut -Timeout 90000
Invoke-PowerAutomateFlowRequest -url "/flows/$($createdFlow.name)" -Method DELETE
