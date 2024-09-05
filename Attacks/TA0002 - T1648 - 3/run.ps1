<#
.SYNOPSIS
Connect to Power Automate Web API, create a flow to create a file in OneDrive, triggers it and delete the flow

.DESCRIPTION
TA0002: Defense evasion
T1648: Serverless Execution
3rd attack method
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

$connectorType = "shared_onedriveforbusiness"
$odconnector = Add-PowerAutomateConnector -connectorType $connectorType

# Define the new flow according to https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-workflow-definition-language
$flowName = "TA0002 - T1648 - 3 - $(Get-Random -Minimum 1000 -Maximum 9999)"
$newFlow = @{
    "properties" = @{
        "displayName" = $flowName;
        "environment" = @{
            "name" = "$(Get-PowerAutomateEnvironmentId)";
        };
        "connectionReferences" = @{
            "$connectorType" = @{
                "id" = "/providers/Microsoft.PowerApps/apis/$connectorType";
                "connectionName" = $odconnector.name;
            };
        };
        "definition" = @{
            "`$schema" = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#";
            "contentVersion" = "undefined";
            "triggers" = @{
                "Recurrence" = @{
                    "recurrence" = @{
                        "interval" = 5;
                        "frequency" = "Month";
                        "startTime" = "$([int](Get-Date -UFormat "%Y") + 4)-12-31T23:59:59Z";
                    };
                    "type" = "Recurrence";
                };
            };
            "actions" = @{
                "Create_new_folder" = @{
                    "type" = "OpenApiConnection";
                    "inputs" = @{
                        "parameters" = @{
                            "folderPath" = "/";
                            "name" = "$flowName.docx";
                            "body" = " ";
                        };
                        "host" = @{
                            "apiId" = "/providers/Microsoft.PowerApps/apis/$connectorType";
                            "connectionName" = "$connectorType";
                            "operationId" = "CreateFile";
                        };
                    };
                    "runAfter" = @{};
                    "runtimeConfiguration" = @{
                        "contentTransfer" = @{
                            "transferMode" = "Chunked";
                        };
                    };
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
            "connectionName" = $odconnector.name;
            "displayName" = "OneDrive for Business";
        };
    }
};
$installedFlow = Invoke-PowerAutomateFlowRequest -url "/flows/$($createdFlow.name)/install?api-version=2016-11-01" -Method POST -Body $body
Write-Host "done"

# Alternative trigger based on recurrence (avoids api hub but somehow does not work for all actions)
Invoke-PowerAutomateFlowRequest -url "/flows/$($createdFlow.name)/triggers/Recurrence/run?api-version=2016-11-01" -Method POST

# We can wait a while and then delete the flow again
Wait-KeyOrTimeOut -Timeout 90000
Invoke-PowerAutomateFlowRequest -url "/flows/$($createdFlow.name)" -Method DELETE
