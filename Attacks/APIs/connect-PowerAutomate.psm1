Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module $PSScriptRoot/oauth-microsoft.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module -Scope global $PSScriptRoot/custom.psm1

$script:apiUrl = $null
$script:apiEnvironmentId = $null

function Get-PowerAutomateDiscoveryEndpoint {
    "https://globaldisco.crm.dynamics.com"
}

# Discvery endpoint do discover the service, flow to manage the flows and apihub to trigger manual flows
function Get-PowerAutomateScopes {
    $discoveryEndpoint = Get-PowerAutomateDiscoveryEndpoint
    "$discoveryEndpoint/user_impersonation https://service.flow.microsoft.com/Flows.Manage.All https://apihub.azure.com/Runtime.All"
}
Export-ModuleMember -Function Get-PowerAutomateScopes

function Connect-PowerAutomate {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$refreshToken,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$tenantId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$clientId
    )


    <#
    This function has two phases: we first have to determine the URL which we will be using to access the dataverse.
    For this we have to connect with a discovery endpoint (https://learn.microsoft.com/en-us/power-apps/developer/data-platform/discovery-service#global-discovery-service)
    #>

    $discoveryEndpoint = Get-PowerAutomateDiscoveryEndpoint
    # With the refresh token, we can create an access token for the discovery endpoint
    $accessToken = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $tenantId -clientId $clientId -scope "$discoveryEndpoint/user_impersonation"

    $url = "$discoveryEndpoint/api/discovery/v2.0/Instances"
    $resp = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}
    $environments = $resp.value
    if ($environments.Count -eq 0) {
        # Documentation is not clear whether the default environment is created when the first user users Power Apps or whether it automatically happens
        # when a license is assigned. 
        Write-Error "No environments found, possibly nobody in the tenant is using Power Automate/Power Apps"
    }
    Write-Host "Environments the user has access to: $($environments.EnvironmentId)"
    $defaultEnvironments = $environments | Where-Object { $_.EnvironmentId -like "Default*" }
    if ($defaultEnvironments.Count -ne 1) {
        Write-Error "Found $($defaultEnvironments.Count) default environments, possibly also other tenants. Select the one with the right tenant ID"
    }
    $script:apiUrl = $defaultEnvironments[0].ApiUrl
    $script:apiEnvironmentId = $defaultEnvironments[0].EnvironmentId
    
    # If we want to change other things than flows, we might want to use this url:
    # $url = "$apiUrl/api/data/v9.2/workflows"
    Write-Host "Using $apiUrl / $apiEnvironmentId"

    # From now on, we only need an access token to interact with the API itself
    $script:accessToken = Get-AccessTokenFromRefreshToken -refreshToken $refreshToken -tenantId $env:TENANT_ID -clientId $env:PWRAU_DELEGATE_CLIENT_ID -scope "https://service.flow.microsoft.com/Flows.Manage.All"

    $url = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$apiEnvironmentId/flows?api-version=2016-11-01"

}
Export-ModuleMember -Function Connect-PowerAutomate

function Get-PowerAutomateEnvironmentId {
    $script:apiEnvironmentId
}
Export-ModuleMember -Function Get-PowerAutomateEnvironmentId

function Add-PowerAutomateConnector {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$connectorType
    )

    $sendmailconnector = $null
    

    while ($null -eq $sendmailconnector) {
        Write-Host "Connections: " -NoNewline
        $connections = Invoke-PowerAutomateFlowRequest -url "https://europe.api.powerapps.com/providers/Microsoft.PowerApps/connections?api-version=2016-11-01&%24filter=ApiId%20not%20in%20(%27shared_logicflows%27%2C%27shared_powerflows%27%2C%27shared_pqogenericconnector%27)%20and%20environment%20eq%20%27Default-801d2213-4df9-466e-aeff-aef47206f9ce%27"
        Write-Host $connections.value
        foreach ($connection in $connections.value) {
            if ($connection.properties.apiId -eq "/providers/Microsoft.PowerApps/apis/$connectorType" -and $connection.properties.statuses[0].status -eq "Connected") {
                $sendmailconnector = $connection
            }
        }

        # If we don't have an Office 365 connector yet, we have to create one
        if ($null -eq $sendmailconnector) {
            Write-Warning "No $connectorType connector found, creating a new one..."

            # Pick a semi-random ID (the client can pick)
            $connId = "connector-$(Get-Random -Minimum 1000 -Maximum 9999)"
            # Create URL
            $filter = [URI]::EscapeDataString("environment eq '$(Get-PowerAutomateEnvironmentId)'")
            $url = "https://europe.api.powerapps.com/providers/Microsoft.PowerApps/apis/$connectorType/connections/${connId}?api-version=2020-06-01&`$filter=$filter"
            Write-Host $url
            $options = @{
                "properties" = @{
                    "environment" = @{
                        "id" = "/providers/Microsoft.PowerApps/environments/$(Get-PowerAutomateEnvironmentId)";
                        "name" = "$(Get-PowerAutomateEnvironmentId)";
                    };
                    "connectionParameters" = @{};
                };
            }
            Invoke-PowerAutomateFlowRequest -url $url -Method PUT -Body $options > $null
            
            # Add consent to the newly created connection
            $url = "https://europe.api.powerapps.com/providers/Microsoft.PowerApps/apis/$connectorType/connections/$connId/getConsentLink?api-version=2020-06-01&`$filter=$filter"
            $options = @{
                "redirectUrl" = "http://localhost";
            }
            $resp = Invoke-PowerAutomateFlowRequest -url $url -Method POST -Body $options

            Write-Host "Open the following link and grant consent: " -NoNewline
            Write-Host $resp.consentLink
            if ($env:AUTO_FIREFOX -and -not $isLinux) {
                & 'C:\Program Files\Mozilla Firefox\firefox.exe' -foreground -url $resp.consentLink
            }
            Write-Host "Press any key when done..."
            try {
                $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            } catch [System.NotImplementedException] {
                Read-Host -Prompt "Readkey is not supported, press enter to continue..."
            }
        }
    }
    $sendmailconnector
}
Export-ModuleMember -Function Add-PowerAutomateConnector


# We can use the Flow API which is also used by Power Automate to create flows
# Allow sfor processing independent of the environment 
function Invoke-PowerAutomateFlowRequest {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$url,
        [Microsoft.PowerShell.Commands.WebRequestMethod]$method = "GET",
        [object]$body = $null
    )

    $headers = @{"Authorization"="Bearer $script:accessToken"}
    if ($null -ne $body) {
        $headers["Content-Type"] = "application/json";
        $body = ConvertTo-Json -Depth 99 $body
    }

    if ($url -notlike "http*") {
        $url = "https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/environments/$apiEnvironmentId$url"
    }
    
    Invoke-RestMethod -Uri $url -Method $method -Body $body -Headers $headers
}
Export-ModuleMember -Function Invoke-PowerAutomateFlowRequest
