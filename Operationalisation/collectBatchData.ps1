<#
.SYNOPSIS
Extract data from a production environment for a proof of concept.

.DESCRIPTION
Connect to a live environemnt, and extract a range of data for Exchange Online
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../Attacks/APIs/readEnv.psm1
Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../Attacks/APIs/oauth-microsoft.psm1

# We use the ews environment variables
Import-Environment "purview.env"

$scope = "https://manage.office.com/.default"
$accessToken = Get-ClientAccessToken -tenantId $env:TENANT_ID -clientId $env:PURVIEW_IMPERSONATE_CLIENT_ID -clientSecret $env:PURVIEW_IMPERSONATE_CLIENT_SECRET -scope $scope

$baseURL = "https://manage.office.com/api/v1.0/$env:TENANT_ID/activity/feed"

$day = Read-Host -Prompt "Day yyyy-MM-dd"
$day = (Get-Date $day -Hour 0 -Minute 0 -Second 0 -Millisecond 0)
$start = Get-Date $day -Format "yyyy-MM-dd\THH:mm:ss"
$end = Get-Date $day.AddDays(1) -Format "yyyy-MM-dd\THH:mm:ss"

$contentURLs = New-Object System.Collections.Generic.List[System.String]
$contentTypes = @("Audit.General", "Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint")
#$contentTypes = @("Audit.Exchange")

foreach ($contentType in $contentTypes) {
    $url = "$baseURL/subscriptions/content?startTime=$start&endTime=$end&contentType=$contentType"
    $downloads = Invoke-RestMethod $url -Headers @{"Authorization"="Bearer $accessToken"}

    # If we have 0 or more than 1 downloads this can be a mistake
    if ($downloads.Length -ne 1) {
        Write-Warning "$($downloads.Length) downloads for $contentType"
    }

    foreach ($download in $downloads) {
        $contentURLs.Add($download.contentUri)
    }
}

New-Item -ItemType Directory -Path "$PWD/data" -Force
$logs = @()
$dateF = Get-Date $day -Format "yyyy-MM-dd HH.mm.ss"
$null | Out-File "$PWD/data/$dateF.raw.json"

$i = 0
foreach ($contentURL in $contentURLs) {
    Write-Progress -Activity "Donloading data" -Status "${i}/$($contentURLs.Count)" -PercentComplete ([int]($i/$contentURLs.Count*100))
    $response = Invoke-WebRequest $contentURL -Headers @{"Authorization"="Bearer $accessToken"}
    # For raw logging we do not do any conversion from or to JSON, because the JSON format differs slightly with Powershell's
    $response.Content | Out-File -Append "$PWD/data/$dateF.raw.json"
    #$content = [ExchangeLogEntry[]] ($response.Content | ConvertFrom-Json)
    $content = ($response.Content | ConvertFrom-Json)
    $logs += $content
    $i += 1
}
Write-Progress -Activity "Donloading data" -Status "Done" -Completed
$outputLogs = $logs #| Where-Object {
    #$_.Workload -eq "Exchange"
#}

$outputLogs = $outputLogs | Sort-Object -Property CreationTime

# https://stackoverflow.com/a/55384556
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
    $indent = 0;
    ($json -Split "`n" | ForEach-Object {
        if ($_ -match '[\}\]]\s*,?\s*$') {
            # This line ends with ] or }, decrement the indentation level
            $indent--
        }
        $line = ('  ' * $indent) + $($_.TrimStart() -replace '":  (["{[])', '": $1' -replace ':  ', ': ')
        if ($_ -match '[\{\[]\s*$') {
            # This line ends with [ or {, increment the indentation level
            $indent++
        }
        $line
    }) -Join "`n"
}

#($outputLogs | ConvertTo-Json -Depth 10) | Format-Json | Out-File "$PWD/data/$dateF.json"
