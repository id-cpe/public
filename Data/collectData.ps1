Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../Attacks/APIs/readEnv.psm1
Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../Attacks/APIs/oauth-microsoft.psm1

# We explicitly define all columns and constraints here so we can always use them
class AppAccessContext
{
    [AllowNull()][string]$IssuedAtTime = $null
    [AllowNull()][string]$UniqueTokenId #Can be empty

    AppAccessContext() {
        if ($this.UniqueTokenId.Length -eq 0) {
            $this.UniqueTokenId = $null
        } elseif ($this.UniqueTokenId -as [Guid] -eq $null) {
            throw "UniqueTokenId must be a valid Guid, $($this.UniqueTokenId) given"
        }
    }
}

class FolderLog
{
    [AllowNull()][string]$Id
    [AllowNull()][string]$Path
}

class ExchangeMetaDataLog
{
    [MailAddress]$From
    [MailAddress[]]$To
    [MailAddress[]]$CC
    [MailAddress[]]$BCC
    [string]$Subject
    [int]$FileSize
    [bool]$IsViewableByExternalUsers
    [string]$MessageID
    [Guid]$UniqueID
    [int]$RecipientCount
    [DateTime]$Sent
}

class RulesLog
{
    [string[]]$Actions
    [object]$ConditionsMatched
    [Guid]$RuleId
    [string]$RuleName
    [ValidateSet('Enable')][string]$RuleMode
    [ValidateSet('Low')][string]$Severity
}

class PolicyDetailLog
{
    [Guid]$PolicyId
    [RulesLog[]]$Rules
}

# To get a reasonale 
class ExchangeLogEntry
{
	[ValidateNotNullOrEmpty()][string]$CreationTime
	[ValidateNotNullOrEmpty()][Guid]$Id
	[ValidateNotNullOrEmpty()][string]$Operation
	[ValidateNotNullOrEmpty()][Guid]$OrganizationId
	[ValidateNotNull()][int]$RecordType
    [ValidateSet('Succeeded', 'PartiallySucceeded', 'True')][string]$ResultStatus
    [AllowNull()][string]$UserId = $null
    [ValidateNotNull()][int]$UserType
    [ValidateRange(1,1)][int]$Version
    [ValidateSet('Exchange')][string]$Workload
	[AllowNull()][string]$UserKey = $null
	[AllowNull()][AppAccessContext]$AppAccessContext = $null
	[AllowNull()][string]$AppId
	[AllowNull()][string]$SessionId
	[AllowNull()][string]$AppPoolName = $null
	[AllowNull()][string]$ClientAppId
	[AllowNull()][string]$ClientIP #Can also contain a port
	[ValidateNotNullOrEmpty()][string]$ClientIPAddress
	[AllowNull()][Guid]$ClientRequestId
	[AllowNull()][string]$ClientVersion
	[AllowNull()][string]$ClientProcessName
	[ValidateNotNull()][string]$ClientInfoString
	[ValidateNotNull()][bool]$ExternalAccess
	[ValidateNotNull()][int]$InternalLogonType
	[ValidateNotNull()][int]$LogonType
    #[ValidateNotNullOrEmpty()][System.Security.Principal.SecurityIdentifier]$LogonUserSid
    [ValidateNotNullOrEmpty()][string]$LogonUserSid
    [AllowNull()][string]$MailboxGuid
    #[ValidateNotNullOrEmpty()][System.Security.Principal.SecurityIdentifier]$MailboxOwnerSid
    [ValidateNotNullOrEmpty()][string]$MailboxOwnerSid
    [ValidateNotNullOrEmpty()][MailAddress]$MailboxOwnerUPN
    [AllowNull()][string]$ObjectId = $null
    [AllowNull()][object]$OperationProperties = $null
    [ValidateNotNullOrEmpty()][string]$OrganizationName
    [ValidateNotNullOrEmpty()][string]$OriginatingServer
    [AllowNull()][array]$Folders
    [AllowNull()][array]$AffectedItems
    [AllowNull()][array]$Parameters
	[AllowNull()][int]$OperationCount
	[string]$RequestId
    [AllowNull()][object]$Item
    [AllowNull()][bool]$CrossMailboxOperation
    [AllowNull()][FolderLog]$Folder
    [AllowNull()][FolderLog]$DestFolder
    # Items seen primarily for handling mip labels
    [AllowNull()][ValidateSet('Standard')][string]$ApplicationMode
    [AllowNull()][string]$ItemName
    [AllowNull()][ValidateSet('None')][string]$LabelAction
	[AllowNull()][DateTime]$LabelAppliedDateTime
	[AllowNull()][Guid]$LabelId
	[AllowNull()][string]$LabelName
	[AllowNull()][MailAddress[]]$Receivers
	[AllowNull()][MailAddress]$Sender
	[AllowNull()][ExchangeMetaDataLog]$ExchangeMetaData
	[AllowNull()][Guid]$IncidentId
	[AllowNull()][PolicyDetailLog[]]$PolicyDetails
	[AllowNull()][bool]$SensitiveInfoDetectionIsIncluded


    ExchangeLogEntry() {
        if ($this.UserId.length -eq 0) {
            $this.UserId = $null
        } elseif (!$this.UserId.Contains("NT AUTHORITY") -and $this.UserId -as [MailAddress] -eq $null) {
            throw "Invalid UserId: $($this.UserId)"
        }

        if ($this.AppId.Length -eq 0) {
            $this.AppId = $null
        } elseif ($this.AppId -as [Guid] -eq $null) {
            throw "AppId must be a valid Guid, $($this.AppId) given"
        }

        if ($this.ClientAppId.Length -eq 0) {
            $this.ClientAppId = $null
        } elseif ($this.ClientAppId -as [Guid] -eq $null) {
            throw "ClientAppId must be a valid Guid, $($this.ClientAppId) given"
        } else {
            Write-Host $this.ClientAppId
        }

        if ($this.RequestId -ne $null -and $this.RequestId -as [Guid] -eq $null) {
            throw "RequestId must be a valid Guid or null, $($this.RequestId) given"
        }

        if ($this.MailboxGuid -ne $null -and $this.MailboxGuid -as [Guid] -eq $null) {
            throw "MailboxGuid must be a valid Guid or null, $($this.MailboxGuid) given"
        }

        if ($this.LogonUserSid -ne $null -and $this.LogonUserSid -as [System.Security.Principal.SecurityIdentifier] -eq $null) {
            throw "LogonUserSid must be a valid SID or null, $($this.LogonUserSid) given"
        }

        if ($this.MailboxOwnerSid -ne $null -and $this.MailboxOwnerSid -as [System.Security.Principal.SecurityIdentifier] -eq $null) {
            throw "MailboxOwnerSid must be a valid SID or null, $($this.MailboxOwnerSid) given"
        }
    }
}

# If we get casting errors
# $props = [ExchangeLogEntry].DeclaredProperties.Name
# $propsnew = (($response.Content | ConvertFrom-Json) | gm -MemberType NoteProperty).Name
# Differences: Compare-Object $props $propsnew
# foreach ($item in ($response.Content | ConvertFrom-Json)) {
#     $propsnew = ($item | gm -MemberType NoteProperty).Name
#     Write-Host (Compare-Object $props $propsnew | Where-Object {$_.SideIndicator -ne "<="})
# }

# We use the ews environment variables
Import-Environment "purview.env"

$scope = "https://manage.office.com/.default"
$accessToken = Get-ClientAccessToken -tenantId $env:TENANT_ID -clientId $env:PURVIEW_IMPERSONATE_CLIENT_ID -clientSecret $env:PURVIEW_IMPERSONATE_CLIENT_SECRET -scope $scope

$baseURL = "https://manage.office.com/api/v1.0/$env:TENANT_ID/activity/feed"

$timeInput = Read-Host -Prompt "Time Zero yyyy-MM-dd HH:mm:ss"
if ([bool] $timeInput) {
    $timeZero = [DateTime] $timeInput
} else {
    $timeZero = Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0
}
$timeShift = New-TimeSpan -start ([DateTime] "1999-12-31 00:00:00") -End $timeZero.ToUniversalTime()

# Obtain the data from the start to the end, add some hours for timezones
$start = Get-Date $timeZero.ToUniversalTime().AddHours(-2) -Format "yyyy-MM-dd\THH:mm:ss"
$end = Get-Date $timeZero.ToUniversalTime().AddHours(2) -Format "yyyy-MM-dd\THH:mm:ss"
$upn = Read-Host -Prompt "UPN ($env:TENANT_ID will be appended if no domain is given)"
if ($upn.Length -ne 0 -and !$upn.Contains("@")) { $upn = "$upn@$env:TENANT_ID" }

$contentURLs = New-Object System.Collections.Generic.List[System.String]
$contentTypes = @("Audit.General", "Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint")

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

$logs = @()
$dateF = Get-Date $timeZero -Format "yyyy-MM-dd HH.mm.ss"
$null | Out-File "./$dateF - $upn.raw.json"

foreach ($contentURL in $contentURLs) {
    $response = Invoke-WebRequest $contentURL -Headers @{"Authorization"="Bearer $accessToken"}
    # For raw logging we do not do any conversion from or to JSON, because the JSON format differs slightly with Powershell's
    $response.Content | Out-File -Append "./$dateF - $upn.raw.json"
    #$content = [ExchangeLogEntry[]] ($response.Content | ConvertFrom-Json)
    $content = ($response.Content | ConvertFrom-Json)
    $logs += $content
}
$outputLogs = $logs | Where-Object {
    $_.UserId -like "$upn*" -or
    $_.ObjectId -like "$upn*" -or
    $_.MailboxOwnerUPN -like "$upn*" -or
    $_.UserId -notlike "*@$env:TENANT_ID"
} #| Where-Object {
  #  # We include these operations in the raw logs, but we do not include signin logs in our output
  #  $_.Operation -ne "UserLoggedIn"
#}

$outputLogs = $outputLogs | Sort-Object -Property CreationTime

$countToEarly = ($outputLogs | Where-Object { (Get-Date $_.CreationTime) -lt $timeZero.AddHours(-2) }).Count
if ($countToEarly -gt 0) {
    Write-Warning "Logs earlier than time zero have been included, starting at $($outputLogs[0].CreationTime)"
}

# We then start the mapping part for clarity
# In accordance with RFC 5737, attacker IPs get matched to an IP in the range 192.0.2.0/24
# Victim IPs get matched to 198.51.100.0/24
# IPs owned by Microsoft are not mapped
$ipMap = @{
    "::1" = "::1";
    "255.255.255.255" = "255.255.255.255";
    
    # Attacker IPs
    "109.201.130.8"  = "192.0.2.1";
    "46.166.129.2"   = "192.0.2.2";
    "185.107.81.130" = "192.0.2.3";
    "109.201.130.17" = "192.0.2.4";
    "185.107.95.55"  = "192.0.2.5";
    "185.107.95.59"  = "192.0.2.6";
    "185.107.95.53"  = "192.0.2.7";
    "46.166.179.210" = "192.0.2.8";
    "185.107.81.145" = "192.0.2.9";
    "46.166.129.10"  = "192.0.2.10";
    "46.166.179.211" = "192.0.2.11";
    "109.201.130.25" = "192.0.2.12";
    "185.107.81.138" = "192.0.2.13";
    "109.201.130.24" = "192.0.2.14";
    "46.166.129.7"   = "192.0.2.15";
    "109.201.130.11" = "192.0.2.16";
    "185.107.81.136" = "192.0.2.17";
    "46.166.129.6"   = "192.0.2.18";
    "46.166.179.212" = "192.0.2.19";
    "46.166.129.9"   = "192.0.2.20";
    "109.201.130.12" = "192.0.2.21";
    "185.107.95.50"  = "192.0.2.22";
    "185.107.81.143" = "192.0.2.23";
    "185.107.95.54"  = "192.0.2.24";
    "46.166.129.5"   = "192.0.2.25";
    "46.166.129.4"   = "192.0.2.26";
    "185.107.81.140" = "192.0.2.27";
    "185.107.81.142" = "192.0.2.28";
    "109.201.130.20" = "192.0.2.29";
    "109.201.130.10" = "192.0.2.30";
    "46.166.129.8"   = "192.0.2.31";
    "185.107.95.57"  = "192.0.2.32";
    "185.107.95.58"  = "192.0.2.33";
    "109.201.130.16" = "192.0.2.34";

    # Victim IPs
    "80.57.241.128"  = "198.51.100.254";
    "149.36.51.140"  = "198.51.100.1";
    "84.17.46.17"    = "198.51.100.2";
    "84.17.46.18"    = "198.51.100.3";
    "84.17.46.9"     = "198.51.100.4";
    "149.36.51.137"  = "198.51.100.5";
    "195.181.172.153"= "198.51.100.6";
    "84.17.46.16"    = "198.51.100.7";
    "84.17.46.19"    = "198.51.100.8";
    "195.181.172.152"= "198.51.100.9";
    "84.17.46.13"    = "198.51.100.10";
    "149.36.51.135"  = "198.51.100.11";
    "149.36.51.134"  = "198.51.100.12";
    "84.17.46.26"    = "198.51.100.13";
    "84.17.46.6"     = "198.51.100.14";
    "195.181.172.151"= "198.51.100.15";
    "149.36.51.142"  = "198.51.100.16";
    "149.36.51.145"  = "198.51.100.17";
    "195.181.172.149"= "198.51.100.18";
    "149.36.51.132"  = "198.51.100.19";
    "149.36.51.139"  = "198.51.100.20";
    "149.36.51.152"  = "198.51.100.21";
    "195.181.172.148"= "198.51.100.22";
    "84.17.46.23"    = "198.51.100.23";
    "149.36.51.130"  = "198.51.100.24";
    "149.36.51.138"  = "198.51.100.25";
    "149.36.51.149"  = "198.51.100.26";
    "84.17.46.8"     = "198.51.100.27";
    "149.36.51.144"  = "198.51.100.28";
    "84.17.46.11"    = "198.51.100.29";
    "84.17.46.25"    = "198.51.100.30";
    "84.17.46.15"    = "198.51.100.31";
}

Import-Environment "ews.env"
Import-Environment "exops.env"
Import-Environment "graph.env"

# Client app IDs that are not publicly known are mapped to something more representative
# possibly no longer a valid GUID. Well-known IDs are not replaced
# https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
$appIdMap = @{
    $env:GRAPH_DELEGATE_CLIENT_ID   = "40404040-4040-4040-4APP-GRAPHDELCLID"
    $env:EWS_IMPERSONATE_CLIENT_ID  = "40404040-4040-4040-4APP-EWSXXIMPCLID"
    $env:EWS_DELEGATE_CLIENT_ID     = "40404040-4040-4040-4APP-EWSXXDELCLID"
    $env:EXOPS_DELEGATE_CLIENT_ID   = "40404040-4040-4040-4APP-EXOPSDELCLID"
    "00000002-0000-0ff1-ce00-000000000000" = "00000002-0000-0ff1-ce00-000000000000" # OWA
    "00000003-0000-0000-c000-000000000000" = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    "13937bba-652e-4c46-b222-3003f4d1ff97" = "13937bba-652e-4c46-b222-3003f4d1ff97" # Substrate Context Service
    "3138fe80-4087-4b04-80a6-8866c738028a" = "3138fe80-4087-4b04-80a6-8866c738028a" # SharePoint Notification service
    "497effe9-df71-4043-a8bb-14cf78c4b63b" = "497effe9-df71-4043-a8bb-14cf78c4b63b" # Exchange Admin Cnter
    "7ab7862c-4c57-491e-8a45-d52a7e023983" = "7ab7862c-4c57-491e-8a45-d52a7e023983" # App Service (Power Automate)
    "812fcd2a-bd10-44fa-8608-fd56e4c001e3" = "812fcd2a-bd10-44fa-8608-fd56e4c001e3" 
    "82d8ab62-be52-a567-14ea-1616c4ee06c4" = "82d8ab62-be52-a567-14ea-1616c4ee06c4" # Exchange Online (not documented)
    "a3883eba-fbe9-48bd-9ed3-dca3e0e84250" = "a3883eba-fbe9-48bd-9ed3-dca3e0e84250" # Exchange Online (reads mail, but only for admin?)
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "d3590ed6-52b3-4102-aeff-aad2292ab01c" # Microsoft Office
}

function Is-MicrosoftIp {
    param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][IPAddress]$ip
    )
    $ipinfo = (Invoke-RestMethod "https://ip.ward.nl/$ip").data[0]
    $isMs = ($ipInfo.bogon -ne $True -and ($ipinfo.postal -eq "98052" -or $ipinfo.org.Contains("Microsoft Corporation")))

    $isMs
}

function Mask-IP {
    param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$ipAndPort
    )
    if ($ipAndPort -as [IPAddress] -eq $null) {
        $ip = ($ipAndPort -split ":")[0]
        $port = ($ipAndPort -split ":")[1]
        if ($port -ne "") { $port = ":$port" }
    } else {
        $ip = $ipAndPort
        $port = ""
    }

    # Fix the fake IPv6
    if ($ip -like "::ffff:*") {
        $prefix = "::ffff:"
        $ip = $ip.replace($prefix, "")
    } else {
        $prefix = ""
    }

    if ($ipMap.ContainsKey($ip)) {
        $ip = $ipMap[$ip]
    } elseif (!(Is-MicrosoftIp -ip $ip)) {
        Write-Warning "Unknown mapping for $ip"
    }
    return "$prefix$ip$port"
}

function Explain-AppId {
    param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$appId
    )
    if ($appIdMap.ContainsKey($appId)) {
        return $appIdMap[$appId]
    } else {
        Write-Warning "Unknown app id mapping for $appId"
    }
}

function Anonymize-UPN {
    param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$upn
    )
    $upn.Replace($env:TENANT_ID, "detectabil.it")
}

function Replace-OrganizationIDs {
    param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$orgId
    )
    $orgId.Replace("801d2213-4df9-466e-aeff-aef47206f9ce", "40404040-4040-4040-4040-404040404040")
}

# https://stackoverflow.com/a/55384556
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
    $indent = 0;
    ($json -Split "`n" | % {
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

foreach ($outputLog in $outputLogs) {
    # The creation time will be mapped to the start of the test. Each test starts at 01-01-2000 at 00.00.00 UTC
    $outputLog.CreationTime = Get-Date (([DateTime] $outputLog.CreationTime) - $timeShift) -Format "yyyy-MM-dd\THH:mm:ss"
    if ($outputLog.AppAccessContext.IssuedAtTime -ne $null) {
        $outputLog.AppAccessContext.IssuedAtTime = Get-Date (([DateTime] $outputLog.AppAccessContext.IssuedAtTime) - $timeShift) -Format "yyyy-MM-dd\THH:mm:ss"
    }

    if ($outputLog.ClientIP.Length -gt 0) { $outputLog.ClientIP = Mask-IP -ip $outputLog.ClientIP }
    if ($outputLog.ActorIpAddress.Length -gt 0) { $outputLog.ActorIpAddress = Mask-IP -ip $outputLog.ActorIpAddress }
    if ($outputLog.ClientIPAddress.Length -gt 0) { $outputLog.ClientIPAddress = Mask-IP -ip $outputLog.ClientIPAddress }
    if ($outputLog.ClientAppId.Length -gt 0) { $outputLog.ClientAppId = Explain-AppId -appId $outputLog.ClientAppId }
    if ($outputLog.AppId.Length -gt 0) { $outputLog.AppId = Explain-AppId -appId $outputLog.AppId }
    if ($outputLog.UserId.Length -gt 0) { $outputLog.UserId = Anonymize-UPN -upn $outputLog.UserId }
    if ($outputLog.UserUPN.Length -gt 0) { $outputLog.UserUPN = Anonymize-UPN -upn $outputLog.UserUPN }
    if ($outputLog.MailboxOwnerUPN.Length -gt 0) { $outputLog.MailboxOwnerUPN = Anonymize-UPN -upn $outputLog.MailboxOwnerUPN }
    if ($outputLog.OrganizationName.Length -gt 0) { $outputLog.OrganizationName = Anonymize-UPN -upn $outputLog.OrganizationName }
    if ($outputLog.OrganizationId.Length -gt 0) { $outputLog.OrganizationId = Replace-OrganizationIDs -orgId $outputLog.OrganizationId }

    if ($outputLog.AdditionalInfo.Length -gt 0) {
        try {
            $outputLog.AdditionalInfo = $outputLog.AdditionalInfo | ConvertFrom-Json
        } catch {}
    }

    # Replace 
}

if ($upn.Length -eq 0) { $upn = "ALL" }
($outputLogs | ConvertTo-Json -Depth 10) | Format-Json | Out-File "./$dateF - $upn.json"