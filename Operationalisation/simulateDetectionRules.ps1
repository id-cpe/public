<#
.SYNOPSIS
From downloaded data, run the signature simulation

.DESCRIPTION
To show how the findings can be operationalised, we simulate signature-based detection algorithms here.
We converted the rules to elasticsearch rules using https://sigconverter.io/ and then manually created an equivalent PowerShell expression
#>

$name = $null
while (!(Test-Path "$PWD/data/$name.raw.json")) {
    $name = Read-Host -Prompt "Log file (.raw.json)"
    $name = $name.Replace(".raw.json", "")
}

# Rule definitions based on `rules.MD`
function Test-OwaForward (
    [Parameter(Mandatory)][object] $logRecord
) {
    $selection_rightevent = $logRecord.Workload -like "Exchange*" -and $logRecord.Operation -in $('New-InboxRule', 'Set-InboxRule')
    if (!$selection_rightevent) { return } #Speed up, does not affect result
    
    $scope_restricted = $logRecord.Parameters.BodyContainsWords.Length -gt 0 -or `
        $logRecord.Parameters.SubjectContainsWords.Length -gt 0 -or `
        $logRecord.Parameters.SubjectOrBodyContainsWords.Length -gt 0 -or `
        $logRecord.Parameters.From -like "*@*" -or `
        $logRecord.Parameters.MessageTypeMatches -in @('AutomaticReply', 'AutomaticForward', 'Calendaring', 'CalendaringResponse', 'Voicemail', 'ReadReceipt', 'NonDeliveryReport')
    
    $scope_sensitivescope2 = $logRecord.Parameters.BodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
        $logRecord.Parameters.SubjectContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
        $logRecord.Parameters.SubjectOrBodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware"
    
    $action_sensitiveaction = $logRecord.Parameters.RedirectTo -like '*@*' -or `
        $logRecord.Parameters.ForwardTo -like '*@*' -or `
        $logRecord.Parameters.ForwardAsAttachmentTo -like '*@*'
    
    $selection_rightevent -and (!$scope_restricted -or $scope_sensitivescope2) -and $action_sensitiveaction
}

function Test-OwaDelete (
    [Parameter(Mandatory)][object] $logRecord
) {
    $selection_rightevent = $logRecord.Workload -like "Exchange*" -and $logRecord.Operation -in $('New-InboxRule', 'Set-InboxRule')
    if (!$selection_rightevent) { return } #Speed up, does not affect result
    
    $scope_restricted = $logRecord.Parameters.BodyContainsWords.Length -gt 0 -or `
        $logRecord.Parameters.SubjectContainsWords.Length -gt 0 -or `
        $logRecord.Parameters.SubjectOrBodyContainsWords.Length -gt 0 -or `
        $logRecord.Parameters.From -like "*@*" -or `
        $logRecord.Parameters.MessageTypeMatches -in @('AutomaticReply', 'AutomaticForward', 'Calendaring', 'CalendaringResponse', 'Voicemail', 'ReadReceipt', 'NonDeliveryReport')
    
    $scope_sensitivescope2 = $logRecord.Parameters.BodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
        $logRecord.Parameters.SubjectContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware" -or `
        $logRecord.Parameters.SubjectOrBodyContainsWords -match "account|password|reset|secure|confidential|hack|virus|malware"
    
    $action_sensitiveaction = $logRecord.Parameters.DeleteMessage -eq $True -or `
        $logRecord.Parameters.SoftDeleteMessage -eq $True -or `
        $logRecord.Parameters.MoveToFolder -like '*deleted*'
    
    $selection_rightevent -and (!$scope_restricted -or $scope_sensitivescope2) -and $action_sensitiveaction
}

function Test-OutlookForward (
    [Parameter(Mandatory)][object] $logRecord
) {
    $selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
        $logRecord.Operation -eq 'UpdateInboxRules' -and `
        $logRecord.OperationProperties.RuleOperation -in $('AddMailboxRule', 'ModifyMailboxRule')
    if (!$selection_rightevent) { return } #Speed up, does not affect result

    $scope_fullscope = $logRecord.OperationProperties.RuleCondition -eq '' -or `
        $logRecord.OperationProperties.RuleCondition -eq 'MessageToMe\ Equal\ True'

    $scope_sensitivescope1 = $logRecord.OperationProperties.RuleCondition -match 'SubString|SubjectProperty|BodyProperty'
    $scope_sensitivescope2 = $logRecord.OperationProperties.RuleCondition -match 'account|password|reset|secure|confidential'

    $action_sensitiveaction = $logRecord.OperationProperties.RuleActions -like '*Forward*'
    
    $selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
}

function Test-OutlookDelete (
    [Parameter(Mandatory)][object] $logRecord
) {
    $selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
        $logRecord.Operation -eq 'UpdateInboxRules' -and `
        $logRecord.OperationProperties.RuleOperation -in $('AddMailboxRule', 'ModifyMailboxRule')
    if (!$selection_rightevent) { return } #Speed up, does not affect result

    $scope_fullscope = $logRecord.OperationProperties.RuleCondition -eq '' -or `
        $logRecord.OperationProperties.RuleCondition -eq 'MessageToMe\ Equal\ True'

    $scope_sensitivescope1 = $logRecord.OperationProperties.RuleCondition -match 'SubString|SubjectProperty|BodyProperty'
    $scope_sensitivescope2 = $logRecord.OperationProperties.RuleCondition -match 'account|password|reset|secure|confidential|hack|virus|malware'

    $action_sensitiveaction = $logRecord.OperationProperties.RuleActions -match 'Move|Delete'
    
    $selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
}

function Test-GraphForward (
    [Parameter(Mandatory)][object] $logRecord
) {
    $selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
        $logRecord.Operation -eq 'UpdateInboxRules' -and `
        $logRecord.OperationProperties.RuleOperation -in $('Create')
    if (!$selection_rightevent) { return } #Speed up, does not affect result

    $scope_fullscope = $logRecord.OperationProperties.Conditions -eq ''

    $scope_sensitivescope1 = $logRecord.OperationProperties.Conditions -match 'Contains|Subject|Body'
    $scope_sensitivescope2 = $logRecord.OperationProperties.ServerRule -match 'QUNDT1VOV|FDQ09VTl|BQ0NPVU5U|UEFTU1dPUk|BBU1NXT1JE|QQVNTV09SR|UkVTRV|JFU0VU|SRVNFV|U0VDVVJF|NFQ1VSR|TRUNVUk|Q09ORklERU5USUFM|NPTkZJREVOVElBT|DT05GSURFTlRJQU'

    $action_sensitiveaction = $logRecord.OperationProperties.Actions -match 'Forward'

    $selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
}

function Test-GraphDelete (
    [Parameter(Mandatory)][object] $logRecord
) {
    $selection_rightevent = $logRecord.Workload -like "Exchange*" -and `
        $logRecord.Operation -eq 'UpdateInboxRules' -and `
        $logRecord.OperationProperties.RuleOperation -in $('Create')
    if (!$selection_rightevent) { return } #Speed up, does not affect result

    $scope_fullscope = $logRecord.OperationProperties.Conditions -eq ''

    $scope_sensitivescope1 = $logRecord.OperationProperties.Conditions -match 'Contains|Subject|Body'
    $scope_sensitivescope2 = $logRecord.OperationProperties.ServerRule -match 'QUNDT1VOV|FDQ09VTl|BQ0NPVU5U|UEFTU1dPUk|BBU1NXT1JE|QQVNTV09SR|UkVTRV|JFU0VU|SRVNFV|U0VDVVJF|NFQ1VSR|TRUNVUk|Q09ORklERU5USUFM|NPTkZJREVOVElBT|DT05GSURFTlRJQU|SEFDS|hBQ0|IQUNL|VklSVV|ZJUlVT|WSVJVU|TUFMV0FSR|1BTFdBUk|NQUxXQVJF'

    $action_sensitiveaction = $logRecord.OperationProperties.Actions -match 'Move|Delete'

    $selection_rightevent -and ($scope_fullscope -or ($scope_sensitivescope1 -and $scope_sensitivescope2)) -and $action_sensitiveaction
}


# Start PRE
$logs = @()
# End PRE

[System.IO.StreamReader]$sr = [System.IO.File]::Open("$PWD/data/$name.raw.json", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
while (-not $sr.EndOfStream){
    $line = $sr.ReadLine()
    $outputLogs = $line | ConvertFrom-Json

    $outputLogs | ForEach-Object {
        # For certain operations and certain attributes, we change the formatting of those attributes for easy reference
        if ($_.Operation -in @("New-InboxRule", "Set-InboxRule")) {
            $newParametersObject = @{}
            foreach ($param in $_.Parameters) {
                $newParametersObject."$($param.Name)" = $param.Value
            }

            $_.Parameters = $newParametersObject
        }

        if ($_.Operation -in @("UpdateInboxRules")) {
            $newOperationPropertiesObject = @{}
            foreach ($param in $_.OperationProperties) {
                $newOperationPropertiesObject."$($param.Name)" = $param.Value
            }

            $_.OperationProperties = $newOperationPropertiesObject
        }

        if (Test-OwaForward $_) {
            Write-Warning "Suspicious mailbox forward OWA"
            Write-Host $_
        }
        if (Test-OwaDelete $_) {
            Write-Warning "Suspicious mailbox rule for deleting through OWA"
            Write-Host $_
        }
        if (Test-OutlookForward $_) {
            Write-Warning "Suspicious mailbox forward Outlook.exe"
            Write-Host $_
        }
        if (Test-OutlookDelete $_) {
            Write-Warning "Suspicious mailbox rule for deleting in Outlook.exe"
            Write-Host $_
        }
        if (Test-GraphForward $_) {
            Write-Warning "Suspicious mailbox forward Graph API"
            Write-Host $_
        }
        if (Test-GraphDelete $_) {
            Write-Warning "Suspicious mailbox rule for deleting Graph API"
            Write-Host $_
        }
    }
    $logs += $filteredLogs
}
$sr.Close()
