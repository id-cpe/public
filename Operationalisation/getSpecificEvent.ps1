<#
.SYNOPSIS
From exported data, extract specific events and format them

.DESCRIPTION
As input, takes log output (e.g. collectBatchData.ps1) and formats a specific Operation
#>

$day = Read-Host -Prompt "Day yyyy-MM-dd"
$day = (Get-Date $day -Hour 0 -Minute 0 -Second 0 -Millisecond 0)
$dateF = Get-Date $day -Format "yyyy-MM-dd HH.mm.ss"

# Start PRE
$operationNames = Read-Host -Prompt "Operation names"
# we have a default for our experiment
if ($operationNames -eq "") { $operationNames = "New-InboxRule,Set-InboxRule,Remove-InboxRule,UpdateInboxRules" }
$operationNameList = $operationNames -split ","
$logs = @()
# End PRE

[System.IO.StreamReader]$sr = [System.IO.File]::Open("$PWD/data/$dateF.raw.json", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
while (-not $sr.EndOfStream){
    $line = $sr.ReadLine()
    $outputLogs = $line | ConvertFrom-Json

    $filteredLogs = $outputLogs | Where-Object { $_.Operation -in $operationNameList } 
    $logs += $filteredLogs
}
$sr.Close()


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

#Write-Host $logs
($logs | ConvertTo-Json -Depth 10) | Format-Json | Out-File "$PWD/data/$dateF-$operationNames.json"
