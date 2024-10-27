<#
.SYNOPSIS
For a 1 day export, compute certain statistics.

.DESCRIPTION
Given a 1 day export (such as the `collectBatchData.ps1` output), comput certain statistics that are useful to include as general information on the dataset
#>

# https://stackoverflow.com/a/78683824/6367506
function Get-Sha256Hash (
    [Parameter(Mandatory)][string] $string
) {
    $stream = [IO.MemoryStream]::new([byte[]][char[]]$string)
    (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash
}

function Get-Actor (
    [Parameter(Mandatory, ValueFromPipeline)][object] $log
) {

    # If it was system or an application, there is no human-actor so we do not count this for statistics
    if ($log.UserType -eq 3) { # Microsoft (not a partner, Microsoft)
        return $null
    }
    if ($log.UserType -eq 4) { #system
        return $null
    }
    if ($log.UserType -eq 5) { #app-only auth
        return $null
    }
    if ($log.UserType -eq 6) { #service principal
        return $null
    }

    # Microsoft exceptions that use the wrong usertype
    if ($log.UserType -eq 0 -and $log.UserId -in @("fim support service","SHAREPOINT\system", "Microsoft\ServiceAccount", "app@sharepoint")) {
        return $null
    }

    # Exceptions where the action is performed by an unknown admin
    if ($log.UserType -eq 2 -and $log.UserId -in @("S-1-5-18")) {
        return $null
    }

    # When a partner technician cannot sign in, we do not know who this is
    if ($log.UserType -eq 9 -and $log.Operation -eq "UserLoginFailed") {
        return $null
    }

    # The general case wher ean admin is signed in and we know their email
    if ($log.UserType -in @(0,2) -and $log.UserId -like "*@*") {
        return $log.UserId
    }

    # the userid is not a upn, we can count them as unique interactive user for a specific operation, but not globally
    if ($log.UserType -in @(0,2) -and $log.UserId -eq $log.UserKey) {
        return $log.UserId
    }

    # In rare instances we get a 16 character classic ID, this is also not a UPN so we can only use this if we do a per-operation count
    if ($log.UserType -in @(0,2) -and $log.UserKey.Length -eq 16) {
        return $log.UserKey
    }

    Write-Host $log
    exit 0
}


$day = Read-Host -Prompt "Day yyyy-MM-dd"
$day = (Get-Date $day -Hour 0 -Minute 0 -Second 0 -Millisecond 0)
$dateF = Get-Date $day -Format "yyyy-MM-dd HH.mm.ss"

# Start PRE
$operationCount = @{}
$operationUsers = @{}
$allUsers = New-Object System.Collections.Generic.List[System.String]
# End PRE

[System.IO.StreamReader]$sr = [System.IO.File]::Open("$PWD/data/$dateF.raw.json", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
while (-not $sr.EndOfStream){
    $line = $sr.ReadLine()
    $outputLogs = $line | ConvertFrom-Json

    $outputLogs | ForEach-Object {
        # Start FOREACH
        # Increase or create if not exist
        $operationCount[$_.Workload + ";" + $_.Operation] += 1
        $actor = Get-Actor $_
        if ($null -ne $actor) {
            $actorHash = Get-Sha256Hash $actor
            if (!$operationUsers.ContainsKey($_.Workload + ";" + $_.Operation)) {
                $operationUsers[$_.Workload + ";" + $_.Operation] = New-Object System.Collections.Generic.List[System.String]
            }
            if ($null -ne $actor -and $actor -notin $operationUsers[$_.Workload + ";" + $_.Operation]) {
                $operationUsers[$_.Workload + ";" + $_.Operation].Add($actor)
                #Write-Host $operationUsers[$_.Workload + ";" + $_.Operation]
            }
            if ($null -ne $actor -and $actor -like "*@*" -and $actorHash -notin $allUsers) {
                $allUsers.Add($actorHash)
            }
        }
        # End FOREACH
    }
}
$sr.Close()


# Give a small summary
$allUsers -join "`r`n" | Out-File "$PWD/data/$dateF.allusers.txt"
"Workload;Operation;Count;UniqueUserCount" | Out-File "$PWD/data/$dateF.summary.txt"
$operationCount.keys | Foreach-Object {
    "$_;$($operationCount[$_]);$($operationUsers[$_].Count)" | Out-File "$PWD/data/$dateF.summary.txt" -Append
}