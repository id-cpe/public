# This is a template file to run an attack

$tactic = Read-Host -Prompt "Tactic"
$technique = Read-Host -Prompt "Technique"
$method = Read-Host -Prompt "Method"

$env:AUTO_FIREFOX = $True

$exists = Test-Path -Path "../$tactic - $technique - $method/run.ps1"
if ($exists -eq $False) {
    Write-Error "../$tactic - $technique - $method/run.ps1 does not exist"
    exit
}

$start = Get-Date
Write-Host "Starting at $start..."

Add-Content -Path "./todo.txt" -Value "$start : $tactic - $technique - $method"

& "..\$tactic - $technique - $method\run.ps1"