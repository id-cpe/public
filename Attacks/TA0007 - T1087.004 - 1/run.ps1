<#
.SYNOPSIS
Use AADInternals to discover whether a user account exists

.DESCRIPTION
TA0007: Discovery
T1087.004: Account Discovery - Cloud Account
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1

# We use the ews environment variables
Import-Environment "graph.env"

# We make use of AADInternals
Get-Module | Where-Object name -eq use-aadtools | Remove-Module -Verbose
Import-Module ../APIs/use-aadtools.psm1

Invoke-AADIntUserEnumerationAsOutsider -UserName "user@$env:TENANT_ID" -Method Normal
Invoke-AADIntUserEnumerationAsOutsider -UserName "administrator@$env:TENANT_ID" -Method Normal