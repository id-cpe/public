function Get-ClientAccessToken {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$tenantId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$clientId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$clientSecret,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$scope
    )

    $RequestBody = @{
        client_id=$clientId;
        client_secret=$clientSecret;
        grant_type="client_credentials";
        scope=$scope;
    }
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $RequestBody
    $accessToken = $response.access_token
    $accessToken
}
Export-ModuleMember -Function Get-ClientAccessToken

function Get-DelegatedAccessToken {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$tenantId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$clientId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$redirectUrl,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$scope,
        [string]$responseMode = "query",
        [switch]$refreshToken,
        [switch]$codeOnly,
        [switch]$includeIdToken
    )

    if ($includeIdToken) {
        $responseType = "code id_token";
    } else {
        $responseType = "code";
    }

    $url = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize?client_id=$clientId&response_type=" + 
        [URI]::EscapeUriString($responseType) + "&redirect_uri=" +
        [URI]::EscapeUriString($redirectUrl) + "&response_mode=$responseMode&scope=" +
        [URI]::EscapeUriString($scope) + "&prompt=select_account"

    if ($env:AUTO_FIREFOX -and -not $isLinux) {
        & 'C:\Program Files\Mozilla Firefox\firefox.exe' -foreground -url $url
    }
    Write-Warning $url

    # In Linux multi-line read-hosts are very slow:
    $prompt = "Return URL (" + $redirectUrl + "?code=xxxx)"
    if ($isLinux -or $isMacOS) {        
        Write-Host -NoNewLine ($prompt + ": ")
        $returnURL = [Console]::ReadLine()
    } else {
        $returnURL = Read-Host -Prompt $prompt
    }

    $code = ($returnURL -split "code=")[1].Split("&")[0]

    if ($codeOnly) {
        return $code
    }

    if ($refreshToken) {
        $scope = $scope.split(" ")[0] + " offline_access";
    }

    $RequestBody = @{
        client_id=$clientId;
        code=$code;
        redirect_uri=$redirectUrl;
        grant_type="authorization_code";
        scope=$scope;
    }
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $RequestBody

    if ($refreshToken) {
        $accessToken = $response.refresh_token
    } else {
        $accessToken = $response.access_token
    }
    $accessToken
}
Export-ModuleMember -Function Get-DelegatedAccessToken

function Get-SAMLAccessToken {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$tenantId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$SAMLToken,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$clientId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$scope
    )

    $encodedSamlToken= [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SAMLToken))

    $RequestBody = @{
        client_id=$clientId;
        code=$code;
        grant_type="urn:ietf:params:oauth:grant-type:saml1_1-bearer";
        assertion=$encodedSamlToken;
        scope=$scope;
    }
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $RequestBody

    if ($refreshToken) {
        $accessToken = $response.refresh_token
    } else {
        $accessToken = $response.access_token
    }
    $accessToken
}
Export-ModuleMember -Function Get-SAMLAccessToken

function Get-AccessTokenFromRefreshToken {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$tenantId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$refreshToken,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$clientId,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()][string]$scope
    )

    $RequestBody = @{
        client_id=$clientId;
        refresh_token=$refreshToken;
        grant_type="refresh_token";
        scope=$scope;
    }
    # OIDC standard says we should now switch to using the new refresh token, but for our use cases it suffices to keep using the old one
    $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $RequestBody
    $accessToken = $response.access_token
    $accessToken
}
Export-ModuleMember -Function Get-AccessTokenFromRefreshToken