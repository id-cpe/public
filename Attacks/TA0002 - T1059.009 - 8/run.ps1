<#
.SYNOPSIS
Connect to EWS, create a subfolder of the inbox, and delete it again

.DESCRIPTION
TA0002: Execution
T1059.009: Cloud API
8th attack method
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
if ($null -eq $accessToken) { $accessToken = Get-DelegatedAccessToken -tenantId $env:TENANT_ID -clientId $env:EWS_DELEGATE_CLIENT_ID -scope $scope -redirectUrl $env:EWS_DELEGATE_REDIRECT_URI }

$exchService = Connect-EWSService -accessToken $accessToken

# Alternatively, we can also run this with a client grant instead of delegated credentials
# That allows us to impersonate any user
# $exchService = Connect-EWSService -impersonate -clientId $env:EWS_IMPERSONATE_CLIENT_ID -clientSecret $env:EWS_IMPERSONATE_CLIENT_SECRET -tenantId $env:TENANT_ID -upn $env:VICTIM_UPN

$folderName = "TA0002 - T1059.009 - 8 - $(Get-Random -Minimum 1000 -Maximum 9999)"

$folderView = New-Object Microsoft.Exchange.WebServices.Data.FolderView(100)
$folders = $exchService.FindFolders([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot,$folderView)
$folders | Select-Object DisplayName, FolderClass, UnreadCount | Format-Table

$itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView(100)
$inbox = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox
# $messages = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchService, $inbox)
#$messages = $exchService.FindItems($inbox, $itemView)
#$messages | Format-List

$conflictingFolders = $exchService.FindFolders($inbox,$folderView) | Where-Object { $_.DisplayName -eq $folderName }
if ($conflictingFolders.Count -gt 0) {
    Write-Warning "Conflicting folders found, save operation will fail"
}

$newFolder = New-Object Microsoft.Exchange.WebServices.Data.Folder($exchService)
$newFolder.DisplayName = $folderName
$newFolder.Save($inbox)

# Now we want to look for the folder again in order to delete is
$folders = $exchService.FindFolders($inbox,$folderView)
$toBeDeleted = $folders | Where-Object { $_.DisplayName -eq $folderName }

# Delete modes are MoveToDeletedItems, HardDelete, SoftDelete.
# Both Move and Delete with MoveToDeletedItems work, neither works if the destination folder exists already
$deletedItemsFolder = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::DeletedItems

$conflictingFolders = $exchService.FindFolders($deletedItemsFolder,$folderView) | Where-Object { $_.DisplayName -eq $folderName }
if ($conflictingFolders.Count -gt 0) {
    Write-Warning "Conflicting folders found, delete operation will fail"
}

foreach ($deleteFolder in $toBeDeleted) {
    $deleteFolder.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::MoveToDeletedItems)
    #$deleteFolder.Move($deletedItemsFolder)
}