Get-Module | Where-Object name -eq oauth-microsoft | Remove-Module
Import-Module $PSScriptRoot/oauth-microsoft.psm1
