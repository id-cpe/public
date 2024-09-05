function Import-Environment {
    param(
    [ValidateNotNullOrEmpty()][string]$envName = ".env"
    )

    Get-Content ($PSScriptRoot + "/" + $envName) | foreach {
        if ($_.length -gt 0 -and -not $_.StartsWith("#")) {
            $name, $value = $_.split('=',2)
            Set-Content env:\$name $value
        }
    }
}
Export-ModuleMember -Function Import-Environment
