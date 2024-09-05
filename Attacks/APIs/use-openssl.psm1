#Requires -RunAsAdministrator

function Install-OpenSSL {
    param(
    [ValidateNotNullOrEmpty()][string]$version = "3.0.14"
    )

    $version = $version.Replace(".", "_")

    Invoke-WebRequest "https://slproweb.com/download/Win64OpenSSL_Light-$version.msi" -OutFile "$PSScriptRoot/openssl-$version.msi"

    Start-Process msiexec.exe -Wait -ArgumentList "/i `"$PSScriptRoot\openssl-$version.msi`"  /passive"

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}
Export-ModuleMember -Function Install-OpenSSL

function Get-OpenSSLPath {
    if ($isLinux) {
        $global:opensslpath = "openssl"
    } else {
        Install-OpenSSL
        $global:opensslpath = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    }

    $global:opensslpath
}
Export-ModuleMember -Function Get-OpenSSLPath