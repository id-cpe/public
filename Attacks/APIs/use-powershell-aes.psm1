$Script:AESImport = $False

function Import-PsAES {
    param(
    [ValidateNotNullOrEmpty()][string]$version = "3.3.1"
    )

    $Script:AESImport = $True

    $version = $version.Replace(".", "_")

    New-Item -ItemType Directory -Path "$PSScriptRoot\AES\" -Force | Out-Null
    Invoke-WebRequest "https://raw.githubusercontent.com/mnghsn/powershell-aes/67241ccf60aaaab2f59d159e6890c4d462656574/Scripts/New-AesKey.ps1" -OutFile "$PSScriptRoot\AES\New-AesKey.ps1"
    Invoke-WebRequest "https://raw.githubusercontent.com/mnghsn/powershell-aes/67241ccf60aaaab2f59d159e6890c4d462656574/Scripts/Protect-AesFile.ps1" -OutFile "$PSScriptRoot\AES\Protect-AesFile.ps1"
    Invoke-WebRequest "https://raw.githubusercontent.com/mnghsn/powershell-aes/67241ccf60aaaab2f59d159e6890c4d462656574/Scripts/Unprotect-AesFile.ps1" -OutFile "$PSScriptRoot\AES\Unprotect-AesFile.ps1"
}
Export-ModuleMember -Function Import-PsAES

function ConvertTo-ArgString {
    param(
    [AllowEmptyCollection()][string[]]$argArray
    )
    
    $output = ""
    $i = 0
    foreach ($arg in $argArray) {
        if ($i % 2 -eq 0) {
            $output += $arg + " "
        } else {
            $output += "`"$arg`"" + " "
        }
        $i += 1
    }
    return $output
}

function New-AesKey {
    $argString = ConvertTo-ArgString -argArray $args
    Invoke-Expression ". `"$PSScriptRoot\AES\New-AesKey.ps1`" $argString"
}
Export-ModuleMember -Function New-AesKey

function Protect-AesFile {
    $argString = ConvertTo-ArgString -argArray $args
    Invoke-Expression ". `"$PSScriptRoot\AES\Protect-AesFile.ps1`" $argString"
}
Export-ModuleMember -Function Protect-AesFile

function Unprotect-AesFile {
    $argString = ConvertTo-ArgString -argArray $args
    Invoke-Expression ". `"$PSScriptRoot\AES\Unprotect-AesFile.ps1`" $argString"
}
Export-ModuleMember -Function Unprotect-AesFile