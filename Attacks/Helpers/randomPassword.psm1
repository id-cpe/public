function Create-OKPassword {
    do {
        $userPassword = -join ((35..38) + (33)+(42)+(43)+(48..57)+(61)+(63..90)+(97..122) | Get-Random -Count 12 | % {[char]$_})
    } until ( $userPassword -cmatch '\d' -and $userPassword -cmatch '[a-z]' -and $userPassword -cmatch '[A-Z]' -and $userPassword -cmatch '[$@#%!]')
    $userPassword
}
Export-ModuleMember -Function Create-OKPassword