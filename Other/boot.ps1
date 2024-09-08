sleep 5
if ((Get-NetIPAddress | Where-Object IPAddress -like 10.138.*).IPAddress.Count -gt 0) {
    Set-MpPreference -DisableRealtimeMonitoring $True
    reg import .\enableonedrive.reg
    $count = 0
    do {
        $count = $count + 1
        $ping = Get-CimInstance -ClassName Win32_PingStatus -Filter "Address='github.com' AND Timeout=1000";
        sleep 2
        Write-Host -NoNewLine "`rWaiting for connection ($count)..."
    } until ($ping.StatusCode -eq 0) 
    Write-Host
    Set-Location $HOME/Desktop
    git clone git@github.com:id-cpe/private --single-branch --depth=1 id-cpe
    robocopy /E /copyall secrets id-cpe
}