REM place me in shell:startup
REM place boot.ps1 and enableonedrive.reg on the desktop
REM copy all env variables to a secrets folder, also on the desktop
REM then, snapshot the VM and only then attach a network card
powershell -Command "Set-ExecutionPolicy -Scope CurrentUser Unrestricted"
powershell %userprofile%/Desktop/boot.ps1