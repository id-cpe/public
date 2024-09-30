# Intrusion Detection in Cloud Productivity Environments

## About the scripts
This repository contains the scripts that are used in the work. Scripts are located in the `Attacks` subfolder. For each attack method, a specific subfolder is created. The attack methods in the work describe the scripts that are needed; typically there is a `run.ps1` script that simulates the attacker behaviour. If there are other scripts for comparable normal methods or for preparation, they are named differently and the attack method specifies who runs the script.

Scripts are tested on:
- Fedora Linux 39, PowerShell v7.4.5
- Windows 11 23H2 build 22631.2715, PowerShell 5.1.22621.2506

In the work, unless otherwise indicated, a (frozen) virtual machine with the following software was used, both for the victim and for the attacker:
- Windows 11 23H2, build 22631.2715
- Firefox LTS 115.9.1 Extended Support Release
- Git for Windows 2.44.0.windows.1
- Microsoft Office Monthly Enterprise Channel, version 2402¹

¹ Only used for specific attacks, OneDrive's automatic start was disabled

On boot of the machine, the `aa_start.bat` script runs.

A VPN is used for all traffic of the virtual machine. A Canadian VPN provider was used with four locations in Amsterdam. One location was exclusively used for traffic by the 'attacker'; another location was exclusively used by the 'victim'. The VPN service runs outside of the virtual machine, except in the case of the Windows server.

## About the data
Outputted logs are located in the `Data` subfolder. Both the `.json` and the `.raw.json` files are created using the `collectData.ps1` script and use the Office 365 Management APIs.

The script downloads the data for a specific time period to the `.raw.json` file. This file contains outputs as they were received from Microsoft and data there was not altered. It is important to note the boundaries of these time periods are not exact; sometimes the APIs return more or slightly less data.

The output in the `.json` files is filtered. 
- For recognisiability when looking at the data, the script changes maps the IP addresses to either `192.0.2.0/24` (victim) and `198.51.100.0/24` (attacker). Public IP addresses belonging to Microsoft or located in the same datacenter as Microsoft are not replaced. No other IP addresses are present in the `.json` files.
- For recognisability, the tenant ID is replaced with a fixed string and UPNs are also replaced with a non-existing domain.
- Time is shifted such that the start of a test is always marked by the data 1999-12-31T00:00:00. If data before that point was present in the generated `.json`, it was manually inspected before being removed, to avoid mistakes. This maximum time difference is bound by the time period used for obtaining the raw data. 

## Operationalisation
As part of the findings, a small study was done on data in a production environment. That data is not included here. The scripts used to collect the data for a 24-hour period (`collectPathData.ps1`), used to summarise the data (`runStats.ps1`), and to filter the data for relevant events (`getSpecificEvents.ps1`) are included. 

## Included work

### Exchange Web Services
To interact with Exchange Web Services, in [`connect-EWS.ps1`](https://github.com/rinkp/id-cpe/blob/main/Attacks/APIs/connect-EWS.psm1#L11), we have included a binary made for that purpose from [O365-InvestigationTooling](https://github.com/OfficeDev/O365-InvestigationTooling/blob/fa42eed8f0f1548743225786662385d8cd45f18e/Get-AllTenantRulesAndForms.ps1#L96).

Authors: [Microsoft Corporation](https://github.com/OfficeDev), [Brandon Koeller](https://github.com/bkoeller), [Will Schroeder](https://github.com/harmj0y), and [Matt Graeber](https://github.com/mattifestation)<br/>
License: [MIT](https://github.com/OfficeDev/ews-managed-api/blob/25a393dbc68b420d25999bdf0a03c23d86412f57/license.txt) (original), [MIT](https://github.com/OfficeDev/O365-InvestigationTooling/blob/fa42eed8f0f1548743225786662385d8cd45f18e/LICENSE) (modifications)<br/>
Available from: [https://github.com/OfficeDev/O365-InvestigationTooling/blob/fa42eed8f0f1548743225786662385d8cd45f18e/Get-AllTenantRulesAndForms.ps1#L96](https://github.com/OfficeDev/O365-InvestigationTooling/blob/fa42eed8f0f1548743225786662385d8cd45f18e/Get-AllTenantRulesAndForms.ps1#L96)

### SMTP Console
For T1078.002, to implement SMTP using STARTTLS, we make use of `SMTPConsole.exe` version 1.0.1.0. 

Authors: [SocketLabs](https://github.com/socketlabs), [Bill Volz](https://github.com/BillVolz)<br/>
Available from: [https://download.socketlabs.com/smtpconsole.zip](https://download.socketlabs.com/smtpconsole.zip)<br/>
License: SocketLabs, all rights reserved

### SharePoint Online Client Components SDK
To implement the authentication for the listdata.svc endpoint, we make use of existing redistributable SharePoint DLLs. These can be extracted using msiextract from the `sharepointclientcomponents_16-6906-1200_x64-en-us.msi` file.

Authors: [Microsoft Corporation](https://microsoft.com)<br/>
Available from: [https://www.microsoft.com/en-us/download/details.aspx?id=42038](https://www.microsoft.com/en-us/download/details.aspx?id=42038)<br/>
License: [MicrosoftSharePointClientComponentsEULA](https://go.microsoft.com/fwlink/?LinkId=280198) (also included as MicrosoftSharePointClientComponentsEULA.docx)

### AADInternals
For some attacks we make use of the AADInternals PowerShell module v0.9.3 that can be used for administering Azure AD and Office 365.

Authors: [Gerenios Ltd.](https://gerenios.com) / [dr. Nestori Syynimaa](https://github.com/NestoriSyynimaa)<br/>
Available from: [https://github.com/Gerenios/AADInternals](https://github.com/Gerenios/AADInternals)<br/>
License: [MIT](https://github.com/Gerenios/AADInternals/blob/4b4ec88a16ff3af2cc35e87977fb0fa6fe5cba79/LICENSE.md)

### OpenSSL
For some attacks we make use of OpenSSL v3.3.1 that can be used for various asymmetric encryption operations

Authors: [OpenSSL Software Foundation, Inc. and others](https://github.com/openssl/openssl/blob/af403db090ee66715e81f0062d1ef614e8d921b5/AUTHORS.md) (source) and [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html) (Windows)<br/>
Available from: [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)<br/>
License: [Apache 2.0](https://github.com/openssl/openssl/blob/036cbb6bbf30955abdcffaf6e52cd926d8d8ee75/LICENSE.txt)

### powershell-aes
For an attack where we encrypt files, we use the `67241cc` commit of powershell-aes.

Authors: [Jimmy Lin](https://github.com/mnghsn)<br/>
Available from: [https://github.com/mnghsn/powershell-aes/tree/67241cc](https://github.com/mnghsn/powershell-aes/tree/67241cc)<br/>
License: [MIT](https://github.com/mnghsn/powershell-aes/blob/67241ccf60aaaab2f59d159e6890c4d462656574/LICENSE.md)

### IP address lookup
To verify whether an IP address is in use by Microsoft, a call to `https://ip.ward.nl/{ip}` is made in `collectData.ps1`. At the time of writing, this service is available for free without authentication and replies relatively fast. Other services that lookup the organisation name and postal code for an IP address are available as well and can be used in its place.

If you wish to avoid third parties, it is possible to lookup IP addresses through the web interface of right Regional Internet registry. When using the `whois` command for large number of IP addresses, rate limiting may occur. 

- AFRINIC ([https://afrinic.net/whois-web/public/?lang=en](https://afrinic.net/whois-web/public/?lang=en))
- ARIN ([https://search.arin.net/rdap/](https://search.arin.net/rdap/))
- APNIC ([https://wq.apnic.net/static/search.html](https://wq.apnic.net/static/search.html))
- LACNIC ([https://query.milacnic.lacnic.net/search](https://query.milacnic.lacnic.net/search))
- RIPE NCC ([https://apps.db.ripe.net/db-web-ui/query](https://apps.db.ripe.net/db-web-ui/query))

## Notable changes to the tenant
### Power Automate / Azure API Hub
In order to manually invoke a Power Automate Flow, you need to obtain an access token for Azure API Hub. By default, it is not possible to add these permissions to custom applications and it requires a service principal. See also [a similar question on Microsoft Learn Q&A](https://learn.microsoft.com/en-us/answers/questions/1409369/could-not-grant-admin-consent-your-organization-do).

As a global administrator (or other administrator with similar permissions), using Microsoft Graph with a token with the following scopes: `Application.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, and `ServicePrincipalEndpoint.ReadWrite.All`, do a POST to `https://graph.microsoft.com/v1.0/servicePrincipals` with the following body:

```json
{
    "appId": "fe053c5f-3692-4f14-aef2-ee34fc081cae"
}
```
