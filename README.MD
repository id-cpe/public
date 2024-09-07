# Intrusion Detection in Cloud Productivity Environments

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
For an attack where we encrypt files, we use the 67241cc commit of PowerShell.

Authors: [Jimmy Lin](https://github.com/mnghsn)
Available from: [https://github.com/mnghsn/powershell-aes/tree/67241cc](https://github.com/mnghsn/powershell-aes/tree/67241cc)
License: [MIT](https://github.com/mnghsn/powershell-aes/blob/67241ccf60aaaab2f59d159e6890c4d462656574/LICENSE.md)

## Notable changes to the tenant
### Power Automate / Azure API Hub
In order to manually invoke a Power Automate Flow, you need to obtain an access token for Azure API Hub. By default, it is not possible to add these permissions to custom applications and it requires a service principal. See also [a similar question on Microsoft Learn Q&A](https://learn.microsoft.com/en-us/answers/questions/1409369/could-not-grant-admin-consent-your-organization-do).

As a global administrator (or other administrator with similar permissions), using Microsoft Graph with a token with the following scopes: `Application.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, and `ServicePrincipalEndpoint.ReadWrite.All`, do a POST to `https://graph.microsoft.com/v1.0/servicePrincipals` with the following body:

```json
{
    "appId": "fe053c5f-3692-4f14-aef2-ee34fc081cae"
}
```
