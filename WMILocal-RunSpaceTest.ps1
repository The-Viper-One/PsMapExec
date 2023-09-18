$directoryEntry = [ADSI]"LDAP://security.local"
$searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.PropertiesToLoad.AddRange(@("dnshostname", "operatingSystem"))
$computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }
$Command = "hostname"
$LocalAuth = $true

$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
$runspacePool.Open()
$runspaces = New-Object System.Collections.ArrayList


$scriptBlock = {
    param ($computerName, $Command, $Username, $Password, $LocalAuth)

    Function LocalWMI {

param (
    [string]$Command = "ipconfig",
    [string]$Username = "",
    [string]$Password = "",
    [string]$ComputerName = "",
    [switch]$LocalAuth = $true,
    [string]$Class = "PMEClass"
)


$LocalUsername = "$ComputerName\$UserName"
$LocalPassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($LocalUsername,$LocalPassword)


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
return $result
}



if ($LocalAuth){
$wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"  -Credential $cred
Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName  -Credential $cred
}

elseif (!$LocalAuth){
$wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"
Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName
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
    

    # Start non-local WMI
        Function WMI {

param (
  [string]$Command,
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
    return $result
    $wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"
    Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName | Out-Null
    

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
    try {
        $Ping = New-Object System.Net.NetworkInformation.Ping
        $IP = $($Ping.Send($ComputerName).Address).IPAddressToString
        Write-Host ("{0,-16}" -f $IP) -NoNewline
    } catch {
        Write-Host ("{0,-16}" -f "") -NoNewline
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

# Create and invoke runspaces for each computer
foreach ($computer in $computers) {
    $ComputerName = $computer.Properties["dnshostname"][0]
    $OS = $computer.Properties["operatingSystem"][0]

    $tcpClient = New-Object System.Net.Sockets.TcpClient -ErrorAction SilentlyContinue
    $asyncResult = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
    $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)
    
    if ($wait) { 
        try {
            $tcpClient.EndConnect($asyncResult)
            $tcpClient.Close()
        } catch {}

        if ($LocalAuth) {
            $LocalUsername = "$ComputerName\$UserName"
            $LocalPassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($LocalUsername, $LocalPassword)
            $osInfo = $null 

            # OSinfo
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Cred
            if (!$osInfo) {
                Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                continue
            }
        } else {
            $osInfo = $null
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
            if ($osInfo) {
                Display-ComputerStatus -ComputerName $ComputerName -OS $OS -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
                continue
            }
        }

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
}



# Poll the runspaces and display results as they complete
do {
    foreach ($runspace in $runspaces | Where-Object {-not $_.Completed}) {
        if ($runspace.Handle.IsCompleted) {
            $runspace.Completed = $true
            $result = $runspace.Runspace.EndInvoke($runspace.Handle)
            
            if ($result -eq "Access Denied"){

            Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ACCESS DENIED" -NameLength $NameLength -OSLength $OSLength
            continue

}
            elseif ($result -eq "Unspecified Error"){

            Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor "Red" -statusSymbol "[-] " -statusText "ERROR" -NameLength $NameLength -OSLength $OSLength
            continue

}
            elseif ($result) {
            
            Display-ComputerStatus -ComputerName $($runspace.ComputerName) -OS $($runspace.OS) -statusColor Green -statusSymbol "[+] " -statusText "SUCCESS" -NameLength $NameLength -OSLength $OSLength
            $result | Write-Host 
            
            }

        }
    }
    Start-Sleep -Milliseconds 100
} while ($runspaces | Where-Object {-not $_.Completed})

# Clean up
$runspacePool.Close()
$runspacePool.Dispose()

