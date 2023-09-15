$directoryEntry = [ADSI]"LDAP://security.local"
$searcher = [System.DirectoryServices.DirectorySearcher]$directoryEntry
$searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$searcher.PropertiesToLoad.AddRange(@("dnshostname", "operatingSystem"))
$computers = $searcher.FindAll() | Where-Object { $_.Properties["dnshostname"][0]-notmatch "$env:COMPUTERNAME.$env:USERDNSDOMAIN" }
$Command = "whoami"

# Create a runspace pool
$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
$runspacePool.Open()

# Create an array to hold the runspaces
$runspaces = @()

# Function to check if a runspace is completed and collect its result
function Collect-RunspaceResult($runspace) {
    if ($runspace.Pipe.IsCompleted) {
        $result = $runspace.Pipe.EndInvoke($runspace.Status)
        $runspace.Pipe.Dispose()
        $allResults += $result
        $runspace.Completed = $true
    }
}

# Iterate through the computers, creating a runspace for each
foreach ($computer in $computers) {
$ComputerName = $computer.Properties["dnshostname"][0]
$OS = $computer.Properties["operatingSystem"][0]

        $OS = $computer.Properties["operatingSystem"][0]
        $ComputerName = $computer.Properties["dnshostname"][0]

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($ComputerName, 5985, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)

        if (!$wait) {return}
            else {

try {
    $AuthAttempt = New-PSSession -ComputerName $ComputerName -ErrorAction "Stop"
} catch {
    # Check if the error message contains "Access is denied"
    if ($_.Exception.Message -match "Access is denied") {
        
        # Handle the "Access is denied" error
                    
                    Write-Host "WinRM " -ForegroundColor Yellow -NoNewline
                    Write-Host "   " -NoNewline
                    try {$Ping = New-Object System.Net.NetworkInformation.Ping
                    $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
                    Write-Host ("{0,-16}" -f $IP) -NoNewline}
                    catch { Write-Host ("{0,-16}" -f "") -NoNewline}
                    Write-Host "   " -NoNewline
                    Write-Host $ComputerName -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host $OS -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host "[-] " -ForegroundColor Red -NoNewline
                    Write-Host "ACCESS DENIED "
                    continue
    } else {
        
        # Handle other errors
                    Write-Host "WinRM " -ForegroundColor Yellow -NoNewline
                    Write-Host "   " -NoNewline
                    try {$Ping = New-Object System.Net.NetworkInformation.Ping
                    $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
                    Write-Host ("{0,-16}" -f $IP) -NoNewline}
                    catch { Write-Host ("{0,-16}" -f "") -NoNewline}
                    Write-Host "   " -NoNewline
                    Write-Host $ComputerName -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host $OS -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host "[-] " -ForegroundColor Red -NoNewline
                    Write-Host "Unspecified Error "      
        }
    }
}
 
 if ($Command -eq ""){

                    Write-Host "WinRM " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "   " -NoNewline
                    try {$Ping = New-Object System.Net.NetworkInformation.Ping
                    $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
                    Write-Host ("{0,-16}" -f $IP) -NoNewline}
                    catch { Write-Host ("{0,-16}" -f "") -NoNewline}
                    Write-Host "   " -NoNewline
                    Write-Host $ComputerName -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host $OS -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host "[+] " -ForegroundColor Green -NoNewline
                    Write-Host "SUCCESS"

 }

 else{
    
    # ScriptBlock that contains the processing code
    $scriptBlock = {
        param($computer, $Command)

        $OS = $computer.Properties["operatingSystem"][0]
        $ComputerName = $computer.Properties["dnshostname"][0]

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($ComputerName, 5985, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)

        if (!$wait) {
            $result = $null  # No result
        } elseif ($wait) {
            try {
                $tcpClient.EndConnect($asyncResult)
                $tcpClient.Close()
            } catch {}
            $Session = New-PSSession -ComputerName $ComputerName -ErrorAction "Ignore"
            $b = Invoke-Command -Session $Session {IEX $Using:Command} -ErrorAction "Ignore"

            try {
                $Ping = New-Object System.Net.NetworkInformation.Ping
                $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
            } catch {
                $IP = ""
            }
        }

        # Output the result
        $b

        # Remove the session
        Remove-PSSession -Session $Session
    }
        # Create a PowerShell runspace
    $runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($computer).AddArgument($Command)
    $runspace.RunspacePool = $runspacePool
    $runspaces += [PSCustomObject]@{
        Pipe = $runspace
        Status = $runspace.BeginInvoke()
        Completed = $false
        
        }
    }
}

# Monitor the runspaces for completion and collect results
while ($runspaces.Count -gt 0) {
    foreach ($runspace in $runspaces) {
        if (!$runspace.Completed) {
            Collect-RunspaceResult $runspace
        }
    }
    $runspaces = $runspaces | Where-Object { !$_.Completed }
    Start-Sleep -Milliseconds 100  # Optional: Add a small delay to avoid high CPU usage
}

# Close the runspace pool
$runspacePool.Close()
$runspacePool.Dispose()

# Output all results
$allResults | ForEach-Object {
                    
                    Write-Host "WinRM " -ForegroundColor "Yellow" -NoNewline
                    Write-Host "   " -NoNewline
                    try {$Ping = New-Object System.Net.NetworkInformation.Ping
                    $IP = $($Ping.Send("$ComputerName").Address).IPAddressToString
                    Write-Host ("{0,-16}" -f $IP) -NoNewline}
                    catch { Write-Host ("{0,-16}" -f "") -NoNewline}
                    Write-Host "   " -NoNewline
                    Write-Host $ComputerName -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host $OS -NoNewline
                    Write-Host "   " -NoNewline
                    Write-Host "[+] " -ForegroundColor Green -NoNewline
                    Write-Host "SUCCESS"
    Write-Host $_
}
