# Check for admin rights
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Administrator privileges required. Please restart as admin."
    Exit
}

# Create timestamped folder
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$destinationFolder = "C:\Collection_$timestamp"
$zipFilePath = "$destinationFolder.zip"

# Create the destination folder if it doesn't exist
if (-Not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder
}

# VSS snapshot creation and management
$shadow = $null
try {
    Write-Output "Creating VSS snapshot..."
    $shadow = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
    Start-Sleep -Seconds 2
    
    if ($shadow.ShadowID) {
        $shadowPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" + $shadow.ShadowID.Substring(1,8) + "\"
        Write-Output "Shadow copy created successfully at: $shadowPath"
        
        # Registry hives collection
        $registryPath = Join-Path $destinationFolder "Registry"
        New-Item -ItemType Directory -Path $registryPath -Force
        
        # System Registry Hives with full paths
        $registryFiles = @(
            @{Path="HKLM\SAM"; Name="SAM"}
            @{Path="HKLM\SECURITY"; Name="SECURITY"}
            @{Path="HKLM\SOFTWARE"; Name="SOFTWARE"}
            @{Path="HKLM\SYSTEM"; Name="SYSTEM"}
            @{Path="HKCU"; Name="NTUSER"}
            @{Path="HKCU\Software\Classes"; Name="USRCLASS"}

        )
        
        # Save system registry hives using reg save
        foreach ($file in $registryFiles) {
            try {
                $backupPath = Join-Path $env:TEMP "$($file.Name).bak"
                $regSaveCommand = "reg save `"$($file.Path)`" `"$backupPath`" /y"
                Write-Output "Saving $($file.Path) to $backupPath"
                Invoke-Expression $regSaveCommand
                
                if (Test-Path $backupPath) {
                    $destination = Join-Path $registryPath $file.Name
                    Copy-Item -Path $backupPath -Destination $destination -Force
                    Remove-Item -Path $backupPath -Force
                    Write-Output "Successfully saved and copied: $($file.Path)"
                } else {
                    Write-Error "Failed to save registry hive $($file.Path)"
                }
            } catch {
                Write-Error "Failed to save registry hive $($file.Path): $_"
            }
        
        
        }
    } else {
        Write-Error "Failed to create shadow copy"
    }
} catch {
    Write-Error "VSS operation failed: $_"
} finally {
    if ($shadow) {
        $shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
        $shadowObj.Delete()
    }
}

# Collect event logs
$eventLogPath = Join-Path $destinationFolder "EventLogs"
New-Item -ItemType Directory -Path $eventLogPath -Force

# Export active logs
$eventLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 }
foreach ($log in $eventLogs) {
    try {
        $logName = $log.LogName
        $sanitizedName = $logName -replace '[\\/:*?"<>|]', '_'
        wevtutil export-log $logName "$eventLogPath\$sanitizedName.evtx" /ow
    } catch {
        Write-Error "Failed to export log $logName : $_"
    }
}

# Direct copy from Windows Event Logs folder
$eventLogSource = "$env:SystemRoot\System32\winevt\Logs"
if (Test-Path $eventLogSource) {
    try {
        $result = Start-Process robocopy -ArgumentList "`"$eventLogSource`" `"$eventLogPath`" *.evtx /ZB /COPY:DAT /R:1 /W:1" -NoNewWindow -Wait -PassThru
        if ($result.ExitCode -gt 7) {
            Write-Error "Robocopy failed with exit code $($result.ExitCode)"
        }
    } catch {
        Write-Error "Failed to copy event logs using robocopy: $_"
    }
}

# Prefetch files
$prefetchPath = Join-Path $destinationFolder "Prefetch"
New-Item -ItemType Directory -Path $prefetchPath -Force
Copy-Item "$env:SystemRoot\Prefetch\*" -Destination $prefetchPath -Force

# LNK Files
$lnkPath = Join-Path $destinationFolder "LNK"
New-Item -ItemType Directory -Path $lnkPath -Force
# Copy LNK files from each user profile with separate folders
foreach ($userProfile in Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }) {
    $username = Split-Path $userProfile.LocalPath -Leaf
    $userLnkPath = Join-Path $lnkPath $username
    New-Item -ItemType Directory -Path $userLnkPath -Force

    $recentFolder = Join-Path $userProfile.LocalPath "AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $recentFolder) {
        Copy-Item "$recentFolder\*.lnk" -Destination $userLnkPath -Force -ErrorAction SilentlyContinue
    }
}

# Create zip file
Compress-Archive -Path $destinationFolder -DestinationPath $zipFilePath -Force

# Cleanup
Remove-Item -Path $destinationFolder -Recurse -Force

Write-Output "Collection complete. Files saved to: $zipFilePath"