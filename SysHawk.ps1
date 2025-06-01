function Show-SystemHealthDashboard {
    Write-SectionHeader "System Health Dashboard" "📊"
    
    # Calculate overall health score
    $healthScore = 100
    $issues = @()
    
    # Disk health impact
    if ($Global:SysHawkData.Disks) {
        $criticalDisks = @($Global:SysHawkData.Disks | Where-Object { $_.PercentFree -lt 10 })
        $warningDisks = @($Global:SysHawkData.Disks | Where-Object { $_.PercentFree -lt 20 -and $_.PercentFree -ge 10 })
        $healthScore -= ($criticalDisks.Count * 20) + ($warningDisks.Count * 10)
        if ($criticalDisks.Count -gt 0) { $issues += "Critical disk space" }
    }
    
    # Memory health impact
    if ($Global:SysHawkData.Memory -and $Global:SysHawkData.Memory.PercentUsed -gt 80) {
        $healthScore -= if ($Global:SysHawkData.Memory.PercentUsed -gt 90) { 25 } else { 15 }
        if ($Global:SysHawkData.Memory.PercentUsed -gt 80) { $issues += "High memory usage" }
    }
    
    # Network health impact
    if ($Global:SysHawkData.Network) {
        if (-not $Global:SysHawkData.Network.InternetAccess) { $healthScore -= 20; $issues += "No internet access" }
        if (-not $Global:SysHawkData.Network.DNSConnectivity) { $healthScore -= 15; $issues += "DNS connectivity issues" }
    }
    
    # Pending reboot impact
    if ($Global:SysHawkData.SystemHealth.PendingReboot) {
        $healthScore -= 10
        $issues += "Pending reboot required"
    }
    
    # Ensure health score doesn't go negative
    $healthScore = [math]::Max(0, $healthScore)
    
    # Display health meter
    Write-Host "    ├─ Overall System Health " -NoNewline -ForegroundColor Gray
    $healthColor = if ($healthScore -ge 80) { "Green" } elseif ($healthScore -ge 60) { "Yellow" } else { "Red" }
    Write-ProgressBar $healthScore 20 $healthColor
    
    # Display component status grid
    Write-Host ""
    Write-Host "    ├─ Component Status:" -ForegroundColor Gray
    
    $components = @(
        @{ Name = "Disk Space"; Status = if ($Global:SysHawkData.Disks -and ($Global:SysHawkData.Disks | Where-Object { $_.PercentFree -lt 20 })) { "[!]" } else { "[+]" } },
        @{ Name = "Memory"; Status = if ($Global:SysHawkData.Memory.PercentUsed -gt 80) { "[!]" } else { "[+]" } },
        @{ Name = "Network"; Status = if ($Global:SysHawkData.Network.InternetAccess) { "[+]" } else { "[X]" } },
        @{ Name = "Security"; Status = if ($Global:SysHawkData.Security.DefenderEnabled) { "[+]" } else { "[!]" } },
        @{ Name = "Services"; Status = "[+]" },
        @{ Name = "Updates"; Status = if ($Global:SysHawkData.SystemHealth.PendingReboot) { "[!]" } else { "[+]" } }
    )
    
    $grid = ""
    for ($i = 0; $i -lt $components.Count; $i += 3) {
        $line = "    |  "
        for ($j = 0; $j -lt 3 -and ($i + $j) -lt $components.Count; $j++) {
            $comp = $components[$i + $j]
            $status = $comp.Status
            $color = if ($status -eq "[+]") { "Green" } elseif ($status -eq "[!]") { "Yellow" } else { "Red" }
            $line += "$status $($comp.Name)".PadRight(18)
        }
        Write-Host $line -ForegroundColor Gray
    }
    
    # Show top issues if any
    if ($issues.Count -gt 0) {
        Write-Host ""
        Write-Host "    ├─ Issues requiring attention:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "    |  • $issue" -ForegroundColor Yellow
        }
    }
}

#Requires -Version 5.1

<#
.SYNOPSIS
    SysHawk - PowerShell System Hunter
    
.DESCRIPTION
    Comprehensive point-in-time system snapshot for Windows environments.
    Hunts down system information across multiple domains for rapid diagnostics.
    
.PARAMETER QuickScan
    Reduced scope for faster execution (skips detailed event log analysis)
    
.EXAMPLE
    .\SysHawk.ps1
    
.NOTES
    Author: Ulises Paiz
    Version: 1.4
    Linkedin: https://www.linkedin.com/in/ulises-paiz/
#>


# Global variables for data collection
$Global:SysHawkData = @{}
$Global:StartTime = Get-Date

#region ASCII Art and Branding
function Show-SysHawkBanner {
    $banner = @"

  _____           _    _                _    
 / ____|         | |  | |              | |   
| (___  _   _ ___| |__| | __ ___      _| | __
 \___ \| | | / __|  __  |/ _` \ \ /\ / / |/ /
 ____) | |_| \__ \ |  | | (_| |\ V  V /|   < 
|_____/ \__, |___/_|  |_|\__,_| \_/\_/ |_|\_\
         __/ |                               
        |___/                                
                    | 
____________    __ -+-  ____________ 
\_____     /   /_ \ |   \     _____/        🎯 HUNTING SYSTEM QUARRY
 \_____    \____/  \____/    _____/         ═══════════════════════════ 
  \_____                    _____/          ► Swooping for Intel...
     \___________  ___________/
               /____\
                                                                  
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 QUARRY DETECTED:                                        │
    │  💾 Disk Usage        📊 Memory Stats      🔗 Network Info   │
    │  📝 Event Logs        🛡️  Security Status  ⚙️  Services     │
    │  👤 AD Users          🔄 System Health    📈 Performance    │
    └─────────────────────────────────────────────────────────────┘
                                                                  
                ░░░  S Y S T E M   R E C O N   ░░░                
               ░░░░░  H A W K   E Y E   V I E W  ░░░░░            
                                                                  
    ═══════════════════════════════════════════════════════════════
     🦅 PowerShell Predator  |  Hunting Down System Issues  🎯    
    ═══════════════════════════════════════════════════════════════

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "    Scan initiated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
    Write-Host "    Target: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host ""
}
#endregion

#region Utility Functions
function Write-SectionHeader {
    param([string]$Title, [string]$Icon = "🔍")
    Write-Host ""
    Write-Host "    $Icon ══════ $Title ══════" -ForegroundColor Cyan
}

function Write-StatusLine {
    param([string]$Label, [string]$Value, [string]$Status = "INFO")
    $statusColor = switch ($Status) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    $statusIcon = switch ($Status) {
        "OK" { "[+]" }
        "WARNING" { "[!]" }
        "ERROR" { "[X]" }
        default { "[-]" }
    }
    Write-Host "    ├─ $statusIcon $Label`: " -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $statusColor
}

function Write-ProgressBar {
    param([int]$Percent, [int]$Width = 20, [string]$Color = "Green")
    $filled = [math]::Floor($Width * $Percent / 100)
    $empty = $Width - $filled
    $bar = ("#" * $filled) + ("." * $empty)
    Write-Host $bar -ForegroundColor $Color -NoNewline
    Write-Host " $Percent%" -ForegroundColor White
}

function Show-CriticalAlerts {
    Write-Host ""
    Write-Host "    🚨 ══════ CRITICAL ALERTS ══════" -ForegroundColor Red
    $alertsFound = $false
    
    # Check for critical conditions
    if ($Global:SysHawkData.Disks) {
        $criticalDisks = $Global:SysHawkData.Disks | Where-Object { $_.PercentFree -lt 10 }
        foreach ($disk in $criticalDisks) {
            Write-Host "    ├─ [!] CRITICAL: Drive $($disk.Drive) only $($disk.PercentFree)% free!" -ForegroundColor Red
            $alertsFound = $true
        }
    }
    
    if ($Global:SysHawkData.Memory -and $Global:SysHawkData.Memory.PercentUsed -gt 90) {
        Write-Host "    ├─ [!] CRITICAL: Memory usage at $($Global:SysHawkData.Memory.PercentUsed)%!" -ForegroundColor Red
        $alertsFound = $true
    }
    
    if ($Global:SysHawkData.SystemHealth.PendingReboot) {
        Write-Host "    ├─ [!] WARNING: System requires reboot ($($Global:SysHawkData.SystemHealth.RebootReasons -join ', '))" -ForegroundColor Yellow
        $alertsFound = $true
    }
    
    if (-not $alertsFound) {
        Write-Host "    ├─ [+] No critical alerts detected" -ForegroundColor Green
    }
}

function Get-FormattedBytes {
    param([long]$Bytes)
    $sizes = 'B','KB','MB','GB','TB','PB'
    for($i = 0; $Bytes -ge 1KB -and $i -lt $sizes.Length; $i++) { $Bytes /= 1KB }
    return "{0:N2} {1}" -f $Bytes, $sizes[$i]
}
#endregion

#region Data Collection Functions
function Get-DiskIntelligence {
    Write-SectionHeader "Disk Intelligence" "💾"
    Write-Host "    └─ Scanning drives..." -ForegroundColor Gray
    $diskData = @()
    
    try {
        $disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        foreach ($disk in $disks) {
            $freeSpace = [math]::Round(($disk.FreeSpace / 1GB), 2)
            $totalSpace = [math]::Round(($disk.Size / 1GB), 2)
            $usedSpace = $totalSpace - $freeSpace
            $percentFree = [math]::Round(($freeSpace / $totalSpace) * 100, 1)
            $percentUsed = 100 - $percentFree
            
            $status = if ($percentFree -lt 10) { "ERROR" } elseif ($percentFree -lt 20) { "WARNING" } else { "OK" }
            
            Write-Host "    ├─ Drive $($disk.DeviceID) " -NoNewline -ForegroundColor Gray
            Write-ProgressBar $percentUsed 15 $(if ($status -eq "ERROR") { "Red" } elseif ($status -eq "WARNING") { "Yellow" } else { "Green" })
            Write-StatusLine "   └─ Space" "$usedSpace GB / $totalSpace GB used ($percentFree% free)" $status
            
            $diskData += @{
                Drive = $disk.DeviceID
                TotalGB = $totalSpace
                UsedGB = $usedSpace
                FreeGB = $freeSpace
                PercentFree = $percentFree
                Status = $status
            }
        }
    }
    catch {
        Write-StatusLine "Disk Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
    
    $Global:SysHawkData.Disks = $diskData
}

function Get-MemoryIntelligence {
    Write-SectionHeader "Memory Intelligence" "📊"
    Write-Host "    └─ Analyzing memory usage..." -ForegroundColor Gray
    
    try {
        $memory = Get-WmiObject -Class Win32_OperatingSystem
        $totalMem = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
        $freeMem = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
        $usedMem = $totalMem - $freeMem
        $percentUsed = [math]::Round(($usedMem / $totalMem) * 100, 1)
        
        $status = if ($percentUsed -gt 90) { "ERROR" } elseif ($percentUsed -gt 80) { "WARNING" } else { "OK" }
        
        Write-Host "    ├─ Physical Memory " -NoNewline -ForegroundColor Gray
        Write-ProgressBar $percentUsed 15 $(if ($status -eq "ERROR") { "Red" } elseif ($status -eq "WARNING") { "Yellow" } else { "Green" })
        Write-StatusLine "   └─ Usage" "$usedMem GB / $totalMem GB used ($percentUsed%)" $status
        Write-StatusLine "Available Memory" "$(Get-FormattedBytes ($freeMem * 1GB))" "OK"
        
        # Top memory consumers
        $topProcesses = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5
        Write-StatusLine "Top Memory Consumer" "$($topProcesses[0].ProcessName) ($(Get-FormattedBytes $topProcesses[0].WorkingSet))" "INFO"
        
        $Global:SysHawkData.Memory = @{
            TotalGB = $totalMem
            UsedGB = $usedMem
            FreeGB = $freeMem
            PercentUsed = $percentUsed
            Status = $status
            TopProcesses = $topProcesses | ForEach-Object { 
                @{ Name = $_.ProcessName; MemoryMB = [math]::Round($_.WorkingSet / 1MB, 2) }
            }
        }
    }
    catch {
        Write-StatusLine "Memory Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}

function Get-NetworkIntelligence {
    Write-SectionHeader "Network Intelligence" "🔗"
    Write-Host "    └─ Scanning network adapters..." -ForegroundColor Gray
    
    try {
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $networkData = @()
        
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            if ($ipConfig -and $ipConfig.IPv4Address) {
                # Convert LinkSpeed to Mbps safely
                $linkSpeedMbps = "Unknown"
                try {
                    if ($adapter.LinkSpeed -match '(\d+)\s*(Gbps|Mbps|Kbps)') {
                        $speed = [double]$matches[1]
                        $unit = $matches[2]
                        switch ($unit) {
                            "Gbps" { $linkSpeedMbps = "$($speed * 1000) Mbps" }
                            "Mbps" { $linkSpeedMbps = "$speed Mbps" }
                            "Kbps" { $linkSpeedMbps = "$($speed / 1000) Mbps" }
                        }
                    }
                    elseif ($adapter.LinkSpeed -is [int64]) {
                        $linkSpeedMbps = "$([math]::Round($adapter.LinkSpeed / 1MB, 0)) Mbps"
                    }
                }
                catch {
                    $linkSpeedMbps = $adapter.LinkSpeed.ToString()
                }
                
                # Display adapter info
                Write-StatusLine "$($adapter.Name)" "$($ipConfig.IPv4Address.IPAddress) ($linkSpeedMbps)" "OK"
                
                # Display detailed network config
                Write-StatusLine "  └─ Subnet Mask" "/$($ipConfig.IPv4Address.PrefixLength)" "INFO"
                
                if ($ipConfig.IPv4DefaultGateway) {
                    Write-StatusLine "  └─ Default Gateway" $ipConfig.IPv4DefaultGateway.NextHop "INFO"
                }
                
                if ($ipConfig.DNSServer) {
                    $dnsServers = $ipConfig.DNSServer.ServerAddresses -join ", "
                    Write-StatusLine "  └─ DNS Servers" $dnsServers "INFO"
                }
                
                # Get DHCP info if available
                try {
                    $dhcpEnabled = (Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4).Dhcp
                    Write-StatusLine "  └─ DHCP" $(if ($dhcpEnabled -eq "Enabled") { "Enabled" } else { "Static" }) "INFO"
                }
                catch {
                    Write-StatusLine "  └─ DHCP" "Unknown" "INFO"
                }
                
                $networkData += @{
                    Name = $adapter.Name
                    IPAddress = $ipConfig.IPv4Address.IPAddress
                    SubnetMask = $ipConfig.IPv4Address.PrefixLength
                    Gateway = if ($ipConfig.IPv4DefaultGateway) { $ipConfig.IPv4DefaultGateway.NextHop } else { "None" }
                    DNSServers = if ($ipConfig.DNSServer) { $ipConfig.DNSServer.ServerAddresses } else { @() }
                    LinkSpeed = $linkSpeedMbps
                    DHCPEnabled = $dhcpEnabled
                }
            }
        }
        
        # Connectivity tests
        Write-Host "    └─ Testing connectivity..." -ForegroundColor Gray
        $dnsTest = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue
        $internetTest = Test-NetConnection -ComputerName "google.com" -InformationLevel Quiet -WarningAction SilentlyContinue
        
        Write-StatusLine "DNS Connectivity" $(if ($dnsTest) { "Online" } else { "Failed" }) $(if ($dnsTest) { "OK" } else { "ERROR" })
        Write-StatusLine "Internet Access" $(if ($internetTest) { "Online" } else { "Failed" }) $(if ($internetTest) { "OK" } else { "ERROR" })
        
        $Global:SysHawkData.Network = @{
            Adapters = $networkData
            DNSConnectivity = $dnsTest
            InternetAccess = $internetTest
        }
    }
    catch {
        Write-StatusLine "Network Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}

function Get-SecurityIntelligence {
    Write-SectionHeader "Security Intelligence" "🛡️"
    
    try {
        # Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $rtProtection = $defenderStatus.RealTimeProtectionEnabled
            $lastScan = $defenderStatus.QuickScanStartTime
            
            Write-StatusLine "Real-time Protection" $(if ($rtProtection) { "Enabled" } else { "Disabled" }) $(if ($rtProtection) { "OK" } else { "ERROR" })
            Write-StatusLine "Last Quick Scan" $(if ($lastScan) { $lastScan.ToString() } else { "Never" }) "INFO"
        }
        
        # Firewall status
        $firewallProfiles = Get-NetFirewallProfile
        foreach ($profile in $firewallProfiles) {
            $status = if ($profile.Enabled) { "OK" } else { "WARNING" }
            Write-StatusLine "Firewall ($($profile.Name))" $(if ($profile.Enabled) { "Enabled" } else { "Disabled" }) $status
        }
        
        # Recent security events (if not quick scan)
        if (-not $QuickScan) {
            $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Level=2,3; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction SilentlyContinue
            Write-StatusLine "Security Alerts (24h)" "$(@($securityEvents).Count) events" $(if (@($securityEvents).Count -gt 5) { "WARNING" } else { "OK" })
        }
        
        $Global:SysHawkData.Security = @{
            DefenderEnabled = $rtProtection
            LastScan = $lastScan
            FirewallProfiles = $firewallProfiles | ForEach-Object { @{ Name = $_.Name; Enabled = $_.Enabled } }
        }
    }
    catch {
        Write-StatusLine "Security Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}

function Get-ADIntelligence {
    Write-SectionHeader "Active Directory Intelligence" "👤"
    
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $domain = $computerSystem.Domain
        $domainRole = switch ($computerSystem.DomainRole) {
            0 { "Standalone Workstation" }
            1 { "Member Workstation" }
            2 { "Standalone Server" }
            3 { "Member Server" }
            4 { "Backup Domain Controller" }
            5 { "Primary Domain Controller" }
        }
        
        Write-StatusLine "Domain" $domain "OK"
        Write-StatusLine "Domain Role" $domainRole "INFO"
        
        if ($computerSystem.PartOfDomain) {
            # Current user info
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            Write-StatusLine "Current User" $currentUser.Name "INFO"
            
            # Domain connectivity test
            $dcTest = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
            Write-StatusLine "Domain Trust" $(if ($dcTest) { "Secure" } else { "Broken" }) $(if ($dcTest) { "OK" } else { "ERROR" })
            
            # Try to get domain controller info
            try {
                $dc = Get-ADDomainController -Discover -Service PrimaryDC -ErrorAction SilentlyContinue
                if ($dc) {
                    Write-StatusLine "Primary DC" $dc.Name "OK"
                }
            }
            catch {
                Write-StatusLine "DC Discovery" "AD Module not available" "WARNING"
            }
        }
        
        $Global:SysHawkData.ActiveDirectory = @{
            Domain = $domain
            DomainRole = $domainRole
            PartOfDomain = $computerSystem.PartOfDomain
            CurrentUser = $currentUser.Name
            DomainTrust = $dcTest
        }
    }
    catch {
        Write-StatusLine "AD Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}

function Get-ServiceIntelligence {
    Write-SectionHeader "Service Intelligence" "⚙️"
    
    try {
        $criticalServices = @(
            "Spooler", "BITS", "Themes", "AudioSrv", "Dhcp", "Dnscache", 
            "EventLog", "PlugPlay", "RpcSs", "Schedule", "Winmgmt"
        )
        
        $serviceData = @()
        foreach ($serviceName in $criticalServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $status = if ($service.Status -eq "Running") { "OK" } else { "WARNING" }
                Write-StatusLine $service.DisplayName $service.Status $status
                
                $serviceData += @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status.ToString()
                    StartType = $service.StartType.ToString()
                }
            }
        }
        
        # Count of all services by status
        $allServices = Get-Service
        $runningCount = ($allServices | Where-Object { $_.Status -eq "Running" }).Count
        $stoppedCount = ($allServices | Where-Object { $_.Status -eq "Stopped" }).Count
        
        Write-StatusLine "Total Services" "$runningCount running, $stoppedCount stopped" "INFO"
        
        $Global:SysHawkData.Services = @{
            CriticalServices = $serviceData
            TotalRunning = $runningCount
            TotalStopped = $stoppedCount
        }
    }
    catch {
        Write-StatusLine "Service Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}

function Get-SystemHealth {
    Write-SectionHeader "System Health" "🔄"
    
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
        
        Write-StatusLine "System Uptime" "$($uptime.Days) days, $($uptime.Hours) hours" "INFO"
        Write-StatusLine "OS Version" "$($os.Caption) $($os.Version)" "INFO"
        Write-StatusLine "Last Boot" $os.ConvertToDateTime($os.LastBootUpTime).ToString() "INFO"
        
        # Check for pending reboot
        $pendingReboot = $false
        $rebootReasons = @()
        
        # Check Windows Update
        if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
            $pendingReboot = $true
            $rebootReasons += "Windows Update"
        }
        
        # Check pending file rename operations
        if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) {
            $pendingReboot = $true
            $rebootReasons += "File Operations"
        }
        
        Write-StatusLine "Pending Reboot" $(if ($pendingReboot) { "Yes ($($rebootReasons -join ', '))" } else { "No" }) $(if ($pendingReboot) { "WARNING" } else { "OK" })
        
        $Global:SysHawkData.SystemHealth = @{
            UptimeDays = $uptime.Days
            OSVersion = "$($os.Caption) $($os.Version)"
            LastBoot = $os.ConvertToDateTime($os.LastBootUpTime)
            PendingReboot = $pendingReboot
            RebootReasons = $rebootReasons
        }
    }
    catch {
        Write-StatusLine "System Health Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}

function Get-EventLogIntelligence {
    Write-SectionHeader "Event Log Intelligence" "📝"
    
    if ($QuickScan) {
        Write-StatusLine "Event Log Analysis" "Skipped (Quick Scan mode)" "INFO"
        return
    }
    
    try {
        $timeFrame = (Get-Date).AddHours(-24)
        $eventData = @()
        
        # System errors
        $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=$timeFrame} -MaxEvents 50 -ErrorAction SilentlyContinue
        $systemErrorCount = @($systemErrors).Count
        
        # Application errors
        $appErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=$timeFrame} -MaxEvents 50 -ErrorAction SilentlyContinue
        $appErrorCount = @($appErrors).Count
        
        Write-StatusLine "System Errors (24h)" "$systemErrorCount events" $(if ($systemErrorCount -gt 10) { "WARNING" } else { "OK" })
        Write-StatusLine "Application Errors (24h)" "$appErrorCount events" $(if ($appErrorCount -gt 20) { "WARNING" } else { "OK" })
        
        # Top error sources
        if ($systemErrors) {
            $topSystemSource = $systemErrors | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 1
            Write-StatusLine "Top System Error Source" "$($topSystemSource.Name) ($($topSystemSource.Count) events)" "INFO"
        }
        
        $Global:SysHawkData.EventLogs = @{
            SystemErrors24h = $systemErrorCount
            ApplicationErrors24h = $appErrorCount
            TimeFrame = $timeFrame
        }
    }
    catch {
        Write-StatusLine "Event Log Collection" "Failed: $($_.Exception.Message)" "ERROR"
    }
}
#endregion

#region Main Execution
function Invoke-SysHawkHunt {
    Show-SysHawkBanner
    
    # Execute intelligence gathering
    Get-DiskIntelligence
    Get-MemoryIntelligence  
    Get-NetworkIntelligence
    Get-SecurityIntelligence
    Get-ADIntelligence
    Get-ServiceIntelligence
    Get-SystemHealth
    Get-EventLogIntelligence
    
    # Show critical alerts
    Show-CriticalAlerts
    
    # Show health dashboard
    Show-SystemHealthDashboard
    
    # Summary
    $scanDuration = ((Get-Date) - $Global:StartTime).TotalSeconds
    Write-SectionHeader "Hunt Complete" "🎯"
    Write-StatusLine "Scan Duration" "$([math]::Round($scanDuration, 2)) seconds" "OK"
    Write-StatusLine "Target System" $env:COMPUTERNAME "OK"
    Write-StatusLine "Data Points Collected" $Global:SysHawkData.Keys.Count "OK"
    
    # Export JSON if requested
    if ($ExportJson) {
        $jsonPath = "SysHawk_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $Global:SysHawkData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-StatusLine "JSON Export" $jsonPath "OK"
    }
    
    Write-Host ""
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "     🦅 SysHawk Hunt Complete - System Intelligence Gathered 🎯    " -ForegroundColor Green
    Write-Host "    ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

# Execute the hunt
Invoke-SysHawkHunt
#endregion
