# SysHawk 🦅
## PowerShell System Hunter - Comprehensive System Intelligence Tool

**SysHawk** is a comprehensive PowerShell-based system diagnostic tool designed for Windows system administrators. It provides a complete point-in-time snapshot of system health, network configuration, security posture, and performance metrics in an easy-to-read, color-coded format.

## 🚀 Features

### 💾 **Disk Intelligence**
- Real-time disk usage for all drives
- Visual progress bars with color-coded warnings
- Critical space alerts (< 10% free)
- Capacity and utilization reporting

### 📊 **Memory Intelligence** 
- Physical memory usage with visual indicators
- Available memory reporting
- Top memory consuming processes
- Performance threshold monitoring

### 🔗 **Network Intelligence**
- Active network adapter configuration
- IP addresses, subnets, and CIDR notation
- Default gateway and DNS server information
- DHCP vs. static configuration detection
- Internet and DNS connectivity testing
- Link speed reporting with proper unit conversion

### 🛡️ **Security Intelligence**
- Windows Defender real-time protection status
- Firewall status across all profiles (Domain/Private/Public)
- Recent security event analysis
- Last antivirus scan information

### 👤 **Active Directory Intelligence**
- Domain membership status and role
- Current user context and permissions
- Domain controller connectivity testing
- Computer account health verification

### ⚙️ **Service Intelligence**
- Critical Windows service monitoring
- Service status reporting with color coding
- Total running/stopped service counts
- Startup type information

### 🔄 **System Health Monitoring**
- System uptime tracking
- OS version and build information
- Pending reboot detection with reasons
- Windows Update status indicators

### 📝 **Event Log Intelligence**
- Recent system and application errors (24-hour window)
- Event correlation and pattern recognition
- Top error sources identification
- Security event analysis

### 📊 **Health Dashboard**
- Overall system health score (0-100%)
- Component status grid with visual indicators
- Critical alert prioritization
- Issue summary with recommended actions

## 🛠️ Requirements

- **Operating System**: Windows 10/11, Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Permissions**: Local Administrator rights recommended for full functionality
- **Network**: Internet connectivity for external connectivity tests

## 📥 Installation

1. **Download the script:**
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Coach40oz/SysHawk/main/SysHawk.ps1" -OutFile "SysHawk.ps1"
   ```

2. **Set execution policy (if needed):**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Run the script:**
   ```powershell
   .\SysHawk.ps1
   ```

## 🎯 Usage

### Basic System Scan
```powershell
.\SysHawk.ps1
```
Performs a comprehensive system scan with full event log analysis.

### Quick Scan Mode
```powershell
.\SysHawk.ps1 -QuickScan
```
Faster execution with reduced event log analysis scope.

### Export to JSON
```powershell
.\SysHawk.ps1 -ExportJson
```
Saves scan results to a timestamped JSON file for integration with external tools.

### Combined Options
```powershell
.\SysHawk.ps1 -QuickScan -ExportJson
```
Quick scan with JSON export for automated monitoring workflows.

## 📊 Sample Output

### System Health Dashboard
```
🔍 ══════ System Health Dashboard ══════
├─ Overall System Health #################### 87%
├─ Component Status:
|  [+] Disk Space      [+] Memory         [+] Network       
|  [+] Security        [+] Services       [!] Updates       

├─ Issues requiring attention:
|  • Pending reboot required
```

### Network Intelligence
```
🔗 ══════ Network Intelligence ══════
└─ Scanning network adapters...
├─ [+] Ethernet: 192.168.1.100 (1000 Mbps)
├─ [-]   └─ Subnet Mask: /24
├─ [-]   └─ Default Gateway: 192.168.1.1
├─ [-]   └─ DNS Servers: 8.8.8.8, 8.8.4.4
├─ [-]   └─ DHCP: Enabled
└─ Testing connectivity...
├─ [+] DNS Connectivity: Online
├─ [+] Internet Access: Online
```

### Critical Alerts
```
🚨 ══════ CRITICAL ALERTS ══════
├─ [!] CRITICAL: Drive C: only 8.3% free!
├─ [!] WARNING: System requires reboot (Windows Update)
```

## 📈 Integration

### JSON Export Structure
```json
{
  "Disks": [
    {
      "Drive": "C:",
      "TotalGB": 465.75,
      "UsedGB": 427.13,
      "FreeGB": 38.62,
      "PercentFree": 8.3,
      "Status": "ERROR"
    }
  ],
  "Memory": {
    "TotalGB": 15.87,
    "UsedGB": 9.45,
    "FreeGB": 6.42,
    "PercentUsed": 59.5,
    "Status": "OK"
  }
}
```

### Automation Examples

**Scheduled Task Integration:**
```powershell
# Create daily health check
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\SysHawk.ps1 -ExportJson"
$Trigger = New-ScheduledTaskTrigger -Daily -At "08:00"
Register-ScheduledTask -TaskName "SysHawk-DailyHealthCheck" -Action $Action -Trigger $Trigger
```

**SIEM Integration:**
```powershell
# Export and send to log collector
.\SysHawk.ps1 -ExportJson
$jsonData = Get-Content "SysHawk_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
# Send to your SIEM/log management system
```

## 🔧 Customization

### Modifying Thresholds
Edit the script to adjust warning thresholds:
```powershell
# Disk space warnings
$status = if ($percentFree -lt 10) { "ERROR" } elseif ($percentFree -lt 20) { "WARNING" } else { "OK" }

# Memory usage warnings  
$status = if ($percentUsed -gt 90) { "ERROR" } elseif ($percentUsed -gt 80) { "WARNING" } else { "OK" }
```

### Adding Custom Services
Modify the `$criticalServices` array to monitor additional services:
```powershell
$criticalServices = @(
    "Spooler", "BITS", "Themes", "AudioSrv", "Dhcp", "Dnscache", 
    "EventLog", "PlugPlay", "RpcSs", "Schedule", "Winmgmt",
    "YourCustomService"  # Add your services here
)
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines
1. Follow PowerShell best practices and conventions
2. Maintain compatibility with PowerShell 5.1+
3. Include appropriate error handling
4. Update documentation for new features
5. Test on multiple Windows versions

### Reporting Issues
Please include the following information when reporting issues:
- Windows version and PowerShell version
- Full error message and stack trace
- Steps to reproduce the issue
- Expected vs. actual behavior

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](#license-text) section below for details.

### License Text

```
MIT License

Copyright (c) 2025 Ulises Paiz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 👨‍💻 Author

**Ulises Paiz**
- **LinkedIn**: [https://www.linkedin.com/in/ulises-paiz/](https://www.linkedin.com/in/ulises-paiz/)
- **Version**: 1.4

## 🏷️ Version History

- **v1.4** - Enhanced network intelligence, improved error handling, ASCII compatibility mode
- **v1.3** - Added health dashboard, critical alerts, progress bars
- **v1.2** - Implemented JSON export, quick scan mode
- **v1.1** - Added Active Directory intelligence, service monitoring  
- **v1.0** - Initial release with core system monitoring capabilities

## 📞 Support

For support, questions, or feature requests:
1. Check the [Issues](https://github.com/Coach40oz/SysHawk/issues) section for existing solutions
2. Create a new issue with detailed information
3. Connect with the author on LinkedIn for professional inquiries

---

**⭐ If you find SysHawk useful, please consider giving it a star on GitHub!**

*Happy hunting! 🎯*
