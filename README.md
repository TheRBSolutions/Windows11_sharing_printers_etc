# Windows 11 Network Printer Connection Fix Guide

# 🖨️ Windows Network Printer Fix Guide (Advanced Settings)

The images you've provided show advanced system configuration steps (Registry, Group Policy, and Windows Features) often used to resolve complex network printer sharing errors like 0x0000011b, 0x00000709, or RPC communication failures.

These steps involve modifying Windows' security and network protocols. Apply the server steps **ONLY** to the PC that is **SHARING** the printer (the Server PC). Client steps apply to the PC(s) attempting to connect to the shared printer.

**Important Notes:**
- Always back up your registry before making changes.
- These fixes are based on common resolutions for the mentioned errors, which often stem from security updates or protocol mismatches.
- After applying changes, test printing from the client to verify.
- If issues persist, run the built-in Printer Troubleshooter on both PCs (search for "troubleshoot" in Settings).

## 1. Server PC Configuration (Sharing PC)

1. **⚙️ Enable LPR Port Monitor (Windows Features)**  
   This ensures the Line Printer Remote (LPR) protocol, an alternative printing service, is active. This step is shown in image 1000395273.jpg and should be done on the Server PC.  
   - Open the Run dialog (Win + R) and type `optionalfeatures` (or search for *Turn Windows features on or off*).  
   - Expand *Print and Document Services*.  
   - Check the box next to *LPR Port Monitor*.  
   - Click OK and restart the PC if prompted.  
   > Note: While not strictly required for SMB/RPC sharing, enabling LPR provides a fallback mechanism and ensures all print services are available.

2. **📝 Configure RPC over TCP Port (Group Policy)**  
   This step (image 1000395272.jpg) configures the port used for RPC communication, which the Print Spooler service uses. This must be done on the Server PC.  
   - Open the Run dialog (Win + R) and type `gpedit.msc` to open the Local Group Policy Editor.  
   - Navigate to:  
     Computer Configuration > Administrative Templates > Printers.  
   - Find and double-click the policy setting: *Configure RPC over TCP port*.  
   - Set the policy to *Enabled*.  
   - In the option box, enter a specific, unused TCP port number (e.g., 9100 or 50000).  
   > Note: Configuring a static port is often necessary if firewalls are blocking the dynamic RPC ports.  
   - Click OK.  
   - Open Command Prompt (as Admin) and run `gpupdate /force` to apply the changes.

3. **🛡️ Registry Configuration for RPC Communication**  
   These registry modifications are related to forcing the Print Spooler to use specific communication protocols.  

   **A. Configure RPC over TCP and Named Pipes (image 1000395271.jpg)**  
   - Open the Run dialog (Win + R) and type `regedit` to open the Registry Editor.  
   - Navigate to:  
     `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC`  
     > If the RPC key does not exist under Printers, you must create it.  
   - Create or modify the following DWORD (32-bit) values:  
     - *RpcOverTCP*  
       - Type: REG_DWORD  
       - Value: 0 (Zero)  
     - *RpcUseNamedPipeProtocol*  
       - Type: REG_DWORD  
       - Value: 1 (One)  

   **B. Configure Print Spooler Execution (Images 1000395274.jpg & 1000395275.jpg)**  
   These steps relate to permissions and default printer settings.  
   - Navigate to:  
     `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows`  
   - Check Permissions: Right-click the Windows key and select *Permissions...* (image 1000395275.jpg).  
     - Ensure *ALL APPLICATION PACKAGES* has *Read* permissions allowed.  
   - Ensure the following DWORD is set (as shown in image 1000395274.jpg):  
     - *LegacyDefaultPrinterMode*  
       - Type: REG_DWORD  
       - Value: 1 (One)

4. **🚀 Final Step: Restart Services on Server**  
   After applying all the changes (especially the Group Policy and Registry edits), you must restart the Print Spooler service and the computer.  
   - Open PowerShell or Command Prompt as an Administrator.  
   - Stop and restart the Spooler service:  
     ```
     net stop spooler
     net start spooler
     ```  
   - Restart the Server PC to ensure all Group Policy and Registry changes take full effect.

## 2. Client PC Configuration (Connecting PC)

After applying the server fixes, perform these steps on the Client PC to connect to the shared printer. These address common client-side issues like driver restrictions, network discovery, and connection errors.

1. **🛡️ Registry Configuration for Point and Print (Optional but Recommended for Error 0x0000011b)**  
   This relaxes driver installation restrictions imposed by security updates.  
   - Open the Run dialog (Win + R) and type `regedit` to open the Registry Editor.  
   - Navigate to:  
     `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint`  
     > If the PointAndPrint key does not exist, create it (right-click Printers > New > Key).  
   - Create or modify the following DWORD (32-bit) value:  
     - *RestrictDriverInstallationToAdministrators*  
       - Type: REG_DWORD  
       - Value: 0 (Zero)  
   - Close the Registry Editor and restart the Client PC.

2. **🌐 Enable Network Discovery and File/Printer Sharing**  
   Ensure the client can discover and access shared resources.  
   - Open Settings (Win + I) > Network & Internet > Status > Change adapter options (or search for "Network and Sharing Center").  
   - Click *Change advanced sharing settings* on the left.  
   - Under Private (or current profile):  
     - Turn on *Network discovery*.  
     - Turn on *File and printer sharing*.  
   - Save changes.  
   - In Windows Firewall (search for "firewall"), ensure *File and Printer Sharing* is allowed for Private networks.

3. **📥 Add the Shared Printer**  
   - Open Settings (Win + I) > Devices (or Bluetooth & devices) > Printers & scanners.  
   - Click *Add a printer or scanner*. Wait for it to search.  
   - If the printer doesn't appear, click *The printer that I want isn't listed*.  
   - Select *Select a shared printer by name* and enter the UNC path: `\\ServerPCName\PrinterShareName` (replace with actual names).  
   - Follow the prompts to install drivers if prompted.  
   > Alternative: If direct addition fails, add via local port:  
   > - Choose *Add a local printer or network printer with manual settings*.  
   > - Select *Create a new port* > Type: *Local Port*.  
   > - For Port Name, enter `\\ServerPCName\PrinterShareName`.  
   > - Select the printer driver or let Windows install it.

4. **🚀 Restart Services on Client**  
   - Open PowerShell or Command Prompt as an Administrator.  
   - Stop and restart the Spooler service:  
     ```
     net stop spooler
     net start spooler
     ```  
   - Restart the Client PC if needed.

5. **Additional Troubleshooting (If Errors Persist)**  
   - Check for Windows Updates on the Client PC: Settings > Update & Security > Windows Update > Check for updates. Install any available.  
   - If a recent update caused the issue, uninstall it: View update history > Uninstall updates (e.g., look for KB updates related to printing).  
   - Run the Printer Troubleshooter: Settings > Update & Security > Troubleshoot > Additional troubleshooters > Printer > Run the troubleshooter.  
   - Ensure both PCs are on the same network and workgroup (Control Panel > System > Change settings > Computer name).  
   - For RPC failures, verify the static port (from server step 2) is open in the client's firewall if using TCP.

These steps should resolve most connection issues. If you encounter specific errors during testing, provide details for further assistance.

---

## 🖨️ Network Printer "Couldn't Connect" — Full Troubleshooting Guide

### 🔍 Overview
Resolves **"Couldn't connect to the printer"** or **Error 0x00000709** caused by Windows security updates breaking LAN printer sharing.

---

## 🧩 Step 1: Registry Fix (RPC Authentication Level)

### Host (Server) Fixes
**Apply to PC sharing the printer:**
The registry keys you provided are related to settings Microsoft implemented after the PrintNightmare security vulnerabilities (CVE-2021-1678 and CVE-2021-34481) to secure the Windows Print Spooler service.
Are known workarounds to resolve network printer connection errors (like 0x0000011b)

```reg
; Save as Host_Fix.reg and run
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print]
"RpcAuthnLevelPrivacyEnabled"=dword:00000000
"CopyFilesPolicy"=dword:00000001
"RestrictDriverInstallationToAdministrators"=dword:00000000
```

### Client PC Fixes
**Apply to PC connecting to printer:**

```reg
; Save as Client_Fix.reg and run
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print]
"RpcAuthnLevelPrivacyEnabled"=dword:00000000
"RpcAuthnLevelClient"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint]
"RestrictDriverInstallationToAdministrators"=dword:00000000
"NoWarningNoElevationOnInstall"=dword:00000001
"UpdatePromptSettings"=dword:00000002
```

---

## ⚙️ Step 2: Essential Service Restart

**Run on both Host and Client (Elevated PowerShell):**
```powershell
net stop spooler
net start spooler
```

---

## 🧱 Step 3: SMB1 Compatibility (Legacy Printers Only)

⚠️ **Warning:** SMB1 is insecure - enable only if necessary

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart
```

---


-----


## 🧱 Step 4: Consolidated Print Fix Steps

These steps should be applied to the Client PC (the one connecting to the shared printer).

1. ⚙️ Group Policy Fix (Client PC)

    Press Win + R, type gpedit.msc, and press Enter.

    Navigate to: Computer Configuration → Administrative Templates → Printers.

    Double-click Point and Print Restrictions and set it to Enabled.

        Set the security prompts to: "Do not show warning or elevation prompt".

        Check the box "Users can only point and print to these servers".

        Click the Show button next to the server list and add your print server name:

        FAREED-PC

    Double-click Package Point and Print - Approved Servers and set it to Disabled (if you are not using Package Point and Print).

2. 🔄 Update Policies

    Press Win + R, type cmd, and press Enter to open the Command Prompt.

    Run the command to apply the changes immediately:
    Bash

    gpupdate /force

And here is a reminder of the necessary Host (Server) Fix (applied to FAREED-PC):

3. 💾 Host (Server) Fix (FAREED-PC)

    Create a file named Host_Fix.reg containing the following text:
    Code snippet

    Windows Registry Editor Version 5.00

    [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print]
    "RpcAuthnLevelPrivacyEnabled"=dword:00000000
    "CopyFilesPolicy"=dword:00000001
    "RestrictDriverInstallationToAdministrators"=dword:00000000

    Double-click Host_Fix.reg to merge the settings.

    Restart the Host PC (FAREED-PC).

By completing these steps on both the client and server, you should successfully address common network printing errors related to the PrintNightmare security updates.Update policies:
```bash
gpupdate /force
```

---

## 🌐 Step 5: Network Profile & Discovery

1. **Settings → Network & Internet → Properties**
2. Set Network Profile = **Private**
3. Enable **Network discovery** and **File and printer sharing**

---

## ⚙️ Step 6: Dependency Services Check

Open `services.msc` and ensure these are **Running** and **Automatic**:
- Print Spooler
- Remote Procedure Call (RPC)
- Function Discovery Resource Publication
- SSDP Discovery

---

## 🔐 Step 7: Firewall & SMB Configuration

### Disable SMB Signing/Encryption
```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbServerConfiguration -EncryptData $false -Force
```

### Create Firewall Exceptions
```powershell
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
netsh advfirewall firewall add rule name="Allow RPC EPM Port 135" dir=in action=allow protocol=TCP localport=135 enable=yes
netsh advfirewall firewall add rule name="Allow Spoolsv.exe" dir=in action=allow program="%systemroot%\System32\spoolsv.exe" enable=yes
```

---

## 🧹 Step 8: Clear Spooler Cache

**Run on both Host and Client:**
```powershell
net stop spooler
Remove-Item -Path "$env:systemroot\System32\spool\PRINTERS\*" -Force
Remove-Item -Path "$env:systemroot\System32\spool\DRIVERS\*" -Force
net start spooler
```

---

## 🧠 Step 9: Manual Printer Add (Bypass Method)

1. **Settings → Bluetooth & Devices → Printers → Add Device → Add manually**
2. Choose: **"Create a new port → Standard TCP/IP Port"**
3. Enter printer IP (e.g., 192.168.1.10)
4. Install driver manually

---

## 🔐 Step 10: Credential Manager Setup

Add explicit credentials:
- **Network address:** \\FAREED-PC
- **Username:** host PC login username
- **Password:** host PC login password

## 🔐 Step 11: Final Debugging 
Here is the **final, clean, non-redundant Markdown document** — fully updated per your request:

- **A (Main Script)**: Now includes **Event ID 616** (connection failed – RPC/SMB)
- **B (Quick Checks)**: Also filters for **616**
- **C**: **Removed** (fully redundant)
- Added `net stop spooler && net start spooler` in **Manual Section**
- Added **"helpline" note** under **Log Locations**
- Perfect flow, zero duplication, ready for GitHub
## First Script For diagnostics
```powershell
---
<# 
.SYNOPSIS
  Full diagnostic for shared printer connection failures (0x0000011b, 0x00000709, etc.)
.DESCRIPTION
  - Enables PrintService Operational log
  - Enables verbose spooler logging (EnableLog=1)
  - Restarts Print Spooler
  - Exports Event IDs 616, 808, 821 to Desktop (TXT + CSV)
  - Shows log locations
.NOTES
  Author: RB (IT Admin)
  Run as: Administrator
#>

# -------------------------------
# 1. Enable PrintService Operational Log
# -------------------------------
$log = Get-WinEvent -ListLog "Microsoft-Windows-PrintService/Operational" -ErrorAction SilentlyContinue
if ($log -and -not $log.IsEnabled) {
    wevtutil sl "Microsoft-Windows-PrintService/Operational" /e:true
    Write-Host "[+] PrintService Operational Log enabled." -ForegroundColor Green
} else {
    Write-Host "[Check] PrintService Operational Log already active." -ForegroundColor Cyan
}

# -------------------------------
# 2. Enable Advanced Spooler Logging
# -------------------------------
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty -Path $regPath -Name "EnableLog" -PropertyType DWord -Value 1 -Force | Out-Null
Write-Host "[+] Advanced Spooler Logging enabled (EnableLog=1)" -ForegroundColor Green

# -------------------------------
# 3. Restart Print Spooler
# -------------------------------
Write-Host "[Process] Restarting Print Spooler..." -ForegroundColor Yellow
net stop spooler > $null 2>&1
Start-Sleep -Seconds 2
net start spooler > $null 2>&1
Write-Host "[Check] Print Spooler restarted." -ForegroundColor Cyan

# -------------------------------
# 4. Export Key Failure Events (616, 808, 821)
# -------------------------------
Write-Host "[Export] Collecting Event IDs 616, 808, 821..." -ForegroundColor Yellow

$events = Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" -ErrorAction SilentlyContinue |
          Where-Object { $_.Id -in 616, 808, 821 } |
          Select-Object TimeCreated, Id, LevelDisplayName, Message

if ($events) {
    $txtPath = "$env:USERPROFILE\Desktop\Printer_Failures.txt"
    $csvPath = "$env:USERPROFILE\Desktop\Printer_Failures.csv"
    $events | Out-File -FilePath $txtPath -Encoding UTF8
    $events | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[Check] Logs exported:" -ForegroundColor Green
    Write-Host "    -> $txtPath"
    Write-Host "    -> $csvPath"
} else {
    Write-Host "[Warning] No Event ID 616, 808, or 821 found." -ForegroundColor Yellow
    Write-Host "    -> Try reconnecting the printer, then re-run." -ForegroundColor Yellow
}

# -------------------------------
# 5. Log Locations Reminder
# -------------------------------
Write-Host "`n[Info] Advanced logs are saved to:" -ForegroundColor Cyan
Write-Host "    C:\Windows\System32\LogFiles\PrintService\" -ForegroundColor White
Write-Host "    C:\Windows\System32\spool\PRINTERS\" -ForegroundColor White
Write-Host "    Event Viewer -> PrintService -> Operational" -ForegroundColor White
Write-Host "`n[Success] Diagnostic complete. Check Desktop for logs." -ForegroundColor Green
---
```

## Second Script Printer-QuickCheck.ps1 (Live View Only)
```powershell

<# 
.SYNOPSIS
  Quick live inspection of printer events (no file export)
.DESCRIPTION
  Shows:
  - Last 20 PrintService events
  - Failures: 616, 808, 821
  - System log Print/Spooler entries
.NOTES
  Run anytime (Admin recommended for full view)
#>

Write-Host "`n[Live Check] Last 20 PrintService events:" -ForegroundColor Cyan
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" -MaxEvents 20 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-Table -AutoSize

Write-Host "`n[Failures] Event IDs 616, 808, 821:" -ForegroundColor Yellow
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 616, 808, 821 } |
    Select-Object TimeCreated, Id, Message |
    Format-List

Write-Host "`n[System Log] Print/Spooler errors:" -ForegroundColor Magenta
Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match "Print|Spooler" } |
    Select-Object TimeCreated, Id, Message |
    Format-List

Write-Host "`n[Info] Done. Use Printer-Troubleshoot.ps1 for full export." -ForegroundColor Green

```

## How to Save & Run (Step-by-Step)
Save the Files

Open Notepad (or VS Code)
Copy first script → Paste → Save As
→ Printer-Troubleshoot.ps1
→ Save as type: All Files
Copy second script → Paste → Save As
→ Printer-QuickCheck.ps1


Save both in: C:\Scripts\ (create folder) or Desktop


**Run the Scripts
Option 1: Right-Click (Easiest)

Right-click .ps1 file → "Run with PowerShell"
If blocked → use Option 2**

## Option 2: PowerShell (Admin)
powershell

# Allow local scripts (once)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Run full diagnostic
.\Printer-Troubleshoot.ps1

# Run quick check
.\Printer-QuickCheck.ps1





## 🔍 2. Key Event IDs to Monitor

| Event ID | Meaning |
|---------|--------|
| **616** | **Connection failed** (often **RPC/SMB**, firewall, or share access) |
| **808** | Connection attempted / queue created |
| **821** | **Driver installation failed** (common with `0x0000011b`) |
| **307** | Print job sent successfully |
| **310 / 372** | Print job failed |

> **Look for** `\\FAREED-PC\HP-LaserJet`, error codes, and user context.

---

## 📂 3. Log Locations

| Type | Path | Format | Use Case |
|------|------|--------|---------|
| **Operational Events** | `Event Viewer → Applications and Services → Microsoft → Windows → PrintService → Operational` | `.evtx` | Standard connection & driver events |
| **Verbose Spooler Logs** | `C:\Windows\System32\LogFiles\PrintService\` | `.log` | Deep RPC, SMB, driver load tracing |
| **Spooler Temp Files** | `C:\Windows\System32\spool\PRINTERS\` | `.SPL`, `.SHD` | Raw print job data (for Microsoft PSS) |

> **Helpline**:  
> - If **616** appears → check **SMB1**, **firewall**, **RPC ports (135, 445)**, or **printer share permissions**  
> - If **821** → driver mismatch or **Point and Print restrictions**  
> - Enable log first: Right-click **Operational** → **Enable Log**

---





## 🧾 6️⃣ (Optional) Enable Advanced Logging (Spooler Verbose Mode)

For deep debugging:

1. Open **Registry Editor**
2. Navigate to:

   ```
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print
   ```
3. Create a **DWORD (32-bit)** value:

   ```
   EnableLog
   ```

   Set **Value = 1**
4. Restart **Print Spooler**:

   ```powershell
   net stop spooler
   net start spooler
   ```

📁 Logs appear under:

```
C:\Windows\System32\LogFiles\PrintService
```

and

```
C:\Windows\System32\spool\PRINTERS
```

---

---

## ✅ Recommended Workflow

1. **Run the One-Click Script** (as Admin)  
2. **Try connecting** to `\\FAREED-PC\HP-LaserJet`  
3. **If fails** → re-run script  
4. **Check** `Printer_Failures.txt` / `.csv` on **Desktop**  
5. **Review** `C:\Windows\System32\LogFiles\PrintService\*.log`

---

**Author**: RB (IT Admin)  
**Purpose**: Diagnose shared printer connection failures  
**OS**: Windows 10 / 11 (Client & Server)  
**License**: Free for IT diagnostic use  

---
```

---

### Summary of Updates

| Feature | Added / Updated |
|--------|-----------------|
| **Event ID 616** | In **main script**, **quick checks**, and **event table** |
| **Helpline** | Under **Log Locations** with actionable tips |
| `net stop && net start` | In **Manual Section** |
| **C (Manual Registry)** | Removed from main script (already included) |
| **Redundancy** | Eliminated – one source of truth |

**Upload this `.md` file directly to GitHub — perfect, complete, and professional.**
```
---


## ✅ Summary: Where to Check Failed Printer Connection Events

| **Location**               | **Path**                               | **What You’ll Find**                        |
| -------------------------- | -------------------------------------- | ------------------------------------------- |
| PrintService → Operational | Microsoft → Windows → PrintService     | Detailed printer connection + driver events |
| Windows Logs → System      | Core printer and spooler errors        |                                             |
| Windows Logs → Security    | Authentication/SMB permission failures |                                             |
| PowerShell (Get-WinEvent)  | Fast export of logs to text or CSV     |                                             |

---

Would you like me to include an **automated PowerShell script version** (`.ps1`) that collects all these logs, exports them, and optionally clears the old entries for a clean diagnostic run?


---

## ✅ Quick Checklist

| ✓ | Task |
|---|------|
| ☐ | Profiles updated to private |
| ☐ | See Events Logs  |
| ☐ | Host Registry applied & Spooler restarted |
| ☐ | Client Registry applied & Spooler restarted |
| ☐ | SMB Signing disabled & Firewall rules applied |
| ☐ | Network Profile set to Private |
| ☐ | Point and Print policies configured |
| ☐ | Credentials added in Credential Manager |
| ☐ | Manual IP Port test successful |

---

**End Summary:** High complexity project requiring 2-4 days, $18-48 budget, involves system-level Windows modifications for printer connectivity.
