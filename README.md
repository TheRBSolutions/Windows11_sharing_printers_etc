# Windows 11 Network Printer Connection Fix Guide



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

---

```markdown
# 🖨️ Windows Shared Printer Troubleshooting Guide

**Diagnose connection failures** like `0x0000011b`, `0x00000709`, or **"Couldn't connect to printer"**  
*(e.g., `\\FAREED-PC\HP-LaserJet`)*

---

## 🧰 1. One-Click Diagnostic Script (Run as **Administrator**)

> **Copy & paste** this entire block into **PowerShell (Admin)**.

```powershell
# -------------------------------
# 1️⃣ Enable PrintService Operational Log
# -------------------------------
$log = Get-WinEvent -ListLog "Microsoft-Windows-PrintService/Operational" -ErrorAction SilentlyContinue
if ($log -and -not $log.IsEnabled) {
    wevtutil sl "Microsoft-Windows-PrintService/Operational" /e:true
    Write-Host "[+] PrintService Operational Log enabled." -ForegroundColor Green
} else {
    Write-Host "[✓] PrintService Operational Log already active." -ForegroundColor Cyan
}

# -------------------------------
# 2️⃣ Enable Advanced Spooler Logging (Verbose)
# -------------------------------
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
New-ItemProperty -Path $regPath -Name "EnableLog" -PropertyType DWord -Value 1 -Force | Out-Null
Write-Host "[+] Advanced Spooler Logging enabled (EnableLog=1)" -ForegroundColor Green

# Restart spooler
Write-Host "[…] Restarting Print Spooler..." -ForegroundColor Yellow
net stop spooler > $null 2>&1
net start spooler > $null 2>&1
Write-Host "[✓] Print Spooler restarted." -ForegroundColor Cyan

# -------------------------------
# 3️⃣ Export Key Failure Events (616, 808, 821)
# -------------------------------
Write-Host "[…] Exporting connection & driver failure logs..." -ForegroundColor Yellow

$events = Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" -ErrorAction SilentlyContinue |
          Where-Object { $_.Id -in 616, 808, 821 } |
          Select-Object TimeCreated, Id, LevelDisplayName, Message

if ($events) {
    $txtPath = "$env:USERPROFILE\Desktop\Printer_Failures.txt"
    $csvPath = "$env:USERPROFILE\Desktop\Printer_Failures.csv"
    $events | Out-File -FilePath $txtPath -Encoding UTF8
    $events | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[✓] Logs exported:" -ForegroundColor Green
    Write-Host "    → $txtPath"
    Write-Host "    → $csvPath"
} else {
    Write-Host "[!] No Event ID 616, 808, or 821 found. Try reconnecting the printer, then re-run." -ForegroundColor Yellow
}

# -------------------------------
# 4️⃣ Log Locations Reminder
# -------------------------------
Write-Host "`n[ℹ️] Advanced logs will appear in:" -ForegroundColor Cyan
Write-Host "    C:\Windows\System32\LogFiles\PrintService\" -ForegroundColor White
Write-Host "    C:\Windows\System32\spool\PRINTERS\" -ForegroundColor White
Write-Host "    Event Viewer → PrintService → Operational" -ForegroundColor White
Write-Host "`n✅ Script completed. Check Desktop for logs." -ForegroundColor Green
```

---

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

## 🧰 4. Quick Live Checks (Optional – No Export)

> Use **after** main script for real-time inspection.

```powershell
# Last 20 printer events
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" -MaxEvents 20 |
  Select TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize
```

```powershell
# Filter failures: 616 (RPC/SMB), 808, 821
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" |
  Where-Object {$_.Id -in 616, 808, 821} |
  Select TimeCreated, Id, Message | Format-List
```

```powershell
# System log: Print/Spooler errors
Get-WinEvent -LogName System | Where-Object {$_.ProviderName -match "Print|Spooler"} |
  Select TimeCreated, Id, Message | Format-List
```

---

## 🛠️ 5. (Optional) Manual Verbose Logging  
> **Only if PowerShell Admin is blocked**

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
