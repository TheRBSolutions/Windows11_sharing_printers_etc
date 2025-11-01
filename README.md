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

## 🔐 Step 11:
Perfect, RB 👍 — below is the **complete Markdown-formatted guide**, now including the **PowerShell one-liner** to export all failed printer connection logs for analysis.

---

# 🧭 Windows Printer Connection Log & Troubleshooting Guide

This guide helps you **trace and export event logs** related to failed or successful printer connections on **Windows 10/11** — including errors like `0x00000709`, `0x0000011b`, or `"Couldn't connect to the printer"`.

---

## 🧭 1️⃣ Event Viewer — Printer Connection Logs

### 📂 Path 1: Operational Printer Logs

**Open Event Viewer →**
`Applications and Services Logs → Microsoft → Windows → PrintService → Operational`

If you don’t see it:
➡️ Right-click **PrintService → Operational → Enable Log**

Once enabled, this log records **all printer connection, driver, and spooler events**.

---

### 📋 Key Event IDs to Check

| **Event ID**        | **Meaning**                                                  |
| ------------------- | ------------------------------------------------------------ |
| **808**             | Print queue created successfully                             |
| **819 / 808**       | Client printer connection attempted                          |
| **616 / 808 / 808** | Connection or driver installation failed                     |
| **821**             | Printer driver installation failure                          |
| **808 / 821 / 808** | “Couldn’t connect to printer” or `0x00000709` / `0x0000011b` |
| **307**             | Print job sent successfully (for test prints)                |
| **310 / 372**       | Print job failed or incomplete                               |

📌 **Tip:** Look for **Event ID 821 or 808** when troubleshooting connection or driver issues.
They will show:

* The printer path (`\\FAREED-PC\HP-LaserJet`)
* The **error code** (`0x0000011b`, etc.)
* The **user** attempting the connection

---

## 🧭 2️⃣ System Event Logs

**Path:**
`Event Viewer → Windows Logs → System`

Then filter for **Sources** like:

* `PrintService`
* `Spooler`
* `SharedAccess_NAT` (for SMB/firewall issues)

🧰 PowerShell quick check:

```powershell
Get-WinEvent -LogName System | Where-Object {$_.ProviderName -match "Print"}
```

---

## 🧭 3️⃣ Security Logs (Optional)

If auditing is enabled:

**Path:**
`Event Viewer → Windows Logs → Security`

Check for:

* **Event ID 4625** — Failed network logon (bad credentials)
* **Event ID 5140** — Network share accessed (`\\FAREED-PC`)

---

## 🧰 4️⃣ PowerShell Quick Checks

Get the **last 20 printer-related events**:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" -MaxEvents 20 |
Select TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize
```

Filter **only failed installs/connections (821, 808):**

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" |
Where-Object {$_.Id -in 821,808} |
Select TimeCreated, Message | Format-List
```

---

## 💾 5️⃣ Export Failed Printer Logs (One-Liner)

To automatically export **all failed printer connection logs (Event ID 808, 821, etc.)** into a text or CSV file:

### ▶ Export to `.txt`:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" |
Where-Object {$_.Id -in 808,821} |
Select TimeCreated, Id, Message |
Out-File "$env:USERPROFILE\Desktop\Printer_Failures.txt"
```

### ▶ Export to `.csv`:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Operational" |
Where-Object {$_.Id -in 808,821} |
Select TimeCreated, Id, Message |
Export-Csv "$env:USERPROFILE\Desktop\Printer_Failures.csv" -NoTypeInformation -Encoding UTF8
```

✅ **Output:**
Your log file will appear on the **Desktop** as:

* `Printer_Failures.txt`
* or `Printer_Failures.csv`

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
