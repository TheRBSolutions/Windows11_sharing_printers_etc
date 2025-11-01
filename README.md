# Windows 11 Network Printer Connection Fix Guide

## 📋 Project Analysis

### Complexity: **HIGH**
**Why it's complex:**
- Multiple registry modifications across different systems
- Requires admin privileges and system-level changes
- Involves security policy modifications
- Network configuration and firewall rules
- Multiple troubleshooting paths if initial steps fail
- Risk of system instability if done incorrectly

**How to tackle complexity:**
- Create system restore points before changes
- Test on one client first before mass deployment
- Document each step's outcome
- Have rollback scripts ready
- Work in phases, not all at once

## 💰 Budget & Timeline

| Timeline | Days | Hours | USD | INR |
|----------|------|-------|-----|-----|
| **Minimum** | 2 days | 6-8 hrs | $18-24 | ₹1,500-2,000 |
| **Recommended** | 3-4 days | 12-16 hrs | $36-48 | ₹3,000-4,000 |

**Minimum Budget:** $18 USD (₹1,500 INR)
**Minimum Timeline:** 2 days

---

## 🖨️ Network Printer "Couldn't Connect" — Full Troubleshooting Guide

### 🔍 Overview
Resolves **"Couldn't connect to the printer"** or **Error 0x00000709** caused by Windows security updates breaking LAN printer sharing.

---

## 🧩 Step 1: Registry Fix (RPC Authentication Level)

### Host (Server) Fixes
**Apply to PC sharing the printer:**

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

## 🧰 Step 4: Group Policy Fixes

1. Run `gpedit.msc`
2. Navigate to: **Computer Configuration > Administrative Templates > Printers**
3. Configure:
   - **Point and Print Restrictions** → Enabled
     - Set prompts to: *Do not show warning or elevation prompt*
     - Add trusted server name (e.g., FAREED-PC)
   - **Package Point and Print - Approved Servers** → Disabled

Update policies:
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

---

## ✅ Quick Checklist

| ✓ | Task |
|---|------|
| ☐ | Host Registry applied & Spooler restarted |
| ☐ | Client Registry applied & Spooler restarted |
| ☐ | SMB Signing disabled & Firewall rules applied |
| ☐ | Network Profile set to Private |
| ☐ | Point and Print policies configured |
| ☐ | Credentials added in Credential Manager |
| ☐ | Manual IP Port test successful |

---

**End Summary:** High complexity project requiring 2-4 days, $18-48 budget, involves system-level Windows modifications for printer connectivity.
