# 🔧 VM Nested Virtualization aktivieren

## Problem:
```
[X] Hypervisor Launch Type: NOT SET!
[!] Credential Guard NOT RUNNING
```

**Grund:** Deine VM hat KEINE Nested Virtualization aktiviert!

---

## ✅ LÖSUNG (je nach Hypervisor):

### **VMware Workstation/Player:**

1. **VM herunterfahren** (WICHTIG!)

2. **VMX-Datei bearbeiten:**
   ```
   C:\Users\...\Documents\Virtual Machines\VM\VM.vmx
   ```

3. **Folgende Zeilen hinzufügen:**
   ```
   vhv.enable = "TRUE"
   hypervisor.cpuid.v0 = "FALSE"
   mce.enable = "TRUE"
   vvtd.enable = "TRUE"
   ```

4. **VM starten**

5. **Verify:**
   ```powershell
   bcdedit /set hypervisorlaunchtype auto
   bcdedit /enum | Select-String hypervisor
   # Sollte zeigen: hypervisorlaunchtype    Auto
   ```

---

### **Hyper-V:**

```powershell
# VM herunterfahren, dann:
Set-VMProcessor -VMName "VM" -ExposeVirtualizationExtensions $true

# VM starten
```

---

### **VirtualBox:**

VirtualBox **unterstützt KEINE** Nested Virtualization mit Hyper-V!

**Alternativen:**
1. Verwende VMware Workstation/Player
2. Verwende Hyper-V (kostenlos in Windows Pro)
3. **ODER:** Akzeptiere dass VBS/Credential Guard nicht funktioniert
   - Script funktioniert TROTZDEM zu 99%!
   - Nur VBS/Credential Guard fehlt

---

## 🎯 Nach dem Fix:

```powershell
# Neustart
Restart-Computer

# Nach Neustart - Verify:
$vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
$vbs.SecurityServicesRunning
# Erwartete Ausgabe: 1 oder 2 (Credential Guard läuft)
```

---

## ⚠️ WICHTIG:

**Auch OHNE Nested Virtualization:**
- ✅ 134/136 Checks PASSED (99%)
- ✅ ASR Rules: AKTIV
- ✅ Defender: MAXIMUM
- ✅ Firewall: STRICT
- ✅ Privacy: MAXIMUM
- ❌ Nur VBS/Credential Guard fehlt

**Das Script ist TROTZDEM extrem sicher!**
VBS ist nur 1 von 478 Security-Settings!
