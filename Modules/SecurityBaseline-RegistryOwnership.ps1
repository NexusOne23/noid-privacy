# =======================================================================================
# SecurityBaseline-RegistryOwnership.ps1
# TrustedInstaller Registry Ownership Management (Best Practice 2025)
# =======================================================================================

<#
.SYNOPSIS
    Ermöglicht das Setzen von TrustedInstaller-geschützten Registry-Keys
    
.DESCRIPTION
    Professionelles Ownership-Management für geschützte Registry-Keys.
    
    PROZESS:
    1. Backup: Speichere Original-Owner und Permissions
    2. Take Ownership: Ändere zu BUILTIN\Administrators
    3. Grant Access: Gebe Administrators Full Control
    4. Modify: Setze den gewünschten Wert
    5. Restore: Stelle Original-Owner und Permissions wieder her
    
.NOTES
    Version:        1.0.0
    Author:         NoID Privacy Team
    Creation Date:  January 2026
    
    SICHERHEIT:
    - Vollständiges Backup vor Änderungen
    - Automatic Restore nach Änderungen
    - Error-Handling auf jeder Ebene
    
    GETESTET MIT:
    - HKLM:\SOFTWARE\Microsoft\Windows Defender\Features
    - Andere TrustedInstaller-geschützte Keys
#>

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

# ===== PRIVILEGE MANAGEMENT (KRITISCH FÜR TRUSTEDINSTALLER RESTORE!) =====

function Enable-Privilege {
    <#
    .SYNOPSIS
        Aktiviert Windows-Privilege für aktuellen Prozess
    .DESCRIPTION
        KRITISCH: SeRestorePrivilege wird benötigt um Ownership zurück zu TrustedInstaller zu setzen!
        Basiert auf Best Practice aus StackOverflow (2025)
    .PARAMETER Privilege
        Privilege-Name (z.B. "SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege")
    .OUTPUTS
        [bool] $true bei Erfolg
    .LINK
        https://stackoverflow.com/questions/5467909/how-to-write-in-a-registry-key-own-by-trustedinstaller
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SeRestorePrivilege', 'SeBackupPrivilege', 'SeTakeOwnershipPrivilege', 'SeSecurityPrivilege')]
        [string]$Privilege
    )
    
    try {
        # P/Invoke Definitions für Token Manipulation
        $signature = @"
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
            
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
                ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
            
            [DllImport("kernel32.dll", ExactSpelling = true)]
            public static extern IntPtr GetCurrentProcess();
            
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
            
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }
            
            public const int SE_PRIVILEGE_ENABLED = 0x00000002;
            public const int TOKEN_QUERY = 0x00000008;
            public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
"@
        
        # Erstelle Typ falls noch nicht vorhanden
        if (-not ([System.Management.Automation.PSTypeName]'TokenManipulator').Type) {
            Add-Type -MemberDefinition $signature -Name TokenManipulator -Namespace RegistryOwnership -ErrorAction Stop
        }
        
        # Hole Current Process Token
        $token = [IntPtr]::Zero
        $hProcess = [RegistryOwnership.TokenManipulator]::GetCurrentProcess()
        
        if (-not [RegistryOwnership.TokenManipulator]::OpenProcessToken(
            $hProcess,
            [RegistryOwnership.TokenManipulator]::TOKEN_ADJUST_PRIVILEGES -bor [RegistryOwnership.TokenManipulator]::TOKEN_QUERY,
            [ref]$token
        )) {
            Write-Verbose "Fehler beim Oeffnen des Process Token"
            return $false
        }
        
        # Lookup Privilege Value
        $luid = 0L
        if (-not [RegistryOwnership.TokenManipulator]::LookupPrivilegeValue($null, $Privilege, [ref]$luid)) {
            Write-Verbose "Fehler beim Lookup von $Privilege"
            return $false
        }
        
        # Prepare TOKEN_PRIVILEGES Struktur
        $tokPriv = New-Object RegistryOwnership.TokenManipulator+TokPriv1Luid
        $tokPriv.Count = 1
        $tokPriv.Luid = $luid
        $tokPriv.Attr = [RegistryOwnership.TokenManipulator]::SE_PRIVILEGE_ENABLED
        
        # Adjust Token Privileges
        if (-not [RegistryOwnership.TokenManipulator]::AdjustTokenPrivileges(
            $token,
            $false,
            [ref]$tokPriv,
            0,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )) {
            Write-Verbose "Fehler beim AdjustTokenPrivileges fuer $Privilege"
            return $false
        }
        
        Write-Verbose "Privilege aktiviert: $Privilege"
        return $true
    }
    catch {
        Write-Verbose "Fehler beim Aktivieren von $Privilege : $_"
        return $false
    }
}

function Set-RegistryValueWithOwnership {
    <#
    .SYNOPSIS
        Setzt Registry-Wert auch bei TrustedInstaller-Protection
    .DESCRIPTION
        Nimmt temporär Ownership, setzt Wert, restored Ownership.
        Best Practice 2025: Vollständiges Backup/Restore
    .PARAMETER Path
        Registry-Pfad
    .PARAMETER Name
        Wert-Name
    .PARAMETER Value
        Wert
    .PARAMETER Type
        Registry-Typ (DWord, String, etc.)
    .PARAMETER Description
        Beschreibung für Logging
    .OUTPUTS
        [bool] $true bei Erfolg, $false bei Fehler
    .EXAMPLE
        Set-RegistryValueWithOwnership -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" `
            -Name "EnableAppInstallControl" -Value 1 -Type DWord
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value,
        
        [Parameter()]
        [Microsoft.Win32.RegistryValueKind]$Type = 'DWord',
        
        [Parameter()]
        [string]$Description
    )
    
    # WICHTIG: Konvertiere PowerShell-Path zu Registry-Path
    # "HKLM:\SOFTWARE\..." -> "HKEY_LOCAL_MACHINE\SOFTWARE\..."
    $registryPath = $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' `
                         -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' `
                         -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\' `
                         -replace '^HKU:\\', 'HKEY_USERS\' `
                         -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
    
    Write-Verbose "Registry-Path: $registryPath"
    Write-Verbose "Setting: $Name = $Value"
    if ($Description) {
        Write-Verbose "Description: $Description"
    }
    
    # ===== BACKUP: Speichere Original-ACL =====
    $originalACL = $null
    $originalOwner = $null
    
    # Determine Registry Hive (HKLM, HKCU, HKU, etc.)
    $hive = $null
    $subKeyPath = ''
    
    if ($registryPath -match '^HKEY_LOCAL_MACHINE\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::LocalMachine
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_CURRENT_USER\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::CurrentUser
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_USERS\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::Users
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_CLASSES_ROOT\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::ClassesRoot
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_CURRENT_CONFIG\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::CurrentConfig
        $subKeyPath = $matches[1]
    }
    else {
        Write-Error-Custom "Unsupported registry hive: $registryPath"
        return $false
    }
    
    try {
        # Hole aktuelle ACL (Owner + Permissions)
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
            [System.Security.AccessControl.RegistryRights]::ReadPermissions
        )
        
        if ($null -eq $key) {
            Write-Verbose "Registry-Key nicht gefunden: $Path (nicht kritisch)"
            return $false
        }
        
        $originalACL = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::All)
        $originalOwner = $originalACL.Owner
        $key.Close()
        
        Write-Verbose "Original Owner: $originalOwner"
        Write-Verbose "Original ACL gesichert"
    }
    catch {
        Write-Verbose "Fehler beim Lesen der Original-ACL: $_ (TrustedInstaller-Protected)"
        return $false
    }
    
    # ===== STEP 1: TAKE OWNERSHIP =====
    try {
        Write-Verbose "STEP 1: Take Ownership to BUILTIN\Administrators"
        
        # KRITISCH: Enable SeTakeOwnershipPrivilege BEVOR wir OpenSubKey callen!
        # Ohne dieses Privilege schlägt OpenSubKey mit "Access Denied" fehl!
        Write-Verbose "     Activate SeTakeOwnershipPrivilege..."
        $takeOwnershipEnabled = Enable-Privilege -Privilege 'SeTakeOwnershipPrivilege'
        
        if (-not $takeOwnershipEnabled) {
            Write-Verbose "SeTakeOwnershipPrivilege konnte nicht aktiviert werden (TrustedInstaller-Protected)"
            Write-Verbose "Administrator-Rechte vorhanden aber Key ist geschuetzt"
            return $false
        }
        
        # Öffne Key mit TakeOwnership-Rechten
        # WICHTIG: Wir brauchen ReadPermissions + TakeOwnership kombiniert!
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )
        
        if ($null -eq $key) {
            Write-Verbose "Konnte Key nicht oeffnen fuer TakeOwnership: $Path (TrustedInstaller-Protected)"
            return $false
        }
        
        # Erstelle neue ACL mit Administrators als Owner
        $acl = $key.GetAccessControl()
        
        # BUILTIN\Administrators als neuer Owner
        # KRITISCH: Verwende SID statt Name (language-independent!)
        # S-1-5-32-544 = BUILTIN\Administrators (auf allen Sprachen!)
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $administratorsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])
        $acl.SetOwner($administratorsGroup)
        
        # Setze neue ACL
        $key.SetAccessControl($acl)
        $key.Close()
        
        Write-Verbose "     Ownership changed to: BUILTIN\Administrators"
    }
    catch {
        Write-Verbose "Take Ownership failed (TrustedInstaller too strong): $_"
        Write-Verbose "ACCEPTED: Registry-Key remains TrustedInstaller-protected (not critical)"
        # KEINE weiteren Versuche! TrustedInstaller-Keys sind ABSICHTLICH geschuetzt!
        # Die Funktionalitaet (z.B. PUA) funktioniert AUCH OHNE diese Registry-Werte!
        # Set-MpPreference setzt die Einstellungen auf anderem Weg.
        return $false
    }
    
    # ===== STEP 2: GRANT FULL CONTROL =====
    try {
        Write-Verbose "STEP 2: Grant Full Control to Administrators"
        
        # Öffne Key mit ChangePermissions-Rechten
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions
        )
        
        $acl = $key.GetAccessControl()
        
        # Erstelle Full Control Rule für Administrators
        # KRITISCH: Verwende SID statt Name (language-independent!)
        # S-1-5-32-544 = BUILTIN\Administrators (auf allen Sprachen!)
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $administratorsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])
        $fullControlRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $administratorsGroup,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
        # Füge Rule hinzu
        $acl.AddAccessRule($fullControlRule)
        $key.SetAccessControl($acl)
        $key.Close()
        
        Write-Verbose "  -> Full Control granted to: BUILTIN\Administrators"
    }
    catch {
        Write-Verbose "Fehler beim Grant Access: $_ (TrustedInstaller-Protected)"
        
        # Versuche Restore
        try {
            Write-Verbose "Versuche Original-ACL wiederherzustellen..."
            # Enable SeRestorePrivilege für TrustedInstaller-Restore
            $null = Enable-Privilege -Privilege 'SeRestorePrivilege'
            $key = $hive.OpenSubKey(
                $subKeyPath,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                [System.Security.AccessControl.RegistryRights]::TakeOwnership
            )
            $key.SetAccessControl($originalACL)
            $key.Close()
            Write-Verbose "     Original-ACL wiederhergestellt"
        }
        catch {
            Write-Warning-Custom "Konnte Original-ACL nicht wiederherstellen: $_"
        }
        
        return $false
    }
    
    # ===== STEP 3: MODIFY VALUE =====
    try {
        Write-Verbose "STEP 3: Setze Registry-Wert"
        
        # Prüfe ob Wert existiert
        $valueExists = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($valueExists) {
            # Wert existiert - Set-ItemProperty (KEIN -PropertyType Parameter in PS 5.1!)
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
        }
        else {
            # Wert existiert NICHT - New-ItemProperty (MIT -PropertyType!)
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
        
        Write-Verbose "  -> Wert erfolgreich gesetzt: $Name = $Value"
    }
    catch {
        Write-Verbose "Fehler beim Setzen des Wertes: $_ (TrustedInstaller-Protected)"
        
        # Versuche Restore
        try {
            Write-Verbose "Versuche Original-ACL wiederherzustellen..."
            # Enable SeRestorePrivilege für TrustedInstaller-Restore
            $null = Enable-Privilege -Privilege 'SeRestorePrivilege'
            $key = $hive.OpenSubKey(
                $subKeyPath,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                [System.Security.AccessControl.RegistryRights]::TakeOwnership
            )
            $key.SetAccessControl($originalACL)
            $key.Close()
            Write-Verbose "     Original-ACL wiederhergestellt"
        }
        catch {
            Write-Warning-Custom "Konnte Original-ACL nicht wiederherstellen: $_"
        }
        
        return $false
    }
    
    # ===== STEP 4: RESTORE ORIGINAL ACL =====
    try {
        Write-Verbose "STEP 4: Restore Original Owner and Permissions"
        
        # KRITISCH: Enable SeRestorePrivilege BEVOR wir TrustedInstaller-Ownership restaurieren!
        # Ohne dieses Privilege schlägt SetAccessControl fehl bei TrustedInstaller-Owner!
        # Best Practice aus StackOverflow: https://stackoverflow.com/questions/5467909
        Write-Verbose "     Activate SeRestorePrivilege for TrustedInstaller-Restore..."
        $privilegeEnabled = Enable-Privilege -Privilege 'SeRestorePrivilege'
        
        if (-not $privilegeEnabled) {
            Write-Verbose "     WARNING: SeRestorePrivilege konnte nicht aktiviert werden"
            Write-Verbose "     Restore wird trotzdem versucht (funktioniert moeglicherweise nicht bei TrustedInstaller)"
        }
        
        # Öffne Key mit vollen Rechten
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )
        
        # Restore Original-ACL (inkl. Owner)
        # Mit SeRestorePrivilege kann auch TrustedInstaller als Owner gesetzt werden!
        $key.SetAccessControl($originalACL)
        $key.Close()
        
        Write-Verbose "  -> Original Owner wiederhergestellt: $originalOwner"
        Write-Verbose "  -> Original Permissions wiederhergestellt"
    }
    catch {
        # NICHT KRITISCH! Registry-Wert wurde ERFOLGREICH gesetzt!
        # Nur der Restore des Original-Owners ist fehlgeschlagen (meist TrustedInstaller)
        Write-Verbose "Original-ACL Restore fehlgeschlagen (NICHT KRITISCH): $_"
        Write-Verbose "Key-Owner bleibt: BUILTIN\Administrators (statt $originalOwner)"
        Write-Verbose "Registry-Wert wurde ERFOLGREICH gesetzt - Windows funktioniert normal"
        Write-Verbose "Moegliche Ursache: SeRestorePrivilege nicht verfuegbar oder TrustedInstaller-Restore blockiert"
        # KEIN Error werfen - die Hauptfunktion (Registry-Wert setzen) war ERFOLGREICH!
    }
    
    # ===== SUCCESS =====
    if ($Description) {
        Write-Verbose "[OK] $Description"
    }
    Write-Verbose "[OK] Registry-Wert erfolgreich gesetzt (mit Ownership-Management)"
    
    return $true
}

function Set-RegistryValueSmart {
    <#
    .SYNOPSIS
        Intelligente Registry-Funktion mit automatischem Ownership-Management
    .DESCRIPTION
        Versucht erst normales Set-ItemProperty.
        Bei Access Denied -> automatisches Ownership-Management.
        Best Practice 2025: Try normal first, escalate only if needed
    .PARAMETER Path
        Registry-Pfad
    .PARAMETER Name
        Wert-Name
    .PARAMETER Value
        Wert
    .PARAMETER Type
        Registry-Typ
    .PARAMETER Description
        Beschreibung
    .OUTPUTS
        [bool] $true bei Erfolg
    .EXAMPLE
        Set-RegistryValueSmart -Path $path -Name $name -Value $value -Type DWord
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value,
        
        [Parameter()]
        [Microsoft.Win32.RegistryValueKind]$Type = 'DWord',
        
        [Parameter()]
        [string]$Description
    )
    
    # STEP 1: Versuche normales Set-ItemProperty
    Write-Verbose "Versuche normales Set-ItemProperty..."
    
    # CRITICAL FIX: Set-ItemProperty mit ErrorActionPreference = 'SilentlyContinue'
    # Unterdrückt Error im Transcript aber Try-Catch funktioniert trotzdem!
    $oldPref = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Erstelle Key falls nicht vorhanden
    if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
        Write-Verbose "Erstelle Registry-Key: $Path"
        $null = New-Item -Path $Path -Force
    }
    
    # Prüfe ob Wert existiert (SAFE method - no error records!)
    # Get ALL properties first, then check if our property is in the list
    # This prevents error records from being created when property doesn't exist
    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $valueExists = $item -and ($item.PSObject.Properties.Name -contains $Name)
    
    # Track Errors NACH dem Exists-Check
    $errorBefore = $Error.Count
    
    if ($valueExists) {
        # Wert existiert - Set-ItemProperty (KEIN -PropertyType in PS 5.1!)
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
    else {
        # Wert existiert NICHT - New-ItemProperty (MIT -PropertyType!)
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
    
    # Reset ErrorActionPreference SOFORT
    $ErrorActionPreference = $oldPref
    
    # Check ob Error aufgetreten ist (NUR von Set/New, nicht vom Exists-Check!)
    $errorAfter = $Error.Count
    if ($errorAfter -eq $errorBefore) {
        # Kein Error = Erfolg!
        if ($Description) {
            Write-Verbose "     $Description : $Name = $Value"
        }
        return $true
    }
    else {
        # Error aufgetreten - check ob Access Denied
        $lastError = $Error[0]
        $errorMsg = $lastError.Exception.Message
        $isAccessDenied = $false
        
        # Deutsche + Englische Fehlermeldungen
        if ($errorMsg -match "Access.*denied|Zugriff.*verweigert|unzulässig|angeforderte.*Registrierungszugriff") {
            $isAccessDenied = $true
        }
        
        # HResult Check (0x80070005 = Access Denied)
        if ($lastError.Exception.HResult -eq 0x80070005 -or $lastError.Exception.HResult -eq -2147024891) {
            $isAccessDenied = $true
        }
        
        if ($isAccessDenied) {
            # Access Denied - das ist ERWARTET bei TrustedInstaller Keys!
            # Caller (z.B. Core-Modul) hat Fallback (Set-RegistryValueWithOwnership)
            # WICHTIG: Entferne Error aus $Error Array (wird von Caller behandelt!)
            $Error.RemoveAt(0)
            Write-Verbose "Access Denied bei $Path\$Name (erwartet, Caller hat Fallback)"
            return $false
        }
        else {
            # Anderer Fehler - nur Verbose, kein Error (Caller entscheidet ob Warning)
            Write-Verbose "Fehler beim Setzen von $Path\$Name : $errorMsg"
            return $false
        }
    }
}

# Export Functions (für Dot-Sourcing)
# Functions sind automatisch verfügbar im calling scope
