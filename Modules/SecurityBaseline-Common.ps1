# =======================================================================================
# SecurityBaseline-Common.ps1 - Gemeinsame Helper-Functions
# =======================================================================================

<#
.SYNOPSIS
    Gemeinsame Helper-Functions fuer alle SecurityBaseline-Module
.DESCRIPTION
    Zentralisiert Code-Duplikation von Logging/Output-Funktionen.
    Best Practice 25H2: DRY (Don't Repeat Yourself)
#>

# Best Practice 25H2: Strict Mode aktivieren
Set-StrictMode -Version Latest

function Write-Section {
    <#
    .SYNOPSIS
        Schreibt einen Section-Header
    .PARAMETER Text
        Header-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Info {
    <#
    .SYNOPSIS
        Schreibt eine Info-Meldung
    .PARAMETER Message
        Info-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[i] $Message" -ForegroundColor Cyan
}

function Write-Success {
    <#
    .SYNOPSIS
        Schreibt eine Success-Meldung
    .PARAMETER Message
        Success-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning-Custom {
    <#
    .SYNOPSIS
        Schreibt eine Custom-Warning (nicht Write-Warning weil das zu verbose ist)
    .PARAMETER Message
        Warning-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    <#
    .SYNOPSIS
        Schreibt eine Custom-Error-Meldung (nicht Write-Error weil das zu disruptiv ist)
    .PARAMETER Message
        Error-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Set-RegistryValue {
    <#
    .SYNOPSIS
        Setzt einen Registry-Wert mit automatischer Key-Erstellung
    .DESCRIPTION
        Helper-Function die automatisch fehlende Registry-Keys erstellt.
        Best Practice 25H2: Robuste String-Formatierung, Error-Handling
        
        HINWEIS: Fuer TrustedInstaller-geschuetzte Keys verwende Set-RegistryValueSmart
                 aus dem RegistryOwnership-Modul!
    .PARAMETER Path
        Registry-Pfad
    .PARAMETER Name
        Wert-Name
    .PARAMETER Value
        Wert
    .PARAMETER Type
        Registry-Typ (DWord, String, etc.)
    .PARAMETER Description
        Optionale Beschreibung fuer Logging
    .OUTPUTS
        [bool] $true bei Erfolg, $false bei Fehler
    .EXAMPLE
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Test" -Name "Value" -Value 1 -Type DWord
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
    
    try {
        # Erstelle Key falls nicht vorhanden
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "Erstelle Registry-Key: $Path"
            $null = New-Item -Path $Path -Force -ErrorAction Stop
        }
        
        # Prüfe ob Wert existiert
        $valueExists = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($valueExists) {
            # Wert existiert - Set-ItemProperty (KEIN -Type Parameter in PS 5.1!)
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
        }
        else {
            # Wert existiert NICHT - New-ItemProperty (MIT -PropertyType!)
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
        
        if ($Description) {
            Write-Verbose "     $Description : $Name = $Value"
        }
        else {
            Write-Verbose "     Registry gesetzt: $Path\$Name = $Value"
        }
        
        return $true
    }
    catch {
        Write-Error-Custom "Fehler bei Registry-Aenderung: $Path\$Name - $_"
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
}

function Stop-ServiceSafe {
    <#
    .SYNOPSIS
        Stoppt und deaktiviert einen Service race-condition-frei
    .DESCRIPTION
        Best Practice 25H2: Automatisches Ownership Management + Rollbacke Condition
        
        PROBLEM (alt):
            Stop-Service -> Service stoppt
            Set-Service -StartupType Disabled
            -> RACE: Service koennte zwischen Stop und SetStartupType neu starten!
        
        LOESUNG (neu):
            1. Set-Service -StartupType Disabled ZUERST (verhindert Restart)
            2. Stop-Service mit -NoWait
            3. Warte bis Service wirklich gestoppt ist (max. MaxWaitSeconds)
            4. Final-Check ob wirklich Disabled
    .PARAMETER ServiceName
        Name des Service
    .PARAMETER MaxWaitSeconds
        Maximale Wartezeit in Sekunden (Standard: 10)
    .OUTPUTS
        [bool] $true bei Erfolg, $false bei Fehler
    .EXAMPLE
        Stop-ServiceSafe -ServiceName "DiagTrack"
    .EXAMPLE
        Stop-ServiceSafe -ServiceName "WerSvc" -MaxWaitSeconds 5
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName,
        
        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$MaxWaitSeconds = 10
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Verbose "Service '$ServiceName' nicht gefunden (normal bei Legacy-Services in Windows 11)"
            return $false
        }
        
        Write-Verbose "Deaktiviere Service: $ServiceName (Status: $($service.Status))"
        
        # === STEP 1: StartupType auf Disabled ZUERST ===
        # KRITISCH: Verhindert dass Service zwischen Stop und SetStartupType neu startet
        # Track Errors via $Error.Count (reliable!)
        $errorBefore = $Error.Count
        
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        
        # Check ob Error aufgetreten ist via Error.Count
        if ($Error.Count -eq $errorBefore) {
            # Kein Error = Erfolg
            Write-Verbose "     StartupType: Disabled"
        } else {
            # Error = Legacy Service nicht konfigurierbar
            Write-Verbose "     Set-Service fehlgeschlagen (Legacy Service nicht konfigurierbar)"
            return $false
        }
        
        # === STEP 2: Pruefe ob Service laeuft ===
        if ($service.Status -ne "Stopped") {
            # === STEP 3: Stoppe Service ===
            Stop-Service -Name $ServiceName -Force -NoWait -ErrorAction Stop
            Write-Verbose "     Stop-Command gesendet"
            
            # === STEP 4: Warte bis wirklich gestoppt ===
            $waited = 0
            do {
                Start-Sleep -Milliseconds 500
                $waited += 0.5
                
                $service = Get-Service -Name $ServiceName
                if ($service.Status -eq "Stopped") {
                    Write-Verbose "     Service gestoppt nach ${waited}s"
                    break
                }
                
                if ($waited -ge $MaxWaitSeconds) {
                    Write-Warning "Service $ServiceName stoppt nicht - Timeout nach ${MaxWaitSeconds}s"
                    Write-Warning "  Status: $($service.Status)"
                    # Nicht kritisch - StartupType=Disabled ist wichtiger
                    break
                }
            } while ($true)
        }
        else {
            Write-Verbose "     Service war bereits gestoppt"
        }
        
        # === STEP 5: Final-Check ===
        # CRITICAL FIX: Get-Service hat KEINE StartupType Property in PowerShell 5.1!
        # LÖSUNG: Verwende Get-CimInstance für StartupType-Check
        try {
            $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
            if ($serviceCim.StartMode -eq "Disabled") {
                $service = Get-Service -Name $ServiceName  # Refresh für Status
                if ($service.Status -eq "Stopped") {
                    Write-Verbose "[OK] $($ServiceName) - Disabled + Stopped"
                    return $true
                }
                else {
                    # StartupType=Disabled ist erreicht, Status ist weniger kritisch
                    Write-Verbose "[OK] $($ServiceName) - Disabled (Status=$($service.Status) - wird beim naechsten Reboot nicht starten)"
                    return $true
                }
            }
            else {
                Write-Error-Custom "Service $ServiceName konnte nicht deaktiviert werden (StartMode=$($serviceCim.StartMode))"
                return $false
            }
        }
        catch {
            Write-Verbose "CIM-Check fehlgeschlagen, verwende Fallback: $_"
            # Fallback: Annahme dass Set-Service erfolgreich war
            Write-Verbose "[OK] $($ServiceName) - Disabled (angenommen - Set-Service war erfolgreich)"
            return $true
        }
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        # Service existiert nicht - das ist OK (bereits deinstalliert oder nie installiert)
        Write-Verbose "Service $ServiceName nicht gefunden (OK - nicht installiert)"
        return $true
    }
    catch {
        Write-Error-Custom "Fehler beim Deaktivieren von Service $ServiceName : $_"
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
