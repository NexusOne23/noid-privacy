<#
.SYNOPSIS
    Localization utilities for international Windows support

.DESCRIPTION
    Provides functions for detecting system locale and handling
    locale-specific paths (e.g., ADMX templates in en-US, de-DE, etc.)
#>

function Get-SystemLocale {
    <#
    .SYNOPSIS
        Detect system locale for ADMX template paths
        
    .DESCRIPTION
        Detects the current Windows UI language and returns the locale string
        (e.g., "de-DE", "en-US", "fr-FR") for use in ADMX template paths.
        Falls back to "en-US" if detection fails.
        
    .OUTPUTS
        String - Locale identifier (e.g., "en-US")
        
    .EXAMPLE
        $locale = Get-SystemLocale
        # Returns "en-US" on English Windows
        
    .NOTES
        Uses Get-Culture as primary method, with multiple fallbacks
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    
    try {
        Write-Log -Level DEBUG -Message "Detecting system locale..." -Module "Localization"
        
        # Method 1: Get UI Culture (most reliable)
        $culture = Get-Culture
        $locale = $culture.Name
        
        Write-Log -Level DEBUG -Message "Culture detected: $locale" -Module "Localization"
        
        # Validate format (should be xx-XX)
        if ($locale -match '^[a-z]{2}-[A-Z]{2}$') {
            Write-Log -Level INFO -Message "Using system locale: $locale" -Module "Localization"
            return $locale
        }
        
        # Method 2: Try WinSystemLocale as fallback
        try {
            $systemLocale = Get-WinSystemLocale
            $locale = $systemLocale.Name
            
            if ($locale -match '^[a-z]{2}-[A-Z]{2}$') {
                Write-Log -Level INFO -Message "Using system locale from WinSystemLocale: $locale" -Module "Localization"
                return $locale
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "Get-WinSystemLocale failed: $_" -Module "Localization"
        }
        
        # Method 3: Registry fallback
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language"
            $regValue = Get-ItemProperty -Path $regPath -Name "InstallLanguage" -ErrorAction Stop
            $languageId = $regValue.InstallLanguage
            
            # Map common language IDs to locale strings
            $languageMap = @{
                "0409" = "en-US"  # English (US)
                "0809" = "en-GB"  # English (UK)
                "0407" = "de-DE"  # German
                "040c" = "fr-FR"  # French
                "0410" = "it-IT"  # Italian
                "0c0a" = "es-ES"  # Spanish
                "0413" = "nl-NL"  # Dutch
                "0416" = "pt-BR"  # Portuguese (Brazil)
                "0419" = "ru-RU"  # Russian
                "0411" = "ja-JP"  # Japanese
                "0804" = "zh-CN"  # Chinese (Simplified)
                "0404" = "zh-TW"  # Chinese (Traditional)
                "0412" = "ko-KR"  # Korean
            }
            
            if ($languageMap.ContainsKey($languageId)) {
                $locale = $languageMap[$languageId]
                Write-Log -Level INFO -Message "Using locale from registry: $locale (ID: $languageId)" -Module "Localization"
                return $locale
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "Registry locale detection failed: $_" -Module "Localization"
        }
        
        # Ultimate fallback: en-US (universally available)
        Write-Log -Level WARNING -Message "Could not reliably detect locale, using en-US" -Module "Localization"
        return "en-US"
    }
    catch {
        Write-Log -Level WARNING -Message "Locale detection failed: $_. Using en-US" -Module "Localization" -Exception $_
        return "en-US"
    }
}

function Test-LocaleAvailability {
    <#
    .SYNOPSIS
        Check if a specific locale exists in a directory
        
    .DESCRIPTION
        Checks if a locale subdirectory exists and contains files
        
    .PARAMETER BasePath
        Base path containing locale subdirectories
        
    .PARAMETER Locale
        Locale to check (e.g., "de-DE")
        
    .PARAMETER FilePattern
        Optional file pattern to check for (e.g., "*.admx")
        
    .OUTPUTS
        Boolean - True if locale directory exists with files
        
    .EXAMPLE
        Test-LocaleAvailability -BasePath "C:\Templates" -Locale "de-DE"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        
        [Parameter(Mandatory = $true)]
        [string]$Locale,
        
        [Parameter(Mandatory = $false)]
        [string]$FilePattern = "*"
    )
    
    $localePath = Join-Path $BasePath $Locale
    
    Write-Log -Level DEBUG -Message "Checking locale availability: $localePath" -Module "Localization"
    
    if (Test-Path $localePath) {
        # Check if directory contains files
        $files = Get-ChildItem -Path $localePath -Filter $FilePattern -ErrorAction SilentlyContinue
        
        if ($files.Count -gt 0) {
            Write-Log -Level DEBUG -Message "Locale $Locale found with $($files.Count) files" -Module "Localization"
            return $true
        }
    }
    
    Write-Log -Level DEBUG -Message "Locale $Locale not available" -Module "Localization"
    return $false
}

function Get-AvailableLocaleWithFallback {
    <#
    .SYNOPSIS
        Get best available locale with fallback to en-US
        
    .DESCRIPTION
        Tries to find the system locale first, falls back to en-US if not found
        
    .PARAMETER BasePath
        Base path containing locale subdirectories
        
    .PARAMETER FilePattern
        Optional file pattern to check for
        
    .OUTPUTS
        String - Best available locale
        
    .EXAMPLE
        $locale = Get-AvailableLocaleWithFallback -BasePath "C:\Templates"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        
        [Parameter(Mandatory = $false)]
        [string]$FilePattern = "*"
    )
    
    # Get system locale
    $systemLocale = Get-SystemLocale
    
    # Check if system locale is available
    if (Test-LocaleAvailability -BasePath $BasePath -Locale $systemLocale -FilePattern $FilePattern) {
        Write-Log -Level INFO -Message "Using detected locale: $systemLocale" -Module "Localization"
        return $systemLocale
    }
    
    # Fallback to en-US
    $fallbackLocale = "en-US"
    Write-Log -Level WARNING -Message "Locale $systemLocale not available, falling back to $fallbackLocale" -Module "Localization"
    
    if (Test-LocaleAvailability -BasePath $BasePath -Locale $fallbackLocale -FilePattern $FilePattern) {
        return $fallbackLocale
    }
    
    # If even en-US is not available, throw error
    throw "Neither $systemLocale nor $fallbackLocale locale available in $BasePath"
}
