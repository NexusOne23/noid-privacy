<#
.SYNOPSIS
    Unified logging system for NoID Privacy Framework
    
.DESCRIPTION
    Provides centralized logging functionality with multiple severity levels,
    file output, and optional console output with color coding.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Requires: PowerShell 5.1+
#>

# Log severity levels
enum LogLevel {
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    SUCCESS = 4
}

# Global logger configuration - MUST be $global: for cross-module session sharing
# Using $script: would create separate log files per Import-Module call!
# NOTE: Must use Get-Variable to check existence (direct access fails in Strict Mode)
if (-not (Get-Variable -Name 'LoggerConfig' -Scope Global -ErrorAction SilentlyContinue)) {
    $global:LoggerConfig = @{
        LogFilePath     = ""
        MinimumLevel    = [LogLevel]::INFO
        EnableConsole   = $true
        EnableFile      = $true
        TimestampFormat = "yyyy-MM-dd HH:mm:ss"
    }
}

function Initialize-Logger {
    <#
    .SYNOPSIS
        Initialize the logging system
        
    .PARAMETER LogDirectory
        Directory path for log files
        
    .PARAMETER MinimumLevel
        Minimum log level to record (DEBUG, INFO, WARNING, ERROR, SUCCESS)
        
    .PARAMETER EnableConsole
        Enable console output
        
    .PARAMETER EnableFile
        Enable file output
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogDirectory = (Join-Path $PSScriptRoot "..\Logs"),
        
        [Parameter(Mandatory = $false)]
        [LogLevel]$MinimumLevel = [LogLevel]::INFO,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableConsole = $true,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableFile = $true
    )
    
    # Reuse existing session if already initialized
    if ($global:LoggerConfig.LogFilePath -and (Test-Path -Path $global:LoggerConfig.LogFilePath)) {
        Write-Host "[Logger] Reusing existing log session: $($global:LoggerConfig.LogFilePath)" -ForegroundColor DarkGray
        return
    }
    
    # Create log directory if it doesn't exist
    if ($EnableFile) {
        if (-not (Test-Path -Path $LogDirectory)) {
            try {
                New-Item -ItemType Directory -Path $LogDirectory -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[ERROR] Failed to create log directory: $LogDirectory" -ForegroundColor Red
                Write-Host "[ERROR] Exception: $_" -ForegroundColor Red
                $EnableFile = $false
            }
        }
    }
    
    # Generate log file name with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "NoIDPrivacy_$timestamp.log"
    $global:LoggerConfig.LogFilePath = Join-Path $LogDirectory $logFileName
    $global:LoggerConfig.MinimumLevel = $MinimumLevel
    $global:LoggerConfig.EnableConsole = $EnableConsole
    $global:LoggerConfig.EnableFile = $EnableFile
    
    # Test if we can write to the log file
    if ($EnableFile) {
        try {
            "# NoID Privacy Log File" | Out-File -FilePath $global:LoggerConfig.LogFilePath -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Host "[ERROR] Failed to create log file: $($global:LoggerConfig.LogFilePath)" -ForegroundColor Red
            Write-Host "[ERROR] Exception: $_" -ForegroundColor Red
            $global:LoggerConfig.EnableFile = $false
        }
    }
    
    # Write initial log entry
    Write-Log -Level INFO -Message "Logger initialized" -Module "Logger"
    Write-Log -Level INFO -Message "Log file: $($global:LoggerConfig.LogFilePath)" -Module "Logger"
}

function Write-Log {
    <#
    .SYNOPSIS
        Write a log entry
        
    .PARAMETER Level
        Log severity level
        
    .PARAMETER Message
        Log message content
        
    .PARAMETER Module
        Module or component name generating the log
        
    .PARAMETER Exception
        Optional exception object for error logging
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [LogLevel]$Level,
        
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$Module = "Framework",
        
        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception = $null
    )
    
    # Check if level meets minimum threshold
    if ($Level -lt $global:LoggerConfig.MinimumLevel) {
        return
    }
    
    # Format timestamp
    $timestamp = Get-Date -Format $global:LoggerConfig.TimestampFormat
    
    # Build log entry
    $logEntry = "[$timestamp] [$Level] [$Module] $Message"
    
    # Add exception details if present
    if ($null -ne $Exception) {
        $logEntry += "`n    Exception: $($Exception.Message)"
        $logEntry += "`n    StackTrace: $($Exception.StackTrace)"
    }
    
    # Write to file with robust retry logic
    if ($global:LoggerConfig.EnableFile -and $global:LoggerConfig.LogFilePath) {
        $maxRetries = 5
        $retryDelayMs = 100
        $writeSuccess = $false
        $lastError = $null

        for ($i = 0; $i -lt $maxRetries; $i++) {
            try {
                Add-Content -Path $global:LoggerConfig.LogFilePath -Value $logEntry -Encoding UTF8 -ErrorAction Stop
                $writeSuccess = $true
                break
            }
            catch {
                $lastError = $_
                Start-Sleep -Milliseconds $retryDelayMs
                # Exponential backoff
                $retryDelayMs *= 2
            }
        }

        if (-not $writeSuccess) {
            # Write error to console with detailed info only after all retries failed
            Write-Host "[FILE WRITE ERROR] Failed to write to log file after $maxRetries attempts: $($global:LoggerConfig.LogFilePath)" -ForegroundColor Red
            Write-Host "[FILE WRITE ERROR] Last Exception: $lastError" -ForegroundColor Red
            # Disable file logging to prevent spam
            $global:LoggerConfig.EnableFile = $false
        }
    }
    
    # Write to console with color coding (suppress DEBUG-level on console)
    if ($global:LoggerConfig.EnableConsole -and $Level -ge [LogLevel]::INFO) {
        $consoleColor = switch ($Level) {
            ([LogLevel]::DEBUG) { "Gray" }
            ([LogLevel]::INFO) { "White" }
            ([LogLevel]::WARNING) { "Yellow" }
            ([LogLevel]::ERROR) { "Red" }
            ([LogLevel]::SUCCESS) { "Green" }
            default { "White" }
        }
        
        Write-Host $logEntry -ForegroundColor $consoleColor
    }
}

function Get-LogFilePath {
    <#
    .SYNOPSIS
        Get the current log file path
        
    .OUTPUTS
        String containing the log file path
    #>
    return $global:LoggerConfig.LogFilePath
}

function Get-ErrorContext {
    <#
    .SYNOPSIS
        Extract detailed error context from PowerShell error record
        
    .DESCRIPTION
        Provides comprehensive error information including message, location,
        line number, command, and stack trace for better debugging.
        
    .PARAMETER ErrorRecord
        The error record to analyze (defaults to $_ in catch block)
        
    .OUTPUTS
        Hashtable with error details
        
    .EXAMPLE
        catch {
            $errorContext = Get-ErrorContext -ErrorRecord $_
            Write-Log -Level ERROR -Message $errorContext.Summary -Module "MyModule"
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $_
    )
    
    $context = @{
        Message      = ""
        Exception    = ""
        Category     = ""
        TargetObject = ""
        ScriptName   = ""
        LineNumber   = 0
        Command      = ""
        StackTrace   = ""
        Summary      = ""
    }
    
    if ($null -eq $ErrorRecord) {
        $context.Summary = "No error record available"
        return $context
    }
    
    # Extract basic error information
    $context.Message = $ErrorRecord.Exception.Message
    $context.Exception = $ErrorRecord.Exception.GetType().FullName
    $context.Category = $ErrorRecord.CategoryInfo.Category.ToString()
    $context.TargetObject = if ($ErrorRecord.TargetObject) { $ErrorRecord.TargetObject.ToString() } else { "N/A" }
    
    # Extract script location information
    if ($ErrorRecord.InvocationInfo) {
        $context.ScriptName = if ($ErrorRecord.InvocationInfo.ScriptName) { 
            Split-Path -Leaf $ErrorRecord.InvocationInfo.ScriptName 
        }
        else { 
            "N/A" 
        }
        $context.LineNumber = $ErrorRecord.InvocationInfo.ScriptLineNumber
        $context.Command = if ($ErrorRecord.InvocationInfo.MyCommand) { 
            $ErrorRecord.InvocationInfo.MyCommand.Name 
        }
        else { 
            "N/A" 
        }
    }
    
    # Extract stack trace
    if ($ErrorRecord.ScriptStackTrace) {
        $context.StackTrace = $ErrorRecord.ScriptStackTrace
    }
    
    # Build comprehensive summary
    $summary = "$($context.Message)"
    
    if ($context.ScriptName -and $context.LineNumber -gt 0) {
        $summary += " [File: $($context.ScriptName), Line: $($context.LineNumber)]"
    }
    
    if ($context.Command) {
        $summary += " [Command: $($context.Command)]"
    }
    
    if ($context.Category -ne "NotSpecified") {
        $summary += " [Category: $($context.Category)]"
    }
    
    $context.Summary = $summary
    
    return $context
}

function Write-ErrorLog {
    <#
    .SYNOPSIS
        Write a comprehensive error log entry with full context
        
    .DESCRIPTION
        Convenience function that combines error context extraction
        and logging in one call. Provides detailed error information.
        
    .PARAMETER Message
        Custom error message (will be prefixed to error details)
        
    .PARAMETER Module
        Module or component name
        
    .PARAMETER ErrorRecord
        The error record to log (defaults to $_ in catch block)
        
    .PARAMETER IncludeStackTrace
        Include full stack trace in log (default: true)
        
    .EXAMPLE
        catch {
            Write-ErrorLog -Message "Failed to apply security settings" -Module "SecurityBaseline" -ErrorRecord $_
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$Module = "Framework",
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $_,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeStackTrace = $true
    )
    
    $errorContext = Get-ErrorContext -ErrorRecord $ErrorRecord
    
    # Build comprehensive error message
    $fullMessage = "$Message - $($errorContext.Summary)"
    
    # Log error with basic info
    Write-Log -Level ERROR -Message $fullMessage -Module $Module -Exception $ErrorRecord.Exception
    
    # Log additional context if available
    if ($IncludeStackTrace -and $errorContext.StackTrace) {
        Write-Log -Level DEBUG -Message "Stack Trace: $($errorContext.StackTrace)" -Module $Module
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
# All functions are automatically available when dot-sourced
