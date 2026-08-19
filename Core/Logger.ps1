<#
.SYNOPSIS
    Unified logging system for NoID Privacy Framework

.DESCRIPTION
    Provides centralized logging functionality with multiple severity levels,
    file output, and optional console output with color coding.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
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
        LevelCounts     = @{
            DEBUG = 0; INFO = 0; WARNING = 0; ERROR = 0; SUCCESS = 0
        }
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
    if ($global:LoggerConfig.LogFilePath -and (Test-Path -LiteralPath $global:LoggerConfig.LogFilePath -PathType Leaf)) {
        Write-Host "[Logger] Reusing existing log session: $($global:LoggerConfig.LogFilePath)" -ForegroundColor DarkGray
        return
    }

    # Create log directory if it doesn't exist
    if ($EnableFile) {
        if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
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

    # Milliseconds alone are not a uniqueness guarantee (parallel processes can
    # start in the same clock tick). Keep the timestamp human-readable and add a
    # short random nonce so a new process can never truncate another run's log.
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
    $logNonce = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $logFileName = "NoIDPrivacy_${timestamp}_$logNonce.log"
    $global:LoggerConfig.LogFilePath = Join-Path $LogDirectory $logFileName
    $global:LoggerConfig.MinimumLevel = $MinimumLevel
    $global:LoggerConfig.EnableConsole = $EnableConsole
    $global:LoggerConfig.EnableFile = $EnableFile
    $global:LoggerConfig.LevelCounts = @{
        DEBUG = 0; INFO = 0; WARNING = 0; ERROR = 0; SUCCESS = 0
    }

    # Test if we can write to the log file.
    # Use .NET WriteAllText with explicit UTF8 NO-BOM so the file encoding is
    # consistent across PS 5.1 and 7+ (PS 5.1's `Out-File -Encoding UTF8` writes
    # a BOM; PS 7+'s default UTF8 is BOM-less). Mixed-encoding log files trip up
    # downstream parsers that expect a stable byte signature.
    if ($EnableFile) {
        try {
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            [System.IO.File]::WriteAllText($global:LoggerConfig.LogFilePath, "# NoID Privacy Log File`r`n", $utf8NoBom)
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
    # NoID Privacy's internal logging API predates the optional Write-Log command that
    # ships in some PowerShell module catalogs. Renaming it would break every
    # framework module and its public integration contract.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
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

    # Count every accepted log entry at its source. Module result objects may
    # expose a curated Warnings array, but that is not the same thing as the
    # number of WARNING entries actually emitted by helpers during a run.
    if (-not $global:LoggerConfig.ContainsKey('LevelCounts') -or
        $null -eq $global:LoggerConfig.LevelCounts) {
        $global:LoggerConfig.LevelCounts = @{
            DEBUG = 0; INFO = 0; WARNING = 0; ERROR = 0; SUCCESS = 0
        }
    }
    $levelName = $Level.ToString()
    if (-not $global:LoggerConfig.LevelCounts.ContainsKey($levelName)) {
        $global:LoggerConfig.LevelCounts[$levelName] = 0
    }
    $global:LoggerConfig.LevelCounts[$levelName] =
        [int]$global:LoggerConfig.LevelCounts[$levelName] + 1

    # Format timestamp
    $timestamp = Get-Date -Format $global:LoggerConfig.TimestampFormat

    # Build log entry
    $logEntry = "[$timestamp] [$Level] [$Module] $Message"

    # Add exception details if present
    if ($null -ne $Exception) {
        $logEntry += "`n    Exception: $($Exception.Message)"
        $logEntry += "`n    StackTrace: $($Exception.StackTrace)"
    }

    # Write to file through one process-lifetime StreamWriter. The log file is
    # exclusive to this process by construction (timestamp + nonce name), so
    # holding the handle open is safe -- and it removes the per-line
    # open/append/close cycle that made every engine-tree write pay the full
    # Defender/ACL cost again. Measured on an installed copy under
    # C:\Program Files this cycle alone roughly doubled module runtimes.
    # AutoFlush keeps the per-line crash-safety of the old append pattern;
    # FileShare.Read keeps the file tailable while the run is active.
    if ($global:LoggerConfig.EnableFile -and $global:LoggerConfig.LogFilePath) {
        $logWriter = $null
        if ($global:LoggerConfig.ContainsKey('Writer') -and $null -ne $global:LoggerConfig.Writer -and
            $global:LoggerConfig.ContainsKey('WriterPath') -and
            [string]$global:LoggerConfig.WriterPath -ceq [string]$global:LoggerConfig.LogFilePath) {
            $logWriter = $global:LoggerConfig.Writer
        }

        if ($null -eq $logWriter) {
            # A stale writer for a previous log path (session re-init) is
            # closed before the new one opens.
            if ($global:LoggerConfig.ContainsKey('Writer') -and $null -ne $global:LoggerConfig.Writer) {
                try { $global:LoggerConfig.Writer.Dispose() } catch { $null = $_ }
                $global:LoggerConfig.Writer = $null
            }

            $maxRetries = 5
            $retryDelayMs = 100
            $lastError = $null
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            for ($i = 0; $i -lt $maxRetries; $i++) {
                try {
                    # Read: the file stays tailable during the run.
                    # Delete: cleanup paths (test harnesses, the release
                    # gate's staging copy) may remove the log tree while this
                    # process still lives; the file then goes delete-pending
                    # and disappears when the handle closes.
                    $logStream = [System.IO.File]::Open(
                        $global:LoggerConfig.LogFilePath,
                        [System.IO.FileMode]::Append,
                        [System.IO.FileAccess]::Write,
                        ([System.IO.FileShare]::Read -bor [System.IO.FileShare]::Delete))
                    $logWriter = [System.IO.StreamWriter]::new($logStream, $utf8NoBom)
                    $logWriter.AutoFlush = $true
                    $global:LoggerConfig.Writer = $logWriter
                    $global:LoggerConfig.WriterPath = [string]$global:LoggerConfig.LogFilePath
                    break
                }
                catch {
                    $lastError = $_
                    $logWriter = $null
                    Start-Sleep -Milliseconds $retryDelayMs
                    # Exponential backoff for transient locks (AV scans etc.)
                    $retryDelayMs *= 2
                }
            }

            if ($null -eq $logWriter) {
                Write-Host "[FILE WRITE ERROR] Failed to open log file after $maxRetries attempts: $($global:LoggerConfig.LogFilePath)" -ForegroundColor Red
                Write-Host "[FILE WRITE ERROR] Last Exception: $lastError" -ForegroundColor Red
                # Disable file logging to prevent spam
                $global:LoggerConfig.EnableFile = $false
            }
        }

        if ($null -ne $logWriter) {
            try {
                $logWriter.WriteLine($logEntry)
                $global:LoggerConfig.WriteFailureCount = 0
            }
            catch {
                # The held handle failed (disk stall, disk full, forced
                # close): drop the writer so the NEXT log line reopens it
                # (with the open retry above). Only repeated consecutive
                # failures disable file logging - a single transient error
                # must not silently drop the audit trail of every later
                # module, which is what the old retry/backoff also ensured.
                Write-Host "[FILE WRITE ERROR] Failed to write to log file: $($global:LoggerConfig.LogFilePath)" -ForegroundColor Red
                Write-Host "[FILE WRITE ERROR] Exception: $_" -ForegroundColor Red
                try { $logWriter.Dispose() } catch { $null = $_ }
                $global:LoggerConfig.Writer = $null
                $failureCount = if ($global:LoggerConfig.ContainsKey('WriteFailureCount')) {
                    [int]$global:LoggerConfig.WriteFailureCount + 1
                } else { 1 }
                $global:LoggerConfig.WriteFailureCount = $failureCount
                if ($failureCount -ge 5) {
                    Write-Host "[FILE WRITE ERROR] $failureCount consecutive write failures; file logging disabled for this run." -ForegroundColor Red
                    $global:LoggerConfig.EnableFile = $false
                }
            }
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

function Get-LogLevelCount {
    <#
    .SYNOPSIS
        Return the number of accepted entries for one log level.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [LogLevel]$Level
    )

    if (-not $global:LoggerConfig.ContainsKey('LevelCounts') -or
        $null -eq $global:LoggerConfig.LevelCounts) {
        return 0
    }
    $levelName = $Level.ToString()
    if (-not $global:LoggerConfig.LevelCounts.ContainsKey($levelName)) {
        return 0
    }
    return [int]$global:LoggerConfig.LevelCounts[$levelName]
}

function Close-Logger {
    <#
    .SYNOPSIS
        Release the process-lifetime log writer handle

    .DESCRIPTION
        Write-Log keeps one StreamWriter open for the whole run. Callers that
        need the log file released before process exit (test harnesses that
        delete their temporary root, tooling that rotates logs in-session)
        call this; the next Write-Log reopens the handle transparently.
    #>
    [CmdletBinding()]
    param()

    if ($global:LoggerConfig.ContainsKey('Writer') -and $null -ne $global:LoggerConfig.Writer) {
        try { $global:LoggerConfig.Writer.Dispose() } catch { $null = $_ }
        $global:LoggerConfig.Writer = $null
    }
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
