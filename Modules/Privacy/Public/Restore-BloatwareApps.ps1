#Requires -Version 5.1

function Invoke-PrivacyBoundedProcess {
    <#
    .SYNOPSIS
        Runs one fixed executable with a fail-closed wall-clock deadline.

    .DESCRIPTION
        WinGet's non-interactive switch suppresses prompts but does not provide
        a process timeout. App recovery must therefore own the deadline and
        terminate the process tree before it reports a timeout to its caller.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1800)]
        [int]$TimeoutSeconds
    )

    if (-not [IO.File]::Exists($FilePath)) {
        throw "Privacy recovery executable is unavailable: $FilePath"
    }
    foreach ($argument in $ArgumentList) {
        if ([string]$argument -notmatch '^[A-Za-z0-9._~:/+\\-]{1,256}$') {
            throw 'Privacy recovery refused an unsupported process argument'
        }
    }

    $process = $null
    $killer = $null
    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $ArgumentList -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'Privacy recovery process did not start'
        }
        $timeoutMilliseconds = [int]([int64]$TimeoutSeconds * 1000)
        if (-not $process.WaitForExit($timeoutMilliseconds)) {
            $processId = [int]$process.Id
            $terminationErrors = [Collections.Generic.List[string]]::new()
            $taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
            if ([IO.File]::Exists($taskkill)) {
                try {
                    $killInfo = [Diagnostics.ProcessStartInfo]::new()
                    $killInfo.FileName = $taskkill
                    $killInfo.Arguments = "/PID $processId /T /F"
                    $killInfo.UseShellExecute = $false
                    $killInfo.CreateNoWindow = $true
                    $killInfo.RedirectStandardOutput = $true
                    $killInfo.RedirectStandardError = $true
                    $killer = [Diagnostics.Process]::new()
                    $killer.StartInfo = $killInfo
                    $null = $killer.Start()
                    if (-not $killer.WaitForExit(5000)) {
                        try { $killer.Kill() }
                        catch { $terminationErrors.Add("taskkill timeout cleanup failed ($($_.Exception.GetType().Name))") }
                    }
                }
                catch { $terminationErrors.Add("process-tree termination failed ($($_.Exception.GetType().Name))") }
            }
            try {
                if (-not $process.HasExited) { $process.Kill() }
            }
            catch { $terminationErrors.Add("process termination failed ($($_.Exception.GetType().Name))") }
            try {
                if (-not $process.WaitForExit(2000)) {
                    $terminationErrors.Add('process remained active after its termination deadline')
                }
            }
            catch { $terminationErrors.Add("process termination wait failed ($($_.Exception.GetType().Name))") }
            $terminationSuffix = if ($terminationErrors.Count -gt 0) {
                '; ' + ($terminationErrors -join '; ')
            }
            else { '' }
            throw "Privacy recovery process timed out after $TimeoutSeconds seconds$terminationSuffix"
        }
        $process.Refresh()
        return [int]$process.ExitCode
    }
    finally {
        if ($null -ne $killer) { $killer.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Restore-BloatwareApps {
    <#
    .SYNOPSIS
        Best-effort app recovery for the original Privacy interactive user.

    .DESCRIPTION
        Validates the complete sealed session and combines its Tier 1/Tier 2
        app inventories. Missing apps are first re-registered from a staged
        package-family identity recorded before removal. Only when that exact
        local route is unavailable does the command fall back to the verified
        current Microsoft Store product through winget.

        This is best-effort recovery and NOT an exact restore. Exact Privacy
        restore remains the separately verified BAVR policy/state rollback.
        This cannot recover deleted app data, licensing state, or an obsolete
        package version which is no longer staged or offered by the Store.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SessionPath
    )

    $result = [PSCustomObject]@{
        Success = $false; Status = 'Failed'; Attempted = 0; Reinstalled = 0
        RegisteredLocally = 0; InstalledFromStore = 0
        AlreadyPresent = 0; Failed = 0; Skipped = 0
        Details = [System.Collections.Generic.List[string]]::new()
    }

    try {
        $repoRoot = Split-Path (Split-Path $script:ModuleRoot -Parent) -Parent
        if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            . (Join-Path $repoRoot 'Core\Logger.ps1')
            Initialize-Logger -EnableConsole $true -EnableFile $false
        }

        $assessment = Get-BloatwareRestoreAssessment -SessionPath $SessionPath
        foreach ($detail in @($assessment.Details)) { $result.Details.Add([string]$detail) }
        if (-not [bool]$assessment.Success) {
            throw $(if ([string]::IsNullOrWhiteSpace([string]$assessment.Error)) {
                    "Privacy app assessment failed with status $($assessment.Status)"
                }
                else { [string]$assessment.Error })
        }

        $result.AlreadyPresent = [int]$assessment.AlreadyPresent
        $result.Skipped = [int]$assessment.Unmapped
        foreach ($app in @($assessment.AlreadyPresentApps)) {
            $result.Details.Add("$($app.AppName): already registered; no recovery claimed.")
        }
        foreach ($app in @($assessment.UnmappedApps)) {
            $result.Details.Add("$($app.AppName): neither a recorded package family nor a verified Store product is available; skipped.")
        }

        if ([string]$assessment.Status -eq 'NothingToDo') {
            $result.Success = $true
            $result.Status = 'NothingToDo'
            return $result
        }
        if ([string]$assessment.Status -eq 'UnmappedOnly') {
            $result.Status = 'Partial'
            Write-Log -Level WARNING -Message "Privacy app recovery has only $($result.Skipped) app(s) without a recovery route" -Module 'Privacy'
            return $result
        }
        if ([string]$assessment.Status -ne 'Needed' -or [int]$assessment.Missing -lt 1) {
            throw "Privacy app assessment returned an inconsistent status: $($assessment.Status)"
        }

        $currentSid = [string]$assessment.CurrentUserSid
        if (-not $PSCmdlet.ShouldProcess($currentSid, "Recover $($assessment.Missing) currently-missing app identity/identities from sealed Tier 1/Tier 2 inventory; app data is not restored")) {
            $result.Status = 'Cancelled'
            return $result
        }

        $wingetState = $null
        $msstoreRefreshed = $false
        $resolveWinget = {
            try {
                $winget = Get-Command winget -CommandType Application -ErrorAction Stop
                $candidate = @([string]$winget.Path, [string]$winget.Source) |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
                if ([string]::IsNullOrWhiteSpace([string]$candidate) -or
                    -not [IO.File]::Exists([string]$candidate)) {
                    throw 'winget was resolved without an executable path'
                }
                $probeExitCode = Invoke-PrivacyBoundedProcess -FilePath ([string]$candidate) `
                    -ArgumentList @('--version') -TimeoutSeconds 15
                if ($probeExitCode -ne 0) {
                    $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes($probeExitCode), 0)
                    throw "winget startup probe failed with exit code 0x$($unsigned.ToString('X8'))"
                }
                return [PSCustomObject]@{ Path = [string]$candidate; Error = $null }
            }
            catch {
                return [PSCustomObject]@{ Path = $null; Error = $_.Exception.Message }
            }
        }
        $getRegisteredPackages = {
            param([object]$App)
            return @($App.VerificationPackageNames | ForEach-Object {
                    @(Get-AppxPackage -Name ([string]$_) -ErrorAction Stop)
                })
        }

        foreach ($app in @($assessment.MissingApps)) {
            # Contract invariant: Attempted counts every recovery that actually
            # ran and therefore always equals Reinstalled + Failed. An app that
            # never had a runnable route counts as Skipped, never as Attempted.
            $recovered = $false
            $attemptMade = $false
            $localErrors = [System.Collections.Generic.List[string]]::new()

            if ([bool]$app.CanRegisterLocally) {
                $addAppx = Get-Command Add-AppxPackage -ErrorAction SilentlyContinue
                $supportsFamilyRegistration = $addAppx -and $addAppx.Parameters.ContainsKey('RegisterByFamilyName')
                if ($supportsFamilyRegistration) {
                    foreach ($familyName in @($app.PackageFamilyNames)) {
                        $attemptMade = $true
                        try {
                            Add-AppxPackage -RegisterByFamilyName -MainPackage ([string]$familyName) `
                                -ForceApplicationShutdown -ErrorAction Stop
                            if (@(& $getRegisteredPackages $app).Count -gt 0) {
                                $recovered = $true
                                $result.Attempted++
                                $result.RegisteredLocally++
                                $result.Reinstalled++
                                $result.Details.Add("$($app.AppName): re-registered and verified from sealed package family $familyName.")
                                break
                            }
                            $localErrors.Add("$familyName returned without an expected package registration")
                        }
                        catch { $localErrors.Add("${familyName}: $($_.Exception.Message)") }
                    }
                }
                else {
                    $localErrors.Add('this Windows AppX cmdlet does not support package-family registration')
                }
            }
            if ($recovered) { continue }

            if (-not [bool]$app.CanUseStore) {
                $localSummary = if ($localErrors.Count -gt 0) { $localErrors -join '; ' } else { 'no local package-family route was recorded' }
                if ($attemptMade) {
                    $result.Attempted++
                    $result.Failed++
                    $result.Details.Add("$($app.AppName): local recovery failed and no verified Store fallback exists: $localSummary")
                    Write-Log -Level ERROR -Message "Privacy app recovery failed for $($app.AppName): $localSummary" -Module 'Privacy'
                }
                else {
                    $result.Skipped++
                    $result.Details.Add("$($app.AppName): no runnable recovery route on this system; skipped: $localSummary")
                    Write-Log -Level WARNING -Message "Privacy app recovery skipped for $($app.AppName): $localSummary" -Module 'Privacy'
                }
                continue
            }

            if ($null -eq $wingetState) { $wingetState = & $resolveWinget }
            if ([string]::IsNullOrWhiteSpace([string]$wingetState.Path)) {
                $localSummary = if ($localErrors.Count -gt 0) { " Local route: $($localErrors -join '; ')" } else { '' }
                if ($attemptMade) {
                    $result.Attempted++
                    $result.Failed++
                    $result.Details.Add("$($app.AppName): local recovery failed and the Store fallback is unavailable (winget: $($wingetState.Error)).$localSummary")
                    Write-Log -Level ERROR -Message "Privacy app recovery failed for $($app.AppName): local route failed and winget is unavailable: $($wingetState.Error)" -Module 'Privacy'
                }
                else {
                    $result.Skipped++
                    $result.Details.Add("$($app.AppName): Store fallback skipped because winget is unavailable or not runnable: $($wingetState.Error).$localSummary")
                }
                continue
            }

            $storeId = [string]$app.StoreId
            $storeErrors = [System.Collections.Generic.List[string]]::new()
            for ($storeAttempt = 1; $storeAttempt -le 2 -and -not $recovered; $storeAttempt++) {
                $attemptMade = $true
                try {
                    $storeExitCode = Invoke-PrivacyBoundedProcess -FilePath ([string]$wingetState.Path) -ArgumentList @(
                        'install','--id',$storeId,'--exact','--source','msstore',
                        '--accept-package-agreements','--accept-source-agreements','--silent','--disable-interactivity'
                    ) -TimeoutSeconds 600
                    if (@(& $getRegisteredPackages $app).Count -gt 0) {
                        $recovered = $true
                        $result.Attempted++
                        $result.InstalledFromStore++
                        $result.Reinstalled++
                        $result.Details.Add("$($app.AppName): current Store product installed and registration verified (Store ID $storeId); not an exact version/data restore.")
                        break
                    }
                    $storeErrors.Add("attempt $storeAttempt exited $storeExitCode, but no expected package is registered")
                }
                catch { $storeErrors.Add("attempt ${storeAttempt}: $($_.Exception.Message)") }

                if ($storeAttempt -eq 1 -and -not $msstoreRefreshed) {
                    $msstoreRefreshed = $true
                    try {
                        $refreshExitCode = Invoke-PrivacyBoundedProcess `
                            -FilePath ([string]$wingetState.Path) -ArgumentList @(
                            'source','update','--name','msstore','--disable-interactivity'
                        ) -TimeoutSeconds 120
                        if ($refreshExitCode -ne 0) {
                            $storeErrors.Add("msstore source refresh exited $refreshExitCode")
                        }
                    }
                    catch { $storeErrors.Add("msstore source refresh failed: $($_.Exception.Message)") }
                }
            }

            if (-not $recovered) {
                $result.Attempted++
                $result.Failed++
                $combinedErrors = @($localErrors) + @($storeErrors)
                $message = if ($combinedErrors.Count -gt 0) { $combinedErrors -join '; ' } else { 'no recovery route succeeded' }
                $result.Details.Add("$($app.AppName): recovery failed: $message")
                Write-Log -Level ERROR -Message "Privacy app recovery failed for $($app.AppName): $message" -Module 'Privacy'
            }
        }

        $result.Success = ($result.Failed -eq 0 -and $result.Skipped -eq 0)
        $result.Status = if ($result.Success) {
            'Completed'
        }
        elseif ($result.Reinstalled -gt 0 -or $result.AlreadyPresent -gt 0) {
            'Partial'
        }
        else {
            'Failed'
        }
        Write-Log -Level $(if ($result.Success) { 'SUCCESS' } else { 'WARNING' }) -Message "Privacy app recovery: status=$($result.Status), local=$($result.RegisteredLocally), Store=$($result.InstalledFromStore), already present=$($result.AlreadyPresent), failed=$($result.Failed), skipped=$($result.Skipped)" -Module 'Privacy'
        return $result
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Restore-BloatwareApps failed: $($_.Exception.Message)" -Module 'Privacy'
        }
        $result.Details.Add($_.Exception.Message)
        return $result
    }
}
