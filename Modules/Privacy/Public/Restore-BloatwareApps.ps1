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
    [OutputType([int], [PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1800)]
        [int]$TimeoutSeconds,

        [switch]$CaptureOutput
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
        if ($CaptureOutput) {
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
            $startInfo.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
        }
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'Privacy recovery process did not start'
        }
        $stdout = $null
        $stderr = $null
        if ($CaptureOutput) {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
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
        if ($CaptureOutput) {
            return [PSCustomObject]@{
                ExitCode = [int]$process.ExitCode
                Output = [string]$stdout.Result
                ErrorOutput = [string]$stderr.Result
            }
        }
        return [int]$process.ExitCode
    }
    finally {
        if ($null -ne $killer) { $killer.Dispose() }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Get-PrivacyWinGetReleaseFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][uri]$Uri,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$ExpectedBytes,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    # Windows PowerShell 5.1 renders Invoke-WebRequest progress per received
    # block, which slows large downloads by orders of magnitude.
    $ProgressPreference = 'SilentlyContinue'
    $null = Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
    if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -ne $ExpectedBytes -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash -ine $Sha256) {
        throw 'Microsoft App Installer download failed its pinned size/SHA-256 check'
    }
}

function Update-PrivacyWinGet {
    <#
    .SYNOPSIS
        Updates Microsoft App Installer and its dependencies for the original user.

    .DESCRIPTION
        Uses Microsoft's signed MSIX release directly. WinGet's self-upgrade
        dependency manifests can launch an administrator-only runtime installer,
        so that route cannot provide unattended recovery for a standard user.
        Release assets are pinned to upstream SHA-256 digests; Windows also
        validates package signatures during deployment. No backup is rewritten.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $family = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'
    $before = @(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop |
        Where-Object { [string]$_.PackageFamilyName -ceq $family })
    if ($before.Count -ne 1) { throw 'The original user must have exactly one Microsoft App Installer registration for automatic update' }
    $aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    $packagePath = Join-Path ([string]$before[0].InstallLocation) 'winget.exe'
    if ([IO.Path]::GetFullPath($FilePath) -ine [IO.Path]::GetFullPath($aliasPath) -and
        [IO.Path]::GetFullPath($FilePath) -ine [IO.Path]::GetFullPath($packagePath)) {
        throw 'Automatic WinGet update requires the registered Microsoft App Installer executable'
    }
    if (-not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ine 'AMD64') {
        throw 'The reviewed automatic WinGet update supports x64 Windows only'
    }
    $previousVersion = [version]$before[0].Version
    $repairVersion = [version]'1.29.290.0'
    if ($previousVersion -ge $repairVersion) {
        throw 'The installed App Installer is already at or above the reviewed repair version; its Store failure needs a newer reviewed repair or another diagnosis'
    }
    if (-not $PSCmdlet.ShouldProcess('Microsoft App Installer', 'Install the verified Microsoft MSIX update and required dependencies for this user')) {
        throw 'Microsoft App Installer update was cancelled'
    }

    # https://github.com/microsoft/winget-cli/releases/tag/v1.29.290
    # Both hashes match the upstream release-asset digests. The bundle hash
    # also matches Microsoft's accompanying .txt file. Refresh as one release.
    $release = 'https://github.com/microsoft/winget-cli/releases/download/v1.29.290/'
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('NoIDPrivacy-WinGet-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    try {
        Write-Log -Level INFO -Message 'Updating Microsoft App Installer automatically from the verified Microsoft MSIX release...' -Module 'Privacy'
        $bundle = Join-Path $directory 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
        $archivePath = Join-Path $directory 'DesktopAppInstaller_Dependencies.zip'
        Get-PrivacyWinGetReleaseFile -Uri ($release + 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle') `
            -Path $bundle -ExpectedBytes 216783252 -Sha256 '6824b6e9484ab24687d99a0c829d2bcbcc7849a70a4d0f596fc43c89d20dff15'
        Get-PrivacyWinGetReleaseFile -Uri ($release + 'DesktopAppInstaller_Dependencies.zip') `
            -Path $archivePath -ExpectedBytes 97760717 -Sha256 '50c377516749002dcdda9c8e52f26e8e2ea73d52131ce96ffd082dcf60ca6677'
        $dependencies = @(
            @{ Name='Microsoft.VCLibs.140.00'; Version='14.0.33519.0'; Entry='x64/Microsoft.VCLibs.140.00_14.0.33519.0_x64.appx' },
            @{ Name='Microsoft.VCLibs.140.00.UWPDesktop'; Version='14.0.33728.0'; Entry='x64/Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64.appx' },
            @{ Name='Microsoft.WindowsAppRuntime.1.8'; Version='8000.616.304.0'; Entry='x64/Microsoft.WindowsAppRuntime.1.8_8000.616.304.0_x64.appx' }
        )
        $dependencyPaths = [Collections.Generic.List[string]]::new()
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
        try {
            foreach ($dependency in $dependencies) {
                $installed = @(Get-AppxPackage -Name $dependency.Name -ErrorAction Stop |
                    Where-Object { [string]$_.Architecture -ieq 'X64' -and [version]$_.Version -ge [version]$dependency.Version })
                if ($installed.Count -gt 0) { continue }
                # Extract only fixed members to fixed leaf names; never unpack
                # arbitrary archive paths or invoke dependency EXE installers.
                $entry = $archive.GetEntry($dependency.Entry)
                if ($null -eq $entry) { throw 'The verified WinGet release is missing a required x64 dependency' }
                $target = Join-Path $directory ([IO.Path]::GetFileName($dependency.Entry))
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target)
                $dependencyPaths.Add($target)
            }
        }
        finally { $archive.Dispose() }
        $deployment = @{ Path=$bundle; ForceTargetApplicationShutdown=$true; ErrorAction='Stop' }
        if ($dependencyPaths.Count -gt 0) { $deployment.DependencyPath = $dependencyPaths.ToArray() }
        Add-AppxPackage @deployment
        $after = @(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction Stop |
            Where-Object { [string]$_.PackageFamilyName -ceq $family })
        if ($after.Count -ne 1 -or [version]$after[0].Version -lt $repairVersion -or [version]$after[0].Version -le $previousVersion) {
            throw 'Microsoft App Installer did not advance to the verified repair version'
        }
        $probeExitCode = Invoke-PrivacyBoundedProcess -FilePath $aliasPath `
            -ArgumentList @('--version') -TimeoutSeconds 15
        if ($probeExitCode -ne 0) { throw "Updated WinGet did not start (exit code $probeExitCode)" }
        return [PSCustomObject]@{ Path=$aliasPath; PreviousVersion=[string]$previousVersion; Version=[string]$after[0].Version }
    }
    finally {
        Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
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
        Store client compatibility failures automatically update Microsoft App
        Installer before the app install, once per recovery invocation.

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
        AlreadyPresent = 0; Failed = 0; Skipped = 0; NeedsNetwork = 0
        Details = [System.Collections.Generic.List[string]]::new()
    }
    # Add-AppxPackage draws a progress pane per package. Windows PowerShell 5.1
    # leaves panes of deployments that report no final state over the console
    # text that follows; the result and its details report every outcome.
    $ProgressPreference = 'SilentlyContinue'

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
        if (-not $PSCmdlet.ShouldProcess($currentSid, "Recover $($assessment.Missing) currently-missing app identity/identities from sealed Tier 1/Tier 2 inventory; update Microsoft App Installer if required for Store recovery; app data is not restored")) {
            $result.Status = 'Cancelled'
            return $result
        }

        $wingetState = $null
        $networkAvailable = $null
        $msstoreRefreshed = $false
        $storeClientChecked = $false
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
        $getStoreRegisteredPackages = {
            param([object]$App)
            return @($App.ExpectedPackageNames | ForEach-Object {
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
                            # Local recovery restores the recorded family, not
                            # a possibly different current Store replacement.
                            $localRegistration = @(Get-AppxPackage -Name ([string]$app.AppName) -ErrorAction Stop |
                                Where-Object { [string]$_.PackageFamilyName -eq [string]$familyName })
                            if ($localRegistration.Count -gt 0) {
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

            # The Store route needs a network. Without any connection it
            # cannot run, which is a precondition and not a failure: nothing
            # was changed for this app, and recovery can simply run again.
            if ($null -eq $networkAvailable) { $networkAvailable = Test-NoIDNetworkConnection }
            if (-not $networkAvailable) {
                $result.NeedsNetwork++
                $localNote = if ($localErrors.Count -gt 0) { " Local route: $($localErrors -join '; ')" } else { '' }
                $result.Details.Add("$($app.AppName): needs the Microsoft Store and a network connection; not reinstalled now. Run app recovery again when this PC is online.$localNote")
                Write-Log -Level INFO -Message "Note: $($app.AppName) can only come back from the Microsoft Store, which needs a network connection; run app recovery again when this PC is online." -Module 'Privacy'
                continue
            }

            if ($null -eq $wingetState) { $wingetState = & $resolveWinget }
            if (-not [string]::IsNullOrWhiteSpace([string]$wingetState.Path) -and -not $storeClientChecked) {
                $storeClientChecked = $true
                try {
                    $clientExitCode = Invoke-PrivacyBoundedProcess -FilePath ([string]$wingetState.Path) -ArgumentList @(
                        'show','--id',([string]$app.StoreId),'--exact','--source','msstore',
                        '--accept-source-agreements','--disable-interactivity'
                    ) -TimeoutSeconds 120
                    # Official WinGet client/REST compatibility errors. Ordinary
                    # network, license and missing-product failures do not ask
                    # for an unrelated App Installer update.
                    if ($clientExitCode -in @(-1978335230, -1978335176, -1978335170, -1978335138)) {
                        $updated = Update-PrivacyWinGet -FilePath ([string]$wingetState.Path) -Confirm:$false
                        $wingetState = [PSCustomObject]@{ Path=$updated.Path; Error=$null }
                        $result.Details.Add("Microsoft App Installer updated automatically from $($updated.PreviousVersion) to $($updated.Version) for Store app recovery.")
                    }
                }
                catch {
                    $wingetState = [PSCustomObject]@{ Path=$null; Error=$_.Exception.Message }
                }
            }
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
                    if (@(& $getStoreRegisteredPackages $app).Count -gt 0) {
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

        $result.Success = ($result.Failed -eq 0 -and $result.Skipped -eq 0 -and $result.NeedsNetwork -eq 0)
        $result.Status = if ($result.Success) {
            'Completed'
        }
        elseif ($result.Failed -eq 0 -and $result.Skipped -eq 0) {
            # Only apps whose Store route waits for a network remain.
            'NeedsNetwork'
        }
        elseif ($result.Reinstalled -gt 0 -or $result.AlreadyPresent -gt 0) {
            'Partial'
        }
        else {
            'Failed'
        }
        $summaryLevel = switch ($result.Status) { 'Completed' { 'SUCCESS' } 'NeedsNetwork' { 'INFO' } default { 'WARNING' } }
        Write-Log -Level $summaryLevel -Message "Privacy app recovery: status=$($result.Status), local=$($result.RegisteredLocally), Store=$($result.InstalledFromStore), already present=$($result.AlreadyPresent), failed=$($result.Failed), skipped=$($result.Skipped), needs network=$($result.NeedsNetwork)" -Module 'Privacy'
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
