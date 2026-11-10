#Requires -Version 5.1

$script:PrivacyAppRecoveryHelperPath = $PSCommandPath

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

function Invoke-PrivacyAppRecoveryLoop {
    <#
    .SYNOPSIS
        Recovers already assessed missing apps in the current user's context.

    .DESCRIPTION
        Local package-family registration first, then the verified Microsoft
        Store product through winget. Counters, details and one outcome per
        app are added to the caller's result object. Restore-BloatwareApps runs
        it in-process; the desktop-user worker runs the same code in the
        original user's own token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$MissingApps,
        [Parameter(Mandatory = $true)]$Result
    )

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

    foreach ($app in @($MissingApps)) {
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
                            $Result.Attempted++
                            $Result.RegisteredLocally++
                            $Result.Reinstalled++
                            $Result.Details.Add("$($app.AppName): re-registered and verified from sealed package family $familyName.")
                            $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'RegisteredLocally' })
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
                $Result.Attempted++
                $Result.Failed++
                $Result.Details.Add("$($app.AppName): local recovery failed and no verified Store fallback exists: $localSummary")
                $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'Failed' })
                Write-Log -Level ERROR -Message "Privacy app recovery failed for $($app.AppName): $localSummary" -Module 'Privacy'
            }
            else {
                $Result.Skipped++
                $Result.Details.Add("$($app.AppName): no runnable recovery route on this system; skipped: $localSummary")
                $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'Skipped' })
                Write-Log -Level WARNING -Message "Privacy app recovery skipped for $($app.AppName): $localSummary" -Module 'Privacy'
            }
            continue
        }

        # The Store route needs a network. Without any connection it
        # cannot run, which is a precondition and not a failure: nothing
        # was changed for this app, and recovery can simply run again.
        if ($null -eq $networkAvailable) { $networkAvailable = Test-NoIDNetworkConnection }
        if (-not $networkAvailable) {
            $Result.NeedsNetwork++
            $localNote = if ($localErrors.Count -gt 0) { " Local route: $($localErrors -join '; ')" } else { '' }
            $Result.Details.Add("$($app.AppName): needs the Microsoft Store and a network connection; not reinstalled now. Run app recovery again when this PC is online.$localNote")
            $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'NeedsNetwork' })
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
                    $Result.Details.Add("Microsoft App Installer updated automatically from $($updated.PreviousVersion) to $($updated.Version) for Store app recovery.")
                }
            }
            catch {
                $wingetState = [PSCustomObject]@{ Path=$null; Error=$_.Exception.Message }
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$wingetState.Path)) {
            $localSummary = if ($localErrors.Count -gt 0) { " Local route: $($localErrors -join '; ')" } else { '' }
            if ($attemptMade) {
                $Result.Attempted++
                $Result.Failed++
                $Result.Details.Add("$($app.AppName): local recovery failed and the Store fallback is unavailable (winget: $($wingetState.Error)).$localSummary")
                $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'Failed' })
                Write-Log -Level ERROR -Message "Privacy app recovery failed for $($app.AppName): local route failed and winget is unavailable: $($wingetState.Error)" -Module 'Privacy'
            }
            else {
                $Result.Skipped++
                $Result.Details.Add("$($app.AppName): Store fallback skipped because winget is unavailable or not runnable: $($wingetState.Error).$localSummary")
                $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'Skipped' })
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
                    $Result.Attempted++
                    $Result.InstalledFromStore++
                    $Result.Reinstalled++
                    $Result.Details.Add("$($app.AppName): current Store product installed and registration verified (Store ID $storeId); not an exact version/data restore.")
                    $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'InstalledFromStore' })
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
            $Result.Attempted++
            $Result.Failed++
            $combinedErrors = @($localErrors) + @($storeErrors)
            $message = if ($combinedErrors.Count -gt 0) { $combinedErrors -join '; ' } else { 'no recovery route succeeded' }
            $Result.Details.Add("$($app.AppName): recovery failed: $message")
            $Result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'Failed' })
            Write-Log -Level ERROR -Message "Privacy app recovery failed for $($app.AppName): $message" -Module 'Privacy'
        }
    }
}

$script:PrivacyAppRecoveryOutcomes = @('RegisteredLocally', 'InstalledFromStore', 'Failed', 'Skipped', 'NeedsNetwork')
$script:PrivacyAppRecoveryCounters = @('Attempted', 'Reinstalled', 'RegisteredLocally', 'InstalledFromStore', 'Failed', 'Skipped', 'NeedsNetwork')

function Assert-PrivacyAppRecoveryRequest {
    <#
    .SYNOPSIS
        Validates a desktop-user app recovery request on both sides of the worker boundary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)][string]$ExpectedSid,
        [Parameter(Mandatory = $true)][int]$ExpectedSessionId
    )

    $properties = @($Request.PSObject.Properties.Name)
    if ($properties.Count -ne 4 -or
        @(Compare-Object -ReferenceObject @('SchemaVersion','UserSid','SessionId','Apps') -DifferenceObject $properties).Count -ne 0 -or
        $Request.SchemaVersion -isnot [int] -or [int]$Request.SchemaVersion -ne 1 -or
        [string]$Request.UserSid -cne $ExpectedSid -or
        $Request.SessionId -isnot [int] -or [int]$Request.SessionId -ne $ExpectedSessionId) {
        throw 'Privacy app recovery request schema or user binding is invalid'
    }
    $apps = @($Request.Apps)
    if ($apps.Count -lt 1 -or $apps.Count -gt 64) {
        throw 'Privacy app recovery request has an invalid app count'
    }
    $namePattern = '^[A-Za-z0-9][A-Za-z0-9.]{2,127}$'
    $familyPattern = '^[A-Za-z0-9][A-Za-z0-9.]{2,127}_[a-z0-9]{13}$'
    $appFields = @('AppName','StoreId','ExpectedPackageNames','VerificationPackageNames','PackageFamilyNames','CanRegisterLocally','CanUseStore')
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($app in $apps) {
        $fields = @($app.PSObject.Properties.Name)
        if ($fields.Count -ne $appFields.Count -or
            @(Compare-Object -ReferenceObject $appFields -DifferenceObject $fields).Count -ne 0 -or
            $app.AppName -isnot [string] -or $app.AppName -cnotmatch $namePattern -or
            -not $seen.Add([string]$app.AppName) -or
            $app.StoreId -isnot [string] -or ($app.StoreId.Length -gt 0 -and $app.StoreId -cnotmatch '^[A-Za-z0-9]{1,32}$') -or
            $app.CanRegisterLocally -isnot [bool] -or $app.CanUseStore -isnot [bool]) {
            throw 'Privacy app recovery request contains a malformed app entry'
        }
        $expected = @($app.ExpectedPackageNames)
        $verification = @($app.VerificationPackageNames)
        $families = @($app.PackageFamilyNames)
        foreach ($value in @($expected + $verification)) {
            if ($value -isnot [string] -or $value -cnotmatch $namePattern) {
                throw "Privacy app recovery request has an invalid package name for $($app.AppName)"
            }
        }
        foreach ($value in $families) {
            if ($value -isnot [string] -or $value -cnotmatch $familyPattern) {
                throw "Privacy app recovery request has an invalid package family for $($app.AppName)"
            }
        }
        $expectedVerification = @(@([string]$app.AppName) + $expected | Sort-Object -Unique)
        if ((@($verification | Sort-Object -Unique) -join [char]31) -cne ($expectedVerification -join [char]31) -or
            [bool]$app.CanRegisterLocally -ne ($families.Count -gt 0) -or
            ([bool]$app.CanUseStore -and ($app.StoreId.Length -eq 0 -or $expected.Count -lt 1)) -or
            (-not [bool]$app.CanRegisterLocally -and -not [bool]$app.CanUseStore)) {
            throw "Privacy app recovery request has inconsistent routes for $($app.AppName)"
        }
    }
    return $apps
}

function Assert-PrivacyAppRecoveryUserContext {
    <# The worker must be the original desktop user, never an elevated token. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedSid,
        [Parameter(Mandatory = $true)][int]$ExpectedSessionId
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($identity.User.Value -cne $ExpectedSid -or $sessionId -ne $ExpectedSessionId -or $sessionId -lt 1) {
        throw 'Privacy app recovery is not running as the original desktop user'
    }
    $user = Get-PrivacyUserContext -Refresh
    if ([string]$user.Sid -cne $ExpectedSid -or [int]$user.SessionId -ne $ExpectedSessionId) {
        throw 'Privacy app recovery desktop identity changed'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Only an account without a filtered token can keep a full token: UAC
        # off, or the built-in Administrator without Admin Approval Mode.
        $policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
        $enableLua = $policy.PSObject.Properties['EnableLUA']
        $filterAdministrator = $policy.PSObject.Properties['FilterAdministratorToken']
        $unfiltered = ($null -ne $enableLua -and [int64]$enableLua.Value -eq 0) -or
            ($identity.User.Value -match '-500$' -and ($null -eq $filterAdministrator -or [int64]$filterAdministrator.Value -eq 0))
        if (-not $unfiltered) { throw 'Privacy app recovery worker unexpectedly received an elevated token' }
    }
}

function Invoke-PrivacyAppRecoveryWorker {
    <#
    .SYNOPSIS
        Runs app recovery inside the original desktop user's own token.

    .DESCRIPTION
        Started by Invoke-PrivacyDesktopUserAppRecovery through a transient
        original-user task. Reads only the request whose SHA-256 the elevated
        caller named and writes its result through the caller's open file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^S-1-(?:5-21|12-1)-[0-9-]+$')][string]$ExpectedSid,
        [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$ExpectedSessionId,
        [Parameter(Mandatory = $true)][string]$RequestPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$RequestSha256,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $repoRoot = Split-Path (Split-Path (Split-Path (Split-Path $script:PrivacyAppRecoveryHelperPath -Parent) -Parent) -Parent) -Parent
    foreach ($relativePath in @('Core\Runtime.ps1', 'Core\Logger.ps1', 'Modules\Privacy\Private\Get-PrivacyUserContext.ps1')) {
        . (Join-Path $repoRoot $relativePath)
    }
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $record = [ordered]@{
        SchemaVersion = 1; UserSid = $ExpectedSid; SessionId = $ExpectedSessionId; Success = $false
        Attempted = 0; Reinstalled = 0; RegisteredLocally = 0; InstalledFromStore = 0
        Failed = 0; Skipped = 0; NeedsNetwork = 0
        Details = @(); Apps = @(); Error = ''
    }
    try {
        Assert-PrivacyAppRecoveryUserContext -ExpectedSid $ExpectedSid -ExpectedSessionId $ExpectedSessionId
        $stream = [IO.FileStream]::new($RequestPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            if ($stream.Length -lt 2 -or $stream.Length -gt 262144) { throw 'Privacy app recovery request has an invalid size' }
            $bytes = [byte[]]::new([int]$stream.Length)
            $read = 0
            while ($read -lt $bytes.Length) {
                $count = $stream.Read($bytes, $read, $bytes.Length - $read)
                if ($count -le 0) { throw 'Privacy app recovery request changed while it was read' }
                $read += $count
            }
        }
        finally { $stream.Dispose() }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) }
        finally { $sha.Dispose() }
        if ($digest -cne $RequestSha256) { throw 'Privacy app recovery request does not match its pinned SHA-256' }
        $request = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -ErrorAction Stop
        $apps = @(Assert-PrivacyAppRecoveryRequest -Request $request -ExpectedSid $ExpectedSid -ExpectedSessionId $ExpectedSessionId)

        $loop = [PSCustomObject]@{
            Attempted = 0; Reinstalled = 0; RegisteredLocally = 0; InstalledFromStore = 0
            Failed = 0; Skipped = 0; NeedsNetwork = 0
            Details = [Collections.Generic.List[string]]::new()
            AppOutcomes = [Collections.Generic.List[object]]::new()
        }
        Invoke-PrivacyAppRecoveryLoop -MissingApps $apps -Result $loop
        foreach ($counter in $script:PrivacyAppRecoveryCounters) { $record[$counter] = [int]$loop.$counter }
        $record.Details = @($loop.Details | Select-Object -First 200 | ForEach-Object {
                $text = [string]$_
                if ($text.Length -gt 4096) { $text.Substring(0, 4093) + '...' } else { $text }
            })
        $record.Apps = @($loop.AppOutcomes | ForEach-Object {
                [ordered]@{ AppName = [string]$_.AppName; Outcome = [string]$_.Outcome }
            })
        $record.Success = ($record.Failed -eq 0 -and $record.Skipped -eq 0 -and $record.NeedsNetwork -eq 0)
    }
    catch {
        $message = [string]$_.Exception.Message
        if ($message.Length -gt 4096) { $message = $message.Substring(0, 4093) + '...' }
        foreach ($counter in $script:PrivacyAppRecoveryCounters) { $record[$counter] = 0 }
        $record.Details = @()
        $record.Apps = @()
        $record.Success = $false
        $record.Error = if ([string]::IsNullOrWhiteSpace($message)) { 'Privacy app recovery worker failed' } else { $message }
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject ([pscustomobject]$record) -Depth 6 -Compress))
    if ($bytes.Length -gt 1048576) { throw 'Privacy app recovery result exceeds its permitted size' }
    $output = [IO.File]::Open($OutputPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $output.SetLength(0)
        $output.Write($bytes, 0, $bytes.Length)
        $output.Flush()
    }
    finally { $output.Dispose() }
    return [pscustomobject]$record
}

function Assert-PrivacyAppRecoveryWorkerResult {
    <# Rejects a worker result whose identity, app set or counters do not add up. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$UserSid,
        [Parameter(Mandatory = $true)][int]$SessionId,
        [Parameter(Mandatory = $true)][string[]]$AppNames
    )

    $fields = @('SchemaVersion','UserSid','SessionId','Success','Attempted','Reinstalled','RegisteredLocally',
        'InstalledFromStore','Failed','Skipped','NeedsNetwork','Details','Apps','Error')
    $properties = @($Record.PSObject.Properties.Name)
    if ($properties.Count -ne $fields.Count -or
        @(Compare-Object -ReferenceObject $fields -DifferenceObject $properties).Count -ne 0 -or
        $Record.SchemaVersion -isnot [int] -or [int]$Record.SchemaVersion -ne 1 -or
        [string]$Record.UserSid -cne $UserSid -or $Record.SessionId -isnot [int] -or [int]$Record.SessionId -ne $SessionId -or
        $Record.Success -isnot [bool] -or $Record.Error -isnot [string]) {
        throw 'Privacy app recovery result has an invalid schema or user binding'
    }
    foreach ($counter in $script:PrivacyAppRecoveryCounters) {
        if ($Record.$counter -isnot [int] -or [int]$Record.$counter -lt 0) { throw 'Privacy app recovery result has an invalid counter' }
    }
    foreach ($detail in @($Record.Details)) {
        if ($detail -isnot [string]) { throw 'Privacy app recovery result has an invalid detail' }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$Record.Error)) {
        if (@($Record.Apps).Count -ne 0 -or [bool]$Record.Success) { throw 'Privacy app recovery failure result is inconsistent' }
        throw "Privacy app recovery worker failed: $($Record.Error)"
    }
    $apps = @($Record.Apps)
    $outcomeNames = @($apps | ForEach-Object {
            $appFields = @($_.PSObject.Properties.Name)
            if ($appFields.Count -ne 2 -or
                @(Compare-Object -ReferenceObject @('AppName','Outcome') -DifferenceObject $appFields).Count -ne 0 -or
                $_.AppName -isnot [string] -or $_.Outcome -isnot [string] -or
                [string]$_.Outcome -cnotin $script:PrivacyAppRecoveryOutcomes) {
                throw 'Privacy app recovery result has an invalid app outcome'
            }
            [string]$_.AppName
        } | Sort-Object)
    if ((@($outcomeNames) -join [char]31) -cne (@($AppNames | Sort-Object) -join [char]31)) {
        throw 'Privacy app recovery result does not name every requested app exactly once'
    }
    $count = { param($Outcome) @($apps | Where-Object { [string]$_.Outcome -ceq $Outcome }).Count }
    if ([int]$Record.RegisteredLocally -ne (& $count 'RegisteredLocally') -or
        [int]$Record.InstalledFromStore -ne (& $count 'InstalledFromStore') -or
        [int]$Record.Failed -ne (& $count 'Failed') -or
        [int]$Record.Skipped -ne (& $count 'Skipped') -or
        [int]$Record.NeedsNetwork -ne (& $count 'NeedsNetwork') -or
        [int]$Record.Reinstalled -ne ([int]$Record.RegisteredLocally + [int]$Record.InstalledFromStore) -or
        [int]$Record.Attempted -ne ([int]$Record.Reinstalled + [int]$Record.Failed) -or
        [bool]$Record.Success -ne ([int]$Record.Failed -eq 0 -and [int]$Record.Skipped -eq 0 -and [int]$Record.NeedsNetwork -eq 0)) {
        throw 'Privacy app recovery result counters do not match its app outcomes'
    }
}

function Confirm-PrivacyDesktopUserAppRecovery {
    <# The elevated caller checks every claimed recovery against the user's live registrations. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][object[]]$MissingApps,
        [Parameter(Mandatory = $true)][string]$UserSid
    )

    $details = [Collections.Generic.List[string]]::new()
    foreach ($detail in @($Record.Details)) { $details.Add([string]$detail) }
    foreach ($outcome in @($Record.Apps)) {
        if ([string]$outcome.Outcome -cnotin @('RegisteredLocally', 'InstalledFromStore')) { continue }
        $app = @($MissingApps | Where-Object { [string]$_.AppName -ceq [string]$outcome.AppName })[0]
        $verified = $false
        try {
            if ([string]$outcome.Outcome -ceq 'RegisteredLocally') {
                $verified = @(Get-AppxPackage -User $UserSid -Name ([string]$app.AppName) -ErrorAction Stop | Where-Object {
                        [string]$_.PackageFamilyName -in @($app.PackageFamilyNames)
                    }).Count -gt 0
            }
            else {
                $verified = @($app.ExpectedPackageNames | ForEach-Object {
                        @(Get-AppxPackage -User $UserSid -Name ([string]$_) -ErrorAction Stop)
                    }).Count -gt 0
            }
        }
        catch { $verified = $false }
        if ($verified) { continue }
        $Record.($outcome.Outcome) = [int]$Record.($outcome.Outcome) - 1
        $Record.Reinstalled = [int]$Record.Reinstalled - 1
        $Record.Failed = [int]$Record.Failed + 1
        $outcome.Outcome = 'Failed'
        $details.Add("$($app.AppName): recovery was reported, but the app is not registered for the signed-in user in the independent check.")
    }
    $Record.Details = @($details)
    $Record.Success = ([int]$Record.Failed -eq 0 -and [int]$Record.Skipped -eq 0 -and [int]$Record.NeedsNetwork -eq 0)
    return $Record
}

function Invoke-PrivacyDesktopUserAppRecovery {
    <#
    .SYNOPSIS
        Recovers apps for the signed-in original user from an elevated process that runs as another account.

    .DESCRIPTION
        With Windows Administrator protection, every elevated process runs as
        a separate system-managed account, so it cannot register or install
        apps for the user who removed them. The same happens when a standard
        user elevates with another administrator's credentials. A transient
        task runs Invoke-PrivacyAppRecoveryLoop in the original user's own
        limited token, the same route Apply uses to remove the apps. The
        request is pinned by SHA-256, the result is read through the caller's
        open handle, and every claimed recovery is checked against the user's
        live registrations. Temporary task and exchange data are removed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]$User,
        [Parameter(Mandatory = $true)][object[]]$MissingApps
    )

    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Desktop-user app recovery requires an elevated administrator token'
    }
    $sid = [string]$User.Sid
    $session = $User.SessionId
    if ($sid -notmatch '^S-1-(?:5-21|12-1)-[0-9-]+$' -or $session -isnot [int] -or $session -lt 1) {
        throw 'Desktop-user app recovery binding is invalid'
    }
    $desktop = Get-PrivacyUserContext -Refresh
    if ([string]$desktop.Sid -cne $sid -or [int]$desktop.SessionId -ne $session) {
        throw 'The signed-in desktop user changed before app recovery'
    }
    $requestApps = @($MissingApps | ForEach-Object {
            [ordered]@{
                AppName = [string]$_.AppName
                StoreId = [string]$_.StoreId
                ExpectedPackageNames = @($_.ExpectedPackageNames | ForEach-Object { [string]$_ })
                VerificationPackageNames = @($_.VerificationPackageNames | ForEach-Object { [string]$_ })
                PackageFamilyNames = @($_.PackageFamilyNames | ForEach-Object { [string]$_ })
                CanRegisterLocally = [bool]$_.CanRegisterLocally
                CanUseStore = [bool]$_.CanUseStore
            }
        })
    $requestJson = ConvertTo-Json -InputObject ([ordered]@{ SchemaVersion = 1; UserSid = $sid; SessionId = $session; Apps = $requestApps }) -Depth 6 -Compress
    $appNames = @(Assert-PrivacyAppRecoveryRequest -Request ($requestJson | ConvertFrom-Json) -ExpectedSid $sid -ExpectedSessionId $session |
        ForEach-Object { [string]$_.AppName })
    if (-not $PSCmdlet.ShouldProcess('apps of the signed-in desktop user', "Recover $($appNames.Count) app(s) in that user's own account")) { return }

    # Local registration takes seconds; a Store install can take minutes.
    $timeoutSeconds = [Math]::Min(3600, 300 + 300 * $appNames.Count)
    $requestBytes = [Text.UTF8Encoding]::new($false).GetBytes($requestJson)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $requestDigest = -join ($sha.ComputeHash($requestBytes) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }

    $parent = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $exchangePath = Join-Path $parent ('NoID-PrivacyAppRecovery-' + [Guid]::NewGuid().ToString('N'))
    $requestPath = Join-Path $exchangePath 'request.json'
    $resultPath = Join-Path $exchangePath 'result.json'
    $taskName = 'NoID-PrivacyAppRecovery-' + [Guid]::NewGuid().ToString('N')
    $exchangeCreated = $false
    $requestStream = $null
    $resultStream = $null
    $hidden = $null
    $registered = $false
    $quiesced = $true
    $operationError = $null
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    $record = $null
    try {
        $directory = [IO.DirectoryInfo]::new($exchangePath)
        if ($directory.Exists -or [IO.File]::Exists($exchangePath)) { throw 'App recovery exchange path already exists' }
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $security.SetAccessRuleProtection($true, $false)
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($grantSid in @('S-1-5-18', 'S-1-5-32-544', $sid)) {
            $rights = if ($grantSid -ceq $sid) { [Security.AccessControl.FileSystemRights]::ReadAndExecute }
                else { [Security.AccessControl.FileSystemRights]::FullControl }
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($grantSid), $rights, $inheritance,
                    [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
        }
        $directory.Create($security)
        $exchangeCreated = $true
        Assert-PrivacyWorkerExchangeDirectory -Path $exchangePath
        $actual = $directory.GetAccessControl()
        if (-not $actual.AreAccessRulesProtected -or
            $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or
            @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])).Count -ne 3) {
            throw 'App recovery exchange ownership or permissions are unsafe'
        }
        # The request is deleted when its handle closes; the user can read it
        # but neither replace it nor the directory.
        $requestStream = [IO.FileStream]::new($requestPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::Read, 4096, [IO.FileOptions]::DeleteOnClose)
        $requestStream.Write($requestBytes, 0, $requestBytes.Length)
        $requestStream.Flush()
        # FileShare excludes Delete: the result is read back through this
        # handle, so a changed path cannot redirect the privileged read.
        $resultStream = [IO.File]::Open($resultPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        $resultFile = [IO.FileInfo]::new($resultPath)
        $resultAcl = $resultFile.GetAccessControl()
        $resultAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),
                ([Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write),
                [Security.AccessControl.AccessControlType]::Allow))
        $resultFile.SetAccessControl($resultAcl)

        $escapedHelper = ([string]$script:PrivacyAppRecoveryHelperPath).Replace("'", "''")
        $escapedRequest = $requestPath.Replace("'", "''")
        $escapedResult = $resultPath.Replace("'", "''")
        $command = "`$ErrorActionPreference='Stop'; . '$escapedHelper'; " +
            "`$record=Invoke-PrivacyAppRecoveryWorker -ExpectedSid '$sid' -ExpectedSessionId $session " +
            "-RequestPath '$escapedRequest' -RequestSha256 '$requestDigest' -OutputPath '$escapedResult'; " +
            "if(-not `$record.Success){exit 1}"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $hidden = New-NoIDHiddenWorkerTaskAction -EncodedCommand $encoded -UserSid $sid -SessionId $session
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds ($timeoutSeconds + 5))
        $null = Register-ScheduledTask -TaskName $taskName -Action $hidden.Action -Principal $hidden.Principal -Settings $settings -ErrorAction Stop
        $registered = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $info = $null
        do {
            $state = Get-NoIDScheduledTaskState -TaskName $taskName
            if ($state -cnotin @('Ready','Disabled','Running','Queued')) {
                throw 'App recovery worker state could not be verified'
            }
            if ($state -notin @('Running','Queued')) {
                $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
                if ($info.LastRunTime.Year -ge 2000 -and $info.LastTaskResult -notin @(267009, 267011)) { break }
            }
            Start-Sleep -Milliseconds 250
        } while ($timer.Elapsed.TotalSeconds -lt $timeoutSeconds)
        if ($state -in @('Running','Queued') -or $timer.Elapsed.TotalSeconds -ge $timeoutSeconds) {
            throw 'App recovery in the signed-in user''s account timed out'
        }
        if ([int64]$info.LastTaskResult -notin @(0, 1)) {
            throw "App recovery worker could not complete (task result $($info.LastTaskResult))"
        }
        $length = $resultStream.Length
        if ($length -lt 2 -or $length -gt 1048576) { throw 'App recovery result is empty or exceeds its permitted size' }
        $resultStream.Position = 0
        $bytes = [byte[]]::new([int]$length)
        $offset = 0
        while ($offset -lt $length) {
            $read = $resultStream.Read($bytes, $offset, [int]$length - $offset)
            if ($read -lt 1) { throw 'App recovery result changed during its bounded read' }
            $offset += $read
        }
        try { $record = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) | ConvertFrom-Json -ErrorAction Stop }
        catch { throw 'App recovery result is not valid UTF-8 JSON' }
        Assert-PrivacyAppRecoveryWorkerResult -Record $record -UserSid $sid -SessionId $session -AppNames $appNames
        if (([int64]$info.LastTaskResult -eq 0) -ne [bool]$record.Success) {
            throw 'App recovery result disagrees with its worker exit status'
        }
        $record = Confirm-PrivacyDesktopUserAppRecovery -Record $record -MissingApps $MissingApps -UserSid $sid
    }
    catch { $operationError = $_ }
    finally {
        if ($registered) {
            try {
                $state = Get-NoIDScheduledTaskState -TaskName $taskName
                if ($state -in @('Running','Queued')) {
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $stopTimer = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Milliseconds 100
                        $state = Get-NoIDScheduledTaskState -TaskName $taskName
                    } while ($state -in @('Running','Queued') -and $stopTimer.Elapsed.TotalSeconds -lt 10)
                    if ($state -in @('Running','Queued')) { throw 'App recovery worker remained active after its stop deadline' }
                }
            }
            catch { $quiesced = $false; $cleanupErrors.Add("worker stop failed: $($_.Exception.Message)") }
            if ($quiesced) {
                try { $null = Unregister-NoIDScheduledTask -TaskName $taskName -Confirm:$false }
                catch { $cleanupErrors.Add("temporary task removal failed: $($_.Exception.Message)") }
            }
        }
        if ($null -ne $resultStream) { $resultStream.Dispose() }
        if ($null -ne $requestStream) { $requestStream.Dispose() }
        # A worker that could not be stopped keeps its launcher and exchange;
        # nothing is deleted while it may still be writing.
        if ($quiesced) {
            if ($null -ne $hidden) {
                try { Remove-NoIDHiddenWorkerLauncher -Launcher $hidden -Confirm:$false }
                catch { $cleanupErrors.Add("hidden launcher cleanup failed: $($_.Exception.Message)") }
            }
            if ($exchangeCreated) {
                try { Remove-PrivacyWorkerExchangeDirectory -Path $exchangePath -ResultPath $resultPath -Confirm:$false }
                catch { $cleanupErrors.Add("exchange cleanup failed: $($_.Exception.Message)") }
            }
        }
    }
    if ($cleanupErrors.Count -gt 0) {
        $prefix = if ($null -ne $operationError) { "$($operationError.Exception.Message); " } else { '' }
        throw ($prefix + ($cleanupErrors -join '; '))
    }
    if ($null -ne $operationError) { $PSCmdlet.ThrowTerminatingError($operationError) }
    return $record
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
        AppOutcomes = [System.Collections.Generic.List[object]]::new()
    }
    # Add-AppxPackage draws a progress pane per package. Windows PowerShell 5.1
    # leaves panes of deployments that report no final state over the console
    # text that follows; the result and its details report every outcome.
    $ProgressPreference = 'SilentlyContinue'

    try {
        $repoRoot = Split-Path (Split-Path $script:ModuleRoot -Parent) -Parent
        if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
            . (Join-Path $repoRoot 'Core\Logger.ps1')
            # A host that already chose the console style (the interactive
            # menu's Restore runs this without a log file) keeps it; a fresh
            # Initialize-Logger would print its own records and switch the
            # rest of that console session to full log records.
            if (-not $global:LoggerConfig.ContainsKey('ConsoleStyle')) {
                Initialize-Logger -EnableConsole $true -EnableFile $false
            }
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

        if ([string]$assessment.RecoveryContext -ceq 'DesktopUserWorker') {
            # The elevated process runs as another account (Windows
            # Administrator protection, or a standard user who elevated with
            # an administrator's credentials). The apps are recovered in the
            # signed-in original user's own token instead.
            $desktopUser = Get-PrivacyUserContext -Refresh
            if ([string]$desktopUser.Sid -cne [string]$assessment.OriginalUserSid) {
                throw 'The signed-in desktop user changed after the app assessment'
            }
            try {
                $workerRecord = Invoke-PrivacyDesktopUserAppRecovery -User $desktopUser `
                    -MissingApps @($assessment.MissingApps) -Confirm:$false
                foreach ($counter in @('Attempted','Reinstalled','RegisteredLocally','InstalledFromStore','Failed','Skipped','NeedsNetwork')) {
                    $result.$counter += [int]$workerRecord.$counter
                }
                foreach ($detail in @($workerRecord.Details)) { $result.Details.Add([string]$detail) }
                foreach ($outcome in @($workerRecord.Apps)) { $result.AppOutcomes.Add($outcome) }
            }
            catch {
                $workerError = $_.Exception.Message
                foreach ($app in @($assessment.MissingApps)) {
                    $result.Skipped++
                    $result.Details.Add("$($app.AppName): app recovery in the signed-in user's account could not run: $workerError")
                    $result.AppOutcomes.Add([PSCustomObject]@{ AppName = [string]$app.AppName; Outcome = 'Skipped' })
                }
                Write-Log -Level WARNING -Message "Privacy app recovery in the signed-in user's account could not run: $workerError" -Module 'Privacy'
            }
        }
        else {
            Invoke-PrivacyAppRecoveryLoop -MissingApps @($assessment.MissingApps) -Result $result
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
