<#
.SYNOPSIS
    Backup all important data before Windows reinstall
.DESCRIPTION
    Creates a backup of:
    - Git status check
    - SSH keys
    - Important credentials reminder
    - Project files
#>

$backupRoot = "$env:USERPROFILE\Desktop\WINDSURF-BACKUP-$(Get-Date -Format 'yyyy-MM-dd')"

Write-Host "`n=== WINDSURF/CASCADE BACKUP SCRIPT ===" -ForegroundColor Cyan
Write-Host "Backup Location: $backupRoot`n" -ForegroundColor Yellow

# Create backup folder
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

# 1. Check Git Status
Write-Host "[1/6] Checking Git Status..." -ForegroundColor Green
cd C:\Users\nexus\CascadeProjects\windsurf-project
$gitStatus = git status --porcelain
if ($gitStatus) {
    Write-Warning "UNCOMMITTED CHANGES FOUND!"
    Write-Host "Files with changes:" -ForegroundColor Yellow
    git status --short
    Write-Host "`nRun this before reinstall:" -ForegroundColor Red
    Write-Host "  git add ." -ForegroundColor White
    Write-Host "  git commit -m 'backup before reinstall'" -ForegroundColor White
    Write-Host "  git push" -ForegroundColor White
    $gitStatus | Out-File "$backupRoot\GIT-STATUS.txt"
} else {
    Write-Host "  [OK] No uncommitted changes - Git is clean!" -ForegroundColor Green
}

# 2. Backup SSH Keys
Write-Host "`n[2/6] Backing up SSH Keys..." -ForegroundColor Green
$sshPath = "$env:USERPROFILE\.ssh"
if (Test-Path $sshPath) {
    Copy-Item -Path $sshPath -Destination "$backupRoot\ssh" -Recurse -Force
    Write-Host "  [OK] SSH keys backed up" -ForegroundColor Green
} else {
    Write-Host "  [WARN] No SSH keys found (you might use HTTPS)" -ForegroundColor Yellow
}

# 3. Backup Internal folder (if exists)
Write-Host "`n[3/6] Backing up Internal/ folder..." -ForegroundColor Green
$internalPath = "C:\Users\nexus\CascadeProjects\windsurf-project\Internal"
if (Test-Path $internalPath) {
    Copy-Item -Path $internalPath -Destination "$backupRoot\Internal" -Recurse -Force
    Write-Host "  [OK] Internal folder backed up" -ForegroundColor Green
} else {
    Write-Host "  [WARN] No Internal/ folder found" -ForegroundColor Yellow
}

# 4. Create Credentials Reminder
Write-Host "`n[4/6] Creating credentials reminder..." -ForegroundColor Green
$credentialsFile = "$backupRoot\CREDENTIALS-REMINDER.txt"
$credentialsContent = @"
=== WICHTIGE ZUGANGSDATEN AUSFUELLEN ===

WINDSURF/CASCADE ACCOUNT:
Email: ___________________
Password: ___________________
OAuth: GitHub / Google (welche?)

GITHUB:
Username: NexusOne23
Email: ___________________
Password: ___________________
2FA Backup Codes: ___________________
Personal Access Token: ___________________

MICROSOFT PARTNER CENTER:
Email: ___________________
Password: ___________________
Publisher ID: CN=12ADF2FB-DC39-466C-81F4-608F0CC15A70
Product ID: 9MX9WMZQTQPF

SIGNPATH FOUNDATION:
Email: ___________________
Status: Pending seit Oct 30, 2025

GOOGLE FORMS (Waitlist):
Account: ___________________
Form: https://forms.gle/3kcQMtNxPjpqKKU6A

=== NACH NEUAUFSETZEN ===

Windsurf installieren: https://codeium.com/windsurf
Mit GLEICHEM ACCOUNT anmelden (Memories sind automatisch da!)
Git installieren: winget install Git.Git
GitHub konfigurieren:
   git config --global user.name "NexusOne23"
   git config --global user.email "DEINE_EMAIL"
SSH Keys wiederherstellen ODER neu erstellen
Projekt clonen:
   git clone git@github.com:NexusOne23/noid-privacy.git
Windsurf Workspace oeffnen und Fertig!

WICHTIG: Alle MEMORIES sind in der Cloud gespeichert!
Solange du dich mit dem GLEICHEN ACCOUNT anmeldest, ist alles da!
"@

$credentialsContent | Out-File $credentialsFile -Encoding UTF8

Write-Host "  [OK] Credentials reminder created" -ForegroundColor Green

# 5. Backup current Git config
Write-Host "`n[5/6] Backing up Git configuration..." -ForegroundColor Green
git config --global --list | Out-File "$backupRoot\GIT-CONFIG.txt"
Write-Host "  [OK] Git config backed up" -ForegroundColor Green

# 6. Create restoration guide
Write-Host "`n[6/6] Creating restoration guide..." -ForegroundColor Green
$guideFile = "$backupRoot\RESTORATION-GUIDE.txt"
$guideContent = @"
=== WIEDERHERSTELLUNG NACH NEUAUFSETZEN ===

SCHRITT 1: WINDSURF INSTALLIEREN
Download: https://codeium.com/windsurf
Installieren
Anmelden mit GLEICHEM ACCOUNT
CASCADE MEMORIES sind automatisch verfuegbar!

SCHRITT 2: GIT UND GITHUB SETUP
powershell:
  winget install Git.Git
  git config --global user.name "NexusOne23"
  git config --global user.email "SIEHE CREDENTIALS-REMINDER.txt"

OPTION A SSH Keys wiederherstellen:
  Kopiere ssh\ Ordner nach C:\Users\DEINNAME\.ssh\
  In PowerShell: ssh -T git@github.com
  Sollte sagen: "Hi NexusOne23!"

OPTION B Neue SSH Keys:
  ssh-keygen -t ed25519 -C "DEINE_EMAIL"
  cat ~/.ssh/id_ed25519.pub | clip
  Zu GitHub hinzufuegen: Settings, SSH Keys, Add

OPTION C HTTPS mit Token:
  gh auth login  (GitHub CLI)
  ODER: Personal Access Token aus CREDENTIALS-REMINDER.txt

SCHRITT 3: PROJEKT CLONEN
mkdir C:\Users\DEINNAME\CascadeProjects
cd C:\Users\DEINNAME\CascadeProjects
git clone git@github.com:NexusOne23/noid-privacy.git windsurf-project
cd windsurf-project

Falls Internal\ Ordner gesichert:
  Kopiere Internal\ zurueck in windsurf-project\

SCHRITT 4: WINDSURF WORKSPACE OEFFNEN
Windsurf oeffnen
File, Open Folder
C:\Users\DEINNAME\CascadeProjects\windsurf-project
FERTIG! CASCADE erkennt das Projekt und Memories sind da!

REPOS:
Main: https://github.com/NexusOne23/noid-privacy
Companion: https://github.com/NexusOne23/noid-companion
PWA Live: https://nexusone23.github.io/noid-companion/

WICHTIG: Memories sind SERVER-SEITIG!
Du verlierst NICHTS solange du den GLEICHEN WINDSURF ACCOUNT nutzt!
"@

$guideContent | Out-File $guideFile -Encoding UTF8

Write-Host "  [OK] Restoration guide created" -ForegroundColor Green

# Summary
Write-Host "`n=== BACKUP COMPLETE ===" -ForegroundColor Cyan
Write-Host "`nBackup Location: $backupRoot" -ForegroundColor Yellow
Write-Host "`nBacked up:" -ForegroundColor White
Write-Host "  [OK] Git status check" -ForegroundColor Green
Write-Host "  [OK] SSH keys (if present)" -ForegroundColor Green
Write-Host "  [OK] Internal/ folder (if present)" -ForegroundColor Green
Write-Host "  [OK] Git configuration" -ForegroundColor Green
Write-Host "  [OK] Credentials reminder" -ForegroundColor Green
Write-Host "  [OK] Restoration guide" -ForegroundColor Green

Write-Host "`n[WARN] WICHTIG - VOR NEUAUFSETZEN:" -ForegroundColor Red
Write-Host "1. FÜLLE CREDENTIALS-REMINDER.txt aus!" -ForegroundColor Yellow
Write-Host "2. Wenn git status Änderungen zeigt: commit + push!" -ForegroundColor Yellow
Write-Host "3. Kopiere den gesamten Backup-Ordner auf USB/Cloud!" -ForegroundColor Yellow

Write-Host "`n[INFO] NACH NEUAUFSETZEN:" -ForegroundColor Cyan
Write-Host "-> Folge RESTORATION-GUIDE.txt" -ForegroundColor White
Write-Host "-> Melde dich mit GLEICHEM Windsurf Account an" -ForegroundColor White
Write-Host "-> Alle MEMORIES sind automatisch da! [OK]" -ForegroundColor Green

Write-Host "`nPress any key to open backup folder..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
explorer $backupRoot

