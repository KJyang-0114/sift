# Sift installer for Windows.
#   irm https://raw.githubusercontent.com/KJyang-0114/sift/main/install.ps1 | iex
#
# Environment overrides:
#   $env:SIFT_VERSION = "v1.5.0"          install a specific release (default: latest)
#   $env:SIFT_INSTALL_DIR = "C:\tools"    install location (default: %LOCALAPPDATA%\Programs\sift)

# Run in a child scope: under "irm | iex" this script shares the caller's session,
# and the preferences below must not leak into it.
& {
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    $Repo = "KJyang-0114/sift"

    # Throw instead of exit: under "irm | iex", exit would close the caller's PowerShell session.
    function Fail([string]$Message) {
        Write-Host "  x $Message" -ForegroundColor Red
        throw "Sift installation failed: $Message"
    }

    Write-Host ""
    Write-Host "  Sift Installer"
    Write-Host "  --------------"

    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { $Arch = "amd64" }
        "ARM64" { $Arch = "arm64" }
        default { Fail "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
    }
    Write-Host "  - Detected: windows/$Arch"

    $Version = $env:SIFT_VERSION
    if (-not $Version) {
        try {
            $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
        } catch {
            Fail "Unable to determine the latest release. Set SIFT_VERSION=vX.Y.Z and retry."
        }
    }
    if (-not $Version.StartsWith("v")) { $Version = "v$Version" }
    Write-Host "  - Version: $Version"

    $InstallDir = $env:SIFT_INSTALL_DIR
    if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\sift" }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    $Archive = "sift_windows_$Arch.zip"
    $BaseUrl = "https://github.com/$Repo/releases/download/$Version"
    $Temp = Join-Path ([System.IO.Path]::GetTempPath()) ("sift-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $Temp | Out-Null

    try {
        Write-Host "  - Downloading: $BaseUrl/$Archive"
        try {
            Invoke-WebRequest "$BaseUrl/$Archive" -OutFile (Join-Path $Temp $Archive) -UseBasicParsing
            Invoke-WebRequest "$BaseUrl/checksums.txt" -OutFile (Join-Path $Temp "checksums.txt") -UseBasicParsing
        } catch {
            Fail "Download failed: $($_.Exception.Message)"
        }

        $Expected = $null
        foreach ($Line in Get-Content (Join-Path $Temp "checksums.txt")) {
            $Fields = $Line -split "\s+", 2
            if ($Fields.Count -eq 2 -and $Fields[1].TrimStart("*") -eq $Archive) { $Expected = $Fields[0].ToLower() }
        }
        if (-not $Expected) { Fail "No checksum entry for $Archive in checksums.txt" }
        $Actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Temp $Archive)).Hash.ToLower()
        if ($Expected -ne $Actual) { Fail "Checksum mismatch for $Archive (expected $Expected, got $Actual)" }
        Write-Host "  + Checksum verified" -ForegroundColor Green

        $Extract = Join-Path $Temp "extract"
        Expand-Archive (Join-Path $Temp $Archive) -DestinationPath $Extract
        $Binary = Join-Path $Extract "sift.exe"
        if (-not (Test-Path $Binary)) { Fail "Archive does not contain sift.exe" }

        # Stage under a per-run name next to the target, then swap it in. File.Replace
        # replaces an existing binary atomically, so an interrupted upgrade keeps the old one.
        $Target = Join-Path $InstallDir "sift.exe"
        $Staged = Join-Path $InstallDir (".sift.exe." + [guid]::NewGuid() + ".new")
        try {
            Copy-Item $Binary $Staged
            if (Test-Path $Target) {
                [System.IO.File]::Replace($Staged, $Target, [NullString]::Value)
            } else {
                Move-Item $Staged $Target
            }
        } finally {
            Remove-Item $Staged -Force -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -Recurse -Force $Temp -ErrorAction SilentlyContinue
    }

    Write-Host "  + Sift $Version installed to $Target" -ForegroundColor Green

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($UserPath -split ";") -notcontains $InstallDir) {
        Write-Host "  ! $InstallDir is not on PATH. Add it with:" -ForegroundColor Yellow
        Write-Host "    [Environment]::SetEnvironmentVariable('Path', `"$InstallDir;`" + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
    }
    if (-not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
        Write-Host "  ! Semgrep not found. Static analysis requires it: pip install semgrep" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  Next steps:"
    Write-Host "    sift init       # Configure LLM (3 questions max)"
    Write-Host "    sift scan .     # Scan your project"
    Write-Host ""
}
