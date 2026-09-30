<#
 MIT License

 Copyright (c) 2024 CrowdStrike

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
#>

<#
.SYNOPSIS
Installs falcon-installer on Windows.

.DESCRIPTION
Downloads a falcon-installer release from GitHub, verifies its SHA-256
checksum, and saves falcon-installer.exe in the current directory. The
download itself goes to a temporary directory that is removed afterwards.

.PARAMETER Version
Release to install, e.g. v0.27.0. Defaults to $env:FALCON_INSTALLER_VERSION,
or the latest release.

.PARAMETER InstallDir
Directory to save falcon-installer.exe in. Defaults to
$env:FALCON_INSTALLER_DIR, or the current directory.

.PARAMETER Force
Reinstall even if the requested version is already installed.

.EXAMPLE
irm https://raw.githubusercontent.com/CrowdStrike/falcon-installer/main/scripts/install.ps1 | iex

.EXAMPLE
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/CrowdStrike/falcon-installer/main/scripts/install.ps1))) -Version v0.27.0
#>
[CmdletBinding()]
param(
    [string]$Version = $env:FALCON_INSTALLER_VERSION,
    [string]$InstallDir = $env:FALCON_INSTALLER_DIR,
    [switch]$Force
)

# Everything runs inside this function, called on the last line, so a
# truncated download runs nothing. Errors are thrown rather than passed to
# exit, which would close the caller's session under `irm | iex`.
function Install-FalconInstaller {
    [CmdletBinding()]
    param(
        [string]$Version,
        [string]$InstallDir,
        [switch]$Force
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    # The progress bar slows Invoke-WebRequest dramatically on Windows PowerShell 5.1.
    $ProgressPreference = 'SilentlyContinue'

    $binaryName = 'falcon-installer'
    $releasesUrl = 'https://github.com/CrowdStrike/falcon-installer/releases'

    function Get-Arch {
        try {
            $arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        } catch {
            # RuntimeInformation is missing before .NET Framework 4.7.1.
            $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
        }
        switch ($arch) {
            'X64' { return 'x86_64' }
            'AMD64' { return 'x86_64' }
            'Arm64' { return 'arm64' }
        }
        throw "No prebuilt $binaryName for Windows on $arch. See $releasesUrl"
    }

    function Get-File([string]$Url, [string]$Path) {
        Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
    }

    # Get-InstalledVersion returns the X.Y.Z version reported by the binary at
    # Path, or $null if it does not run.
    function Get-InstalledVersion([string]$Path) {
        try {
            $output = & $Path --version | Out-String
        } catch {
            return $null
        }
        if ($output -match '(\d+\.\d+\.\d+)') {
            return $Matches[1]
        }
        return $null
    }

    # Get-ExpectedHash returns the hash listed for Asset. checksums.txt lists
    # both raw binaries and archives, so the name must match exactly.
    function Get-ExpectedHash([string]$ChecksumsPath, [string]$Asset) {
        foreach ($line in Get-Content -LiteralPath $ChecksumsPath) {
            $fields = $line.Trim() -split '\s+'
            if ($fields.Count -eq 2 -and $fields[1] -ceq $Asset) {
                return $fields[0]
            }
        }
        return $null
    }

    # Get-Sha256 returns the file's SHA-256, or $null if it cannot be read.
    function Get-Sha256([string]$Path) {
        try {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        } catch {
            return $null
        }
    }

    # Test-PrivateFile reports whether the file at Path is owned by, and can
    # only be modified, deleted, or re-permissioned by, the current user,
    # SYSTEM, Administrators, or TrustedInstaller, and whether only they can
    # delete files in its directory or change the directory's permissions.
    # falcon-installer runs elevated, so anyone else with those rights could
    # take it over.
    function Test-PrivateFile([string]$Path) {
        # WriteData, AppendData, WriteExtendedAttributes, WriteAttributes,
        # Delete, ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE.
        $fileMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
        # DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership, GENERIC_ALL.
        $dirMask = 0x40 -bor 0x40000 -bor 0x80000 -bor 0x10000000
        $checks = @(
            @{ Path = $Path; Mask = $fileMask },
            @{ Path = (Split-Path -Parent $Path); Mask = $dirMask }
        )
        foreach ($check in $checks) {
            $acl = Get-Acl -LiteralPath $check.Path
            if ($trustedSids -notcontains $acl.GetOwner($sidType).Value) {
                return $false
            }
            foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
                $inheritOnly = ([int]$rule.PropagationFlags -band 2) -ne 0
                if ($rule.AccessControlType -eq 'Allow' -and -not $inheritOnly -and
                    ([int]$rule.FileSystemRights -band $check.Mask) -ne 0 -and
                    $trustedSids -notcontains $rule.IdentityReference.Value) {
                    return $false
                }
            }
        }
        return $true
    }

    # Protect-File replaces the file's permissions with full control for the
    # current user, SYSTEM, and Administrators only. This drops inherited
    # permissions such as the Modify that Authenticated Users get in C:\temp.
    function Protect-File([string]$Path) {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.GetAccessRules($true, $false, $sidType))) {
            [void]$acl.RemoveAccessRuleSpecific($rule)
        }
        foreach ($sid in $trustedSids[0..2]) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'Allow'))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }

    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
        throw 'This script is for Windows. On Linux or macOS, use install.sh: https://github.com/CrowdStrike/falcon-installer#linux-and-macos'
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell 5.1 may not offer TLS 1.2 by default, which GitHub requires.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    # Accounts trusted to control the installed file: the current user, SYSTEM,
    # Administrators, and TrustedInstaller. Protect-File grants the first three.
    $sidType = [Security.Principal.SecurityIdentifier]
    $trustedSids = @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )

    if ($Version) {
        if ($Version -notmatch '^v?\d+\.\d+\.\d+$') {
            throw "Invalid version '$Version': expected a release tag such as v0.27.0"
        }
        if (-not $Version.StartsWith('v')) {
            $Version = "v$Version"
        }
    }

    $arch = Get-Arch
    if (-not $InstallDir) {
        # The current location can be a non-file provider such as HKLM:\.
        $InstallDir = (Get-Location -PSProvider FileSystem).ProviderPath
    }
    # .NET resolves relative paths against the process directory, which is not
    # PowerShell's current location.
    $InstallDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir)
    $target = Join-Path $InstallDir "$binaryName.exe"
    if (Test-Path -LiteralPath $target -PathType Container) {
        throw "$target is a directory. Run from another directory or pass -InstallDir"
    }

    $tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("$binaryName-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmpDir | Out-Null
    try {
        # Without a pinned version, fetch the latest release's checksums.txt
        # through the /releases/latest/download redirect and read the version
        # from the asset names it lists. This avoids the rate-limited GitHub API.
        $checksums = Join-Path $tmpDir 'checksums.txt'
        if ($Version) {
            try {
                Get-File "$releasesUrl/download/$Version/checksums.txt" $checksums
            } catch {
                throw "Release $Version not found. See $releasesUrl for available versions. ($($_.Exception.Message))"
            }
        } else {
            try {
                Get-File "$releasesUrl/latest/download/checksums.txt" $checksums
            } catch {
                throw "Could not download checksums.txt for the latest release. Pin a release with -Version (see $releasesUrl). ($($_.Exception.Message))"
            }
            $latest = Get-Content -LiteralPath $checksums |
                ForEach-Object { if ($_ -match "^\S+\s+$binaryName-(\d+\.\d+\.\d+)-") { $Matches[1] } } |
                Select-Object -First 1
            if (-not $latest) {
                throw 'Could not determine the latest version from its checksums.txt. Pin a release with -Version'
            }
            $Version = "v$latest"
        }
        $versionNumber = $Version.Substring(1)

        # Compare the existing file's hash with the release's raw binary rather
        # than running it, because the file may not be ours.
        if (Test-Path -LiteralPath $target) {
            $binaryHash = Get-ExpectedHash $checksums "$binaryName-$versionNumber-windows-$arch.exe"
            if (-not $Force -and $binaryHash -and (Get-Sha256 $target) -eq $binaryHash -and (Test-PrivateFile $target)) {
                Write-Host "$binaryName $Version is already installed at $target. Use -Force to reinstall."
                return
            }
            Write-Host "Replacing $target"
        }

        $asset = "$binaryName-$versionNumber-windows-$arch.zip"
        $zip = Join-Path $tmpDir $asset
        Write-Host "Downloading $binaryName $Version for windows-$arch"
        try {
            Get-File "$releasesUrl/download/$Version/$asset" $zip
        } catch {
            throw "Release $Version has no $asset. See $releasesUrl/tag/$Version. ($($_.Exception.Message))"
        }

        $expected = Get-ExpectedHash $checksums $asset
        if (-not $expected) {
            throw "checksums.txt for $Version has no entry for $asset"
        }
        $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
        if ($actual -ne $expected) {
            throw "Checksum mismatch for ${asset}: expected $($expected.ToLower()), got $($actual.ToLower()). Nothing was installed"
        }
        Write-Host 'Verified SHA-256 checksum'

        $extractDir = Join-Path $tmpDir 'extract'
        Expand-Archive -LiteralPath $zip -DestinationPath $extractDir -Force
        $source = Join-Path $extractDir "$binaryName.exe"
        $sourceHash = Get-Sha256 $source
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

        # Copy to a new file beside the target, restrict and check its
        # permissions and hash, then rename it into place. Checking after
        # restricting catches anyone who changed the copy before then, and the
        # rename replaces an existing file rather than writing through it.
        $staged = Join-Path $InstallDir (".$binaryName-" + [Guid]::NewGuid().ToString('N') + '.exe')
        try {
            try {
                Copy-Item -LiteralPath $source -Destination $staged
                Protect-File $staged
            } catch {
                throw "Could not write to $InstallDir. ($($_.Exception.Message))"
            }
            if (-not (Test-PrivateFile $staged) -or (Get-Sha256 $staged) -ne $sourceHash) {
                throw "Other users can delete files in $InstallDir or change its permissions, so they could take over $binaryName before it runs elevated. Use another directory, such as your user profile (cd ~), or pass -InstallDir"
            }
            try {
                if (Test-Path -LiteralPath $target) {
                    Remove-Item -LiteralPath $target -Force
                }
                [IO.File]::Move($staged, $target)
            } catch {
                throw "Could not replace $target. Make sure $binaryName is not running. ($($_.Exception.Message))"
            }
        } finally {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }

        if ((Get-Sha256 $target) -ne $sourceHash) {
            throw "$target is not the file this script installed. Remove it and try again, or pass -InstallDir"
        }

        if (-not (Get-InstalledVersion $target)) {
            throw "Installed $target, but it failed to run"
        }
        Write-Host "Installed $binaryName $Version to $target"
        Write-Host "Next: from an elevated PowerShell, run: & '$target' --help"
    } finally {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-FalconInstaller -Version $Version -InstallDir $InstallDir -Force:$Force
