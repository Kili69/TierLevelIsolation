# SPDX-License-Identifier: Apache-2.0

<#
    .AUTHOR
        Andreas Lucas [MSFT]

    .DOWNLOAD
        https://github.com/Kili69/TierLevelIsolation

    .SYNOPSIS
        Update the TierLevelIsolation module on the local machine from the sysvol share.

    .DESCRIPTION
        This script is used to update the TierLevelIsolation module on the local machine. It checks the version of the module in the source location and compares it with the version of the module installed on the local machine. If the source version is newer, it copies the module files from the source location to the target location on the local machine.

    .PARAMETER
        None
    .INPUTS
        None, you cannot pipe objects to this script.
    .OUTPUTS
        None, this script does not return any objects.

    .VERSION
        Version 0.1.20260317
            [Andreas Lucas]
            Initial version
        Version 0.1.20260825.1
            Updated version for initial repository publication
        Version 0.1.20261003.1
            Relicensed the project under Apache License 2.0 and moved the disclaimer to README.md


#>

#region constants and default values
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$ModuleSource = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\PSModules\TierLevelIsolation"
$ModuleTarget = "$Env:ProgramFiles\WindowsPowerShell\Modules\TierLevelIsolation"
#endregion

$SourceVersion = (Import-PowerShellDataFile "$ModuleSource\TierLevelIsolation.psd1").ModuleVersion
$TargetManifest = Join-Path $ModuleTarget "TierLevelIsolation.psd1"

# Check if the module is already installed and if the source version is newer than the target version
if (-not (Test-Path $TargetManifest) -or ([version](Import-PowerShellDataFile $TargetManifest).ModuleVersion -lt [version]$SourceVersion)) {
    if (-not (Test-Path $ModuleTarget)) { New-Item -Path $ModuleTarget -ItemType Directory -Force | Out-Null }
    Copy-Item -Path "$ModuleSource\*" -Destination $ModuleTarget -Force -Recurse -ErrorAction Stop
    Write-Host "TierLevelIsolation module installed/updated to version $SourceVersion" -ForegroundColor Green
} else {
    Write-Host "TierLevelIsolation module is already up to date (version $SourceVersion)" -ForegroundColor Green
}