<#
    .AUTHOR
        Andreas Lucas [MSFT]

    .DOWNLOAD
        https://github.com/Kili69/TierLevelIsolation

    .DISCLAIMER
        This sample script is not supported under any Microsoft standard support program or service.
        The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims
        all implied warranties including, without limitation, any implied warranties of merchantability
        or of fitness for a particular purpose. The entire risk arising out of the use or performance of
        the sample scripts and documentation remains with you. In no event shall Microsoft, its authors,
        or anyone else involved in the creation, production, or delivery of the scripts be liable for any
        damages whatsoever (including, without limitation, damages for loss of business profits, business
        interruption, loss of business information, or other pecuniary loss) arising out of the use of or
        inability to use the sample scripts or documentation, even if Microsoft has been advised of the
        possibility of such damages

    .SYSNOPSIS
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