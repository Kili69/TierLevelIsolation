# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Validates and optionally publishes the TierLevelIsolation PowerShell module.

.DESCRIPTION
    Reads and validates the module manifest in the repository's module directory, copies the
    complete module to an isolated staging directory under the operating system's temporary path,
    and validates the staged package layout.

    Without Publish, the script calls Publish-PSResource with WhatIf to verify the publication
    command without uploading the module. With Publish, the script uploads the staged module to the
    selected PowerShell repository.

    The staging directory is removed after the operation, including when validation or publication
    fails. The source module files are never modified.

.PARAMETER Publish
    Performs the actual module upload. When omitted, the script performs a dry run with WhatIf.

.PARAMETER Repository
    Name of the registered PowerShell repository that receives the module. The default is PSGallery.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    None. Validation and publication status messages are written to the host. Publish-PSResource
    may write verbose information.

.EXAMPLE
    .\publish.ps1

    Validates the source and staged manifests and performs a dry run against PSGallery.

.EXAMPLE
    .\publish.ps1 -Repository InternalGallery

    Validates the package and performs a dry run against the registered InternalGallery repository.

.EXAMPLE
    $env:PSGALLERY_API_KEY = '<API key>'
    .\publish.ps1 -Publish
    Remove-Item Env:\PSGALLERY_API_KEY

    Publishes the module to PSGallery by using the API key from the process environment and then
    removes the key from that environment.

.NOTES
    The Publish parameter requires the PSGALLERY_API_KEY environment variable, including when a
    repository other than PSGallery is selected. Do not place API keys directly in this script or
    in PowerShell command history.

    Microsoft.PowerShell.PSResourceGet must be installed and provide Publish-PSResource. Dependency
    repository checks and the cmdlet's internal Test-ModuleManifest call are skipped because
    ActiveDirectory is a Windows RSAT module declared as an external dependency and is not
    published to PowerShell Gallery. This script validates the manifest data, version, and declared
    root module before publication.

    PowerShell Gallery does not permit overwriting an existing module version. Increment
    ModuleVersion in module\TierLevelIsolation.psd1 before publishing a new release.

.LINK
    https://github.com/Kili69/TierLevelIsolation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Publish,

    [Parameter()]
    [string]$Repository = 'PSGallery'
)

# Stop immediately when validation, file operations, or publication fail.
$ErrorActionPreference = 'Stop'

# Resolve all package paths relative to this script so execution does not depend on the current directory.
$sourcePath = Join-Path $PSScriptRoot 'module'
$manifestPath = Join-Path $sourcePath 'TierLevelIsolation.psd1'
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'TierLevelIsolation-Publish'
$modulePath = Join-Path $stagingRoot 'TierLevelIsolation'

try {
    if (-not (Get-Command Publish-PSResource -ErrorAction SilentlyContinue)) {
        throw 'Publish-PSResource is required. Install Microsoft.PowerShell.PSResourceGet before running this script.'
    }

    # Read the source manifest without importing the module or requiring its Windows-only dependencies.
    $manifest = Import-PowerShellDataFile -Path $manifestPath
    $moduleVersion = [version]$manifest.ModuleVersion
    $rootModulePath = Join-Path $sourcePath $manifest.RootModule
    if (-not (Test-Path $rootModulePath -PathType Leaf)) {
        throw "The root module declared by the manifest was not found: '$rootModulePath'."
    }

    # Start from an empty staging directory to prevent files from an earlier run entering the package.
    if (Test-Path $stagingRoot) {
        Remove-Item -Path $stagingRoot -Recurse -Force
    }

    New-Item -Path $modulePath -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $sourcePath '*') -Destination $modulePath -Recurse -Force

    # Validate the staged copy because its package layout is the exact layout sent to the repository.
    $stagedManifestPath = Join-Path $modulePath 'TierLevelIsolation.psd1'
    $stagedManifest = Import-PowerShellDataFile -Path $stagedManifestPath
    $stagedRootModulePath = Join-Path $modulePath $stagedManifest.RootModule
    if ([version]$stagedManifest.ModuleVersion -ne $moduleVersion) {
        throw 'The staged module version does not match the source module version.'
    }
    if (-not (Test-Path $stagedRootModulePath -PathType Leaf)) {
        throw "The staged root module was not found: '$stagedRootModulePath'."
    }
    Write-Host "Validated TierLevelIsolation $moduleVersion in $modulePath"

    # Both publication modes use the same staged path, repository, and verbose diagnostics.
    $publishParameters = @{
        Path       = $modulePath
        Repository = $Repository
        SkipDependenciesCheck = $true
        SkipModuleManifestValidate = $true
        Verbose    = $true
    }

    if ($Publish) {
        # Read the secret only from the process environment to keep it out of source and command history.
        if ([string]::IsNullOrWhiteSpace($env:PSGALLERY_API_KEY)) {
            throw 'Set the PSGALLERY_API_KEY environment variable before publishing.'
        }

        $publishParameters.ApiKey = $env:PSGALLERY_API_KEY
        Publish-PSResource @publishParameters
        Write-Host "Published TierLevelIsolation $moduleVersion to $Repository"
    }
    else {
        # Publish-PSResource accepts a placeholder API key when WhatIf prevents the upload.
        $publishParameters.ApiKey = 'PLACEHOLDER'
        Publish-PSResource @publishParameters -WhatIf
        Write-Host 'Dry run completed. Use -Publish for the actual upload.'
    }
}
finally {
    # Remove staged package contents after success or failure so credentials and release artifacts do not linger.
    if (Test-Path $stagingRoot) {
        Remove-Item -Path $stagingRoot -Recurse -Force
    }
}