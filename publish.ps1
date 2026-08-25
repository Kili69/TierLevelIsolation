[CmdletBinding()]
param(
    [Parameter()]
    [switch]$Publish,

    [Parameter()]
    [string]$Repository = 'PSGallery'
)

$ErrorActionPreference = 'Stop'

$sourcePath = Join-Path $PSScriptRoot 'module'
$manifestPath = Join-Path $sourcePath 'TierLevelIsolation.psd1'
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'TierLevelIsolation-Publish'
$modulePath = Join-Path $stagingRoot 'TierLevelIsolation'

try {
    $manifest = Test-ModuleManifest -Path $manifestPath

    if (Test-Path $stagingRoot) {
        Remove-Item -Path $stagingRoot -Recurse -Force
    }

    New-Item -Path $modulePath -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $sourcePath '*') -Destination $modulePath -Recurse -Force

    Test-ModuleManifest -Path (Join-Path $modulePath 'TierLevelIsolation.psd1') | Out-Null
    Write-Host "Validated TierLevelIsolation $($manifest.Version) in $modulePath"

    $publishParameters = @{
        Path       = $modulePath
        Repository = $Repository
        Verbose    = $true
    }

    if ($Publish) {
        if ([string]::IsNullOrWhiteSpace($env:PSGALLERY_API_KEY)) {
            throw 'Set the PSGALLERY_API_KEY environment variable before publishing.'
        }

        $publishParameters.NuGetApiKey = $env:PSGALLERY_API_KEY
        Publish-Module @publishParameters
        Write-Host "Published TierLevelIsolation $($manifest.Version) to $Repository"
    }
    else {
        $publishParameters.NuGetApiKey = 'PLACEHOLDER'
        Publish-Module @publishParameters -WhatIf
        Write-Host 'Dry run completed. Use -Publish for the actual upload.'
    }
}
finally {
    if (Test-Path $stagingRoot) {
        Remove-Item -Path $stagingRoot -Recurse -Force
    }
}