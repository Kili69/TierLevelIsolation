# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [version]$BaseVersion,

    [Parameter(Mandatory = $true)]
    [version]$ReleaseVersion,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$ReleaseDate,

    [Parameter()]
    [string]$Path = (Join-Path $PSScriptRoot '..\..\CHANGELOG.md')
)

$ErrorActionPreference = 'Stop'
$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    throw "Changelog not found: '$resolvedPath'."
}
if ($ReleaseVersion -le $BaseVersion) {
    throw "Release version '$ReleaseVersion' must be newer than base version '$BaseVersion'."
}

$content = [System.IO.File]::ReadAllText($resolvedPath).Replace("`r`n", "`n")
$lines = @($content.TrimEnd("`n").Split("`n"))
$unreleasedIndex = [array]::IndexOf($lines, '## [Unreleased]')
if ($unreleasedIndex -lt 0) {
    throw "The changelog does not contain a '## [Unreleased]' section."
}

$basePattern = "^## \[$([regex]::Escape($BaseVersion.ToString()))\](?: - \d{4}-\d{2}-\d{2})?$"
$baseIndex = -1
for ($index = $unreleasedIndex + 1; $index -lt $lines.Count; $index++) {
    if ($lines[$index] -match $basePattern) {
        $baseIndex = $index
        break
    }
}
if ($baseIndex -lt 0) {
    throw "Base release '$BaseVersion' was not found after the Unreleased section."
}

$releasePattern = "^## \[$([regex]::Escape($ReleaseVersion.ToString()))\]"
for ($index = $baseIndex; $index -lt $lines.Count; $index++) {
    if ($lines[$index] -match $releasePattern) {
        throw "Release '$ReleaseVersion' already exists at or before base release '$BaseVersion'."
    }
}

$entries = [ordered]@{}
$categoryOrder = [System.Collections.Generic.List[string]]::new()
$currentCategory = $null

for ($index = $unreleasedIndex + 1; $index -lt $baseIndex; $index++) {
    $line = $lines[$index]
    if ($line -match '^## \[') {
        $currentCategory = $null
        continue
    }
    if ($line -match '^### (?<Category>.+)$') {
        $currentCategory = $Matches.Category
        if (-not $entries.Contains($currentCategory)) {
            $entries[$currentCategory] = [System.Collections.Generic.List[string]]::new()
            $categoryOrder.Add($currentCategory)
        }
        continue
    }
    if ($currentCategory -and $line -match '^- .+') {
        if (-not $entries[$currentCategory].Contains($line)) {
            $entries[$currentCategory].Add($line)
        }
    }
}

$entryCount = ($entries.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
if (-not $entryCount) {
    throw "No changelog entries were found between Unreleased and base release '$BaseVersion'."
}

$preferredCategories = @('Added', 'Changed', 'Deprecated', 'Removed', 'Fixed', 'Security')
$orderedCategories = @(
    $preferredCategories | Where-Object { $entries.Contains($_) -and $entries[$_].Count -gt 0 }
)
$orderedCategories += @(
    $categoryOrder | Where-Object {
        $_ -notin $preferredCategories -and $entries[$_].Count -gt 0
    }
)

$output = [System.Collections.Generic.List[string]]::new()
for ($index = 0; $index -le $unreleasedIndex; $index++) {
    $output.Add($lines[$index])
}
$output.Add('')
$output.Add("## [$ReleaseVersion] - $ReleaseDate")

foreach ($category in $orderedCategories) {
    $output.Add('')
    $output.Add("### $category")
    $output.Add('')
    foreach ($entry in $entries[$category]) {
        $output.Add($entry)
    }
}

$output.Add('')
for ($index = $baseIndex; $index -lt $lines.Count; $index++) {
    $output.Add($lines[$index])
}

[System.IO.File]::WriteAllText(
    $resolvedPath,
    (($output -join "`n").TrimEnd("`n") + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Consolidated $entryCount changelog entries into release $ReleaseVersion."
