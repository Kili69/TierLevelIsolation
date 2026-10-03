# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FromCommit,

    [Parameter(Mandatory = $true)]
    [string]$ToCommit,

    [Parameter()]
    [string]$Path = (Join-Path $PSScriptRoot '..\..\CHANGELOG.md')
)

$ErrorActionPreference = 'Stop'
$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
    throw "Changelog not found: '$resolvedPath'."
}

$range = if ($FromCommit -match '^0{40}$') {
    $ToCommit
}
else {
    "$FromCommit..$ToCommit"
}

$commitLines = @(& git log --reverse --no-merges '--format=%H%x09%s' $range)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to read commits from '$range'."
}

$content = [System.IO.File]::ReadAllText($resolvedPath).Replace("`r`n", "`n")
$newEntries = [System.Collections.Generic.List[string]]::new()

foreach ($commitLine in $commitLines) {
    if ([string]::IsNullOrWhiteSpace($commitLine)) {
        continue
    }

    $parts = $commitLine.Split("`t", 2)
    $commit = $parts[0]
    $subject = $parts[1].Trim()
    $shortCommit = $commit.Substring(0, 7)

    if (
        $subject -match '\[skip changelog\]' -or
        $subject -match '^Update changelog for Dev commits$' -or
        $subject -match '^Finalize changelog for '
    ) {
        continue
    }

    $changedFiles = @(& git diff-tree --root --no-commit-id --name-only -r $commit)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect files changed by commit '$commit'."
    }
    if ($changedFiles -contains 'CHANGELOG.md') {
        continue
    }

    if ($content -match "\($([regex]::Escape($shortCommit))\)") {
        continue
    }

    $safeSubject = $subject.Replace('`', "'")
    $newEntries.Add("- $safeSubject ($shortCommit)")
}

if ($newEntries.Count -eq 0) {
    Write-Output 'No undocumented Dev commits were found.'
    return
}

$lines = [System.Collections.Generic.List[string]]::new()
foreach ($line in $content.TrimEnd("`n").Split("`n")) {
    $lines.Add($line)
}

$unreleasedIndex = $lines.IndexOf('## [Unreleased]')
if ($unreleasedIndex -lt 0) {
    throw "The changelog does not contain a '## [Unreleased]' section."
}

$nextReleaseIndex = $lines.Count
for ($index = $unreleasedIndex + 1; $index -lt $lines.Count; $index++) {
    if ($lines[$index] -match '^## ') {
        $nextReleaseIndex = $index
        break
    }
}

$changedIndex = -1
for ($index = $unreleasedIndex + 1; $index -lt $nextReleaseIndex; $index++) {
    if ($lines[$index] -eq '### Changed') {
        $changedIndex = $index
        break
    }
}

if ($changedIndex -ge 0) {
    $insertIndex = $nextReleaseIndex
    for ($index = $changedIndex + 1; $index -lt $nextReleaseIndex; $index++) {
        if ($lines[$index] -match '^### ') {
            $insertIndex = $index
            break
        }
    }
    while ($insertIndex -gt $changedIndex + 1 -and [string]::IsNullOrWhiteSpace($lines[$insertIndex - 1])) {
        $insertIndex--
    }

    foreach ($entry in $newEntries) {
        $lines.Insert($insertIndex, $entry)
        $insertIndex++
    }
}
else {
    $insertIndex = $nextReleaseIndex
    while ($insertIndex -gt $unreleasedIndex + 1 -and [string]::IsNullOrWhiteSpace($lines[$insertIndex - 1])) {
        $insertIndex--
    }

    $section = @('', '### Changed', '') + @($newEntries)
    foreach ($line in $section) {
        $lines.Insert($insertIndex, $line)
        $insertIndex++
    }
}

[System.IO.File]::WriteAllText(
    $resolvedPath,
    (($lines -join "`n").TrimEnd("`n") + "`n"),
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Added $($newEntries.Count) Dev commit(s) to the changelog."
