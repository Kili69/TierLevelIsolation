# TierLevelIsolation 1.0 developer guide

## Purpose

This document explains the repository structure, runtime architecture, PowerShell scripts, shared configuration, development process, and release process of TierLevelIsolation. User-facing installation, operation, and troubleshooting instructions remain in [README.md](./README.md).

TierLevelIsolation implements Tier 0 and Tier 1 isolation in an Active Directory forest by combining:

- Kerberos Authentication Policies that restrict where privileged identities can authenticate.
- Universal computer groups that define the permitted systems for each tier.
- Scheduled management scripts that reconcile Active Directory objects with the configured tier model.
- A shared JSON configuration stored in SYSVOL.
- A PowerShell module that validates and updates that configuration.
- A Group Policy backup that deploys the scheduled tasks.

The project targets Windows PowerShell 5.1 and depends on the Windows `ActiveDirectory` module. Installation also requires the `GroupPolicy` module.

## Architecture

The installation and runtime data flow is:

1. `install.ps1` installs the module and collects the desired forest, tier, OU, group, policy, logging, and cleanup settings.
2. The module writes the resulting JSON configuration to `\\<domain>\SYSVOL\<domain>\scripts\TierLevelIsolation.config`.
3. The installer copies the management scripts and module to SYSVOL, creates or validates the required Active Directory objects, and imports the bundled GPO.
4. Scheduled tasks deployed through the GPO invoke the computer and user management scripts.
5. Both management scripts read the shared configuration and reconcile Active Directory with it.
6. `Test-KerberosArmoring.ps1` independently validates client support, domain-controller configuration, and FAST-protected ticket issuance.

SYSVOL is the distribution point for the runtime components:

```text
\\<domain>\SYSVOL\<domain>\
|-- scripts\
|   |-- TierLevelIsolation.config
|   |-- TierLevelComputerManagement.ps1
|   |-- TierLevelUpdateModule.ps1
|   `-- TierLevelUserManagement.ps1
`-- PSModules\
    `-- TierLevelIsolation\
        |-- TierLevelIsolation.psd1
        `-- 1.0\
            `-- TierLevelIsolation.psm1
```

Active Directory remains the source of truth for domains, OUs, groups, users, computers, and Kerberos Authentication Policies. The configuration describes which objects the management scripts should reconcile.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `install.ps1` | Installs the module and solution, builds the configuration, creates Active Directory objects, deploys files to SYSVOL, and imports the GPO. |
| `TierLevelComputerManagement.ps1` | Reconciles Tier 0 and Tier 1 computer-group membership with the configured computer OUs. |
| `TierLevelUserManagement.ps1` | Applies authentication policies and account protections, and optionally cleans privileged-group membership. |
| `TierLevelUpdateModule.ps1` | Updates the locally installed module from the replicated SYSVOL copy when the source version is newer. |
| `Test-KerberosArmoring.ps1` | Tests local FAST support, optional domain-controller policy settings, and Kerberos-armored ticket issuance. |
| `publish.ps1` | Validates, stages, dry-runs, and publishes the PowerShell module. |
| `module/TierLevelIsolation.psd1` | Defines the module version, root module, dependencies, exported functions, and gallery metadata. |
| `module/1.0/TierLevelIsolation.psm1` | Implements configuration read, validation, mutation, and persistence commands. |
| `configuration.md` | Documents the JSON configuration schema and additional-group management commands. |
| `EventID.md` | Catalogs Windows Application log event IDs emitted by the management scripts. |
| `ScheduledTasks.xml` | Reference scheduled-task definition used by the solution. |
| `GPO/` | Importable Group Policy backup containing the production scheduled-task preferences. |
| `.github/workflows/sync-dev-to-main.yml` | Manually prepares the protected Dev-to-main pull request. |
| `.github/workflows/update-dev-changelog.yml` | Adds undocumented Dev commit titles to the Unreleased changelog section. |
| `.github/workflows/release.yml` | Creates a release for every push to `main` and conditionally publishes the module. |
| `.github/scripts/Update-DevChangelog.ps1` | Detects Dev commits that did not directly update the changelog and records their titles. |
| `.github/scripts/Finalize-Changelog.ps1` | Consolidates all changelog categories since the latest main release into one target release. |
| `CHANGELOG.md` | Records user-visible changes by release. |
| `HISTORY.md` | Preserves detailed historical project changes. |
| `LICENSE` and `NOTICE` | Define the Apache 2.0 license and third-party notices. |

## Shared configuration

The default configuration file is:

```text
\\<current-domain>\SYSVOL\<current-domain>\scripts\TierLevelIsolation.config
```

It is JSON despite the `.config` extension. The module builds a complete configuration object with safe defaults before merging values from an existing file. This allows older configurations to gain newly introduced properties without a separate migration.

The main configuration groups are:

- `Domains` and `scope`: define the forest domains and enabled tiers.
- `Tier0ComputerPath` and `Tier1ComputerPath`: identify managed computer OUs.
- `Tier0UsersPath` and `Tier1UsersPath`: identify managed administrator OUs.
- `Tier0ServiceAccountPath` and `Tier1ServiceAccountPath`: exempt configured service-account OUs from user cleanup.
- `Tier0ComputerGroup` and `Tier1ComputerGroup`: identify the universal server groups used in policy claims.
- `T0KerbAuthPolName` and `T1KerbAuthPolName`: identify the Kerberos Authentication Policies.
- `ProtectedUsers`: controls which tier users are maintained in the domain Protected Users group.
- `PrivilegedGroupsCleanUp`: enables removal of unexpected privileged memberships.
- `Tier0Groups` and `Tier1Groups`: store additional managed groups by immutable SID.
- `LogPath`: optionally directs runtime logs to a shared or local directory.

Relative OU distinguished names are expanded for every configured domain. Fully qualified distinguished names are processed only in their own domain. See [configuration.md](./configuration.md) for the complete schema.

## PowerShell module

The module manifest exports the supported public configuration commands and declares `ActiveDirectory` as both a required and external module dependency. The implementation queries the current domain at import time to derive the default SYSVOL path.

The exported commands provide these groups of operations:

- Read configuration with `Get-TierLevelIsolationConfiguration`.
- Add and remove configured domains.
- Add and remove computer, user, and service-account OU paths.
- Add, inspect, and remove additional Tier 0 or Tier 1 groups.
- Set the tier scope, computer groups, and Kerberos Authentication Policy names.
- Enable or disable Protected Users handling and privileged-group cleanup.
- Read or set the debug-log path.

Every mutating command validates its input and immediately persists the complete JSON configuration. Additional groups are resolved when configured, but only their SIDs are stored so renaming a group does not invalidate the configuration.

The `RootModule` value in `module/TierLevelIsolation.psd1` must reference the major/minor implementation directory. For version 1.0 it is `1.0\TierLevelIsolation.psm1`.

## Script execution flows

### install.ps1

`install.ps1` is the provisioning entry point. It supports interactive installation and repeatable non-interactive installation through `-InstallationParameters`.

Its execution flow is:

1. Create a unique transcript in the Windows temporary directory. Installation stops if the transcript cannot be created.
2. Import the `ActiveDirectory` and `GroupPolicy` modules and discover the current domain and a site-aware domain controller.
3. Install or update the TierLevelIsolation module under the system-wide Windows PowerShell module path.
4. Read any existing shared configuration and collect or resolve installation parameters.
5. Persist the selected domains, scope, OU paths, groups, policy names, Protected Users state, cleanup state, and log path through module commands.
6. Create or validate configured OUs in each applicable domain.
7. Create missing universal Tier 0 and Tier 1 computer groups, wait for replication visibility, and set `adminCount`.
8. Create missing enforced Kerberos Authentication Policies. Their conditional access expressions allow authentication only from enterprise domain controllers and the configured tier computer groups.
9. Create or validate the gMSA used by the scheduled tasks and grant its required group membership.
10. Copy the management scripts, configuration, and module to SYSVOL.
11. Update the scheduled-task definitions in the bundled GPO backup, import the GPO, and link it to the Domain Controllers OU.
12. Optionally configure Kerberos claims and armoring policy values.
13. Finish the transcript with status and duration information.

`-InstallPSModuleOnly` stops after installing or updating the module and creating its reusable ZIP package. It does not create isolation objects.

### TierLevelComputerManagement.ps1

This script reconciles computer OU membership with the tier computer groups.

Its execution flow is:

1. Load the explicit `-ConfigFile` or the default SYSVOL configuration.
2. Resolve the requested `-scope`, falling back to the configured scope.
3. Create the `TierLevelIsolation` Windows Event Log source when possible and initialize a rotating text log.
4. Resolve the configured Tier 0 and, when enabled, Tier 1 computer groups.
5. For every configured domain and computer OU, find computer objects and add missing group members.
6. Build the set of permitted fully qualified OUs.
7. Identify current group members outside those OUs and remove them.
8. Record changes, warnings, and failures with the event IDs in [EventID.md](./EventID.md).

The script is a reconciliation loop: repeated execution should converge group membership on the configured OU contents.

### TierLevelUserManagement.ps1

This script reconciles privileged-user controls with the configured tier model.

Its execution flow is:

1. Load the explicit `-ConfigFile` or default SYSVOL configuration.
2. Initialize Windows Event Log and rotating text logging.
3. Validate the requested `-scope` against the configured scope.
4. Expand relative user and service-account OUs into fully qualified distinguished names for the configured domains.
5. For each enabled tier and domain, enumerate users in the configured administrator OUs.
6. Assign the tier's Kerberos Authentication Policy and mark users as sensitive and not delegable.
7. Add users to the domain Protected Users group when enabled for that tier.
8. When `PrivilegedGroupsCleanUp` is enabled, inspect built-in privileged groups and configured additional groups.
9. Preserve users in configured administrator or service-account OUs and remove unexpected members.
10. Maintain `adminCount` on nested Tier 0 groups and log every relevant action.

Additional groups are processed by SID and resolved across the configured domains. This prevents group renames from changing the intended security boundary.

### TierLevelUpdateModule.ps1

This script keeps the system-wide module installation aligned with SYSVOL:

1. Discover the current domain.
2. Read the source manifest from `\\<domain>\SYSVOL\<domain>\PSModules\TierLevelIsolation`.
3. Read the locally installed manifest under `%ProgramFiles%\WindowsPowerShell\Modules\TierLevelIsolation`.
4. Copy the complete module from SYSVOL when no local module exists or the source version is newer.
5. Leave the local installation unchanged when it is already current.

### Test-KerberosArmoring.ps1

This diagnostic script is independent of the scheduled reconciliation tasks. It validates whether Kerberos tickets are protected with FAST.

Its execution flow is:

1. Validate the local operating system, elevation where required, `klist.exe`, and required `klist` commands.
2. Discover the forest, requested domains, and eligible domain controllers.
3. Optionally read effective `EnableCbacAndArmor` registry values from each selected controller.
4. In privileged mode, bind Kerberos requests to a specific controller. In `-Unprivileged` mode, allow Windows to select the KDC.
5. Use an isolated logon session for supplied credentials, or deliberately purge and use the caller's cache with `-UseCurrentUser`.
6. Request an LDAP service ticket for the selected controller.
7. Parse the ticket cache flags and require FAST bit `0x40`.
8. In controller-specific mode, confirm that `Kdc Called` matches the selected controller.
9. Aggregate results, write a color-coded summary, optionally emit objects with `-PassThru`, and return exit code `0` only when all requested checks succeed.
10. Remove bindings and temporary files and restore a current-user home-domain TGT when applicable.

`-TestAllDC` parallelizes credential-based tests up to `-ThrottleLimit`. Current-user tests remain sequential because they share one ticket cache.

### publish.ps1

This script validates and publishes the PowerShell module without modifying source files:

1. Require `Publish-PSResource`.
2. Read the source manifest without importing the module.
3. Validate the declared module version and root-module path.
4. Copy the complete `module` directory to an isolated temporary staging path.
5. Revalidate the staged version and root module.
6. Invoke `Publish-PSResource` against the selected repository.
7. Remove the staging directory after success or failure.

Without `-Publish`, the script uses `-WhatIf`. With `-Publish`, it reads the API key only from `PSGALLERY_API_KEY`.

Dependency and internal manifest validation are skipped in `Publish-PSResource` because `ActiveDirectory` is supplied by Windows RSAT and is not available in PowerShell Gallery. The script performs static manifest, version, and root-module validation before publishing.

## Logging and diagnostics

`install.ps1` writes a unique transcript to the Windows temporary directory. The management scripts write rotating text logs and use the `TierLevelIsolation` source in the Windows Application log. If that source cannot be created, Event Log output is disabled for the run while text logging remains available.

The configured `LogPath` is used when available. Otherwise, the management scripts use the executing account's local application-data directory. A log larger than 1 MB is rotated to `.sav`.

Use these references when investigating behavior:

- [README.md](./README.md) for operator troubleshooting and Kerberos test interpretation.
- [EventID.md](./EventID.md) for event meanings.
- [configuration.md](./configuration.md) for configuration semantics.
- The installation transcript for provisioning errors.
- `-Verbose` and `-PassThru` with `Test-KerberosArmoring.ps1` for complete controller results.

## Development workflow

All code changes are developed and tested on `Dev`. Direct development on `main` is not part of the repository workflow.

1. Update local `Dev` from `origin/Dev`.
2. Make and validate focused changes.
3. Update directly related documentation.
4. Update file-specific versions for every changed file that already contains a current version.
5. Add a new version-history entry only when that file already maintains version history.
6. Use a meaningful commit title. Update `CHANGELOG.md` directly when a curated entry is preferable to the commit title.
7. Commit and push to `Dev`. The **Update Dev changelog** workflow adds undocumented commit titles under `Unreleased` in a separate bot commit.
8. Confirm that a Dev push does not create a release or publish a package. It may only create the expected changelog bot commit.
9. When the accumulated changes are tested, manually start **Sync Dev to main**.
10. Review and manually merge the resulting Dev-to-main pull request.

Do not commit generated logs, credentials, API keys, temporary packages, or local test output. The video files under `DOC/` are intentionally outside the normal release workflow unless Git LFS is deliberately configured.

## Versioning

Versioned files use:

```text
<major>.<minor>.<yyyyMMdd>.<counter>
```

For example, `1.0.20261003.2` is the second version created on 2026-10-03 while retaining major/minor version 1.0.

When committing:

- Preserve the existing major and minor values unless the change explicitly introduces a major or minor release.
- Reset the counter to `1` when the date changes.
- Increment the counter when another version of the same file is created on the same date.
- Keep all active version declarations within a file consistent.
- Do not rewrite historical entries.
- Keep the README title aligned with the current major/minor project version.

The GitHub release version and the module version are related but independent. The manual sync workflow reserves the next `1.0.YYYYMMDD.counter` version and writes it to the changelog. The later `main` push uses that exact version for the GitHub tag and release. PowerShell Gallery publishes the immutable `ModuleVersion` declared in the module manifest.

## Validation expectations

Use the smallest validation set that covers a change. Depending on the changed files, this normally includes:

- PowerShell parser validation for changed scripts and module files.
- PSScriptAnalyzer for changed PowerShell code.
- A dry run of `publish.ps1` for module packaging changes.
- Static manifest and root-module validation.
- Markdownlint and spelling checks for changed Markdown.
- Actionlint for changed GitHub Actions workflows.
- Installation and management testing in a non-production Active Directory forest for behavior changes.
- Kerberos armoring tests on a supported Windows client for changes to FAST diagnostics or policy deployment.

Tests that mutate Active Directory, Group Policy, Kerberos bindings, ticket caches, SYSVOL, or module installations must not be run against production as an initial validation.

## Publish to PowerShell Gallery

Validate the module package without uploading it:

```powershell
.\publish.ps1
```

For a release, create an API key on PowerShell Gallery and enter it without placing it in the PowerShell command history:

```powershell
$secureKey = Read-Host 'PSGallery API key' -AsSecureString
$env:PSGALLERY_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
.\publish.ps1 -Publish
Remove-Item Env:PSGALLERY_API_KEY
```

Increment `ModuleVersion` in `module\TierLevelIsolation.psd1` before every subsequent release because PowerShell Gallery versions are immutable.

The automated workflow requires a repository Actions secret named `PSGALLERY_API_KEY`. Never store the key in the repository, workflow file, shell history, or documentation.

## Automated release workflow

All code changes are made and tested on the `Dev` branch. A push to `Dev` runs **Update Dev changelog**, which records commit titles not already represented by a direct changelog edit. Its changelog-only bot commit cannot publish or synchronize anything. When the tested changes are ready, start the **Sync Dev to main** workflow manually from the GitHub Actions page.

The synchronization workflow:

1. Updates `Dev` from protected `main` when the branches have diverged.
2. Exits without changes when no Dev commits need promotion.
3. Adds any still undocumented Dev commit titles to `Unreleased`.
4. Determines the latest release tag reachable from `main` and reserves the next major/minor/date/counter version.
5. Combines `Unreleased` and any intermediate Dev release sections by changelog category into that one target version.
6. Commits and pushes the consolidated changelog to `Dev`.
7. Opens or reuses a Dev-to-main pull request and sets the required `Dev source branch` status.
8. Leaves review and merge as explicit manual actions.

The protected `main` branch accepts changes only through the Dev-to-main pull request. Merging it creates a push to `main`, which triggers the **Release** workflow.

The release workflow:

1. Reads the prepared version from the first released section after `Unreleased`.
2. Verifies that the corresponding tag does not already point to another commit.
3. Creates a ZIP archive from the exact repository commit.
4. Creates a GitHub release and generated release notes.
5. Detects whether the main push changed files under `module`.
6. Skips PowerShell Gallery when no module file changed.
7. Installs PSResourceGet and verifies that the manifest version is unpublished when module files changed.
8. Invokes `publish.ps1 -Publish` with the repository secret.

Only a push to `main` can enter the module-publication job. Commits and pushes to `Dev` or any other branch cannot publish a package. The publication job fails when the API key is missing or the module version already exists; GitHub release creation remains a separate job.

Before promoting module changes, confirm that:

- `ModuleVersion` was incremented.
- The root-module path exists and matches the major/minor module directory.
- The package dry run succeeds.
- `PSGALLERY_API_KEY` is configured.
- The target module version does not already exist in PowerShell Gallery.
- The changelog contains the release information rather than leaving completed work under `Unreleased`.

## Licensing

The project is licensed under Apache License 2.0. New PowerShell source files should carry the repository's SPDX identifier:

```powershell
# SPDX-License-Identifier: Apache-2.0
```

Third-party material must retain its original notices. Update [NOTICE](./NOTICE) when introducing material that requires attribution.
