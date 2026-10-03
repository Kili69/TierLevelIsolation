<!-- markdownlint-configure-file {"MD024": {"siblings_only": true}} -->

# Changelog

All notable changes to this project are documented in this file. Historical entries available before this changelog was introduced were imported from `Test-KerberosArmoring.ps1`. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release identifiers follow the existing `0.1.YYYYMMDD.revision` convention.

## [Unreleased]

### Added

- Added this GitHub-compatible project changelog and linked it from the README.
- Added manually initiated Dev-to-main synchronization, automatic GitHub release creation for main commits, and conditional PowerShell Gallery publication workflows.

## [0.1.20261002.2] - 2026-10-02

### Fixed

- Reported domain-controller discovery failures per domain and continued testing the remaining reachable domains.

## [0.1.20261002.1] - 2026-10-02

### Added

- Added unprivileged mode, which skips machine-wide KDC bindings and tests one Windows-selected KDC per domain.

## [0.1.20260903.8] - 2026-09-03

### Added

- Added `PassThru` output objects containing domain and domain-controller armoring statuses.

### Changed

- Centralized domain status aggregation.

## [0.1.20260903.7] - 2026-09-03

### Changed

- Distinguished confirmed missing FAST as `False`, an unexpected issuing KDC as `Warning`, and `klist` or validation failures as `Error`.

## [0.1.20260903.6] - 2026-09-03

### Fixed

- Wrapped status reasons before the console edge and separated DC labels from reason text to prevent subsequent domain rows from appearing concatenated.

## [0.1.20260903.5] - 2026-09-03

### Added

- Added a usage example combining `TargetDomain` and `TestAllDC`.

## [0.1.20260903.4] - 2026-09-03

### Added

- Added armoring reasons for `Warning` and `Error` results to the normal output.

## [0.1.20260903.3] - 2026-09-03

### Added

- Added complete code documentation for `Get-KerberosArmoringReason`.

## [0.1.20260903.2] - 2026-09-03

### Added

- Added an explicit armoring-status reason that distinguishes missing FAST from a ticket issued by a different KDC than the selected domain controller.

## [0.1.20260903.1] - 2026-09-03

### Changed

- Clarified `klist add_bind` error 1722 as an unavailable RPC server and added targeted DNS, firewall, RPC, and domain-controller connectivity guidance.

## [0.1.20260902.14] - 2026-09-02

### Added

- Added DC configuration status to the normal summary when the configuration check is requested, independent of verbose output.

## [0.1.20260902.13] - 2026-09-02

### Fixed

- Correctly classified Windows Enterprise multi-session (`ServerRdsh`) as a client instead of a server.

## [0.1.20260902.12] - 2026-09-02

### Added

- Added explicit Client, Server, or Domain Controller classification to verbose local computer information.

## [0.1.20260902.11] - 2026-09-02

### Fixed

- Accepted a `klist` `Kdc Called` short host name when it matches the selected domain controller FQDN.

## [0.1.20260902.10] - 2026-09-02

### Added

- Added the loaded ActiveDirectory module version to verbose startup output.

## [0.1.20260902.9] - 2026-09-02

### Fixed

- Omitted empty architecture fields from verbose output on Windows PowerShell 5.1.

## [0.1.20260902.8] - 2026-09-02

### Added

- Added local computer, operating-system, user, elevation, and PowerShell details to verbose startup output.

## [0.1.20260902.7] - 2026-09-02

### Added

- Added inline data-flow documentation for function calls, key variables, and essential processing blocks.

## [0.1.20260902.6] - 2026-09-02

### Added

- Completed parameter, output, side-effect, and error documentation for all remaining functions.

## [0.1.20260902.5] - 2026-09-02

### Added

- Added detailed code documentation for `Invoke-FastTicketTest` and its temporary isolated-session helper script.

## [0.1.20260902.4] - 2026-09-02

### Added

- Documented the local FAST support result object and operating-system gate.

## [0.1.20260902.3] - 2026-09-02

### Added

- Documented the script-level version, error handling, executable path, and registry path variables.

## [0.1.20260902.2] - 2026-09-02

### Added

- Added a detailed technical description of discovery, ticket acquisition, validation, cleanup, result status, and exit behavior.

## [0.1.20260902.1] - 2026-09-02

### Fixed

- Made Cache Flags parsing compatible with `klist` output that omits the hexadecimal prefix for zero or the descriptive text after the flag value.

## [0.1.20260901.4] - 2026-09-01

### Fixed

- Resolved credential UPNs to down-level logon names before creating isolated Windows logon sessions.

## [0.1.20260901.3] - 2026-09-01

### Added

- Protected controller bindings used by parallel credential tests with realm-specific synchronization.

## [0.1.20260901.2] - 2026-09-01

### Changed

- Moved `klist add_bind` to the elevated process and improved binding errors.

## [0.1.20260901.1] - 2026-09-01

### Changed

- Used the Windows System32 `klist.exe` explicitly.

## [0.1.20260831.1] - 2026-08-31

### Fixed

- Corrected Kerberos armoring status evaluation for current-user tests.

## [0.1.20260826.13] - 2026-08-26

### Added

- Added explicit `OK`, `Warning`, and `Error` armoring status levels.

## [0.1.20260826.12] - 2026-08-26

### Added

- Added target-domain selection.

## [0.1.20260826.10] - 2026-08-26

### Changed

- Improved domain-controller ticket testing and issuing-KDC validation.

## [0.1.20260826.6] - 2026-08-26

### Added

- Added Kerberos armoring validation and troubleshooting output.
