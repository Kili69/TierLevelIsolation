# Change history

This file provides a chronological summary of the changes documented in the script and module files. Version numbers refer to the named component and do not always represent a shared release version.

## 2024

### 2024-02-18

- **TierLevelUserManagement.ps1** (`0.2.20240218`): Updated the documentation. This version appears in the source file before the versions identified as the initial releases in December 2024 and may therefore contain an incorrect date.

### 2024-12-06

- **install.ps1** (`0.2.20241206`): Initial version.
- **TierLevelUserManagement.ps1** (`0.2.20241206`): Initial version.

### 2024-12-20

- **TierLevelComputerManagement.ps1** (`20241220`): Initial version.
- **TierLevelUserManagement.ps1** (`0.2.20241220`): Removes `adminCount` when a user is removed from a privileged group. Users in a service-account OU are not removed from privileged groups.

### 2024-12-23

- **TierLevelComputerManagement.ps1** (`20241223`): Expanded the documentation to cover debug logging in the user data directory and important events in the Application log.
- **TierLevelUserManagement.ps1** (`20241223`): Updated the documentation.

## 2025

### 2025-01-03

- **install.ps1** (`0.2.20250103`): Corrected a typographical error.

### 2025-01-06

- **install.ps1** (`0.2.20250106`): Renamed computer groups to server groups. The Tier 1 server group name can now be changed. Renamed Tier X user OUs to Tier X administrator OUs. The displayed GPO name now uses the `$GPOName` variable.

### 2025-01-09

- **install.ps1** (`0.2.20250109`): Creates required groups on the nearest global catalog server. The script waits for computer-group replication and stops if the group cannot be created.

### 2025-02-17

- **install.ps1** (`0.2.20250217`): Stops the installation when a required OU cannot be created and provides more detailed error messages.

### 2025-02-18

- **install.ps1** (`0.2.20250218`): Updated output messages.

### 2025-02-28

- **install.ps1** (`0.2.20250228`): Fixed an OU creation error and typographical errors.

### 2025-03-03

- **install.ps1** (`0.2.20250303`): Fixed an error while updating the scheduled-task XML file.

### 2025-03-04

- **TierLevelComputerManagement.ps1** (`0.2.20250304`): Displays the log file path in the startup message.
- **TierLevelUserManagement.ps1** (`0.2.20250304`): Displays the log file path in the startup message.

### 2025-03-06

- **install.ps1** (`0.2.20250306`): Sets `adminCount = 1` on newly created Tier 0 and Tier 1 server groups.

### 2025-03-13

- **install.ps1** (`0.2.20250313`): Fixed an error in the Tier 0 Kerberos Authentication Policy claim and added descriptions for the Tier 0 and Tier 1 Kerberos Authentication Policies.

### 2025-03-14

- **install.ps1** (`0.2.20250314`): Adds the GMSA to the `Enterprise Admins` group when required.
- **TierLevelComputerManagement.ps1** (`0.2.20250314`): Updated the documentation.
- **TierLevelUserManagement.ps1** (`0.2.20250314`): Added debug information. Fixed an error when adding users to the `Protected Users` group and added a check for existing membership.

### 2025-03-15

- **TierLevelIsolation.psm1** (`0.1.20250315`): Initial module version.

### 2025-03-20

- **install.ps1** (`0.2.20250320`): Changed the default configuration file name from `Tiering.config` to `TierLevelIsolation.config`.
- **TierLevelComputerManagement.ps1** (`0.2.20250320`): Changed the default configuration file name from `tiering.json` to `TierLevelIsolation.config`.
- **TierLevelUserManagement.ps1** (`0.2.20250320`): Changed the default configuration file name from `tiering.config` to `TierLevelIsolation.config`.

### 2025-03-27

- **install.ps1** (`0.2.20250327`): Creates the configuration through the PowerShell module. Fixed an error in `New-TierLevelOU`. Added module installation and a parameter for module-only installation.
- **TierLevelIsolation.psm1** (`0.1.20250327`): Added functions for managing the Tier Level Isolation configuration and fixed errors. `Add-TierLevelIsolationDomain` now accepts an array as input.
- **TierLevelUserManagement.ps1** (`0.2.20250327`): Corrected the default value of the `$ConfigFile` parameter.

### 2025-03-29

- **TierLevelComputerManagement.ps1** (`0.2.20250329`): Reads the log path from the configuration file.

### 2025-03-31

- **install.ps1** (`0.2.20250331`): Imports the Group Policy so changes to scheduled tasks are applied. Creates the execution-context switch task in the GPO. User tasks are disabled by default in the GPO. Fixed module errors.
- **TierLevelIsolation.psm1** (`0.1.20250331`): Renamed the `Path` parameter to `OU` for the computer-, user-, and service-account-path functions. Added OU existence checks and error handling for invalid Active Directory objects.

### 2025-04-10

- **TierLevelUserManagement.ps1** (`0.2.20250410`): Corrected the detection of relative DNs for privileged users in `ValidateAndRemoveUser`.

### 2025-04-23

- **TierLevelIsolation.psm1** (`0.1.20250423`): Added functions for reading and setting the debug log path.
- **TierLevelUserManagement.ps1** (`0.2.20250423`): Uses the executing user's local AppData directory when no alternative log path is configured.

### 2025-04-28

- **install.ps1** (`0.2.20250428`): Added the `-Force` parameter for setting the computer group and Kerberos Authentication Policy. The solution now always uses a GMSA.
- **TierLevelIsolation.psm1** (`0.2.20250428`): Added the `-Force` parameter to `Set-TierLevelIsolationComputerGroup` and `Set-TierLevelIsolationKerberosAuthenticationPolicy`.

### 2025-06-19

- **TierLevelUserManagement.ps1** (`0.2.20250619`): Fixed an error while writing to the event log.

### 2025-06-23

- **TierLevelComputerManagement.ps1** (`0.2.20250623`): Added error handling for missing or invalid configuration files and added a new exit code.
- **TierLevelUserManagement.ps1** (`0.2.20250623`): Corrected use of the `ConfigFile` parameter and added exit codes.

### 2025-06-25

- **install.ps1** (`0.2.20250625`): Added GMSA validation; names longer than 15 characters are rejected.
- **TierLevelComputerManagement.ps1** (`0.2.20250625`): Aligned configuration-file loading with `TierLevelUserManagement.ps1`.

### 2025-07-14

- **install.ps1** (`0.2.20250714`): Fixed an error when using only Tier 0.
- **TierLevelComputerManagement.ps1** (`0.2.20250714`): Fixed an error while processing the `Scope` parameter.
- **TierLevelUserManagement.ps1** (`0.2.20250714`): Fixed an error while processing the `Scope` parameter.

### 2025-09-23

- **install.ps1** (`0.2.20250923`): Kerberos claim support can be enabled manually; the script displays a warning with guidance.

### 2025-10-14

- **install.ps1** (`0.2.20251014`): Updated Microsoft documentation links for Kerberos Authentication Policies, claims, and Kerberos Armoring.

### 2025-12-02

- **TierLevelComputerManagement.ps1** (`0.2.20251202`): Added error handling for unavailable Active Directory Web Services while checking unexpected computer objects. Corrected startup with the `ConfigFile` parameter.

### 2025-12-19

- **TierLevelIsolation.psm1** (`0.2.20251219`): Added functions for adding and removing additional Tier 0 and Tier 1 groups.
- **TierLevelUserManagement.ps1** (`0.2.20251219`): Added `ConvertTo-DistinguishedNames` to convert relative OU paths to FQDNs. Added processing of privileged domain groups from the configuration.

### 2025-12-23

- **TierLevelIsolation.psm1** (`0.2.20251223`): Prevents assigning a group to Tier 1 when it is already assigned to Tier 0. Group identities support NetBIOS, UPN, and canonical formats.
- **TierLevelUserManagement.ps1** (`0.2.20251223`): Corrected the `Tier-0` and `Tier-1` scope names.

### 2025-12-24

- **TierLevelUserManagement.ps1** (`0.2.20251224`): Updated the documentation and adjusted the behavior of the `AddProtectedUsersGroup` parameter in `Set-TierLevelIsolation`.

### 2025-12-26

- **TierLevelUserManagement.ps1** (`0.2.20251226`): Corrected handling of the `Protected Users` group.

## 2026

### 2026-01-20

- **install.ps1** (`0.2.20260120`): Fixed an error in the tier-level selection.

### 2026-03-06

- **install.ps1** (`0.2.20260306`): The source file does not document a change description for this version.
- **TierLevelComputerManagement.ps1** (`0.2.20260306`): Revised code documentation and structure. Log file names include the scope and computer name for easier identification in shared paths.
- **TierLevelUserManagement.ps1** (`0.2.20260306`): Revised code documentation and structure. Log file names include the scope and computer name. Added event ID `2001`.

### 2026-03-17

- **TierLevelUpdateModule.ps1** (`0.1.20260317`): Initial version.

### 2026-08-25

- **install.ps1** (`0.2.20260825.1`): Shows the `Protected Users` configuration only in advanced setup mode.
- **install.ps1** (`0.2.20260825.2`): Added debug log path configuration to advanced setup mode.
- **install.ps1** (`0.2.20260825.3`): Displays the current domain during OU validation. Uses values from an existing configuration as setup defaults.
- **TierLevelComputerManagement.ps1** (`0.2.20260825.1`): Aligned event IDs and event sources with Windows Event Log guidance.
- **TierLevelIsolation.psm1** (`0.1.20260825.1`): Fixed persistence of the debug log path.
- **TierLevelIsolation.psm1** (`0.1.20260825.2`): Stores additional Tier 0 and Tier 1 groups by SID. Added a command to display configured additional groups.
- **TierLevelUpdateModule.ps1** (`0.1.20260825.1`): Updated the version for the initial repository publication.
- **TierLevelUserManagement.ps1** (`0.2.20260825.1`): Aligned event IDs and event sources with Windows Event Log guidance.
- **TierLevelUserManagement.ps1** (`0.2.20260825.2`): Added SID-based cleanup for additional Tier 0 and Tier 1 groups.
- **TierLevelUserManagement.ps1** (`0.2.20260825.3`): Sets `adminCount` to `1` on nested groups during Tier 0 group processing.
- **TierLevelUserManagement.ps1** (`0.2.20260825.4`): Corrected DNS server resolution for nested groups.

### 2026-08-28

- **install.ps1** (`0.2.20260828.1` through `0.2.20260828.5`): Added a unique and detailed installation transcript in the temporary directory. Added complete code documentation, ZIP export of the PowerShell module to the Documents directory, and non-interactive parameterization through a PowerShell object. Standardized the Tier 0 term as "Tier 0 computer."
- **TierLevelIsolation.psm1** (`0.1.20260828.1` through `0.1.20260828.2`): Added complete module-level, function-level, and inline documentation.
- **TierLevelIsolation.psd1** (`0.1.20260828.2`): Updated the manifest version, minimum PowerShell version, and release notes.
- **TierLevelUserManagement.ps1** (`0.2.20260828.1`): Reads `adminCount` explicitly for nested Tier 0 groups before applying a required update.
