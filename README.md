# TierLevelIsolation

## Overview 
This solution implements Tier Level isolation as described in the blog "Protection Tier 0 the modern way". It prepares your Active Directory forest to support Kerberos Authentication Policies, creating prerequisites to isolate Tier 0 or Tier 1 and automate the Tier 0 / Tier 1 user management. The Kerberos Authentication Policy ensure privileged accounts must use Kerberos as authentication protocol and can only request Kerberos TGT on predefined computers. 
The solution automates the management of Tier 0 and Tier 1 users with Kerberos Authentication Policies through scripts. One script adds AD-Computer objects to an AD group included in the Kerberos Authentication Policy claim. Another script applies the policy to Tier 0 / Tier 1 users in the correct OU, and for Tier 0, removes users from privileged groups if they are not located in the correct OU.
The user management script ensures that users are added to the protected users group and removes users from privileged groups if they are not part of the administrator OU. 
This solution can manage Tier 0 and Tier 1 users within a single Active Directory Domain or across the entire Active Directory Forest. It utilizes scheduled tasks that run on your primary Active Directory domain, typically the Forest Root domain. 
# Installation and activation

Roll out TierLevelIsolation in the following order. Do not enable automated user management until
Kerberos Armoring, the Tier 0 server scope, and a limited user proof of concept have been validated.

## Preparation

1. Download the latest version of TierLevelIsolation.
2. Remove the Mark of the Web from the downloaded files so that PowerShell treats them as trusted.
3. Use an account with Enterprise Administrator permissions for the initial installation.
4. Run the installation from a member server with the Active Directory and Group Policy PowerShell
	 modules installed.
5. Review the files and, when required by organizational policy, sign the PowerShell scripts.

## 1. Install the solution with install.ps1

Run `install.ps1` as an Enterprise Administrator. The script guides you through the configuration
and creates the required Active Directory objects, groups, policies, Group Policy settings, and
scheduled tasks.

```powershell
.\install.ps1
```

### Target and scope selection

Select the Active Directory domains in which TierLevelIsolation will operate, followed by the tier
levels to enable. Review the following values carefully before confirming the installation.

### Tier 0 configuration

- **Tier 0 Administrator OU:** One or more paths containing Tier 0 administrator accounts. Relative
	distinguished names apply the same OU structure to every selected domain. Use fully qualified
	distinguished names when domains use different OU structures.
- **Tier 0 Service Account OU:** One or more paths containing privileged service accounts that must
	not receive the user Kerberos Authentication Policy. Relative and fully qualified distinguished
	names can be combined.
- **Tier 0 Server OU:** One or more paths containing the Tier 0 computer objects.
- **Tier 0 Kerberos Authentication Policy:** Name of the policy assigned to Tier 0 administrators.

### Tier 1 configuration

- **Tier 1 Administrator OU:** One or more relative or fully qualified distinguished names containing
	Tier 1 administrator accounts.
- **Tier 1 Service Account OU:** Reserved for future use.
- **Tier 1 Server OU:** One or more relative or fully qualified distinguished names containing Tier 1
	computer objects.
- **Tier 1 Kerberos Authentication Policy:** Name of the policy assigned to Tier 1 administrators.

### Groups and service account

- **Tier 0 Server group:** Contains the computers allowed by the Tier 0 Kerberos Authentication
	Policy. The installer creates the group in the standard Users container; move it to an OU managed
	as Tier 0 when required.
- **Tier 1 Server group:** Contains the computers allowed by the Tier 1 Kerberos Authentication
	Policy.
- **Protected Users:** Select whether Tier 0 users, Tier 1 users, both tiers, or neither tier are
	managed as members of the Protected Users group.
- **Privileged group cleanup:** When enabled, user management removes privileged group members that
	are outside the configured administrator and service-account OUs. The built-in Administrator and
	supported gMSA accounts are excluded.
- **Group managed service account:** A multi-domain forest requires a gMSA to manage users in forest
	domains. Supply its sAMAccountName during installation. The installer creates the account when
	required and grants the configured permissions.

The TierLevelIsolation Group Policy contains five scheduled tasks:

- **Change user context:** Changes the Tier 0 and Tier 1 User Management tasks from `SYSTEM` to the
	configured gMSA because Group Policy Preferences cannot create these tasks directly in that context.
- **Tier 0 Computer Management:** Adds or removes computer objects from the Tier 0 server group.
- **Tier 1 Computer Management:** Adds or removes computer objects from the Tier 1 server group.
- **Tier 0 User Management:** Assigns the Tier 0 Kerberos Authentication Policy and applies the
	configured account protections.
- **Tier 1 User Management:** Assigns the Tier 1 Kerberos Authentication Policy and applies the
	configured account protections.

The user-management task triggers are disabled initially to prevent an unvalidated policy from
locking out administrators.

## 2. Enable Kerberos Armoring in the AD forest

Kerberos Armoring must be enabled for clients and domain controllers in every domain in scope. The
installer configures the local domain; review and complete the corresponding Group Policy settings
in every other forest domain.

Configure the client policy in the applicable domain policy:

```text
Administrative Templates\System\Kerberos\Kerberos client support for claims, compound authentication and Kerberos armoring
```

Configure the domain-controller policies in the applicable Domain Controllers policy:

```text
Administrative Templates\System\KDC\KDC support for claims, compound authentication and Kerberos armoring
Administrative Templates\System\Kerberos\Kerberos client support for claims, compound authentication and Kerberos armoring
```

Allow Group Policy and Active Directory replication to complete, then run `gpupdate /force` on the
systems used for validation.

## 3. Validate Kerberos Armoring

Run [`Test-KerberosArmoring.ps1`](Test-KerberosArmoring.ps1) from an elevated PowerShell session.
Validate all forest domains, or use `-TargetDomain` to limit the run to the local computer domain and
one additional domain.

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TestAllDC
```

Proceed only when the required domains and domain controllers report `OK`. A `False` result means
that the selected DC issued a ticket without FAST. `Warning` means that another KDC issued the ticket,
and `Error` indicates a technical failure. See [Test Kerberos Armoring](#test-kerberos-armoring) for
all parameters, status definitions, structured output, and troubleshooting.

## 4. Validate Tier 0 member servers

Run or wait for the **Tier 0 Computer Management** scheduled task. Verify that every intended Tier 0
member-server computer object has been added to the configured Tier 0 server group and that no
unintended computer is a member.

Restart all Tier 0 member servers after their group membership is correct. The restart ensures that
the computer obtains a token and Kerberos state based on the current group membership before user
policy testing begins. Do not continue with the user proof of concept until this step is complete.

## 5. Run a single-user proof of concept

Select one Tier 0 test administrator and assign the Tier 0 Kerberos Authentication Policy manually.
Do not enable the automated User Management task yet.

Validate the complete administration workflow with this account:

- Authentication succeeds on the intended Tier 0 member servers and domain controllers.
- Authentication is denied on systems outside the Tier 0 scope.
- Required administrative tools and remote-management workflows continue to work.
- Expected restrictions, including unsupported RDP access from an unprotected system, are understood.
- A recovery account and rollback procedure remain available throughout the test.

Remove or correct the manual policy assignment if the test exposes a missing server, group
membership, or access path.

## 6. Expand the administrator rollout

After the single-user proof of concept succeeds, assign the policy manually to a small additional
group of administrators. Increase the rollout in controlled stages while monitoring authentication
failures and collecting administrator feedback.

Before each stage, confirm that:

- Every administrator account is located in the intended Tier 0 or Tier 1 administrator OU.
- Service accounts are located in the configured service-account OUs and are excluded as intended.
- All required administration systems belong to the correct server group and have been restarted.
- Help desk and recovery procedures are ready for authentication-policy failures.

Continue until the intended administrator population has successfully worked with the policy and
the operational procedures are established.

## 7. Enable the User Management scheduled tasks

Enable the trigger for **Tier 0 User Management** only after the staged administrator rollout has
completed successfully. When Tier 1 is in scope, validate its server and user rollout independently
before enabling **Tier 1 User Management**.

The task trigger is located in the TierLevelIsolation Group Policy under Group Policy Preferences
and Scheduled Tasks. Review the schedule before activation; the default task starts daily and repeats
every ten minutes. Adjust the interval to the operational requirements of the environment.

After activation, verify the first runs in the Windows Application event log and confirm that the
expected Kerberos Authentication Policies, Protected Users memberships, and privileged-group cleanup
actions were applied. Keep monitoring enabled during the initial production rollout.

# Monitoring
Monitoring is done in the Application Event log. For detailed information, a debug log file is also created. The path to the log file is logged as Windows events Source:TierLevelIsolation 1000 or Source:TierLevelIsolation 2000.

Only Information, Warning, and Error events are written to the Windows Application log. Events with severity Debug are written only to the text log file and are documented in `EventID.md`.

## Computer management
To monitor the computer management functions, look for the following events in the event log:

| Event ID | Type | Description | Trigger |
|---|---|---|---|
| 1000 | Information | Computer management script started | The script starts. For the default scheduled task, this event normally appears every 10 minutes. |
| 1003 | Error | Unexpected error while updating the Tier 0 computer group | An unhandled error occurs while processing a Tier 0 computer OU. |
| 1004 | Error | AD Web Service connection failed during computer management | A configured domain cannot be contacted while computer objects are processed. |
| 1101 | Error | Default configuration was not found | Neither the default SYSVOL configuration nor an Active Directory configuration is available. |
| 1102 | Error | Configuration file could not be read | The specified configuration file exists but does not return a configuration object. |
| 1103 | Error | Configuration file was not found | The path supplied with `ConfigFile` does not exist. |
| 1104 | Error | Unexpected error while reading the configuration | An unhandled exception occurs while loading or parsing the configuration. |
| 1200 | Error | Tier 0 computer group was not found | The configured Tier 0 computer group cannot be resolved; processing is aborted. |
| 1202 | Error | Tier 1 computer group was not found | The configured Tier 1 computer group cannot be resolved. |
| 1203 | Error | AD Web Service is unavailable | Active Directory cannot be queried while the computer groups are initialized. |
| 1204 | Warning | Tier 0 computer is not listed in the global catalog | A Tier 0 group update fails because the required object is not yet available through the global catalog. |
| 1300 | Warning | Tier 0 computer OU is missing | A configured Tier 0 computer OU cannot be found in a target domain. |
| 1302 | Information | Computer is added to the Tier 0 computer group | A computer in a configured Tier 0 OU is not yet a member of the Tier 0 computer group. |
| 1304 | Warning | Computer is removed from the Tier 0 computer group | A group member is no longer located in an allowed Tier 0 computer OU. |
| 1306 | Warning | Unexpected computers cannot be verified | AD Web Service is unavailable while existing group members are checked against allowed OUs. |
| 1400 | Warning | Tier 1 computer OU is missing | A configured Tier 1 computer OU cannot be found in a target domain. |
| 1401 | Information | Computer is added to the Tier 1 computer group | A computer in a configured Tier 1 OU is not yet a member of the Tier 1 computer group. |
| 1402 | Error | Unexpected error while updating the Tier 1 computer group | An unhandled error occurs while Tier 1 computer objects are processed. |
| 1403 | Warning | Computer is removed from the Tier 1 computer group | A group member is no longer located in an allowed Tier 1 computer OU. |
| 1404 | Warning | Tier 1 computer is not listed in the global catalog | A Tier 1 group update fails because the required object is not yet available through the global catalog. |

## User management
To monitor the user management functions, look for the following events in the event log:

| Event ID | Type | Description | Trigger |
|---|---|---|---|
| 2000 | Information | User management script started | The script starts. For the default scheduled task, this event normally appears every 10 minutes. |
| 2001 | Warning | Configured log path is invalid | The configured text-log directory does not exist; the script uses the current user's local application data directory. |
| 2002 | Error | Default configuration was not found | Neither the default SYSVOL configuration nor an Active Directory configuration is available. |
| 2003 | Error | Configuration file could not be read | The specified configuration file exists but does not return a configuration object. |
| 2004 | Error | Configuration file was not found | The path supplied with `ConfigFile` does not exist. |
| 2005 | Error | Unexpected error while reading the configuration | An unhandled exception occurs while loading or parsing the configuration. |
| 2006 | Error | Requested scope conflicts with configured scope | The `Scope` parameter requests a tier that is disabled in the configuration. |
| 2101 | Error | Kerberos Authentication Policy was not found | The configured authentication policy cannot be resolved in Active Directory. |
| 2102 | Warning | User OU is missing | A configured Tier 0 or Tier 1 user OU cannot be found in a target domain. |
| 2103 | Warning | Built-in Administrator is located in a Tier 0 user OU | The built-in Administrator account with RID 500 is found in a managed OU and is intentionally skipped. |
| 2104 | Information | Kerberos Authentication Policy is assigned | A managed user does not have the configured authentication policy. |
| 2105 | Information | User is marked as sensitive and cannot be delegated | The AccountNotDelegated flag is not set on a managed user and is enabled by the script. |
| 2106 | Information | User is added to Protected Users | Protected Users management is enabled and a managed user is not yet a member. |
| 2107 | Error | Access denied while changing a user attribute | Active Directory rejects an update to a managed user. |
| 2108 | Error | Active Directory identity was not found | Users or another required identity cannot be enumerated. |
| 2109 | Error | Unexpected error during user isolation | An unhandled exception occurs while authentication policy or account settings are applied. |
| 2200 | Warning | Configured group SID is unavailable | A privileged group cannot be resolved from its configured SID. |
| 2201 | Warning | User is removed from a privileged group | Privileged-group cleanup finds a user outside the allowed administrator and service-account OUs. |
| 2202 | Error | AD Web Service is unavailable during group cleanup | The script cannot contact Active Directory while removing a privileged group member. |
| 2203 | Error | User could not be removed from a privileged group | Active Directory returns an error while a privileged group membership is removed. |
| 2204 | Error | Unexpected error while processing a privileged group member | An unhandled exception occurs during privileged-group cleanup. |
| 2208 | Warning | Additional privileged group is invalid or was not found | A configured additional group SID is malformed or cannot be resolved in any configured domain. |
| 2209 | Warning | Additional privileged group could not be processed | A general error occurs while an additional configured group is resolved. |
| 2210 | Warning | Domain cannot be contacted for an additional group | AD Web Service is unavailable while an additional group SID is resolved in a configured domain. |
| 2211 | Information | `adminCount` is set on a nested Tier 0 group | A nested Tier 0 group does not have `adminCount` set to `1`. |
| 2212 | Error | `adminCount` could not be set on a nested Tier 0 group | The nested group cannot be read or updated. |
| 2213 | Error | DNS domain could not be resolved for a nested group | The naming-context cross-reference for a nested group does not provide a DNS domain name. |
| 2302 | Warning | Domain for a NetBIOS name was not found | A distinguished name contains a NetBIOS domain that cannot be mapped to a forest DNS domain. |
| 2303 | Error | NetBIOS name could not be converted to a DNS domain | An error occurs while the forest cross-reference is queried. |

## Troubleshooting

### Debug log files

`TierLevelComputerManagement.ps1` and `TierLevelUserManagement.ps1` create a detailed text log on every run. When `LogPath` is empty in the TierLevelIsolation configuration, the scripts use the local application data directory of the account running the scheduled task:

```text
%LOCALAPPDATA%
```

The scripts create separate files for computer and user management. The scope and computer name are included so that runs from different tasks or systems remain distinguishable:

```text
TierLevelIsolationComputerManagement-<Scope>-<ComputerName>.log
TierLevelIsolationUserManagement-<Scope>-<ComputerName>.log
```

When a log file exceeds 1 MB, the existing file is rotated to the same name with the `.sav` extension.

Use the TierLevelIsolation PowerShell module to configure a different log directory. The directory must already exist and the identities running the scheduled tasks must have write permission to it. A local directory or a UNC path can be used:

```powershell
Import-Module TierLevelIsolation
Set-DebugLogPath -LogPath 'D:\TierLevelIsolation\Logs'
Set-DebugLogPath -LogPath '\\FileServer\TierLevelIsolationLogs'
```

The currently configured directory can be displayed with:

```powershell
Get-DebugLogPath
```

Set an empty value to restore the default `%LOCALAPPDATA%` behavior:

```powershell
Set-DebugLogPath -LogPath ''
```

### Test Kerberos Armoring

[`Test-KerberosArmoring.ps1`](Test-KerberosArmoring.ps1) verifies that Kerberos FAST (Kerberos Armoring) is used when a client requests service tickets from the domains in the current Active Directory forest. The script requests an LDAP service ticket for a selected domain controller in each domain and verifies both of the following conditions:

- The cached service ticket contains the `FAST` cache flag (`0x40`).
- The ticket was issued by the domain controller selected for the test (`Kdc Called`).

Using a service ticket instead of a referral TGT makes it possible to validate Kerberos Armoring across the forest with one test account. The account can belong to any domain in the forest and does not require administrative permissions.

#### Requirements

- Run the script on Windows 8, Windows Server 2012, or a newer Windows version.
- Start PowerShell with **Run as administrator**. Windows requires elevation for `klist add_bind`
	and `klist purge_bind`; the forest test account itself can remain non-privileged.
- The Active Directory PowerShell module must be installed.
- The computer must be joined to the forest or have the required DNS, trust, LDAP, and Kerberos connectivity to every domain being tested.
- `klist.exe` must support the `get` and `add_bind` commands.
- The optional registry configuration check requires permission to read the remote registry of the selected domain controllers.

#### Basic test

Without additional selection parameters, the script tests one writable domain controller per domain. The controller is selected deterministically by sorting the eligible controllers by host name and choosing the first one.

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential)
```

The same non-privileged forest account is used for every domain. The script creates an isolated logon session for each test, so the Kerberos ticket cache of the current user is not changed.
UPN credentials such as `user@contoso.com` are resolved to their Windows `DOMAIN\user` identity
before the isolated process is created.

To use the currently logged-on user instead:

```powershell
.\Test-KerberosArmoring.ps1 -UseCurrentUser
```

This mode purges the current user's Kerberos ticket cache during the test. Do not use it when existing Kerberos sessions must remain uninterrupted.

#### Test a specific domain

Use `-TargetDomain` with a DNS domain name to test a specific domain while retaining the test of the local computer domain. If the target is the local domain, it is tested only once. Without this parameter, the script continues to test every domain in the forest:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TargetDomain child.contoso.com
```

If the specified domain does not belong to the current forest, the script displays the forest name
and the valid target domains, then exits with code `1`.

Combine `-TargetDomain` with `-TestAllDC` to test every eligible controller in the local and target domains.

```powershell
.\Test-KerberosArmoring.ps1 -UseCurrentUser -TargetDomain child.contoso.com -TestAllDC
```

With `-UseCurrentUser`, these controller tests run sequentially because they share and purge the
current user's Kerberos ticket cache.

#### Test every domain controller

Use `-TestAllDC` to request and validate a ticket against every eligible domain controller. When a
credential is used, ticket tests run in parallel with up to eight concurrent tests by default:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TestAllDC
```

Use `-ThrottleLimit` to adapt concurrency to the size of the environment and the capacity of the
test client. Valid values are 1 through 64:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TestAllDC -ThrottleLimit 16
```

`-UseCurrentUser -TestAllDC` remains sequential because all tests use the current logon session and
would otherwise modify the same Kerberos cache and KDC bindings concurrently.

Read-only domain controllers are excluded by default. Include them with `-IncludeReadOnlyDomainControllers`:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TestAllDC -IncludeReadOnlyDomainControllers
```

#### Detailed output and configuration check

The script displays its version at startup so that test output can be assigned to the exact script revision. The default output contains one status per domain. With `-TestAllDC`, the output contains the domain controller name and an individual status for every tested controller:

| Status | Color | Meaning |
|---|---|---|
| `OK` | Green | An LDAP service ticket was received with FAST and from the selected KDC |
| `False` | Red | A ticket was issued by the selected KDC, but it does not contain the FAST cache flag |
| `Warning` | Yellow | A ticket was received from a KDC other than the selected domain controller |
| `Error` | Red | `klist.exe`, ticket acquisition, or result parsing failed, or no usable ticket was received |

A domain shows the most significant status of its selected controllers using the priority `Error`,
`False`, `Warning`, and `OK`. The process exits with code `0` only when every requested test has
status `OK`; every other status results in exit code `1`.

For every non-`OK` result, the regular output shows the affected domain controller and a wrapped
reason below the domain or controller status. `-Verbose` is not required to see this reason.

Use `-Verbose` to display the result for every tested domain controller:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TestAllDC -Verbose
```

Important verbose properties are:

| Property | Meaning |
|---|---|
| `DomainController` | Domain controller selected for the test |
| `ServicePrincipal` | LDAP SPN used to request the service ticket |
| `TicketReceived` | Indicates whether the requested LDAP service ticket was found in the cache |
| `FastEnabled` | Indicates whether the ticket contains the FAST cache flag |
| `KerberosArmoringStatus` | Final `OK`, `False`, `Warning`, or `Error` status for the controller |
| `KerberosArmoringReason` | Human-readable reason for the controller status |
| `FastCacheFlags` | Ticket cache flags; `0x40` indicates FAST |
| `IssuingKdc` | KDC reported by `klist.exe` as the ticket issuer |
| `IssuingKdcConfirmed` | Indicates whether the issuing KDC matches the selected controller |
| `TicketTestError` | Error message when the ticket test could not be completed |

The effective `EnableCbacAndArmor` registry values can also be checked on the selected controllers:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -CheckDomainControllerConfiguration -Verbose
```

#### Reuse structured results

Specify `-PassThru` to write one structured object per tested domain controller to the PowerShell
success output stream. The color-coded summary is written to the host and is therefore not included
when the output is assigned to a variable:

```powershell
$results = .\Test-KerberosArmoring.ps1 -UseCurrentUser -TestAllDC -PassThru
```

Each object contains both the aggregated domain status and the individual controller status:

| Property | Meaning |
|---|---|
| `Domain` | DNS name of the tested domain |
| `DomainKerberosArmoringStatus` | Aggregated domain status using `Error > False > Warning > OK` |
| `DomainController` | FQDN of the tested domain controller |
| `DomainControllerKerberosArmoringStatus` | Armoring status for this controller |
| `DomainControllerKerberosArmoringReason` | Human-readable reason for the controller status |

The objects can be filtered, grouped, or exported without parsing the displayed table:

```powershell
$results |
	Where-Object DomainKerberosArmoringStatus -ne 'OK' |
	Format-Table -AutoSize

$results | Export-Csv -Path .\KerberosArmoring.csv -NoTypeInformation
```

The process exit code remains unchanged when `-PassThru` is used. Read `$LASTEXITCODE` after the
script completes when automation needs both the result objects and the overall success signal.

#### Common failures

**`klist add_bind` fails with `0xC0000001` / `-1073741823`**

The PowerShell process is not elevated. Start PowerShell with **Run as administrator** and run the
test again. Version `0.1.20260901.2` and later execute the privileged binding operation in the
elevated parent process rather than in the non-privileged credential helper.

**`klist add_bind` fails with Windows error `1722`**

Error `1722` means that the RPC server is unavailable. The failure occurs while the preferred KDC
binding is created, before the LDAP service ticket is requested. Verify name resolution and network
routing to the selected domain controller, the RPC endpoint mapper on TCP 135, dynamic RPC ports,
firewall rules, and the domain controller's RPC services. The regular result output includes the
affected controller and the complete error reason.

**`LocalClientFastSupported` is `False`**

The local operating system or `klist.exe` does not provide the required Kerberos functionality. Run `klist /?` and verify that the `get <SPN>` and `add_bind <DOMAIN> <DC>` commands are listed.
If `whoami /groups` reports `BUILTIN\Administrators` or the domain administrator groups as
`Group used for deny only` and shows `Medium Mandatory Level`, the current process is not elevated.
Membership in Domain Admins alone is insufficient; start PowerShell with **Run as administrator**.

**`FastCacheFlags` does not contain `0x40`**

The service ticket was not obtained through FAST. Verify the Kerberos Armoring settings in the Default Domain Policy for clients and the Default Domain Controllers Policy for KDCs. After Group Policy replication, run `gpupdate /force` and repeat the test from a client that supports FAST.

**`IssuingKdcConfirmed` is `False`**

The ticket was issued by a KDC other than the controller selected for the test. Check DNS resolution, domain-controller reachability, Kerberos ports, AD replication, and the value shown in `IssuingKdc`.

**The LDAP service ticket cannot be requested**

Read the reason displayed below the regular `Error` status. Use `-Verbose` for the complete result
object including `TicketTestError`. Verify that the domain controller FQDN resolves correctly, the
`ldap/<DC-FQDN>` SPN exists on the controller account, the forest trust path is available, and
Kerberos traffic is not blocked.

**Windows cannot create a logon session for the credential**

Verify the password and account state and ensure the account is permitted to log on locally to the
test computer. Version `0.1.20260901.4` and later resolves a supplied UPN to `DOMAIN\user` before
calling `Start-Process`, avoiding UPN interpretation problems in alternate process logons.

**The registry configuration check fails**

`-CheckDomainControllerConfiguration` uses the Remote Registry API. Confirm that the Remote Registry service and firewall rules permit access and that the executing account can read the remote HKLM registry hive. This check is optional and independent of the ticket-based FAST verification.

## Publish to PowerShell Gallery

Validate the module package without uploading it:

```powershell
.\publish.ps1
```

For a release, create an API key on PowerShell Gallery and enter it without
placing it in the PowerShell command history:

```powershell
$secureKey = Read-Host 'PSGallery API key' -AsSecureString
$env:PSGALLERY_API_KEY = [System.Net.NetworkCredential]::new('', $secureKey).Password
.\publish.ps1 -Publish
Remove-Item Env:PSGALLERY_API_KEY
```

Increment `ModuleVersion` in `module\TierLevelIsolation.psd1` before every
subsequent release because PowerShell Gallery versions are immutable.

