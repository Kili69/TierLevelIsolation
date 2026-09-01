# TierLevelIsolation

## Overview 
This solution implements Tier Level isolation as described in the blog "Protection Tier 0 the modern way". It prepares your Active Directory forest to support Kerberos Authentication Policies, creating prerequisites to isolate Tier 0 or Tier 1 and automate the Tier 0 / Tier 1 user management. The Kerberos Authentication Policy ensure privileged accounts must use Kerberos as authentication protocol and can only request Kerberos TGT on predefined computers. 
The solution automates the management of Tier 0 and Tier 1 users with Kerberos Authentication Policies through scripts. One script adds AD-Computer objects to an AD group included in the Kerberos Authentication Policy claim. Another script applies the policy to Tier 0 / Tier 1 users in the correct OU, and for Tier 0, removes users from privileged groups if they are not located in the correct OU.
The user management script ensures that users are added to the protected users group and removes users from privileged groups if they are not part of the administrator OU. 
This solution can manage Tier 0 and Tier 1 users within a single Active Directory Domain or across the entire Active Directory Forest. It utilizes scheduled tasks that run on your primary Active Directory domain, typically the Forest Root domain. 

# The scripts in a nutshell
## Install.ps1
Install the solution into you Active Directory environment
### TierLevelComputerManagement.ps1
Adds computer to the Kerberos Authentication claim group
### TierLevelUserManagement.ps1
Applies the Kerberos Authentication Policy to the Tier Level administrators

# Installation 
Preparation
Before you start installing TierLevelIsolation, there are a few preparatory steps that need to be done. Make sure you have all the necessary materials and tools on hand. 
1.	Download the latest version of TierLevelIsolation
2.	Classify the files as trusted (remove the "mark of the web" attribute) 
3.	The installation process requires Enterprise Administrator permissions.
4.	The installation can be done on a member server on which the Active Directory PowerShell modules and the Group Policy Powershell modules are installed.
5.	(optional) After a review of the files, the files should be signed
6.	Administration

## Installation
The installation process is started via the install.ps1 script. The installation script guides you through the configuration and creates the required resource. The install.ps1 script should be run as an enterprise administrator to avoid access issues with the Kerberos Authentication Police. 

### Target Selection
The script provides a list of the Active Directory domains in the current forest. Here you have to make a selection in which domains the tier-level isolation should take place.

### Scope Selection
In the next step, the tier levels for which the TierLevelIsolation is to be used are defined

## Tier 0
### Tier 0 Administrator OU
Here you have to specify the path in which the Tier0 administrators are stored. The path can be specified as a relative path (without the domain components e.g. OU=Admins,OU=Tier 0,OU=Admin), in which case the same OU structure will be applied in all domains. If the OU structures in the individual domains differ, this should be defined individually for each OU (e.g. OU=Admins,OU=Tier 0,OU=Admin,DC=contoso,DC=com)
If there are Tier 0 users in different OU structures, both relative and fully qualified DN can be specified

### Tier 0 Service Account OU
This is the path where Tier 0 service accounts are stored. Tier 0 service accounts differ from user accounts in that they are not assigned a Kerberos authentication policy, even though they are in AD privileged groups. Again, multiple paths can be specified as relative DN or fully qualified DN.

### Tier 0 Server OU
Is one or more path to the Tier 0 computer objects.

### Tier 0 Kerberos Authentication Policy 
The name of the Tier 0 Kerberos Authentication Policy. 

## Tier 1
### Tier 1 Administrator OU
Is the realtive path where the Tier 1 Administrator accounts are stored. If the path is specified as a relative DN, the OU structure must be present in all domains. Again, multiple DistinguishedNames can be specified.

### Tier 1 Service Account OU
This setting has no function at the moment

### Tier 1 Server OU
Is the absolute or relative DistinguishedName in which the server objects are stored.

### Tier 1 Kerberos Authentication Policy name
Is the name of the Tier 1 Kerberos Authentication Policy

## Server Groups
### Tier 0 Server group name
Is the name of the computer group to be included in the Tier 0 computer. This group is created in the Standard Users container. The group should be moved to a Tier 0 managed OU
### Tier 1 Server group name
Is the name of the group in which the Tier 1 computers are included. This group is created in the Standard Users container. 
### Protected Group
This setting determines whether Tier 0 / Tier 12 users are automatically added to the Protected User group. 
[0] All user objects stored in the Tier 0 Admin OU are automatically added to the Protected Users group
[1] All user objects stored in the Tier 1 Admin OU are automatically added to the Protected Users group
[2] Both Tier 0 and Tier 1 user objects are added to the Protectd Users group
[3] Neither Tier 0 nor Tier 1 administrators will be added to the Protected Users group
### Enable privileged group clean up
If the answer to this question is Y, all user objects from the following groups will be removed, unless they are in the Tier 0 Admin OU, Tier 0 Service Account OU, the Built Administrator and not a GMSA.
### Group managed service account
In a multi-domain forest, a GMSA is needed to manage the users in the forest domains. The SAM account name must be entered here. 
The GMSA is created on demand and added to the Enterprise Administrators group


## Post installation tasks
### Validate Kerberos Armoring
Kerberos Armoring must be active to isolate Tier 0 / Tier 1 administrators. For this purpose, the current Kerberos cache should be set with
KLIST PURGE 
Delete and request a new Kerberos ticket (e.g. dir \\<domain>\SYSVOL). Afterwards, you have the requested Kerberos ticket with 
KLIST
Indicate. In the TGT displayed, the value "Cache Flags" should be set to 0x41 -> PRIMARY FAST
The group policy settings for Kerberos Armoring are made only in the local domain. For all other domains in the AD-Forest, the settings must be manually completed.

If Kerberos Armoring is not available validate:
### Default Domain Policy
This enables support for Kerberos Armoring for all client computers. This is done via the setting:
Administrative Templates\System\Kerberos\Kerberos Armoring

### Default Domain Controller Policy:
In this group policy, Kerberos Armoring is enabled at the domain level. The following settings are made for this purpose:
Administrative Template\System\KDC\Kerberos Armoring Support mode
Administrative Templates\System\Kerberos\Kerberos Armoring

## Activation of Tier Level Isolation
Once installed, you will need to enable TierLevelIsolation. Activation is done via the Tier Level Isolation group policy. This policy group consists of 5 Schedule Tasks that run on the current domain. The schedule tasks are:
### Change user context
Group Policy Preference does not allow you to create a Schedule Task in the context of a GMSA. This task of this Schedule Task is to change the Schedule Tasks Tier 0 User Management / Tier 1 User Management from SYSTEM to the GMSA context
### Tier 0 computer management
The task of this schedule task is to add or remove computer objects from the Tier 0 server group
Both user Schedule Tasks have the trigger disabled by default to ensure that Tier 0 administrators are not locked out.
In the first step, the two schedule tasks "Tier 0 Computer Management" and "Tier 1 Computer Management" should be adapted. The default setting is that the task starts daily at 12 p.m. and then repeats every 10 minutes. 
### Tier 0 user management
This Schedule Task adds the Tier 0 Kerberos Authentication Policy to Tier 0 administrators
### Tier 1 computer management
The task of this schedule task is to add or remove computer objects from the Tier 1 server group
### Tier 1 user management
This Schedule Task adds the Tier 1 Kerberos Authentication Policy to Tier 1 administrators

Once the Computer Management task has been started for the first time, all computer objects must appear in the Tier 0 Computer group. Once this is done, make sure that the Tier 0 Member Server objects have been restarted. 
## Active the Tier 0 and Tier 1 user management tasks
Both user Schedule Tasks have the trigger disabled by default to ensure that Tier 0 administrators are not locked out.
In the first step, the two schedule tasks "Tier 0 Computer Management" and "Tier 1 Computer Management" should be adapted. The default setting is that the task starts daily at 12 p.m. and then repeats every 10 minutes. 
Once the Computer Management task has been started for the first time, all computer objects must appear in the Tier 0 Computer group. Once this is done, make sure that the Tier 0 Member Server objects have been restarted. 
Subsequently, the TierLevel isolation based on "Kerberos Authentication Polices" was to be tested. To do this, the Kerberos Authentication Policy is to add a Tier 0 user and validate the logon with this user object. 
The test is successful if this user can only authenticate on a Tier 0 member server or a domain controller. (RDP from an unprotected system is not supported)
The test can be repeated with several users. Once the administrators are familiar with Kerberos Authentication Policy based Administration, the Tier 0 user management task is enabled in the TierLevelIsolation Group Policy. 
To do this, the trigger in the "Tier 0 User Management" tab must be set to active in the Group Policy in the Preferences/Schedule Task. The Task starts at 12a.m. by default and repeats every 10 minutes. Depending on the environment, these values can be adjusted

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

`Test-KerberosArmoring.ps1` verifies that Kerberos FAST (Kerberos Armoring) is used when a client requests service tickets from the domains in the current Active Directory forest. The script requests an LDAP service ticket for a selected domain controller in each domain and verifies both of the following conditions:

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
| `Warning` | Yellow | A ticket was received, but Kerberos Armoring could not be confirmed |
| `Error` | Red | No usable ticket was received or the ticket test failed technically |

A domain shows the most severe status of its selected controllers. The process exits with code `0` only when every requested test has status `OK`; `Warning` and `Error` result in exit code `1`.

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
| `KerberosArmoringStatus` | Final `OK`, `Warning`, or `Error` status |
| `FastCacheFlags` | Ticket cache flags; `0x40` indicates FAST |
| `IssuingKdc` | KDC reported by `klist.exe` as the ticket issuer |
| `IssuingKdcConfirmed` | Indicates whether the issuing KDC matches the selected controller |
| `TicketTestError` | Error message when the ticket test could not be completed |

The effective `EnableCbacAndArmor` registry values can also be checked on the selected controllers:

```powershell
.\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -CheckDomainControllerConfiguration -Verbose
```

#### Common failures

**`klist add_bind` fails with `0xC0000001` / `-1073741823`**

The PowerShell process is not elevated. Start PowerShell with **Run as administrator** and run the
test again. Version `0.1.20260901.2` and later execute the privileged binding operation in the
elevated parent process rather than in the non-privileged credential helper.

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

Check the `TicketTestError` value with `-Verbose`. Verify that the domain controller FQDN resolves correctly, the `ldap/<DC-FQDN>` SPN exists on the controller account, the forest trust path is available, and Kerberos traffic is not blocked.

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

