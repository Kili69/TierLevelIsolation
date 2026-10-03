# TierLevelManagement configuration file

The configuration is stored in JSON format. The JSON object has the following properties.

## Configuration objects

The following configuration parameters are available:

### Scope

This parameter defines the scope of Tier Level Isolation. Valid values are:

#### Scope: Tier-0

This value enables isolation for Tier 0 users only.

#### Scope: Tier-1

This value enables isolation for Tier 1 users only.

#### Scope: All-Tiers

This value enables isolation for both Tier 0 and Tier 1 users.

### Domains

An array of Active Directory domains in the forest.

### PrivilegedGroupsCleanUp

When this parameter is `true`, Tier 0 users outside the configured administrator and service-account OUs are removed from privileged Active Directory groups.

### ProtectedUsers

An array of tier levels whose users are added to the Protected Users group in their domain.

#### ProtectedUsers: Tier-0

Tier 0 users are added to the Protected Users group.

#### ProtectedUsers: Tier-1

Tier 1 users are added to the Protected Users group.

### Tier0ComputerPath

An array of distinguished names where Tier 0 computer objects are stored. When a relative distinguished name such as `OU=Computers,OU=Tier 0,OU=Admin` is used, the computer management script searches this path in every domain in the domain list. When a fully qualified distinguished name includes the domain components, the script searches only the specified domain.

#### Example

- `OU=Computers,OU=Tier 0,OU=Admin` searches this OU in every configured domain.
- `OU=Computers,OU=Tier 0,OU=Admin,DC=contoso,DC=com` searches only `contoso.com` for Tier 0 computers.

### Tier0ComputerGroup

The sAMAccountName of the Tier 0 computer group. This group should be a universal group in the forest root domain.

### Tier0ServiceAccountPath

The distinguished name of the OU for Tier 0 service accounts. User objects in this OU do not receive a Kerberos Authentication Policy and are not removed from privileged groups.

### Tier1ComputerPath

An array of distinguished names where Tier 1 computer objects are stored. When a relative distinguished name such as `OU=Computers,OU=Tier 1,OU=Admin` is used, the computer management script searches this path in every configured domain. When a fully qualified distinguished name includes the domain components, the script searches only the specified domain.

### Tier1ComputerGroup

The sAMAccountName of the Tier 1 computer group. This group should be a universal group in the forest root domain.

### Tier0UsersPath

An array of distinguished names where Tier 0 user objects are stored. When a relative distinguished name such as `OU=Users,OU=Tier 0,OU=Admin` is used, the user management script searches this path in every configured domain.

### Tier1UsersPath

An array of distinguished names where Tier 1 user objects are stored. When a relative distinguished name such as `OU=Users,OU=Tier 1,OU=Admin` is used, the user management script searches this path in every configured domain.

### Tier0Groups

An array of SIDs for additional Active Directory groups whose members are validated as Tier 0 identities. Group names are not stored in the configuration.

```json
"Tier0Groups": [
    "S-1-5-21-111111111-222222222-333333333-1100"
]
```

### Tier1Groups

An array of SIDs for additional Active Directory groups whose members are validated as Tier 1 identities. A group SID cannot be assigned to both tiers.

```json
"Tier1Groups": [
    "S-1-5-21-111111111-222222222-333333333-1200"
]
```

Additional groups are processed only when `PrivilegedGroupsCleanUp` is enabled. The group SID must resolve in one of the domains listed in `Domains`.

## Managing additional groups

`Add-TierLevelIsolationGroup` accepts a SID or an Active Directory group identity. Names are resolved when the command runs; only the resulting SID is stored.

```powershell
Add-TierLevelIsolationGroup -TierLevel Tier0 -GroupName 'CONTOSO\Tier 0 Operators'
Add-TierLevelIsolationGroup -TierLevel Tier1 -GroupSID 'S-1-5-21-111111111-222222222-333333333-1200'
```

Display all configured groups or only one tier:

```powershell
Get-TierLevelIsolationGroup
Get-TierLevelIsolationGroup -TierLevel Tier0
```

The output includes the stored SID, resolved group name, domain, and resolution state. Remove a group by its stored SID or by an identity that can be resolved:

```powershell
Remove-TierLevelIsolationGroup -TierLevel Tier0 -GroupSID 'S-1-5-21-111111111-222222222-333333333-1100'
```
