# TierLevelManagement configuration file
The configuration ist sorted in JSON format. The JSON object has the following proterties

## configuration objects
The follwing configuration parameters are available: 
### scope
This paramter defines the scope of the Tier Level Isolation. Valid values are:
### Domains
Is a array of Active Directory domains in the forest

### PrivilegedGroupsCleanUp
if this parameter is true Tier-0 users will be removed from privileged Active Directory groups 

#### Tier-0
This value is used for Tier-0 users isolation only
#### Tier-1
This value is used for Tier-1 users isolation only
#### All-Tiers
This vlaue is used if Tier-0 and Tier-1 will be protected by Tier Level Isolation
### ProtectedUsers"
if a array of Tier levels where the users will be added to the protected users group in their domain
#### Tier-0
Tier-0 users will be added to the protected users group
#### Tier-1
Tier-1 users will be added to the protected users group

### Tier0ComputerPath:
Is a array of distinguished names where the Tier 0 computer objects are stored. If a relative distinguished name is used like "OU=Computers,OU=Tier 0,OU=Admin". The computer management script searches for all computer object in this path in every domain defined in the domain list.
If the DN is full qualified (including domain DN) the script will only search in specified domain for Tiering computers
#### Example:
OU=Computers,OU=Tier 0,OU=Admin
searches in every domain in this OU
OU=Computers,OU=Tier 0,OU=Admin,DC=contoso,DC=com
searches only in contoso.com for Tier 0 computers 

### Tier 0 Computers:
is the SAMAccount name of the Tier 0 computers group. This group should be a universal group in the forest root domain. 

### Tier0ServiceAccountPath
is the DN for service accounts. User objects in this ou, won't get a Kerberos Authentication Policy and will not be removed from privileged groups

### Tier1ComputerPath" 
Is a array of distinguished names where the Tier 1 computer objects are stored. If a relative distinguished name is used like "OU=Computers,OU=Tier 1,OU=Admin". The computer managemdn script searches for all computer objects in this path in every domain defined in the domain list
if the DN is full qualified (including domain DN) the script will only search in specified domain for Tiering computers

### Tier1ComputerGroup
is the SAMAccount name of the Tier 1 computers group. This group should be a universal group in the forest

### Tier0UsersPath:
Is a array of distinguished names where the Tier 0 user objects are stored. If a relative distinguished name is used like "OU=Users,OU=Tier 1,OU=Admin". The user management script searches for all users in this path in every domain defined in the domain list

### Tier1UsersPath"
Is a array of distinguished names where the Tier 1 user objects are stored. If a relative distinguished name is used like "OU=Users,OU=Tier 1,OU=Admin". The user management script searches for all users in this path in every domain defined in the domain list

### Tier0Groups

An array of SIDs for additional Active Directory groups whose members are
validated as Tier 0 identities. Group names are not stored in the
configuration.

```json
"Tier0Groups": [
	"S-1-5-21-111111111-222222222-333333333-1100"
]
```

### Tier1Groups

An array of SIDs for additional Active Directory groups whose members are
validated as Tier 1 identities. A group SID cannot be assigned to both tiers.

```json
"Tier1Groups": [
	"S-1-5-21-111111111-222222222-333333333-1200"
]
```

Additional groups are processed only when `PrivilegedGroupsCleanUp` is enabled.
The group SID must resolve in one of the domains listed in `Domains`.

## Managing additional groups

`Add-TierLevelIsolationGroup` accepts a SID or an Active Directory group
identity. Names are resolved when the command runs; only the resulting SID is
stored.

```powershell
Add-TierLevelIsolationGroup -TierLevel Tier0 -GroupName 'CONTOSO\Tier 0 Operators'
Add-TierLevelIsolationGroup -TierLevel Tier1 -GroupSID 'S-1-5-21-111111111-222222222-333333333-1200'
```

Display all configured groups or only one tier:

```powershell
Get-TierLevelIsolationGroup
Get-TierLevelIsolationGroup -TierLevel Tier0
```

The output includes the stored SID, resolved group name, domain, and resolution
state. Remove a group by its stored SID or by an identity that can be resolved:

```powershell
Remove-TierLevelIsolationGroup -TierLevel Tier0 -GroupSID 'S-1-5-21-111111111-222222222-333333333-1100'
```

