<#
Module Info

Author: Andreas Lucas [MSFT]


Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages

Module Name: TierLevelIsolation
Module Version: 0.1.20260828.2
Module GUID: 32c51271-3735-4b61-b80f-7284dafe6c77
Module Description: Manages the shared configuration for Kerberos Authentication Policy based
Tier Level isolation in an Active Directory forest.

Architecture:
    The module stores its configuration as JSON in the forest-root domain SYSVOL path
    \\<DNSRoot>\SYSVOL\<DNSRoot>\scripts\TierLevelIsolation.config. Exported commands read,
    validate, modify, and persist individual configuration properties. Active Directory is the
    source of truth when domains, groups, organizational units, and authentication policies are
    resolved.

Configuration properties:
    Tier0ComputerPath / Tier1ComputerPath
        Organizational units containing managed computers.
    Tier0ComputerGroup / Tier1ComputerGroup
        Server groups referenced by Kerberos authentication policies.
    Tier0ServiceAccountPath / Tier1ServiceAccountPath
        Organizational units containing managed service accounts.
    Tier0UsersPath / Tier1UsersPath
        Organizational units containing managed administrative users.
    T0KerbAuthPolName / T1KerbAuthPolName
        Kerberos authentication policy names assigned to each tier.
    Domains
        Forest domains included in management operations.
    scope
        Enabled scope: Tier-0, Tier-1, or All-Tiers.
    ProtectedUsers
        Tiers whose users are maintained in the Protected Users group.
    PrivilegedGroupsCleanUp
        Controls cleanup of incompatible privileged-group memberships.
    LogPath
        Optional runtime log directory used by the management scripts.
    Tier0Groups / Tier1Groups
        Additional managed groups stored by immutable Active Directory SID.

Prerequisites and side effects:
    - Windows PowerShell 5.1 or later and the ActiveDirectory module.
    - Importing the module queries the current Active Directory domain.
    - The default configuration path requires read/write access to SYSVOL.
    - Set, Add, and Remove commands immediately persist the complete JSON configuration.

Version History:
    0.1.20250315 - Initial version
    0.1.20250327 - Added functions to manage the configuration of TierLevelIsolation, bug fixing
                 - Add-TierLevelIsolationDomain support an array as import parameter
    0.1.20250331 - Change the parameter from Path to OU on Add-TierLevelIsolationComputerPath, Add-TierLevelIsolationUserPath, Add-TierLevelIsolationServiceAccountPath to clarify that it is an Organizational Unit (OU) path.
                 - Added validation to check if the specified OU exists in Active Directory before adding it to the configuration.
                 - Added error handling for invalid inputs and exceptions when retrieving OUs or groups from Active Directory.
    0.1.20250423 - Added function to set the DebugLog Path to the configuration file.
                 - Added function to get the DebugLog Path from the configuration file.
    Version 0.2.20250428
                - Added the force parameter to the Set-TierLevelIsolationComputerGroup, Set-TierLevelIsolationKerberosAuthenticationPolicy
    Version 0.2.20251219 
                - Added functions to add and remove groups to/from Tier0 and Tier1 configurations.
    Version 0.2.20251223
                - Added validation to prevent adding a group to Tier1 if it already exists in Tier0.
                - Supported values in Add-TierLevelIsolationGroup are now in NetBIOS format (DOMAIN\GroupName), UPN (GroupName@DNSName) and canonical name (DNSName/GroupName).
    Version 0.1.20260825.1
                - Fixed persistence of the debug log path.
    Version 0.1.20260825.2
                - Store additional Tier 0 and Tier 1 groups by SID.
                - Added a command to display configured additional groups.
    Version 0.1.20260828.1
                - Added complete module-level and function-level code documentation.
    Version 0.1.20260828.2
                - Added maintainer-focused inline documentation for implementation logic.

#>

#region Module initialization
# Resolve the forest-root DNS name at import time and derive the default shared configuration file.
# Individual functions accept configFile to support testing or an alternate configuration location.
#endregion

#region Global variables
$Global:DnsRoot = (Get-ADDomain).DNSRoot
$global:configFile = "\\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config"


#endregion

#.SYNOPSIS
#   Convert a distinguished name to a DNS domain name
#.DESCRIPTION
#   This function converts a distinguished name (DN) to a DNS domain name. It extracts the domain components (dc=) from the DN and returns the DNS domain name.
#.PARAMETER DistinguishedName
#   The distinguished name to convert. This can be a full DN or just the domain part (e.g. "DC=contoso,DC=com").
#.EXAMPLE
#   ConvertFrom-DN2Dns -DistinguishedName "CN=Users,DC=contoso,DC=com"
#   Returns "contoso.com".
#.OUTPUTS
#   System.String. DNS name of the matching Active Directory naming context, or $null when the
#   distinguished name cannot be resolved.
#.NOTES
#   Internal helper. Requires access to the forest configuration partition.
function ConvertFrom-DN2Dns {
    param(
        [Parameter(Mandatory= $true, ValueFromPipeline)]
        [string]$DistinguishedName
    )
    # Keep only the DC components, then resolve the matching naming-context cross-reference.
    $DistinguishedName = [regex]::Match($DistinguishedName,"(dc=[^,]+,)*dc=.+$",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Value
    return (Get-ADObject -Filter "nCname -eq '$DistinguishedName'" -Searchbase (Get-ADForest).PartitionsContainer -Properties dnsroot).DnsRoot
}

#.SYNOPSIS
#   Reads the Tier Level Isolation configuration.
#.DESCRIPTION
#   Creates a configuration object with every supported property and its safe default, then merges
#   values from the JSON configuration file when it exists. This permits older configuration files
#   to gain newly introduced properties without a migration step. Legacy scope values Tier0 and
#   Tier1 are normalized to Tier-0 and Tier-1 in the returned object.
#.PARAMETER configFile
#   JSON configuration file to read. The default is the TierLevelIsolation.config file in the
#   forest-root domain SYSVOL scripts directory.
#.EXAMPLE
#   Get-TierLevelIsolationConfiguration
#   Returns the shared forest configuration using the default SYSVOL location.
#.EXAMPLE
#   Get-TierLevelIsolationConfiguration -configFile "C:\Temp\TierLevelIsolation.config"
#   Returns a configuration from an alternate file, which is useful for testing.
#.OUTPUTS
#   System.Management.Automation.PSCustomObject. Contains all documented module configuration
#   properties, including defaults for properties absent from the JSON file.
#.NOTES
#   The function does not create a missing file. Use a configuration-changing command to persist
#   the returned default structure.
function Get-TierLevelIsolationConfiguration {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$configFile = $global:configFile
    )
    # Build the complete current schema first. This supplies defaults for new or older files.
    $config = New-Object psobject
    $config | Add-Member -MemberType NoteProperty -Name Tier0ComputerPath       -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier1ComputerPath       -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier0ComputerGroup      -Value ""
    $config | Add-Member -MemberType NoteProperty -Name Tier1ComputerGroup      -Value ""
    $config | Add-Member -MemberType NoteProperty -Name Tier0ServiceAccountPath -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier1ServiceAccountPath -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier0UsersPath          -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier1UsersPath          -Value @()
    $config | Add-Member -MemberType NoteProperty -Name T0KerbAuthPolName       -Value ""
    $config | Add-Member -MemberType NoteProperty -Name T1KerbAuthPolName       -Value ""
    $config | Add-Member -MemberType NoteProperty -Name Domains                 -Value @()
    $config | Add-Member -MemberType NoteProperty -Name scope                   -Value $null
    $config | Add-Member -MemberType NoteProperty -Name ProtectedUsers          -Value @()
    $config | Add-Member -MemberType NoteProperty -Name PrivilegedGroupsCleanUp -Value $false
    $config | Add-Member -MemberType NoteProperty -Name LogPath                 -Value ""
    $config | Add-Member -MemberType NoteProperty -Name Tier0Groups             -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier1Groups             -Value @()

    # Merge only recognized properties so unknown JSON data cannot alter the object shape.
    if (Test-Path $configFile) {
        $CurrentConfig = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        foreach ($configItem in $config.PSObject.Properties) {
            if ($null -ne $CurrentConfig.PSObject.Properties[$configItem.Name]) {
                $config.PSObject.Properties[$configItem.Name].Value = $CurrentConfig.PSObject.Properties[$configItem.Name].Value
            }
        }
    }

    # Normalize legacy internal scope names to the values consumed by current management scripts.
    if ($config.scope -eq "Tier0") {
        $config.scope = "Tier-0"
    } elseif ($config.scope -eq "Tier1") {
        $config.scope = "Tier-1"
    }
    return $config
}

#.SYNOPSIS
#   Persists the complete Tier Level Isolation configuration.
#.DESCRIPTION
#   Serializes the supplied configuration object as JSON and overwrites the target configuration
#   file. All module commands that modify configuration call this internal persistence function.
#.PARAMETER configFile
#   Destination JSON file. The default is the shared configuration in SYSVOL.
#.PARAMETER config
#   Configuration object to serialize. It is normally obtained from
#   Get-TierLevelIsolationConfiguration.
#.EXAMPLE
#   $Configuration = Get-TierLevelIsolationConfiguration
#   Set-TierLevelIsolationConfiguration -config $Configuration
#   Writes the configuration back to the default file.
#.OUTPUTS
#   None.
#.NOTES
#   Internal helper. Write failures are reported to the host and are not rethrown.
function Set-TierLevelIsolationConfiguration {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$configFile = $global:configFile,
        [Parameter(Mandatory = $true, Position = 1)]
        $config
    )
    try {
        # Persist one complete snapshot rather than updating individual JSON fragments.
        $config | ConvertTo-Json | Set-Content -Path $configFile -Force
    } catch {
        Write-Host "Failed to write configuration to file: $configFile $($Error[0])" -ForegroundColor Red
    }
}

#.SYNOPSIS
#   Adds a computer organizational-unit path to a tier.
#.DESCRIPTION
#   Resolves a full distinguished name against its domain or a relative OU path against the current
#   domain. The path is stored once in the selected tier's computer-path collection. A missing OU
#   produces a warning but is still stored so installation workflows can define OUs before creating
#   them.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER OU
#   Relative OU path or complete distinguished name to add.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Add-TierLevelIsolationComputerPath -TierLevel Tier0 -OU "OU=Server,OU=Tier 0,OU=Admin"
#   Adds a current-domain relative Tier 0 computer path.
#.EXAMPLE
#   Add-TierLevelIsolationComputerPath -TierLevel Tier1 -OU "OU=Server,OU=Tier 1,DC=emea,DC=contoso,DC=com"
#   Adds a fully qualified Tier 1 computer path.
#.OUTPUTS
#   None.
function Add-TierLevelIsolationComputerPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        $OU,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    $config = Get-TierLevelIsolationConfiguration $configFile

    # Full DNs are resolved against their own domain; relative paths use the current domain.
    if ($OU -like "*DC=*"){
        $DNSDomain = ConvertFrom-DN2Dns -DistinguishedName $OU
        if ($null -eq $DNSDomain){
            Write-Host "The specified domain does not exist: $OU" -ForegroundColor Yellow
            return
        }
        $oOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -ErrorAction SilentlyContinue -Server $DnsDomain
    } else {
        $oOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OU,$((Get-ADDomain).DistinguishedName)'" -ErrorAction SilentlyContinue
    }
    if ($null -eq $oOU ) {
        Write-Host "The specified path does not exist: $OU" -ForegroundColor Yellow
    }

    # Append only new values to keep repeated setup runs idempotent.
    switch ($TierLevel) {
        "Tier0" {
            if ($null -eq $config.Tier0ComputerPath) { $config.Tier0ComputerPath = @() }
            if ($config.Tier0ComputerPath -notcontains $OU) { $config.Tier0ComputerPath += $OU }
            break
        }
        "Tier1" {
            if ($null -eq $config.Tier1ComputerPath) { $config.Tier1ComputerPath = @() }
            if ($config.Tier1ComputerPath -notcontains $OU) { $config.Tier1ComputerPath += $OU }
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
}

#.SYNOPSIS
#   Resolves an Active Directory group identity and domain.
#.DESCRIPTION
#   Accepts a SID, DOMAIN\GroupName, GroupName@dns.name, dns.name/GroupName, or an unqualified group
#   name. SID lookups search configured domains and the forest-root domain. Other formats determine
#   a domain directly; unqualified names use the current domain.
#.PARAMETER Identity
#   Group SID or supported name format to resolve.
#.PARAMETER Config
#   Tier Level Isolation configuration whose Domains property supplies the SID search scope.
#.EXAMPLE
#   Resolve-TierLevelIsolationGroup -Identity "CONTOSO\Helpdesk" -Config $Configuration
#   Resolves the Helpdesk group and returns both the AD group and DNS domain.
#.OUTPUTS
#   System.Management.Automation.PSCustomObject with Group and Domain properties.
#.NOTES
#   Internal helper. Throws when the group or domain cannot be resolved.
function Resolve-TierLevelIsolationGroup {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,
        [Parameter(Mandatory = $true)]
        $Config
    )
    # SIDs do not encode a DNS domain. Search configured domains and finally the forest root.
    if ($Identity -match '^S-1-(?:\d+-){1,14}\d+$') {
        $Domains = @($Config.Domains) + @($Global:DnsRoot) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        foreach ($Domain in $Domains) {
            try {
                $Group = Get-ADGroup -Identity $Identity -Server $Domain -ErrorAction Stop
                return [pscustomobject]@{ Group = $Group; Domain = $Domain }
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                continue
            } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                continue
            }
        }
        throw "The specified group SID '$Identity' could not be found in a configured domain."
    }

    # Parse supported qualified-name formats and derive the DNS domain used for the lookup.
    $GroupIdentity = $Identity
    switch -regex ($Identity) {
        '^(.+?)\\(.+)$' {
            $DomainNetBios = $matches[1]
            $GroupIdentity = $matches[2]
            $DomainDNSName = (Get-ADObject -SearchBase "CN=Partitions,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(&(objectClass=crossRef)(nETBIOSName=$DomainNetBios))" -Properties dnsRoot -ErrorAction Stop).dnsRoot[0]
            break
        }
        '^(.+)@(.+)$' { $GroupIdentity = $matches[1]; $DomainDNSName = $matches[2]; break }
        '^([^/]+)/(.+)$' { $DomainDNSName = $matches[1]; $GroupIdentity = $matches[2]; break }
        default { $DomainDNSName = $Global:DnsRoot }
    }

    # Return the AD object together with its resolved domain for consistent caller output.
    $Group = Get-ADGroup -Identity $GroupIdentity -Server $DomainDNSName -ErrorAction Stop
    return [pscustomobject]@{ Group = $Group; Domain = $DomainDNSName }
}

#.SYNOPSIS
#   Adds an additional Active Directory group to a tier.
#.DESCRIPTION
#   Resolves the supplied group and stores its immutable SID in Tier0Groups or Tier1Groups. A group
#   cannot be assigned to both tiers. Repeated additions are idempotent.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER GroupIdentity
#   Group SID, DOMAIN\GroupName, GroupName@dns.name, dns.name/GroupName, or unqualified group name.
#   Accepts pipeline input and the aliases GroupName and GroupSID.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Add-TierLevelIsolationGroup -TierLevel Tier0 -GroupIdentity "CONTOSO\Domain Admins"
#   Resolves the group and stores its SID in the Tier 0 group collection.
#.EXAMPLE
#   "S-1-5-21-1000-1000-1000-1234" | Add-TierLevelIsolationGroup -TierLevel Tier1
#   Adds a group by SID through the pipeline.
#.OUTPUTS
#   None.
#.NOTES
#   Resolution or cross-tier assignment failures are reported to the host and not rethrown.
function Add-TierLevelIsolationGroup {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [Alias("GroupName", "GroupSID")]
        [string]$GroupIdentity,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    process {
        try {
            # Resolve names once and persist the immutable SID rather than a renameable group name.
            $config = Get-TierLevelIsolationConfiguration $configFile
            $ResolvedGroup = Resolve-TierLevelIsolationGroup -Identity $GroupIdentity -Config $config
            $GroupSID = $ResolvedGroup.Group.SID.Value
            $TargetProperty = "${TierLevel}Groups"
            $OtherProperty = if ($TierLevel -eq "Tier0") { "Tier1Groups" } else { "Tier0Groups" }

            # A group must not receive conflicting tier assignments.
            if ($config.$OtherProperty -contains $GroupSID) {
                Write-Host "The group $($ResolvedGroup.Group.Name) ($GroupSID) is already assigned to the other tier." -ForegroundColor Red
                return
            }
            if ($config.$TargetProperty -notcontains $GroupSID) {
                # Re-wrap the property as an array because single-item JSON arrays can deserialize variably.
                $config.$TargetProperty = @($config.$TargetProperty) + $GroupSID
                Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
            }
        }
        catch {
            Write-Host "The group '$GroupIdentity' could not be added. $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

#.SYNOPSIS
#   Gets additional groups configured for one or both tiers.
#.DESCRIPTION
#   Reads stored group SIDs and attempts to resolve each SID in the configured domains. Unresolvable
#   SIDs are retained in the output with Resolved set to $false so stale entries remain visible.
#.PARAMETER TierLevel
#   Optional tier filter. Valid values are Tier0 and Tier1. Omit it to return both tiers.
#.PARAMETER configFile
#   Configuration file to read. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Get-TierLevelIsolationGroup
#   Returns configured additional groups for Tier 0 and Tier 1.
#.EXAMPLE
#   Get-TierLevelIsolationGroup -TierLevel Tier0 | Where-Object Resolved
#   Returns only successfully resolved Tier 0 groups.
#.OUTPUTS
#   System.Management.Automation.PSCustomObject with TierLevel, SID, Name, SamAccountName, Domain,
#   and Resolved properties.
function Get-TierLevelIsolationGroup {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    $config = Get-TierLevelIsolationConfiguration $configFile
    # An omitted tier deliberately expands to both configured group collections.
    $TierLevels = if ($TierLevel) { @($TierLevel) } else { @("Tier0", "Tier1") }
    foreach ($CurrentTier in $TierLevels) {
        foreach ($GroupSID in @($config."${CurrentTier}Groups")) {
            try {
                # Enrich the stored SID with current directory attributes when it still resolves.
                $ResolvedGroup = Resolve-TierLevelIsolationGroup -Identity $GroupSID -Config $config
                [pscustomobject]@{
                    TierLevel = $CurrentTier
                    SID = $GroupSID
                    Name = $ResolvedGroup.Group.Name
                    SamAccountName = $ResolvedGroup.Group.SamAccountName
                    Domain = $ResolvedGroup.Domain
                    Resolved = $true
                }
            }
            catch {
                # Preserve stale SIDs in output so administrators can identify and remove them.
                [pscustomobject]@{
                    TierLevel = $CurrentTier
                    SID = $GroupSID
                    Name = $null
                    SamAccountName = $null
                    Domain = $null
                    Resolved = $false
                }
            }
        }
    }
}

#.SYNOPSIS
#   Removes an additional Active Directory group from a tier.
#.DESCRIPTION
#   Accepts a stored SID or any group-name format supported by Add-TierLevelIsolationGroup. Names
#   are resolved to a SID before the SID is removed from the selected tier collection.
#.PARAMETER TierLevel
#   Tier from which to remove the group. Valid values are Tier0 and Tier1.
#.PARAMETER GroupIdentity
#   Group SID or supported group name. Accepts pipeline input and the aliases GroupName and GroupSID.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Remove-TierLevelIsolationGroup -TierLevel Tier1 -GroupIdentity "helpdesk@contoso.com"
#   Removes the resolved group SID from Tier 1.
#.EXAMPLE
#   "S-1-5-21-1000-1000-1000-1234" | Remove-TierLevelIsolationGroup -TierLevel Tier0
#   Removes a stored Tier 0 group directly by SID.
#.OUTPUTS
#   None.
function Remove-TierLevelIsolationGroup {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [Alias("GroupName", "GroupSID")]
        [string]$GroupIdentity,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    process {
        $config = Get-TierLevelIsolationConfiguration $configFile
        $GroupSID = $GroupIdentity

        # Convert supported name formats to the same SID representation used by the configuration.
        if ($GroupIdentity -notmatch '^S-1-(?:\d+-){1,14}\d+$') {
            try {
                $GroupSID = (Resolve-TierLevelIsolationGroup -Identity $GroupIdentity -Config $config).Group.SID.Value
            }
            catch {
                Write-Host "The group '$GroupIdentity' could not be resolved. $($_.Exception.Message)" -ForegroundColor Red
                return
            }
        }
        $TargetProperty = "${TierLevel}Groups"
        if ($config.$TargetProperty -contains $GroupSID) {
            # Filter into a new array to retain predictable JSON array serialization.
            $config.$TargetProperty = @($config.$TargetProperty | Where-Object { $_ -ne $GroupSID })
            Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
        }
    }
}
#.SYNOPSIS
#   Removes a computer organizational-unit path from a tier.
#.DESCRIPTION
#   Removes an exact relative or fully qualified OU path from the selected tier's computer-path
#   collection. No Active Directory organizational unit is deleted.
#.PARAMETER TierLevel
#   Tier from which to remove the path. Valid values are Tier0 and Tier1.
#.PARAMETER OU
#   Exact OU path value stored in the configuration.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Remove-TierLevelIsolationComputerPath -TierLevel Tier0 -OU "OU=Server,OU=Tier 0,OU=Admin"
#   Removes the matching configured path from Tier 0.
#.OUTPUTS
#   None.
function Remove-TierLevelIsolationComputerPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        $OU,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    # Remove only an exact configured value; this command never changes the directory OU itself.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    switch ($TierLevel) {
        "Tier0" { 
            if ($config.Tier0ComputerPath -contains $OU) {
                $config.Tier0ComputerPath = @($config.Tier0ComputerPath | Where-Object { $_ -ne $OU })
            } else {
                Write-Host "The specified path does not exist in the Tier0 configuration: $OU" -ForegroundColor Yellow
                return
            }
            break
        }
        "Tier1" {
            if ($config.Tier1ComputerPath -contains $OU) {
                $config.Tier1ComputerPath = @($config.Tier1ComputerPath | Where-Object { $_ -ne $OU})
            } else {
                Write-Host "The specified path does not exist in the Tier1 configuration: $OU" -ForegroundColor Yellow
                return
            }
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Adds a user organizational-unit path to a tier.
#.DESCRIPTION
#   Validates a relative path in the current domain or a full distinguished name in its specified
#   domain, then stores it once in the selected tier's user-path collection. A missing OU produces
#   a warning but is still stored for installation workflows that create it later.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER OU
#   Relative OU path or complete distinguished name to add.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Add-TierLevelIsolationUserPath -TierLevel Tier0 -OU "OU=Admins,OU=Tier 0,OU=Admin"
#   Adds a current-domain relative user path to Tier 0.
#.EXAMPLE
#   Add-TierLevelIsolationUserPath -TierLevel Tier1 -OU "OU=Admins,OU=Tier 1,DC=emea,DC=contoso,DC=com"
#   Adds a fully qualified user path to Tier 1.
#.OUTPUTS
#   None.
function Add-TierLevelIsolationUserPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OU,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    # Resolve full DNs in their declared domain and relative paths in the current domain.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    if ($OU -like "*DC=*"){
        $DNSDomain = ConvertFrom-DN2Dns -DistinguishedName $OU
        if ($null -eq $DNSDomain){
            Write-Host "The specified domain does not exist: $OU" -ForegroundColor Yellow
            return
        }
        $Path = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -ErrorAction SilentlyContinue -Server $DnsDomain
    } else {
        $Path = Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OU,$((Get-ADDomain).DistinguishedName)'" -ErrorAction SilentlyContinue 
    }
    if ($null -eq $Path) {
        Write-Host "The specified path does not exist: $OU" -ForegroundColor Yellow
    }
    # Store the path once in the selected tier while preserving all existing paths.
    switch ($TierLevel) {
        "Tier0" { 
            if ($null -eq $config.Tier0UsersPath) {
                $config.Tier0UsersPath = @($OU)
            }
            if ($config.Tier0UsersPath -notcontains $OU) {
                $config.Tier0UsersPath += $OU
            }
        }
        "Tier1" {
            if ($null -eq $config.Tier1UsersPath ) {
                $config.Tier1UsersPath = @($OU)
            }
            if ($config.Tier1UsersPath -notcontains $OU) {
                $config.Tier1UsersPath += $OU
            }
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Removes a user organizational-unit path from a tier.
#.DESCRIPTION
#   Removes an exact OU path from the selected tier's user-path collection. No Active Directory
#   organizational unit or user account is deleted.
#.PARAMETER TierLevel
#   Tier from which to remove the path. Valid values are Tier0 and Tier1.
#.PARAMETER OU
#   Exact OU path value stored in the configuration.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Remove-TierLevelIsolationUserPath -TierLevel Tier0 -OU "OU=Admins,OU=Tier 0,OU=Admin"
#   Removes the matching configured path from Tier 0.
#.OUTPUTS
#   None.
function Remove-TierLevelIsolationUserPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OU,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    # Configuration removal is intentionally independent of current OU existence in AD.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    switch ($TierLevel) {
        "Tier0" { 
            if ($config.Tier0UsersPath -contains $OU) {
                $config.Tier0UsersPath = @($config.Tier0UsersPath | Where-Object {$_ -ne $OU})
            }
        }
        "Tier1" {
            if ($config.Tier1UsersPath -contains $OU){
                $config.Tier1UsersPath =@($config.Tier1UsersPath | Where-Object {$_ -ne $OU})
            }
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Sets the Kerberos authentication policy name for a tier.
#.DESCRIPTION   
#   Validates that the policy exists in Active Directory and stores its name for the selected tier.
#   Force bypasses existence validation so an installer can configure the name before creating the
#   policy.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER KerberosPolicyName
#   Authentication policy name to store.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.PARAMETER Force
#   Stores the name without requiring an existing Active Directory authentication policy.
#.EXAMPLE
#   Set-TierLevelIsolationKerberosAuthenticationPolicy -TierLevel Tier0 -KerberosPolicyName "Tier 0 restriction"
#   Validates and stores an existing Tier 0 policy.
#.EXAMPLE
#   Set-TierLevelIsolationKerberosAuthenticationPolicy -TierLevel Tier1 -KerberosPolicyName "Tier 1 restriction" -Force
#   Stores a policy name before the policy is created.
#.OUTPUTS
#   None.
function Set-TierLevelIsolationKerberosAuthenticationPolicy{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        $KerberosPolicyName,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Force
    )
    # Normal administration validates the policy; installation can use Force before policy creation.
    $config = Get-TierLevelIsolationConfiguration $configFile
    if ($Force.IsPresent -eq $false){
        $KerbAuthPol = Get-ADAuthenticationPolicy -Filter "Name -eq '$KerberosPolicyName'" -ErrorAction SilentlyContinue 
        if ($null -eq $KerbAuthPol){
            Write-Host "The specified Kerberos Authentication Policy does not exist: $KerberosPolicyName" -ForegroundColor Red
            return
        }
    }
    # Each tier has a dedicated configuration property consumed by the user-management script.
    switch ($TierLevel) {
        "Tier0" { 
            $config.T0KerbAuthPolName = $KerberosPolicyName
        }
        "Tier1" {
            $config.T1KerbAuthPolName = $KerberosPolicyName
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Adds a forest domain to the configuration.
#.DESCRIPTION
#   Verifies that each pipeline value belongs to the current forest and stores the DNS name once.
#.PARAMETER Domain
#   DNS name of the forest domain to add. Accepts pipeline input.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   "contoso.com","emea.contoso.com" | Add-TierLevelIsolationDomain
#   Adds two existing forest domains.
#.OUTPUTS
#   None.
function Add-TierLevelIsolationDomain{
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile  = $global:configFile
    )
    process{
        $config = Get-TierLevelIsolationConfiguration $configFile 

        # Restrict entries to DNS names advertised by the current forest.
        if ((Get-ADForest).Domains -notcontains $Domain) {
            Write-Host "The specified domain does not exist: $Domain" -ForegroundColor Red
            return
        }
        # Avoid duplicate domain processing during subsequent management runs.
        if ($config.Domains -notcontains $domain) {
            $config.Domains += $domain
            Set-TierLevelIsolationConfiguration    -configFile $configFile -config $config
        }
        return
    }
}
#.SYNOPSIS
#   Removes a forest domain from the configuration.
#.DESCRIPTION
#   Removes an exact DNS name from the Domains collection. No Active Directory domain is modified.
#.PARAMETER Domain
#   The domain to remove from the configuration.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Remove-TierLevelIsolationDomain -Domain "emea.contoso.com"
#   Removes the domain from the managed-domain list.
#.OUTPUTS
#   None.
function Remove-TierLevelIsolationDomain{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Domain,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    # Remove only the configuration reference; no domain or trust is modified.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    if ($config.Domains -contains $domain) {
        $config.Domains = @($config.Domains | Where-Object {$_ -ne $domain})
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Sets the enabled Tier Level Isolation scope.
#.DESCRIPTION
#   Replaces the configuration scope with Tier0, Tier1, or All-Tiers.
#.PARAMETER scope
#   Scope to set. Valid values are All-Tiers, Tier0, and Tier1.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Set-TierLevelIsolationScope -scope All-Tiers
#   Enables both tiers in the configuration.
#.OUTPUTS
#   None.
function Set-TierLevelIsolationScope{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("All-Tiers", "Tier0", "Tier1")]
        [string]$scope,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    # Replace the single active scope value and persist it immediately.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    $config.scope = $scope
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Selects which tiers participate in Protected Users management.
#.DESCRIPTION
#   Stores Tier-0, Tier-1, both tiers, or an empty collection in ProtectedUsers. The scheduled user
#   management script uses this setting to maintain Protected Users membership.
#.PARAMETER TierLevel
#   Tier selection. Valid values are Tier-0, Tier-1, All-Tiers, and None.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Set-TierLevelProtectedUsersState -TierLevel All-Tiers
#   Enables Protected Users management for Tier 0 and Tier 1.
#.EXAMPLE
#   Set-TierLevelProtectedUsersState -TierLevel None
#   Disables Protected Users management.
#.OUTPUTS
#   None.
function Set-TierLevelProtectedUsersState{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier-0", "Tier-1","All-Tiers","None")]
        [string]$TierLevel,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    # Convert the user-facing selection into the array consumed by account management.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    switch ($TierLevel) {
        "All-Tiers" { 
            $config.ProtectedUsers = @("Tier-0", "Tier-1") 
            break
        }
        "None" { 
            $config.ProtectedUsers = @() 
            break
        }
        Default { 
            $config.ProtectedUsers = @($TierLevel) 
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return}
#.SYNOPSIS
#   Enables or disables privileged-group cleanup.
#.DESCRIPTION
#   Controls whether the scheduled management scripts clean up incompatible privileged-group
#   memberships for tier-managed users.
#.PARAMETER state
#   State to store. Valid values are True and False.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Set-TierLevelPrivilegedGroupsCleanUpState -state True
#   Enables privileged-group cleanup.
#.OUTPUTS
#   None.
function Set-TierLevelPrivilegedGroupsCleanUpState{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("True", "False")]
        [string]$state,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile


    )
    # Store the validated state in the shared configuration for scheduled user management.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    $config.PrivilegedGroupsCleanUp = $state
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Sets the server group for a tier.
#.DESCRIPTION
#   Resolves the group through a global catalog and stores its name for the selected tier. Force
#   bypasses group validation so installation can configure the name before creating the group.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER GroupName
#   Active Directory group name to store.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.PARAMETER Force
#   Stores the name without requiring the group to exist.
#.EXAMPLE
#   Set-TierLevelIsolationComputerGroup -TierLevel Tier0 -GroupName "Tier 0 server"
#   Validates and stores an existing Tier 0 server group.
#.EXAMPLE
#   Set-TierLevelIsolationComputerGroup -TierLevel Tier1 -GroupName "Tier 1 server" -Force
#   Stores the Tier 1 server group name before group creation.
#.OUTPUTS
#   None.
function Set-TierLevelIsolationComputerGroup{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$GroupName,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Force
    )
    # Load the current snapshot before validating and replacing one tier-specific property.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    if ($null -eq $GroupName) {
        Write-Host "The specified group name is null or empty." -ForegroundColor Red
        return
    }
    # Query a global catalog so universal groups created elsewhere in the forest can be resolved.
    if ($Force.IsPresent -eq $false){
        $Adgroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue -Server "$((Get-ADDomainController -Discover -Service GlobalCatalog).HostName):3268" 
        if ($null -eq $Adgroup) {
            Write-Host "The specified group does not exist: $GroupName" -ForegroundColor Yellow
            return
        }
    }
    # Force changes validation only; both paths persist the same group-name value.
    switch ($TierLevel) {
        "Tier0" {
            $config.Tier0ComputerGroup = $GroupName
            break
        }
        "Tier1" {
            $config.Tier1ComputerGroup = $GroupName
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Adds a service-account organizational-unit path to a tier.
#.DESCRIPTION
#   Validates a relative path in the current domain or a full distinguished name in its specified
#   domain, then stores it once in the selected tier collection. Force permits a missing OU so an
#   installation can configure the path before creating it.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER OU
#   Relative OU path or complete distinguished name to add.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.PARAMETER Force
#   Stores the path even when the OU does not currently exist.
#.EXAMPLE
#   Add-TierLevelIsolationServiceAccountPath -TierLevel Tier0 -OU "OU=Service Accounts,OU=Tier 0,OU=Admin"
#   Adds a relative Tier 0 service-account path.
#.EXAMPLE
#   Add-TierLevelIsolationServiceAccountPath -TierLevel Tier1 -OU "OU=Service Accounts,OU=Tier 1,DC=contoso,DC=com" -Force
#   Stores a fully qualified path without requiring the OU to exist.
#.OUTPUTS
#   None.
function Add-TierLevelIsolationServiceAccountPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OU,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Force
    )
    $config = Get-TierLevelIsolationConfiguration $configFile
    if ($null -eq $OU) {
        Write-Host "The specified OU is null or empty." -ForegroundColor Red
        return
    }
    # Full DNs select their domain through DC components; relative paths use the current domain.
    if ($OU -like "*DC=*"){
        $DNSDomain = ConvertFrom-DN2Dns -DistinguishedName $OU
        if ($null -eq $DNSDomain){
            Write-Host "The specified domain does not exist: $OU" -ForegroundColor Yellow
            return
        }
        $Path = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -ErrorAction SilentlyContinue -Server $DnsDomain
    } else {
        $Path = Get-ADOrganizationalUnit -Filter "DistinguishedName -like '$OU,$((Get-ADDomain).DistinguishedName)'" -ErrorAction SilentlyContinue 
    }
    if ($null -eq $Path -and !$Force) {
        Write-Host "The specified path does not exist: $OU" -ForegroundColor Yellow
    }
    # Add only missing values so rerunning configuration remains idempotent.
    switch ($TierLevel) {
        "Tier0" {
            if ($null -eq $config.Tier0ServiceAccountPath) {
                $config.Tier0ServiceAccountPath = @($OU)
            }
            if ($config.Tier0ServiceAccountPath -notcontains $OU) {
                $config.Tier0ServiceAccountPath += $OU
            }
            break
        }
        "Tier1" {
            if ($null -eq $config.Tier1ServiceAccountPath) {
                $config.Tier1ServiceAccountPath = @($OU)
            }
            if ($config.Tier1ServiceAccountPath -notcontains $OU) {
                $config.Tier1ServiceAccountPath += $OU
            }
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Removes a service-account organizational-unit path from a tier.
#.DESCRIPTION
#   Removes an exact OU path from the selected tier's service-account-path collection. No Active
#   Directory organizational unit or account is deleted.
#.PARAMETER TierLevel
#   Tier from which to remove the path. Valid values are Tier0 and Tier1.
#.PARAMETER OU
#   Exact OU path value stored in the configuration.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Remove-TierLevelIsolationServiceAccountPath -TierLevel Tier1 -OU "OU=Service Accounts,OU=Tier 1,OU=Admin"
#   Removes the matching path from Tier 1.
#.OUTPUTS
#   None.
function Remove-TierLevelIsolationServiceAccountPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$OU,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    $config = Get-TierLevelIsolationConfiguration $configFile
    if ($null -eq $OU) {
        Write-Host "The specified OU is null or empty." -ForegroundColor Red
        return
    }
    # Remove the exact stored string without deleting the corresponding Active Directory OU.
    switch ($TierLevel) {
        "Tier0" {
            if ($config.Tier0ServiceAccountPath -contains $OU) {
                $config.Tier0ServiceAccountPath = @($config.Tier0ServiceAccountPath | Where-Object { $_ -ne $OU })
            } else {
                Write-Host "The specified path does not exist in the Tier0 configuration: $OU" -ForegroundColor Yellow
                return
            }
            break
          }
        "Tier1" {
            if ($config.Tier1ServiceAccountPath -contains $OU) {
                $config.Tier1ServiceAccountPath = @($config.Tier1ServiceAccountPath | Where-Object { $_ -ne $OU })
            } else {
                Write-Host "The specified path does not exist in the Tier1 configuration: $OU" -ForegroundColor Yellow
                return
            }
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Sets the runtime debug-log directory.
#.DESCRIPTION
#   Stores the directory used by TierLevelComputerManagement.ps1 and
#   TierLevelUserManagement.ps1. An empty value instructs those scripts to use local AppData.
#.PARAMETER LogPath    
#   Existing log directory, or an empty string to select local AppData at runtime.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Set-DebugLogPath -LogPath "C:\Logs\TierLevelIsolation"
#   Configures a central runtime log directory.
#.EXAMPLE
#   Set-DebugLogPath -LogPath ""
#   Restores the local AppData behavior.
#.OUTPUTS
#   None.
function Set-DebugLogPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$LogPath,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    $config = Get-TierLevelIsolationConfiguration $configFile
    # Force creates the property for compatibility with configuration files from older versions.
    $config | Add-Member -MemberType NoteProperty -Name LogPath -Value $LogPath -Force
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
}
#.SYNOPSIS
#   Gets the configured runtime debug-log directory.
#.DESCRIPTION
#   Returns the LogPath value used by the scheduled management scripts. An empty string means the
#   scripts use the local AppData directory of their execution identity.
#.PARAMETER configFile
#   Configuration file to read. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Get-DebugLogPath
#   Returns the configured runtime log directory.
#.OUTPUTS
#   System.String. Configured directory or an empty string.
function Get-DebugLogPath {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$configFile = $global:configFile
    )
    # Reading through the schema-aware loader guarantees that LogPath exists for legacy files.
    $config = Get-TierLevelIsolationConfiguration $configFile 
    return $config.LogPath
}

#.SYNOPSIS
#   Adds a group using the legacy name-based storage format.
#.DESCRIPTION
#   Resolves a group from NetBIOS, UPN-style, canonical, or unqualified input and stores the group
#   as DOMAIN\SamAccountName. Tier 1 rejects groups already assigned to Tier 0.
#.PARAMETER TierLevel
#   Target tier. Valid values are Tier0 and Tier1.
#.PARAMETER GroupName  
#   Group in DOMAIN\GroupName, GroupName@dns.name, dns.name/GroupName, or unqualified format.
#   Accepts pipeline input.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Add-TierLevelIsolationGroupLegacy -TierLevel Tier0 -GroupName "CONTOSO\Legacy Operators"
#   Stores the group's normalized NetBIOS name in Tier 0.
#.EXAMPLE
#   Add-TierLevelIsolationGroupLegacy -TierLevel Tier1 -GroupName "Legacy Operators@emea.contoso.com"
#   Resolves and stores a Tier 1 group from UPN-style input.
#.OUTPUTS
#   None.
#.NOTES
#   Internal compatibility helper; it is not exported. New code must use
#   Add-TierLevelIsolationGroup, which stores stable group SIDs instead of names.
function Add-TierLevelIsolationGroupLegacy {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    process{
        # Read the legacy name-based collections from the shared configuration.
        $config = Get-TierLevelIsolationConfiguration $configFile 
        # Extract domain and group name from each historically supported input format.
        try{
            switch -regex ($GroupName) {
                '^(.+?)\\(.+)$' {
                    # NetBIOS format: DOMAIN\GroupName
                    $DomainNetBios = $matches[1]
                    $GroupName = $matches[2]
                    $DomainDNSName = (Get-ADobject `
                        -SearchBase "CN=Partitions,$((Get-ADRootDSE).configurationNamingContext)" `
                        -LDAPFilter "(&(objectClass=crossRef)(nETBIOSName=$DomainNetBios))" `
                        -Properties nETBIOSName,nCName,dnsRoot -ErrorAction Stop ).dnsRoot[0]
                    break                 
                }
                '@(.+)$' {
                    # UPN format: GroupName@domain.com
                    $DomainDNSName = $matches[1]
                    $GroupName = $GroupName.Split('@')[0]
                    $DomainNetBios = (Get-ADDomain -Server $DomainDNSName -ErrorAction Stop).NetBIOSName
                    break
                }
                '/(.+)$'{
                    # LDAP format: domain.com/GroupName
                    $DomainDNSName = $GroupName.Split('/')[0]
                    $DomainNetBios = (Get-ADDomain -server $DomainDNSName -ErrorAction Stop ).NetBIOSName 
                    $GroupName = $GroupName.Split('/')[1]
                    break
                }
                default {
                    # Just group name without domain
                    $DomainDNSName = (Get-ADDomain -ErrorAction Stop).DNSRoot
                    $DomainNetBios = (Get-ADDomain -ErrorAction Stop).NetBIOSName
                    break
                }
            }
        # Validate the group and normalize it to DOMAIN\SamAccountName before persistence.
        $Adgroup = Get-ADGroup -Identity $GroupName -Server $DomainDNSName -ErrorAction SilentlyContinue
        if ($null -eq $ADgroup) {
            Write-Host "The specified group does not exist for group: $GroupName in $DomainDNSName" -ForegroundColor Red
            return
        }
        $GroupNameInNetBiosNotation = "$DomainNetBios\$($ADgroup.SamAccountName)"
        }
        catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
            Write-Host "The specified domain could not be reached for group: $GroupName" -ForegroundColor Red
            return
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
            Write-Host "The specified group does not exist for group: $GroupName in $DomainDNSName" -ForegroundColor Red
            return
        }
        catch{
            Write-Host "An error occurred while processing the group: $GroupName. Error: $_" -ForegroundColor Red
            return
        }                 
        # Tier 0 takes precedence in the legacy model; cross-tier assignment is rejected.
        if ($TierLevel -eq "Tier0") {
            if ($config.Tier0Groups -notcontains $GroupNameInNetBiosNotation) {
                $config.Tier0Groups += $GroupNameInNetBiosNotation
            }
        } else {
            if ($config.Tier0Groups -contains $GroupNameInNetBiosNotation) {
                Write-Host "The group $GroupNameInNetBiosNotation already exists in Tier0. Remove it from Tier0 before adding it to Tier1." -ForegroundColor Red
                return
            }
            if ($config.Tier1Groups -notcontains $GroupNameInNetBiosNotation) {
                $config.Tier1Groups += $GroupNameInNetBiosNotation
            }
         }
        Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    }
}

#.SYNOPSIS
#   Removes a group stored in the legacy name-based format.
#.DESCRIPTION
#   Normalizes an unqualified group name to the current domain's NetBIOS format and removes the
#   exact DOMAIN\GroupName value from the selected tier collection.
#.PARAMETER TierLevel
#   Tier from which to remove the group. Valid values are Tier0 and Tier1.
#.PARAMETER GroupName
#   Stored DOMAIN\GroupName value or an unqualified current-domain group name. Accepts pipeline input.
#.PARAMETER configFile
#   Configuration file to update. Defaults to the shared SYSVOL configuration.
#.EXAMPLE
#   Remove-TierLevelIsolationGroupLegacy -TierLevel Tier0 -GroupName "CONTOSO\Legacy Operators"
#   Removes the exact legacy Tier 0 entry.
#.OUTPUTS
#   None.
#.NOTES
#   Internal compatibility helper; it is not exported. New code must use
#   Remove-TierLevelIsolationGroup, which operates on SID-based entries.
function Remove-TierLevelIsolationGroupLegacy {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $false, Position = 2)]
        [string]$configFile = $global:configFile
    )
    process{
        $config = Get-TierLevelIsolationConfiguration $configFile 
        # Legacy entries are stored in NetBIOS notation; qualify current-domain names when needed.
        If ($GroupName -notcontains '\'){
            $DomainNetBios = (Get-ADDomain).NetBIOSName
            $GroupName = "$DomainNetBios\$GroupName"    
        }
        # Filter the selected legacy collection and leave the opposite tier untouched.
        if ($TierLevel -eq "Tier0") {
            if ($config.Tier0Groups -contains $GroupName) {
                $config.Tier0Groups = @($config.Tier0Groups | Where-Object {$_ -ne $GroupName})
            }
        } elseif ($TierLevel -eq "Tier1") { 
                if ($config.Tier1Groups -contains $GroupName) {
                    $config.Tier1Groups = @($config.Tier1Groups | Where-Object {$_ -ne $GroupName})
                }        
        }
        Write-Host "Removing group $GroupName from tier level $TierLevel" -ForegroundColor Yellow
        Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
        return
    }
}