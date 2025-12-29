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
Module Version: 0.1.20250327
Module GUID: 0b1c8d3e-4f2a-4b6c-9d5f-7a1b8e2c3d4e
Module Description: This module provides functions to manage theconfiguraiton  TierLevelIsolation 

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

#>

#region Module Metadata
# Module Name: TierLevelIsolation   

# Module Prerequisites: PowerShell 5.1 or higher, Active Directory module for Windows PowerShell
# Module Installation: Import-Module TierLevelIsolation.psd1
# Module Usage:
#   Get-TierLevelIsolationConfiguration returns the current configuration of TierLevelIsolation
#   Add-TierLevelIsolationComputerPath adds a computer OU path to the specified tier level
#   Remove-TierLevelIsolationComputerPath removes a computer OU path from the specified tier level
#   Set-TierLevelIsolationComputerGroup sets the computer group for the specified tier level
#   Add-TierLevelIsolationServiceAccountPath adds a service account OU path to the specified tier level
#   Remove-TierLevelIsolationServiceAccountPath removes a service account OU path from the specified tier level
#   Add-TierLevelIsolationUserPath adds a user OU path to the specified tier level
#   Remove-TierLevelIsolationUserPath removes a user OU path from the specified tier level
#   Set-TierLevelIsolationKerberosAuthenticationPolicy sets the Kerberos Authentication Policy for the specified tier level
#   Add-TierLevelIsolationDomain adds a domain to the Tier Level Isolation configuration
#   Remove-TierLevelIsolationDomain removes a domain from the Tier Level Isolation configuration
#   Set-TierLevelIsolationScope sets the current scope of the Tier Level Isolation configuration
#   Set-TierLevelPrivilegedGroupsCleanUpState sets the state of privileged groups clean up in the Tier Level Isolation configuration
#   Add-TierlevelIsolationGroup adds a group to the specified tier level
#   Remove-TierlevelIsolationGroup removes a group from the specified tier level
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
#    Returns "contoso.com"
#.EXAMPLE
#   ConvertFrom-DN2Dns -DistinguishedName "DC=contoso,DC=com"
#    Returns "contoso.com"
#.NOTES
#   This function requires the Active Directory module for Windows PowerShell.
#   It is used to convert a distinguished name to a DNS domain name for use in other functions.
#   The function uses the Get-ADObject cmdlet to retrieve the DNS root from the Active Directory forest.
#   The function uses a regular expression to extract the domain components from the distinguished name.
#   The function returns the DNS domain name as a string.
#   If the distinguished name does not contain a valid domain component, the function returns $null.
#   If the distinguished name is empty or null, the function returns $null.
#   If the distinguished name does not match the expected format, the function returns $null.
#   If the distinguished name is not found in Active Directory, the function returns $null.
function ConvertFrom-DN2Dns {
    param(
        [Parameter(Mandatory= $true, ValueFromPipeline)]
        [string]$DistinguishedName
    )
    $DistinguishedName = [regex]::Match($DistinguishedName,"(dc=[^,]+,)*dc=.+$",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Value
    return (Get-ADObject -Filter "nCname -eq '$DistinguishedName'" -Searchbase (Get-ADForest).PartitionsContainer -Properties dnsroot).DnsRoot
}

#.SYNOPSIS
#   Reading the tier level isolation configuration 
#.DESCRIPTION
#   This function reads the tier level isolation configuration from the specified file. If the file is not specified, the default location is used.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
#.EXAMPLE
#   Get-TierLevelIsolationConfiguration
#    Read the configuration from the default location.
#.EXAMPLE
#   Get-TierLevelIsolationConfiguration -configFile "C:\TierLevelIsolation.config"
#    Read the configuration from the specified file.  
#.NOTES
#   This function requires the Active Directory module for Windows PowerShell.
#   It is used to read the tier level isolation configuration from a JSON file.
function Get-TierLevelIsolationConfiguration {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$configFile = $global:configFile
    )
    #Inital configuration object
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
    $config | Add-Member -MemberType NoteProperty -Name Tier0Groups              -Value @()
    $config | Add-Member -MemberType NoteProperty -Name Tier1Groups              -Value @()
    # Check if the config file exists
    if (Test-Path $configFile) {
        $CurrentConfig = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        
        foreach ($configItem in $config.PSObject.Properties) {
            if ($null -ne $CurrentConfig.PSObject.Properties[$configItem.Name]) {
                    $config.PSObject.Properties[$configItem.Name].Value = $CurrentConfig.PSObject.Properties[$configItem.Name].Value
            }
        }
        
    } 
    #added a fix to ensure the scope value is correct
    if ($config.scope -eq "Tier0") {
        $config.scope = "Tier-0"
    } elseif ($config.scope -eq "Tier1") {
        $config.scope = "Tier-1"
    }
    return $config
}
#.SYNOPSIS
#   Writing the tier level isolation configuration
#.DESCRIPTION
#   This function writes the tier level isolation configuration to the specified file. If the file is not specified, the default location is used.  
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
#.PARAMETER config
#   The configuration object to write to the file.  
#.EXAMPLE
#   Set-TierLevelIsolationConfiguration -configFile "C:\TierLevelIsolation.config" -config $config
#    Write the configuration to the specified file.
#.EXAMPLE
#   Set-TierLevelIsolationConfiguration -config $config
#    Write the configuration to the default location.
#.NOTES
#   This function requires the Active Directory module for Windows PowerShell.
function Set-TierLevelIsolationConfiguration {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$configFile = $global:configFile,
        [Parameter(Mandatory = $true, Position = 1)]
        $config
    )
    try {
        $config | ConvertTo-Json | Set-Content -Path $configFile -Force
    } catch {
        Write-Host "Failed to write configuration to file: $configFile $($Error[0])" -ForegroundColor Red
    }
}
#.SYNOPSIS
#   Adding a computer path to the specified tier level
#.DESCRIPTION
#   This function adds a computer path to the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to add the computer path to. Valid values are "Tier0" and "Tier1".
#.PARAMETER Path
#   The distinguishedname to the computer organizational unit to add. The can can be full qualified or just the OU part.
#   If the path is not a valid OU, the function will return a warning.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
#.EXAMPLE
#   Add-TierLevelTierComputerPath -TierLevel "Tier0" -Path "OU=Computers,OU=Tier0,OU=Admin,DC=contoso,DC=com"
#    Add the computer path to the Tier0 tier level.
#.EXAMPLE
#   Add-TierLevelTierComputerPath -TierLevel "Tier1" -Path "OU=Computers,OU=Tier1,OU=Admin,DC=contoso,DC=com" 
#    Add the computer path to the Tier1 tier level and ignore the warning if the path does not exist.   
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
    #reading the configuration file
    $config = Get-TierLevelIsolationConfiguration $configFile
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
    switch ($TierLevel) {
        "Tier0" { 
            if ($null -eq $config.Tier0ComputerPath) {
                $config.Tier0ComputerPath = @()
            }
            if ($config.Tier0ComputerPath -notcontains $OU) {
                $config.Tier0ComputerPath += $OU
            }
            break
        }
        "Tier1" {
            if ($null -eq $config.Tier1ComputerPath ) {
                $config.Tier1ComputerPath = @()
            }
            if ($config.Tier1ComputerPath -notcontains $OU) {
                $config.Tier1ComputerPath += $OU
            }
            break
        }
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Removing a computer path from the specified tier level
#.DESCRIPTION
#   This function removes a computer path from the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to remove the computer path from. Valid values are "Tier0" and "Tier1".
#.PARAMETER Path
#   The distinguishedname to the computer organizational unit to remove. The can can be full qualified or just the OU part.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Remove-TierLevelIsolationComputerPath -TierLevel "Tier0" -Path "OU=Computers,OU=Tier0,OU=Admin,DC=contoso,DC=com"
#    Remove the computer path from the Tier0 tier level.
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
#   Adding a user path to the specified tier level
#.DESCRIPTION
#   This function adds a user path to the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to add the user path to. Valid values are "Tier0" and "Tier1".
#.PARAMETER Path
#   The distinguishedname to the user organizational unit to add. The can can be full qualified or just the OU part.
#   If the path is not a valid OU, the function will return a warning.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Add-TierLevelUserPath -TierLevel "Tier0" -Path "OU=Users,OU=Tier0,OU=Admin"
#    Add the user path to the Tier0 tier level.
# .EXAMPLE  
#   Add-TierLevelUserPath -TierLevel "Tier1" -Path "OU=Users,OU=Tier1,OU=Admin,DC=contoso,DC=com" 
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
#   Removing a user path from the specified tier level
#.DESCRIPTION
#   This function removes a user path from the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to remove the user path from. Valid values are "Tier0" and "Tier1".  
#.PARAMETER Path
#   The distinguishedname to the user organizational unit to remove. The can can be full qualified or just the OU part.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used. 
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Remove-TierLevelUserPath -TierLevel "Tier0" -Path "OU=Users,OU=Tier0,OU=Admin"
#    Remove the user path from the Tier0 tier level.
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
#   Add the Kerberos Authentication Policy to the specified tier level
#.DESCRIPTION   
#   This function adds the Kerberos Authentication Policy to the specified tier level in the configuration.
# .PARAMETER TierLevel
#   The tier level to add the Kerberos Authentication Policy to. Valid values are "Tier0" and "Tier1".
# .PARAMETER KerberosPolicyName
#   The name of the Kerberos Authentication Policy to add.
# .PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Set-TierLevelKerberosAuthenticationPolicy -TierLevel "Tier0" -KerberosPolicyName "Tier0KerberosPolicy"
#    Add the Kerberos Authentication Policy to the Tier0 tier level.
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
    
    $config = Get-TierLevelIsolationConfiguration $configFile
    if ($Force.IsPresent -eq $false){
        $KerbAuthPol = Get-ADAuthenticationPolicy -Filter "Name -eq '$KerberosPolicyName'" -ErrorAction SilentlyContinue 
        if ($null -eq $KerbAuthPol){
            Write-Host "The specified Kerberos Authentication Policy does not exist: $KerberosPolicyName" -ForegroundColor Red
            return
        }
    }
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
#   Add a Domain to the Tier Level Isolation configuration
#.DESCRIPTION
#   This function adds a domain to the Tier Level Isolation configuration.
#.PARAMETER Domains
#   The domain to add to the configuration.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Add-TierLevelDomains -Domains "contoso.com","fabrikam.com"
#    Add the domains to the configuration.
function Add-TierLevelIsolationDomain{
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Domain,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile  = $global:configFile
    )
    process{
        $config = Get-TierLevelIsolationConfiguration $configFile 
        
        if ((Get-ADForest).Domains -notcontains $Domain) {
            Write-Host "The specified domain does not exist: $Domain" -ForegroundColor Red
            return
        }
        if ($config.Domains -notcontains $domain) {
            $config.Domains += $domain
            Set-TierLevelIsolationConfiguration    -configFile $configFile -config $config
        }
        return
    }
}
#.SYNOPSIS
#   Remove a Domain from the Tier Level Isolation configuration
#.DESCRIPTION
#   This function removes a domain from the Tier Level Isolation configuration.
#.PARAMETER Domain
#   The domain to remove from the configuration.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Remove-TierLevelDomains -Domain "fabrikam.com"  
#    Remove the domain from the configuration.
function Remove-TierLevelIsolationDomain{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Domain,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    
    $config = Get-TierLevelIsolationConfiguration $configFile 
    if ($config.Domains -contains $domain) {
        $config.Domains = @($config.Domains | Where-Object {$_ -ne $domain})
    }
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Set the current scope of the Tier Level Isolation configuration
#.DESCRIPTION
#   This function sets the current scope of the Tier Level Isolation configuration.
#.PARAMETER scope
#   The scope to set. Valid values are "All-Tiers", "Tier0", and "Tier1".
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Set-TierLevelScope -scope "All-Tiers"
#    Set the scope to "All-Tiers".  
function Set-TierLevelIsolationScope{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("All-Tiers", "Tier0", "Tier1")]
        [string]$scope,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    
    $config = Get-TierLevelIsolationConfiguration $configFile 
    $config.scope = $scope
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Set the current state of protected users in the Tier Level Isolation configuration
#.DESCRIPTION
#   This function sets the current state of protected users in the Tier Level Isolation configuration.  
#.PARAMETER TierLevel
#   The tier level to set the state for. Valid values are "Tier-0", "Tier-1", "All-Tiers", and "None".
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Set-TierLevelProtectedUsersState -TierLevel "All-Tiers"
#    Set the state of protected users to "All-Tiers".
function Set-TierLevelProtectedUsersState{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("Tier-0", "Tier-1","All-Tiers","None")]
        [string]$TierLevel,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    
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
#   Set the state of privileged users clean up in the Tier Level Isolation configuration
#.DESCRIPTION
#   This function sets the state of privileged users clean up in the Tier Level Isolation configuration.
# .PARAMETER state      
#   The state to set. Valid values are "True" and "False".  
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Set-TierLevelPrivilegedGroupsCleanUpState -state "True"
#    Set the state of privileged groups clean up to "True".
function Set-TierLevelPrivilegedGroupsCleanUpState{
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("True", "False")]
        [string]$state,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile


    )
    $config = Get-TierLevelIsolationConfiguration $configFile 
    $config.PrivilegedGroupsCleanUp = $state
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
    return
}
#.SYNOPSIS
#   Set the computer group for the specified tier level 
#.DESCRIPTION
#   This function sets the computer group for the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to set the computer group for. Valid values are "Tier0" and "Tier1".
#.PARAMETER GroupName
#   The name of the computer group to set.  This can be a full qualified name or just the group name.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used. 
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
    
    $config = Get-TierLevelIsolationConfiguration $configFile 
    if ($null -eq $GroupName) {
        Write-Host "The specified group name is null or empty." -ForegroundColor Red
        return
    }
    if ($Force.IsPresent -eq $false){
        $Adgroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue -Server "$((Get-ADDomainController -Discover -Service GlobalCatalog).HostName):3268" 
        if ($null -eq $Adgroup) {
            Write-Host "The specified group does not exist: $GroupName" -ForegroundColor Yellow
            return
        }
    }
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
#   Add a service account path to the specified tier level  
#.DESCRIPTION
#   This function adds a service account path to the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to add the service account path to. Valid values are "Tier0" and "Tier1".
#.PARAMETER OU
#   The distinguishedname to the service account organizational unit to add. The can can be full qualified or just the OU part.
#   If the path is not a valid OU, the function will return a warning.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config   

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
#   Remove a service account path from the specified tier level
#.DESCRIPTION
#   This function removes a service account path from the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to remove the service account path from. Valid values are "Tier0" and "Tier1".
#.PARAMETER OU
#   The distinguishedname to the service account organizational unit to remove. The can can be full qualified or just the OU part.  
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
#   Set the path for the debug log file
#.DESCRIPTION
#   This function sets the path for the debug log file in the configuration.
#.PARAMETER LogPath    
#   The path to the debug log file. This can be a full path or just the file name.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
function Set-DebugLogPath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$LogPath,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$configFile = $global:configFile
    )
    Get-TierLevelIsolationConfiguration $configFile | Add-Member -MemberType NoteProperty -Name LogPath -Value $LogPath -Force
    Set-TierLevelIsolationConfiguration -configFile $configFile -config $config
}
#.SYNOPSIS
#   Get the path for the debug log file
#.DESCRIPTION
#   This function gets the path for the debug log file from the configuration.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
function Get-DebugLogPath {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$configFile = $global:configFile
    )
    $config = Get-TierLevelIsolationConfiguration $configFile 
    return $config.LogPath
}

#.SYNOPSIS
#   Add a group to the specified tier level
#.DESCRIPTION
#   This function adds a group to the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to add the group to. Valid values are "Tier0" and "Tier1".
#.PARAMETER GroupName  
#   The name of the group to add. The groupname format can be
#       NetBIOS format: DOMAIN\GroupName
#       UPN format: GroupName@domain.com
#       LDAP format: domain.com/GroupName
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Add-TierLevelIsolationGroups -TierLevel "Tier0" -GroupName "MyTier0Group"
#    Add the group to the Tier0 tier level.
# .EXAMPLE  
#   Add-TierLevelIsolationGroups -TierLevel "Tier1" -GroupName "DOMAIN\MyTier1Group"
#    Add the group to the Tier1 tier level.
# .EXAMPLE
#   Add-TierLevelIsolationGroups -TierLevel "Tier1" -GroupName "MyTier1Group@DomainDNS"
# .EXAMPLE
#   Add-TierLevelIsolationGroups -TierLevel "Tier1" -GroupName "DomainDNS/MyTier1Group"
# .NOTE
#   This function validates if the group exists in Active Directory before adding it to the configuration.
#   It supports group names in  NetBIOS format (DOMAIN\GroupName) "
#   If the group does not exist, a warning is displayed and the group is not added to the configuration.
#   If the group already exists in Tier0, it cannot be added to Tier1.
function Add-TierLevelIsolationGroup {
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
        #Read the configuration file
        $config = Get-TierLevelIsolationConfiguration $configFile 
        #extract domain and group name from the input
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
            # Validate if the group exists in the specified domain
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
        # switch Tier level
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

#
#.SYNOPSIS
#   Remove a group from the specified tier level
#.DESCRIPTION
#   This function removes a group from the specified tier level in the configuration.
#.PARAMETER TierLevel
#   The tier level to remove the group from. Valid values are "Tier0" and "Tier1".
#.PARAMETER GroupName
#   The name of the group to remove. This can be a full qualified name or just the group name.
#.PARAMETER configFile
#   The path to the configuration file. If not specified, the default location is used.
#   The default location is: \\$DNSRoot\SYSVOL\$DNSRoot\scripts\TierLevelIsolation.config
# .EXAMPLE
#   Remove-TierLevelIsolationGroups -TierLevel "Tier0" -GroupName "Domain\MyTier0Group"
#    Remove the group from the Tier0 tier level.
# .EXAMPLE
#   Remove-TierLevelIsolationGroups -TierLevel "Tier1" -GroupName "MyTier1Group"
#    Remove the group from the Tier1 tier level.
# .NOTE
#   If the group exists in Tier0, it must be removed from Tier0 before it can be removed from Tier1.

function Remove-TierLevelIsolationGroup {
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
        If ($GroupName -notcontains '\'){
            $DomainNetBios = (Get-ADDomain).NetBIOSName
            $GroupName = "$DomainNetBios\$GroupName"    
        }
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