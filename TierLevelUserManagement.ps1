<#
Script Info

Author: Andreas Lucas [MSFT]
Download: https://github.com/Kili69/TierLevelIsolation

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
.Synopsis
    Managing of Tier 0 and Tier 1 user groups

.DESCRIPTION
    This script applies the Kerberos Authentication Policy to the users in the Tier 0 and Tier 1 user groups and adds them to the protected users group.
    The script allows multiple OU's for Tier 0 / 1
    If configured, the script will remove unexpected users from the privileged groups and add users to the protected users group. This can be enabled or disabled
    in the configuration file.
.OUTPUTS 
    The script does not produce any direct outputs.
.PARAMETER ConfigFile
    The full path to the configuration file. If this parameter is not provided, the script will search for the configuration in Active Directory or on the SYSVOL path.
.PARAMETER scope
    Defines the scope of the script. Possible values are:
        Tier-0: Only the Tier 0 user accounts will be managed.
        Tier-1: Only the Tier 1 user accounts will be managed.
        All-Tiers: Both Tier 0 and Tier 1 user accounts will be managed.
.NOTES
    Version 0.2.20241206
    Initial Version
    Version 0.2.20241220
        If a user is removed from a privileged group, the adminCount attribute will be removed from the user
        The script will check if the user is located in a service account OU. If the user is located in a service account OU, the user will not be removed from the privileged group
    Version 20241223
        documentation update  
    Version 0.2.20240218
        Documentation update

    All events written to the log file. Information, Warnings and error events are written to the eventlog
    All event IDs documented in EventID.md
    Version 0.2.20250304
        Provide logfile in the start message
    Version 0.2.20250314
        New debug information added
        Fixed a bug adding the user to the protected users group. The script will now check if the user is already a member of the protected users group
        and add the user to the protected users group.
    Version 0.2.20250320
        Default configuration file name changed from tiering.config to TierLevelIsolation.config
    Version 0.2.20250327
        Bug fix: The parameter $configFile default value fixed
    Version 0.2.20250410
        Bug Fix in ValidateAndRemoveUser function. the function now recognize the relative DN of privileged users
    Version 0.2.20250423
        If a alternative logfile path in the configuration file is not set, the script will use the local appdata path of the user running the script.
    Version 0.2.20250619
        Fixed a error writing to event log
    Version 0.2.20250623
        Error fixed if the configfile parameter is used
        added multiple exit codes if the script terminates with an error
    Version 0.2.20250714
        Fixed a bug in the scope parameter handling
    Version 0.2.20251219
        New function ConvertTo-DistinguishedNames to convert relative OU paths to FQDNs
        New functionality to process privileged domain groups from the configuration file
    Version 0.2.20251223
        Fixed a bug in the naming of Tier-0 and Tier-1 scope
    Version 0.2.20251224
        Documentation update
        The users will not added the users to the protected users group in the Set-TierLevelIsolation function if the parameter AddProtectedUsersGroup
    Version 0.2.20251226
        Issue with protected users fixed

    exist codes:
        0x3E8 - The script terminated with a unexpected error
        0x3E9 - The configuration file could not be found
        0x3EA - The scope parameter does not match to the configuration scope
        0x3EB - The configuration file could not be found


#>
param(
    [Parameter (Mandatory = $false)]
    [string] $ConfigFile,
    [Parameter (Mandatory = $false)]
    [ValidateSet("Tier-0", "Tier-1", "All-Tiers")]
    $scope
)

#region functions
<#
.SYNOPSIS
    Convert NetBIOS domain name to DNS domain name using LDAP query in Configuration Partition
.DESCRIPTION
    This function searches the Active Directory Configuration Partition for the DNS name of a domain
    based on the NetBIOS name. It queries the crossRef objects in the Partitions container.
.PARAMETER NetBIOSName
    The NetBIOS name of the domain to search for
.EXAMPLE
    ConvertFrom-NetBIOSNameToDNS -NetBIOSName "CONTOSO"
    Returns "contoso.com"
.OUTPUTS
    String - The DNS name of the domain, or $null if not found
#>
function ConvertFrom-NetBIOSNameToDNS {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NetBIOSName
    )
    
    try {
        # Get the Configuration Naming Context
        $ConfigurationNC = (Get-ADRootDSE).configurationNamingContext
        $PartitionsContainer = "CN=Partitions,$ConfigurationNC"
        
        # Search for crossRef object with matching NetBIOS name
        $CrossRef = Get-ADObject -SearchBase $PartitionsContainer `
                                 -Filter "objectClass -eq 'crossRef' -and nETBIOSName -eq '$NetBIOSName'" `
                                 -Properties dnsRoot, nETBIOSName, nCName `
                                 -ErrorAction Stop
        
        if ($CrossRef) {
            Write-Log -Message "Found DNS name '$($CrossRef.dnsRoot)' for NetBIOS name '$NetBIOSName'" -Severity Debug -EventID 2301
            return $CrossRef.dnsRoot
        } else {
            Write-Log -Message "No domain found with NetBIOS name '$NetBIOSName'" -Severity Warning -EventID 2302
            return $null
        }
    }
    catch {
        Write-Log -Message "Error converting NetBIOS name '$NetBIOSName' to DNS name: $($_.Exception.Message)" -Severity Error -EventID 2303
        return $null
    }
}

<#
.SYNOPSIS
    Write event to the event log and the debug log file
.DESCRIPTION
    This function will write all events to the log file. If the severity is debug the message will only be written to the debug log file
    This function replaced the write-eventlog and write-host cmdlets in this script
.OUTPUTS
    None
.FUNCTIONALITY
    Write event to the log file and event log
.PARAMETER Message
    Is the message body of the event
.PARAMETER Severity
    Is the event severity. Supported severities are: Debug, Information, Warning and Error
.PARAMETER EventID
    Is the event ID logged in the application log
.EXAMPLE
    write-log -Message "My message" - Severity Information -EventID 0
        This will create a new log line in the debug log file, create a eventlog entry in the application log and writes the 
        message parameter to the console
#>
function Write-Log {
    param (
        # status message
        [Parameter(Mandatory = $true)]
        [string]$Message,
        #Severity of the message
        [Parameter (Mandatory = $true)]
        [ValidateSet('Error', 'Warning', 'Information', 'Debug') ]
        $Severity,
        #Event ID
        [Parameter (Mandatory = $true)]
        [int]$EventID
    )

    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o), [$Severity],[$EventID], $Message"
    if ($LogFile -ne $null) { #Safety check to make sure logfile isn't null
        Add-Content -Path $LogFile -Value $LogLine
    }
    #If the severity is not debug write the even to the event log and format the output
    switch ($Severity) {
        'Error' { 
            Write-Host $Message -ForegroundColor Red
            if ($LogFile -ne $null) { #Safety check to make sure logfile isn't null
                Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
            }
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Error -Message $Message -Category 0
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Warning -Message $Message -Category 0
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Information -Message $Message -Category 0
        }
    }
}
<#
.SYNOPSIS
    Applied the Kerberos Authentication Policy to the users and add them to the protected users group
.DESCRIPTION
    This function applies the Kerberos Authentication policy to all users in the OU parameter and
    add the user to the protected users groups if the AddProtectedUsersGroup is true
.FUNCTIONALITY

.PARAMETER DomainDNS
    The domain DNS Name
.PARAMETER OrgUnits
    Is a array of OU distinguished names of the Tier level users
.PARAMETER AddProtectedUsersGroup
    Is this parameter is true the user will be added to the protected users
.PARAMETER KerbAuthPolName
    Is the name of the Kerberos Authentication Policy
.OUTPUTS 
    $True if all users in the privilege OU are marked as sensitive and the kerberos authentication policy is applied
    $False
.EXAMPLE
    Set-TierLevelIsolation -DomainDNS "contoso.com" -OrgUnits @("OU=Tier0,OU=Admin,DC=contoso,DC=com") -AddProtectedUsersGroup $true -KerbAuthPolName "Tier0KerbAuthPol"
    This will apply the Kerberos Authentication Policy "Tier0KerbAuthPol" to all users in the OU "OU=Tier0,OU=Admin,DC=contoso,DC=com" and add the users to the protected users group
#>
function Set-TierLevelIsolation{
    param(
        [Parameter (Mandatory = $true)]
        [string] $DomainDNS,
        [Parameter (Mandatory = $true)]
        [string[]]$OrgUnits,
        [Parameter (Mandatory = $false)]
        [bool]$AddProtectedUsersGroup = $false,
        [Parameter (Mandatory = $true)]
        [string]$KerbAuthPolName
    )
    $retVal = $false
    try {
        Write-Log -Message "Start Set-TierLevelIsolation for $DomainDNS -ProtectedUsersGroup $AddProtectedUsersGroup" -Severity Debug -EventID 2014
        #Get the domain distinguished name
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        #Getting the Kerberos Authentication Policy object 
        $KerberosAuthenticationPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$($KerbAuthPolName)'"
        #Validate the Kerberos Authentication Policy exists. If not, write an error and return false
        if ($null -eq $KerberosAuthenticationPolicy){
            Write-Log -Message "Tier 0 Kerberos Authentication Policy '$KerberosPolicyName' not found on AD" -Severity Error -EventID 2101
            return $false
        }
        #Get the protected users group object from the domain
        $oProtectedUsersGroup = Get-ADGroup -Identity "$((Get-ADDomain -Server $DomainDNS).DomainSID)-525" -Server $DomainDNS -Properties member
        foreach ($OU in $OrgUnits){
            if($OU -match "OU=[^,]*,$DomainDN"){
                if ($null -eq (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU'" -Server $DomainDNS)){
                    Write-Log -Message "The OU $OU doesn't exists in $DomainDNS" -Severity Warning -EventID 2102
                } else {
                    foreach ($user in (Get-ADUser -SearchBase $OU -Filter * -Properties msDS-AssignedAuthNPolicy,memberOf,UserAccountControl -SearchScope Subtree -Server $DomainDNS)){
                        if ($user.SID -like "*-500"){
                            Write-Log -Message "Built in Administrator (-500) is located in $OU" -Severity Warning -EventID 2103
                            #ignore the built-in administrator
                        } else {
                            #Kerberos Authentication Policy validation
                            if ($user.'msDS-AssignedAuthNPolicy' -ne $KerberosAuthenticationPolicy.DistinguishedName){
                                Write-Log "Adding Kerberos Authentication Policy $KerbAuthPolName on $User" -Severity Information -EventID 2104
                                Set-ADUser $user -AuthenticationPolicy $KerbAuthPolName -Server $DomainDNS
                            }
                            #User account control validation
                            if (($user.UserAccountControl -BAND 1048576) -ne 1048576){
                                Set-ADAccountControl -Identity $user -AccountNotDelegated $True -Server $DomainDNS
                                Write-Log -Message "Mark $($User.DistinguishedName) as sensitive and cannot be delegated" -Severity Information -EventID 2105
                            }
                            #Protected user group validation
                            if ($AddProtectedUsersGroup -and ($oProtectedUsersGroup.member -notcontains $user.DistinguishedName)){
                                Add-ADGroupMember -Identity $oProtectedUsersGroup $user -Server $DomainDNS
                                Write-Log "User $($user.DistinguishedName) is added to protected users in $Domain" -Severity Information -EventID 2106
                            }
                        }
                    }
                }
            }
        }
        $retVal = $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADException]{
        Write-Log "a access denied error occurs while changing $user attribute" -Severity Error -EventID 2107
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Log "Cannot enumerate users" -Severity Error -EventID 2108
    }
    catch{
        Write-Log "A unexpected error occurred $($error[0])" -Severity Error -EventID 2109
    } 
    return $retVal  
}

<#
.SYNOPSIS
    Remove unexpected user to the privileged group 
.DESCRIPTION 
    Searches for users in privileged groups and remove those user if the are not 
    - in the correct OU
    - the built-In Administrator
.PARAMETER SID
    - is the SID of the AD group
.PARAMETER DomainDNSName
    -is the domain DNS name of the AD object
.PARAMETER PrivilegedOU
    -is a array of DistinguishedNames to the privileged user OUs
.PARAMETER ServiceAccountPath
    -is a array of DistinguishedNames to the service account OU
.EXAMPLE
    validateAndRemoveUser -SID "S-1-5-<domain sid>-<group sid>" -DomainDNS contoso.com
#>
function validateAndRemoveUser{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        #The SID uof the group
        [Parameter (Mandatory = $true)]
        [string] $SID,
        #The DNS domain Name
        [Parameter (Mandatory = $true)]
        [string] $DomainDNSName,
        [Parameter(Mandatory = $true)]
        [string[]] $PrivilegedOU,
        [Parameter(Mandatory = $true)]
        [string[]] $ServiceAccountPath

    )
    #if the privileged OU is a relative path, adding "DC=" to the path. This avoid fake Tier 0 OUs path like "OU=Tier 0,OU=Admin,OU=something,DC=contoso,DC=com"
    $tempPrivOU= @()
    foreach ($OU in $PrivilegedOU){
        if ($OU -like "*,DC=*"){
            $tempPrivOU += $OU
        } else {
            $tempPrivOU += "$OU,DC="
        }
    }
    $PrivilegedOU = $tempPrivOU
    $tempPrivOU= @()
    foreach ($OU in $ServiceAccountPath){
        if ($OU -like "*,DC=*"){
            $tempPrivOU += $OU
        } else {
            $tempPrivOU += "$OU,DC="
        }
    }
    $ServiceAccountPath = $tempPrivOU
    $Group = Get-ADGroup -Identity $SID -Properties members,canonicalName -Server $DomainDNSName 
    #validate the SID exists
    if ($null -eq $Group){
        Write-Log "Can't validate $SID. This SID is not available" -Severity Warning -EventID 2200
        return
    }
    #walk through all members of the group and check this member is a valid user or group
    foreach ($GroupMember in $Group.members)
    {
        $member = Get-ADObject -Filter {DistinguishedName -eq $GroupMember} -Properties * -server "$($DomainDNSName):3268"
        switch ($member.ObjectClass){
            "user"{
                if (($member.ObjectSid.value   -notlike "*-500")                              -and ` #ignore if the member is Built-In Administrator
                    ($member.objectSid.value   -notlike "*-512")                              -and ` #ignore if the member is Domain Admins group
                    ($member.ObjectSid.value   -notlike "*-518")                              -and ` #ignore if the member is Schema Admins
                    ($member.ObjectSid.Value   -notlike "*-519")                              -and ` #ignore if the member is Enterprise Admins
                    ($member.objectSid.Value   -notlike "*-520")                              -and ` #ignore if the member is Group Policy Creator
                    ($member.objectSid.Value   -notlike "*-522")                              -and ` #ignore if the member is cloneable domain controllers
                    ($member.objectSid.Value   -notlike "*-527")                              -and ` #ignore if the member is Enterprise Key Admins
                    ($member.objectClass       -ne "msDS-GroupManagedServiceAccount") #        -and ` #ignore if the member is a GMSA
                    ){
                        if (($PrivilegedOU | Where-Object {$member.DistinguishedName -like "*$_*"} ).Count -eq 0){
                            #the user is not located in the privileged OU check the user is located in the service account OU
                            if (($ServiceAccountPath | Where-Object {$member.DistinguishedName -like "*$_*"}).count -eq 0){
                                #The user is not located in the service account OU. Try to remove the user from the current group
                                try{
                                    Write-Log -Message "remove $member from $($Group.DistinguishedName)" -Severity Warning -EventID 2201
                                    Set-ADObject -Identity $Group -Remove @{member="$($member.DistinguishedName)"} -Server $DomainDNSName
                                    Set-ADUser -Identity $member -Remove @{adminCount=1} -Server $member.canonicalName.Split("/")[0]
                                }
                                catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
                                    Write-Log -Message "can't connect to AD-WebServices. $($member.DistinguishedName) is not remove from $($Group.DistinguishedName)" -Severity Error -EventID 2202
                                }
                                catch [Microsoft.ActiveDirectory.Management.ADException]{
                                    Write-Log -Message "Cannot remove $($member.DistinguishedName) from $($Error[0].CategoryInfo.TargetName) $($Error[0].Exception.Message)" -Severity Error -EventID 2203
                                }
                                catch{
                                    Write-Log -Message $Error[0].GetType().Name -Severity Error -EventID 2204
                                }
                            } else {
                                Write-Log -Message "The user $($member.DistinguishedName) is located in a Service account OU and will not be removed from the privileged groups $($Group.DistinguishedName)" -EventID 2205 -Severity Debug
                            }
                        } else {
                            Write-Log -Message "The user $($member.DistinguishedName) is member of a privileged user OU" -Severity Debug -EventID 2206
                        }
                    }
                }
            "group"{
                $MemberDomainDN = [regex]::Match($member.DistinguishedName,"DC=.*").value
                $MemberDNSroot = (Get-ADObject -Filter "ncName -eq '$MemberDomainDN'" -SearchBase (Get-ADForest).PartitionsContainer -Properties dnsRoot).dnsRoot
                validateAndRemoveUser -SID $member.ObjectSid.Value -DomainDNSName $MemberDNSroot -PrivilegedOU $PrivilegedOU -ServiceAccountPath $ServiceAccountPath
            }
        }
    }        
}

<#
.SYNOPSIS
    Convert relative distinguished names to fully qualified distinguished names
.DESCRIPTION
    This function converts relative distinguished names to fully qualified distinguished names
    by appending the domain distinguished name for each domain provided.
.PARAMETER DomainsDNS
    An array of domain DNS names to retrieve the distinguished names.
.PARAMETER DistinguishedNames
    An array of distinguished names to convert.
.OUTPUTS
    An array of fully qualified distinguished names.
.EXAMPLE
    $FQDNs = ConvertTo-DistinguishedNames -DomainsDNS @("contoso.com","child.contoso.com") -DistinguishedNames @("OU=Tier0,OU=Admin","OU=Tier1,OU=Admin")
    This will return an array of fully qualified distinguished names for the provided relative distinguished names
.EXAMPLE
    $FQDNs = ConvertTo-DistinguishedNames -DomainsDNS @("contoso.com") -DistinguishedNames @("OU=Tier0,OU=Admin,DC=contoso,DC=com","OU=Tier1,OU=Admin")
    This will return an array of fully qualified distinguished names, leaving the first DN unchanged and converting the second DN
#>
function ConvertTo-DistinguishedNames{
    param (
        [Parameter(Mandatory = $true)]
        [string[]] $DomainsDNS,
        [Parameter (Mandatory = $true)]
        [string[]] $DistinguishedNames
    )
    $FQDN = @()
    $DomainDN = @()
    
    try {
        foreach ($Domain in $DomainsDNS){
            $DomainDN += (Get-ADDomain -Server $Domain).DistinguishedName
        }        
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException]{
        Write-Log -Message "Failed to contact $domain" -Severity Debug -EventID 2300
    }
    foreach ($DN in $DistinguishedNames){
        if ($DN -like "*,DC=*"){
            $FQDN += $DN
        } else {
            foreach ($DomDN in $DomainDN){
                $FQDN += "$DN,$DomDN"
            }
        }
    }
    return $FQDN
}

<#
.SYNOPSIS
    Remove unexpected users from privileged domain groups defined in the configuration file 
.DESCRIPTION
    This function will remove unexpected users from privileged domain groups defined in the configuration file
.PARAMETER scope
    Defines the scope of the privileged groups to process. Possible values are Tier0 and Tier1
.OUTPUTS
    None
#>
function RemoveUserFromAdditionalGroups{
    param (
        [Parameter(Mandatory = $true)]
        [validateSet("Tier-0","Tier-1")]
        $scope
    )
    if ($scope -eq "Tier-0"){
        $Groups = $config.Tier0Groups
        $OUPath = $config.Tier0UsersPath 
        $ServiceAccountPath = $config.Tier0ServiceAccountPath   
    } else {
        $Groups = $config.Tier1Groups
        $OUPath = $config.Tier1UsersPath
        $ServiceAccountPath = $config.Tier1ServiceAccountPath
    }
    #cleanup of the privileged domain groups defined in the configuration file
    Write-Log "searching for unexpected users $Scope in privileged domain groups defined in the configuration file" -Severity Debug -EventID 2207
    Foreach ($PrivilegedDomainGroup in $Groups){
        # Split the domain and group name because the group is defined as DOMAIN\GroupName
        $DomainNetBiosName = $PrivilegedDomainGroup.Split("\")[0]
        $GroupName = $PrivilegedDomainGroup.Split("\")[1]
        $DomainDNS = ConvertFrom-NetBIOSNameToDNS -NetBIOSName $DomainNetBiosName
        if ($null -ne $DomainDNS){
            try {
                $GroupSID = (Get-ADGroup -Identity $GroupName -Server $DomainDNS).SID  
                validateAndRemoveUser -SID $GroupSID.Value -DomainDNSName $DomainDNS -PrivilegedOU $OUPath -ServiceAccountPath $ServiceAccountPath                  
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
                Write-Log "Cannot find group $GroupName in $DomainDNS" -Severity Warning -EventID 2208
            }
            catch {
                Write-Log "A general error occurred while processing group $PrivilegedDomainGroup in $DomainDNS" -Severity Warning -EventID 2209
            }
        } else {
            Write-Log "Cannot convert NetBIOS name $DomainNetBiosName to DNS name" -Severity Warning -EventID 2210
        }
    }
}
#endregion


##############################################################################################################################
# Main program starts here
##############################################################################################################################
#script Version 
$ScriptVersion = "0.2.20251226"
#Validate and create event log source if required
try {   
    $eventLog = "Application"
    $source = "TierLevelIsolation"
    # Check if the source exists; if not, create it
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
    }
}
catch {
    Write-EventLog -logName $eventLog -source "Application" -EventId 0 -EntryType Error -Message "The event source $source could not be created. The script will use the default event source Application"
    $source = "Application"
}
#region constants
$config = $null #configuration object
#default configuration file path. This path assumes that
#the current domain must contains the Tier level user groups
$CurrentDomainDNS = (Get-ADDomain).DNSRoot #get the current domain DNS name
$DefaultConfigFile = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\TierLevelIsolation.config" #default configuration file path

# A array relative SID of privileged groups
$PrivilegedDomainSid = @(
    "512", #Domain Admins
    "520", #Group Policy Creator Owner
    "522" #Cloneable Domain Controllers
#   "527" #Enterprise Key Admins
)
#endregion


#region read configuration
try{
    # read the configuration file from the provided path or from the default path
    # Terminate the script if the configuration file cannot be found or is not readable
    if ($ConfigFile -eq '') {
        #if the config file parameter is not provided, read the configuration from the default path
        if ((Test-Path -Path $DefaultConfigFile)){
            $config = Get-Content $DefaultConfigFile | ConvertFrom-Json  
            Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 1101          
        } else {
            Write-EventLog -LogName "Application" -source $source -Message "TierLevel Isolation Can't find the configuration in $DefaultConfigFile or Active Directory" -EntryType Error -EventID 0
            return 0xe7
        }
    }
    else {
        # Start reading the configuration from the provided path    
        if (Test-Path -Path $ConfigFile){
            $config = Get-Content $ConfigFile | ConvertFrom-Json
            Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 1101 
            if ($null -eq $config){
                Write-EventLog -LogName "Application" -source $source -Message "TierLevel Isolation Can't read the configuration from $ConfigFile" -EntryType Error -EventID 0
                return 0x3E9    
            }
        } else {
            Write-EventLog -LogName "Application" -source $source -Message "TierLevel Isolation Can't find the configuration file $ConfigFile" -EntryType Error -EventID 0
            return 0x3EB
        }
    }
}
catch {
    Write-EventLog -LogName "Application" -Source "Application" -Message "error reading configuration" -EntryType Error -EventID 0
    return 0x3E8
}
#region Manage log file
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file
if ($null -eq $config.LogPath -or $config.LogPath -eq ""){
    $LogFile = "$($env:LOCALAPPDATA)\$($MyInvocation.MyCommand).log" #Name and path of the log file
} else {
    $LogFile = "$($config.LogPath)\$($MyInvocation.MyCommand).log" #Name and path of the log file
}

#rename existing log files to *.sav if the current log file exceed the size of $MaxLogFileSize
if (Test-Path $LogFile) {
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize) {
        if (Test-Path "$LogFile.sav") {
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion
Write-Log -Message "Tier Isolation user management $Scope version $ScriptVersion started. see $LogFile for more details" -Severity Information -EventID 2000
# If the parameter $scope is not provided, it will use the configuration scope from the configuration file. 
# This is relevant if the script is called from a scheduled task without parameters
switch ($scope) {
    "Tier-0"{ 
        if ($config.scope -eq "Tier1" -or $config.scope -eq "Tier-1"){
            Write-Log -Message "The scope parameter $scope does not match to the configuration scope $($config.scope) the script is terminated" -Severity Error -EventID 2006
            return 0x3EA
        } else {
            $config.Tier0UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0UsersPath
            $config.Tier0ServiceAccountPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0ServiceAccountPath
            break
        }
    }
    "Tier-1"{
        if ($config.scope -eq "Tier0" -or $config.scope -eq "Tier-0"){
            Write-Log -Message "The scope parameter $scope does not match to the configuration scope $($config.scope) the script is terminated" -Severity Error -EventID 2006
            return 0x3EA
        } else {
            $config.Tier1UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier1UsersPath
            $config.Tier1ServiceAccountPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier1ServiceAccountPath
            break
        }
    }
    Default {
        Write-Log -Message "Current scope is Tier 0 and Tier 1" -Severity Debug -EventID 2006
        $config.Tier0UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0UsersPath
        $config.Tier0ServiceAccountPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier0ServiceAccountPath
        $config.Tier1UsersPath = ConvertTo-DistinguishedNames -DomainsDNS $config.Domains -DistinguishedNames $config.Tier1UsersPath
        break
    }
}
#endregion
$T0ProtectedUsers = $false
$T1ProtectedUsers = $false
switch ($config.ProtectedUsers) {
    {$_ -contains "Tier-0"} { $T0ProtectedUsers = $true }
    {$_ -contains "Tier-1"} { $T1ProtectedUsers = $true }
}
#  process each domain defined in the configuration file
foreach ($Domain in $config.Domains){
    #region Tier 0 users
    if ($scope -ne "Tier-1"){
        if ((Set-TierLevelIsolation -DomainDNS $Domain -OrgUnits $config.Tier0UsersPath -AddProtectedUsersGroup $T0ProtectedUsers -KerbAuthPolName $config.T0KerbAuthPolName)){
            Write-Log -Message "Tier 0 user isolated" -Severity Debug -EventID 2010
        } else{
            Write-Log -Message "Tier 0 user isolation failed" -Severity Debug -EventID 2011
        }
    } 
    #endregion
    #region Tier 1 users
    if ($scope -ne "Tier-0") {
        if ((Set-TierLevelIsolation -DomainDNS $Domain -OrgUnits $config.Tier1UsersPath -AddProtectedUsersGroup $T1ProtectedUsers -KerbAuthPolName $config.T1KerbAuthPolName)){
            Write-Log -Message "Tier 1 user isolated" -Severity Debug -EventID 2012
        } else {
            Write-Log -Message "Tier 1 user isolation failed" -Severity Debug -EventID 2013
        }
    }
    #endregion
    #if the PrivilegedGroupsCleanUp is set to true, the script will remove all users from the privileged groups
    if ($config.PrivilegedGroupsCleanUp -and $scope -ne "Tier-1"){
        $DomainSID = (Get-ADDomain -server $Domain).DomainSID
        foreach ($relativeSid in $PrivilegedDomainSid) {
            validateAndRemoveUser -SID "$DomainSID-$RelativeSid" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        }
        #Backup Operators
        validateAndRemoveUser -SID "S-1-5-32-551" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Print Operators
        validateAndRemoveUser -SID "S-1-5-32-550" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-549" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Server Operators
        validateAndRemoveUser -SID "S-1-5-32-548" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
        #Administrators
        validateAndRemoveUser -SID "S-1-5-32-544" -DomainDNSName $Domain -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
    }
}
if ($config.PrivilegedGroupsCleanUp -and $scope -ne "Tier-1"){
    #cleanup of the forest privileged groups
    $forestDNS = (Get-ADDomain).Forest
    $forestSID = (Get-ADDomain -Server $forestDNS).DomainSID.Value
    Write-Log "searching for unexpected users in schema admins" -Severity Debug -EventID 2008
    validateAndRemoveUser -SID "$forestSID-518" -DomainDNSName $forestDNS -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
    Write-Log "searching for unexpected users in enterprise admins" -Severity Debug -EventID 2009
    validateAndRemoveUser -SID "$forestSID-519" -DomainDNSName $forestDNS -PrivilegedOU $config.Tier0UsersPath -ServiceAccountPath $config.Tier0ServiceAccountPath
    RemoveUserFromAdditionalGroups -scope "Tier-0"
} else {
    RemoveUserFromAdditionalGroups -scope "Tier-1"
}

