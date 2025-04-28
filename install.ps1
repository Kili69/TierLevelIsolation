<#
Script Info

Author: Andreas Lucas [MSFT]
Download: https://github.com/Kili69/Tier0-User-Management

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
    Automated installation of Active Directory Tier Level isolation 

.DESCRIPTION
    This script installes the Kerberos Tier Level isolation solution. It will create OU's group managed 
    servcie accounts
.OUTPUTS 
    None
.NOTES
    Version 0.2.20241206
        Initial Version
    Version 0.2.20250103
        Typo correction
    Version 0.2.20250106
        Rename groups from tier X computer to tier X server
        The name of the tier 1 server can now be changed
        OU Tier X users renamed to Tier x admins
        Display the GP name now based on the variable $GPOName
    Version 0.2.20250109
        The required groups will be created on the next closest global catalog server
        The script will wait 10 seconds if the computer group is not visible in the forest
        IF the group cannot be created the script will be aborted
    Version 0.2.20250217
        The installation script aborts if the required OU cannot be created
        More detailed error message
    Version 0.2.20250218
        Update text messages
    Version 0.2.20250228
        fixed a bug whil creating the OUs. 
        Type error removed
    Version 0.2.20250303
        Fixed a bug while updating the Schedulted task XML file
    Version 0.2.20250306
        new created Tier 0 / Tier 1 server group will be set to adminCount = 1
    Version 0.2.20250313
        Fixed an bug in the tier 0 Kerberos Authenticaiton policy claim.
        Added the description to the Tier 0 / Tier 1 Kerberos Authentication policy
    Version 0.2.20250314
        The GMSA will be added to the enterprise admins group if the gmsa is not a member of the enterprise admins group
    Version 0.2.20250320
        Default name of the configurationfile changed from Tiering.config to TierLevelIsolation.config
    Version 0.2.20250327
        The script will now use the powershell module to create the configuration file
        Bug if in the new-TierLevelOU function
        Installation of TierLevelIsolation module
        The script has now a parameter to install the TierLevelIsolation module only.
    Version 0.2.20250331
        The group policy will now be imported instead of creating a new one. This will ensure that any changes to the Schedule tasks will be applied to the new created GPO.
        The context switch task will be created as a scheduled task in the GPO. 
        The user schedule tasks will now be disabled in the group policy. They will not shown up in the local scheduler until they are enabled in the group policy
        Bugfix in the module
    Version 0.2.20250428
        added the -force parameter to the Set-TierLevelIsolationComputerGroup function. This will ensure that the group name is changed even if the group doesn't exists.
        added the -force parameter to the Set-TierLevelIsolationKerberosAuthenticationPolicy function. This will ensure that the group name is changed even if the Kerberos Authentication Policy  doesn't exists.
        The solution will now work in any case with a GMSA. 
#>
param(
    [switch]$InstallPSModuleOnly
)
<# Function create the entire OU path of the relative distinuished name without the domain component. This function
is required to provide the same OU structure in the entrie forest
.SYNOPSIS 
    Create OU path in the current $DomainDNS
.DESCRIPTION
    create OU and sub OU to build the entire OU path. As an example on a DN like OU=Computers,OU=Tier 1,OU=Admin in
    contoso. The funtion create in the 1st round the OU=Admin if requried, in the 2nd round the OU=Tier 1,OU=Admin
    and so on till the entrie path is created
.PARAMETER OUPath 
    the relative OU path withou domain component
.PARAMETER DomainDNS
    Domain DNS Name
.EXAMPLE
    CreateOU -OUPath "OU=Test,OU=Demo" -DomainDNS "contoso.com"
.OUTPUTS
    $True
        if the OUs are sucessfully create
    $False
        If at least one OU cannot created. It the user has not the required rights, the function will also return $false 
#>
function New-TierLevelOU {
    [cmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$OUPath,
        [Parameter (Mandatory)]
        [string]$DomainDNS
    )
    try {
        #load the OU path into array to create the entire path step by step
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        if ($OUPath -like "*dc=*"){
            if ($OUPath -notlike "*$domainDN"){
                return $false
            } else {
                $OUPath = [regex]::Match($OUPath, "^(.*?)(?i)(?=,dc=)").Value
            }
        }
        #normalize OU remove 
        $OUPath = [regex]::Replace($OUPath, "\s?,\s?", ",")
        if ($OUPath.Contains("DC=")) {
            $OUPath = [regex]::Match($OUPath, "((CN|OU)=[^,]+,)+")
            $OUPath = $OUPath.Substring(0, $OUPath.Length - 1)
        }
        $aryOU = $OUPath.Split(",")
        $BuildOUPath = ""
        #walk through the entire domain 
        For ($i = $aryOU.Count; $i -ne 0; $i--) {
            #to create the Organizational unit the string OU= must be removed to the native name
            $OUName = $aryOU[$i - 1].Replace("OU=", "")
            #if this is the first run of the for loop the OU must in the root. The searbase paramenter is not required 
            if ($i -eq $aryOU.Count) {
                #create the OU if it doesn|t exists in the domain root. 
                if ([bool]!(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchScope OneLevel -server $DomainDNS)) {
                    Write-Host "$OUName doesn't exist in $OUPath. Creating OU" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Server $DomainDNS                        
                }
            }
            else {
                #create the sub ou if required
                if ([bool]!(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase "$BuildOUPath$DomainDN" -Server $DomainDNS)) {
                    Write-Host "$OUPath,$DomainDN doesn't exist. Creating" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Path "$BuildOUPath$DomainDN" -Server $DomainDNS
                }
            }
            #extend the OU searchbase with the current OU
            $BuildOUPath = "$($aryOU[$i-1]),$BuildOUPath"
        }
    } 
    catch [System.UnauthorizedAccessException] {
        Write-Host "Access denied to create $OUPath in $domainDNS"
        Return $false
    } 
    catch {
        Write-Host "A error occured while create OU Structure $OUPath" -ForegroundColor Red
        Write-Host $Error[0].Exception.Message -ForegroundColor Red
        Return $false
    }
    Return $true
}
<#
.SYNOPSIS
    creating the Group Managed Service account if required
.DESCRIPTION
    ...
.PARAMETER GMSAName
    Is the name of the group managed service account
.PARAMETER AllowTOLogon
    is the name of the computer where the GMSA is allowed to logon
.OUTPUTS
    $True
        ...
    $False
        ...
#>
function New-GMSA {
    [cmdletBinding (SupportsShouldProcess)]
    param(
        [Parameter (Mandatory)]
        [string] $GMSAName,
        [Parameter (Mandatory = $false)]
        [string] $AllowTOLogon,
        [Parameter (Mandatory = $false)]
        [string] $Description = ""
    )
    try {
        #validate the KDS root key exists. If not create the KDS root key
        if (![bool](Get-KdsRootKey)) {
            Write-Host "KDS Rootkey is missing." -ForegroundColor Red
            Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
        }
        #Test the GMSA already exists. If the GMSA exists leaf the function with $true
        if ([bool](Get-ADServiceAccount -Filter "Name -eq '$GMSAName'")) {
            return $true
        }
        #Provide the list of computers where the GMSA get the allow to logon privilege
        $aryAllowToLogon = @()
        if ($aryAllowToLogon -ne "") {
            #allow to logon to dedicated servers
            foreach ($srv in $AllowTOLogon.Split(";")) {
                $oComputer = Get-ADComputer -Filter "name -eq '$srv'"
                $aryAllowToLogon += $oComputer.ComputerObjectDN
            } 
        }
        else {
            foreach ($srv in (Get-ADDomainController -Filter *)) {
                $aryAllowToLogon += $srv.ComputerObjectDN
            }
        }
        #create the GMSA
        New-ADServiceAccount -Name $GMSAName -DNSHostName "$GmsaName.$((Get-ADDomain).DNSRoot)" -KerberosEncryptionType AES256 -PrincipalsAllowedToRetrieveManagedPassword $aryAllowToLogon -Description $Description
        $retval = $true
    }
    catch {
        Write-Host "A unexpected error has occured while creating the GMSA. $($error[0])"
        $retval = $false
    }
    Return $retval
}

<#
.SYNOPSIS
    Check if the current user is member of the Enterprise Admins group
.DESCRIPTION
    This function checks if the current user is a member of the Enterprise Admins group. This is required to access the configuration partition of the Active Directory forest.
    The function checks the SID of the Enterprise Admins group (-519) in the user's group membership.
    The function returns $true if the user is a member of the Enterprise Admins group and $false otherwise.
.OUTPUTS
    $true
        if the user is a member of the Enterprise Admins group
    $false
        if the user is not a member of the Enterprise Admins group or if an error occurs while checking the group membership.
.EXAMPLE
    $isMember = IsMemberOfEnterpriseAdmins
    if ($isMember) {
        Write-Host "User is a member of the Enterprise Admins group."
    } else {
        Write-Host "User is not a member of the Enterprise Admins group."
    }
#>
function IsMemberOfEnterpriseAdmins{
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.Groups -like "*-519"){
        return $true
    } else {
        return $false
    }
}

<#
.SYNOPSIS
    Get the selected domains from the user input
.DESCRIPTION
    This function prompts the user to select one or more domains from a list of available domains in the Active Directory forest. The user can select multiple domains by entering their indices separated by commas.
    If the user does not provide any input, all domains will be selected by default.
.PARAMETER Domains
    An array of domain names to be displayed for selection. This parameter is mandatory and should be provided as an array of strings.
.OUTPUTS
    An array of selected domain names based on the user's input. If the user selects multiple domains, they will be returned as an array. If no input is provided, all domains will be returned.
.EXAMPLE
    $Domains = Get-ADForest | Select-Object -ExpandProperty Domains
    $SelectedDomains = Get-SelectedDomains -Domains $Domains
    Write-Host "Selected domains: $($SelectedDomains -join ', ')"
    # This will display the selected domains based on user input. If the user selects multiple domains, they will be displayed as a comma-separated list. If the user selects all domains, it will display all domains in the forest.
#>
function Get-SelectedDomains {
    param(
        [Parameter (Mandatory, Position = 0)]
        [string[]]$Domains
    )
    # loop to display the list of domains until the user selects at least one valid domain or all domains
    do {
        # Show all available domains with their indices for selection
        For ($i = 0; $i -lt $Domains.count; $i++){
            Write-Host "[$i] $($Domains[$i])"
        }
        Write-Host "[$($i)] all domains"
        # Prompt the user to select domains by entering their indices separated by commas
        $strReadIndex  = Read-Host "Select domains (you can select multiple domain separated by ',' [$i])"
        if ($strReadIndex -eq '') {
            $strReadIndex = "$i" #select all domains if no input is provided
        }
        $SelectedDomains = @()
        try {           
            foreach ($DomainIndex in $strReadIndex -split ","){ #split the input by commas to allow multiple selections
                $DomainIndex = [int]$DomainIndex.Trim() # Trim any whitespace and convert to integer, if the input is not a valid integer, it will throw an exception
                if ($DomainIndex -eq  $Domains.count){
                    return $Domains
                } else {
                    if ($DomainIndex -ge 0 -and $DomainIndex -le $Domains.Count){ # Check if the index is within the valid range
                        $SelectedDomains += $Domains[$DomainIndex]
                    } else {
                        Write-Host "Invalid value $DomainIndex" -ForegroundColor Red
                    }
                }
            }
        }
        catch {
                Write-Host "Invalid value $DomainIndex" -ForegroundColor Red
        }
    } while ($SelectedDomains.count -eq 0)
    return $SelectedDomains
}

#####################################################################################################################################################################################
#region  Constanst and default value
#####################################################################################################################################################################################
$ScriptVersion = "0.2.202500331"
try{
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy  -ErrorAction Stop
} 
catch {
    Write-Host "Failed to load the required Powerhsell module" -ForegroundColor Red
    Write-Host "validate the Active Directory and Group Policy Powershell modules are installed" -ForegroundColor Red
    exit
}
#The current domain contains the relevant Tier level groups
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$CurrentDC        = (Get-ADDomainController -Discover -Service GlobalCatalog -NextClosestSite ).Name

#This Description will be added to the Tier 0 / Tier 1 Commputers group if it will be created during this setup. This Description can't be changed during the setup. 
$DescriptionT0ComputerGroup = "This group contains all Tier 0 member computer. This group will be used for the Kerberos Authentication Policy claim"
$DescriptionT1ComputerGroup = "This group contains any Tier 1 member computer. This group will be used for the Kerberos Authentication Policy claim"
#This Description will be added to the Group Managemd Service Account if it is required in teh multi-domain forest mode. This Description can't be changed during the setup. 
$DescriptionGMSA = "This Group Managed service account is used to manage user accounts and groups impacted by the Tier Level Model"
#This Description will be added to the Tier 0 / Tier 1 Kerberos Authentication Policy if they doesn't exists.This Description can't be changed during the setup. 
$DescriptionTier0CKerberosAuthenticationPolicy = "This policy aims to isolate Tier 0 systems to ensure the security and integrity of critical IT infrastructures. Users assigned this policy can only log in to computers that are members of the 'Enterprise Domain Controller' group or the 'Tier 0 Server'group. This ensures that only authorized users have access to the most sensitive systems within the organization."
$DescriptionTier1CKerberosAuthenticationPolicy = "This policy aims to isolate Tier 1 systems to ensure the security and integrity of IT infrastructures. Users assigned this policy can only log in to computers that are members of the 'Tier 1 Server' group or 'Enterprise Domain Controller' group or the 'Tier 0 Server'group. This ensures that only authorized users have access to the most sensitive systems within the organization."
#Default values for the Kerberos Authenticaiton policy
$DefaultT0KerbAuthPolName = "Tier 0 restriction"
$DefaultT1KerbAuthPolName = "Tier 1 restriction"
#Default path of the Tier Level users OU
$DefaultT0Users = "OU=Admins,OU=Tier 0,OU=Admin"
$DefaultT1Users = "OU=Admins,OU=Tier 1,OU=Admin"
#Default path of the Tier Level users OU
$DefaultT0Computers          =           "OU=Server,OU=Tier 0,OU=Admin"
$DefaultT0ServiceAccountPath = "OU=Service Accounts,OU=Tier 0,OU=Admin"
$DefaultT1ServiceAccountPath = "OU=Service Accounts,OU=Tier 1,OU=Admin"
$DefaultT1Computers          =           "OU=Server,OU=Tier 1,OU=Admin"
#Default name of the Claim groups
$DefaultT0ComputerGroupName = "Tier 0 server"
$DefaultT1ComputerGroupName = "Tier 1 server"
$DefaultTGTLifeTime = 240
#Default Name of the Group Managed Service account 
$DefaultGMSAName = "TierLevel-mgmt"
#Default script location path
$ScriptTarget              = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts"
#Default FQDN configuration file path
$ConfigFile                = "$ScriptTarget\TierLevelIsolation.config"
#constantes
$GPOName = "Tier Level Isolation"
$GPOBackupID = "68e9eff4-48c4-420d-a229-f1acd8c75c6b"
$RegExDNDomain = "(?i)(DC=[^,]+,)*DC=.+$"
$DefaultDomainControllerPolicy = "6AC1786C-016F-11D2-945F-00C04FB984F9"
$DefaultDomainPolicy = "31B2F340-016D-11D2-945F-00C04FB984F9"
$KDCEnableClaim = @{
    Key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
    ValueName = "EnableCbacAndArmor"
    Value = 1
    Type = 'DWORD'
}
$ClientKerberosAmoring = @{
    Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    ValueName = "EnableCbacAndArmor"
    Value = 1
    Type = 'DWORD'
}


#########################################################################################################
# Main program start here
#########################################################################################################

#This script requires the Active Director and Group Policy Powershell Module. The script terminal if one
#of the module is missing
Write-Host "Welcome to the Tier Level isolation setup script" -ForegroundColor Green
Write-Host "This script will prepare you active directory to protect Administrators with Kerberos Authentication Policies" -ForegroundColor Green 
Write-Host "Tier 0 / Tier 1 isolation setup script ($ScriptVersion)" -ForegroundColor Green

#region install TierLevelIsolation module
try{
    $ModulePath = Join-Path $Env:ProgramFiles\WindowsPowerShell\Modules "TierLevelIsolation"
    if (Test-Path $ModulePath) {
        Write-Host "The TierLevelIsolation module is already installed" -ForegroundColor Green
    } else {
        Write-Host "Installing the TierLevelIsolation module" -ForegroundColor Green        
        New-Item -Path $ModulePath -ItemType Directory -ErrorAction Stop | Out-Null
        copy-item -Path "$PSScriptRoot\module\*" -Destination $ModulePath -Force -recurse -ErrorAction Stop
        Write-Host "The TierLevelIsolation module is installed" -ForegroundColor Green

    }
    if ($InstallPSModuleOnly){
        exit
    }
    if ($null -eq (Get-Module -Name TierLevelIsolation)){
        Write-Host "Loading the TierLevelIsolation module" -ForegroundColor Green
        Import-module TierLevelIsolation -ErrorAction Stop
    } else {
        Write-Host "The TierLevelIsolation module is already loaded" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to install the TierLevelIsolation module" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    exit
}
#endregion
#region Parameter collection
if (!(IsMemberOfEnterpriseAdmins)){
    Write-Host "Enterprise Administrator privileges required to access to configuration partition" -ForegroundColor Yellow
    $strReadHost = Read-Host "Do you want to continue without Enterprise Administrator privileges y/[n]"
    if ($strReadHost -eq '') {$strReadHost = "n"}
    if ($strReadHost -notlike "y*"){
        Write-Host "aborting" -ForegroundColor Yellow
        return
    }
}
$Domains = Get-SelectedDomains (GEt-ADForest).Domains 
$Domains  | Add-TierLevelIsolationDomain 


#Define Tier  Parameters
Write-Host "Scope-Level:"
Write-Host "[0] Tier-0"
Write-Host "[1] Tier-1"
Write-Host "[2] Tier 0 and Tier 1"
do{
    $strReadHost = Read-Host "Select which scope should be enabled (2)" 
    switch ($strReadHost) {
        ""  { $scope = "All-Tiers"}
        "0" { $scope = "Tier0" }
        "1" { $scope = "Tier1" }
        "2" { $scope = "All-Tiers"}
        Default {$scope = ""}
    }
}while ($scope -eq '')
Set-TierLevelIsolationScope $scope
if (($scope -eq "Tier0") -or ( $scope -eq "All-Tiers") ){
    Write-Host "Tier 0 isolation parameter "
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 Admin OU ($DefaultT0Users)"
        if ($strReadHost -eq ''){$strReadHost = $DefaultT0Users}    
        Add-TierLevelIsolationUserPath Tier0 $strReadHost
        $strReadHost = Read-Host "Do you want to add another Tier 0 Admin OU (y/[n])"
    } while ($strReadHost -like "y*")
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 service account OU($defaultT0ServiceAccountPath)"
        if ($strReadHost -eq ''){$strReadHost = $DefaultT0ServiceAccountPath}
        Add-TierLevelIsolationServiceAccountPath Tier0 $strReadHost
        $strReadHost = Read-Host "Do you want to add another Tier 0 service account OU (y/[n])"
    } while ($strReadHost -like "y*")
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 server OU ($defaultT0Computers)"
        if ($strReadHost -eq ''){$strReadHost = $DefaultT0Computers}
        Add-TierLevelIsolationComputerPath Tier0 $strREadHost
        $strReadHost = Read-Host "Do you want to add another Tier 0 server OU (y/[n])"
    }while ($strReadHost -like "y*")
    $strReadHost = Read-Host "Provide the Tier 0 Kerberos Authentication policy name ($DefaultT0KerbAuthPolName)"
    if ($strReadHost -eq ''){$strReadHost = $DefaultT0KerbAuthPolName}
    Set-TierLevelIsolationKerberosAuthenticationPolicy Tier0 $strReadHost -Force
}
if ($scope -eq "Tier1" -or $scope -eq "All-Tiers"){
    Write-Host "Tier 1 isolation parameter "
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 Admin OU ($DefaultT1Users)"
        if ($strReadHost -eq ''){$strReadHost = $DefaultT1Users}
        Add-TierLevelIsolationUserPath Tier1 $strReadHost
        $strReadHost = Read-Host "Do you want to add another Tier 1 Admin OU (y/[n])"
    } while ($strReadHost -like "y*")
    do{
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 service account OU ($DefaultT1ServiceAccountPath)"
        if ($strReadHost -eq ''){$strReadHost = $DefaultT1ServiceAccountPath}
        Add-TierLevelIsolationServiceAccountPath Tier1 $strReadHost
        $strReadHost = Read-Host "Do you want to add another Tier 1 service account OU (y/[n])"
    } while ($strReadHost -like "y*")
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 server OU ($DefaultT1Computers)"
        if ($strReadHost -eq ''){$strReadHost = $DefaultT1Computers}
        Add-TierLevelIsolationComputerPath Tier1 $strReadHost
        $strReadHost = Read-Host "Do you want to add another Tier 1 server OU (y/[n])"
    }while ($strReadHost -like "y*")
    $strReadHost = Read-Host "Provide the Tier 1 Kerberos Authentication policy name ($DefaultT1KerbAuthPolName)"
    if ($strReadHost -eq ''){$strReadHost = $DefaultT1KerbAuthPolName}
    Set-TierLevelIsolationKerberosAuthenticationPolicy Tier1 $strReadHost -force
}
if ($scope -eq "Tier0" -or $scope -eq "All-Tiers"){
    Write-Host "Tier 0 server group parameter "
    $strReadHost = Read-Host "Provide the Tier 0 server samaccount group name ($DefaultT0ComputerGroupName)"
    if ($strReadHost -eq ''){$strReadHost = $DefaultT0ComputerGroupName}
    Set-TierLevelIsolationComputerGroup Tier0 $strReadHost -Force
}
if (($scope -eq "Tier1") -or ( $scope -eq "All-Tiers")){
    Write-Host "Tier 1 isolation parameter "
    $strReadHost = Read-Host "Provide the Tier 1 server samaccount group name ($DefaultT1ComputerGroupName)"
    if ($strReadHost -eq ''){$strReadHost = $DefaultT1ComputerGroupName}
    Set-TierLevelIsolationComputerGroup Tier1 $strReadHost -Force
}
Write-Host "Do you want to manage protected users group with tiering?"
Write-Host "[0] Tier-0 users will be added to protected users"
Write-Host "[1] Tier-1 users will be added tp protected users"
Write-Host "[2] Tier-0 and Tier-1 users will be added to protected users"
Write-Host "[3] Protected users will not be managed with Tiering"
$strReadHost = Read-Host "Select protected users level [3]"
switch ($strReadHost) {
    "0" { Set-TierLevelProtectedUsersState "Tier-0" }
    "1" { Set-TierLevelProtectedUsersState "Tier-1" }
    "2" { Set-TierLevelProtectedUsersState "All-Tiers" }
    Default { Set-TierLevelProtectedUsersState "None" }
}
$strReadHost = Read-Host "Enable privileged Tier 0 group cleanup [Y/N] (y)"
if ($strReadHost -like "n*"){
    Set-TierLevelPrivilegedGroupsCleanUpState $false
} else {
    Set-TierLevelPrivilegedGroupsCleanUpState $true
}
    
#endregion

#region OU validation / creation
$config = Get-TierLevelIsolationConfiguration
foreach ($domain in $config.Domains){
    $DomainDN = (Get-ADDomain -Server $domain).DistinguishedName
    foreach ($OU in $config.Tier0ComputerPath){
        if ($OU -like "*DC=*"){
            if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                if (!(New-TierLevelOU -OUPath "$OU" -DomainDNS $domain )){
                    Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                    Write-Host "script aborted" -ForegroundColor Red
                    return
                }
            }
        } else {
            if (!(New-TierLevelOU -OUPath "$OU,$DomainDN" -DomainDNS $domain )){
                Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                Write-Host "script aborted" -ForegroundColor Red
                return
            }
        }
    }
    foreach ($OU in $config.Tier0UsersPath){
        if ($OU -like "*DC=*"){
            if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                if (!(New-TierLevelOU -OUPath "$OU" -DomainDNS $domain )){
                    Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                    Write-Host "script aborted" -ForegroundColor Red
                    return
                }
            }
        } else {
            if (!(New-TierLevelOU -OUPath "$OU,$DomainDN" -DomainDNS $domain )){
                Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                Write-Host "script aborted" -ForegroundColor Red
                return
            }
        }
    }
    foreach ($OU in $config.Tier0ServiceAccountPath){
        if ($OU -like "*DC=*"){
            if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                if (!(New-TierLevelOU -OUPath "$OU" -DomainDNS $domain)){
                    Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                    Write-Host "script aborted" -ForegroundColor Red
                    return
                }
            }
        } else {
            if (!(New-TierLevelOU -OUPath "$OU,$DomainDN" -DomainDNS $domain )){
                Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                Write-Host "script aborted" -ForegroundColor Red
                return
            }
        }
    }
    if (($scope -eq "Tier-1") -or ($scope -eq "All-Tiers")){
        foreach ($OU in $config.Tier1ComputerPath){
            if ($OU -like "*DC=*"){
                if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                    foreach ($OU in $config.Tier0UsersPath){
                        if ($OU -like "*DC=*"){
                            if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                                if (!(New-TierLevelOU -OUPath "$OU" -DomainDNS $domain )){ 
                                    Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                                    Write-Host "script aborted" -ForegroundColor Red
                                    return
                                }
                            }
                        } else {
                            if (!(New-TierLevelOU -OUPath "$OU,$DomainDN" -DomainDNS $domain )){
                                Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                                Write-Host "script aborted" -ForegroundColor Red
                                return
                            }
                        }
                    } 
                }
            } else {
                if (!(New-TierLevelOU -OUPath "$OU,$DomainDN" -DomainDNS $domain )){
                    Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                    Write-Host "script aborted" -ForegroundColor Red
                    return
                }
            }
        }
        foreach ($OU in $config.tier1UsersPath){
            if ($OU -like "*DC=*"){
                if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                    if (!(New-TierLevelOU -OUPath $OU -DomainDNS $domain )){
                        Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                        Write-Host "script aborted" -ForegroundColor Red
                        return
                    }
                }
            } else {
                if (!(New-TierLevelOU -OUPath "$OU,$DomainDN" -DomainDNS $domain )){
                    Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
                    Write-Host "script aborted" -ForegroundColor Red
                    return
                }
            }
        }
    }
}
#endregion
#Tier 0 server group is needed in any scope
$Tier0ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier0ComputerGroup)'" 
$Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'"
$GroupWaitCounter = 0 #If the universal group is create via a DC who is not a GC, the group is not visible in the forest until the GC is replicated
try {
    if ($Null -eq $Tier0ComputerGroup ){
        New-ADGroup -Name $config.Tier0ComputerGroup -GroupScope Universal -Description $DescriptionT0ComputerGroup -Server $CurrentDC
        Write-Host "The group $($config.Tier0ComputerGroup) is created in $((Get-ADDomain).UsersContainer). Move the group the valid OU" -ForegroundColor Yellow
        $Tier0ComputerGroup = Get-ADgroup -Identity $config.Tier0ComputerGroup -Properties adminCount         
        while (($Null -eq $Tier0ComputerGroup) -and ($GroupWaitCounter -lt 10)){
            Write-Host "The group $($config.Tier0ComputerGroup) is not visible in the forest. Waiting for 10 seconds" -ForegroundColor Yellow   
            Start-Sleep -Seconds 10
            $Tier0ComputerGroup = Get-ADGroup -Identity $config.Tier0ComputerGroup -Server $CurrentDC
            $GroupWaitCounter++
        }
        if ($Null -eq $Tier0ComputerGroup){
            Write-Host "Can't create the group $($config.Tier0ComputerGroup). Script aborted" -ForegroundColor Red
            Write-Host "script aborted" -ForegroundColor Red
            return
        } else {
            $GroupWaitCounter = 0
            $Tier0ComputerGroup | Set-ADObject -replace @{adminCount=1}
        }        
    }
    if (($null -eq $Tier1ComputerGroup ) -and (($scope -eq "Tier-1") -or ($scope -eq "All-Tiers"))){
        New-ADGroup -Name $config.Tier1ComputerGroup -GroupScope Universal -Description $DescriptionT1ComputerGroup -Server $CurrentDC
        $Tier1ComputerGroup = Get-ADGroup -Identity $config.Tier1ComputerGroup
        while (($Null -eq $Tier1ComputerGroup) -and ($GroupWaitCounter -lt 10)){
            Write-Host "The group $($config.Tier1ComputerGroup) is not visible in the forest. Waiting for 10 seconds" -ForegroundColor Yellow   
            Start-Sleep -Seconds 10
            $GroupWaitCounter++
            $Tier1ComputerGroup = Get-ADGroup -Identity $config.Tier1ComputerGroup -Server $CurrentDC
        }
        if ($null -eq $Tier1ComputerGroup){
            Write-Host "Can't create the group $($config.Tier1ComputerGroup). Script aborted" -ForegroundColor Red
            Write-Host "script aborted" -ForegroundColor Red
            return
        } else {
            $Tier1ComputerGroup | Set-ADObject -replace @{adminCount=1}
        }
    }
}
catch [System.UnauthorizedAccessException]{
    Write-Host "Administrator Privileges required to create the Tier 0 / Tier 1 server group" -ForegroundColor Red
    Write-Host $($Error[0].Exception.Message) -ForegroundColor Red
    Write-Host "script aborted" -ForegroundColor Red
    return
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
    Write-Host "Can't find group $($Error[0].CategoryInfo.TargetName). Script aborted" -ForegroundColor Red 
    Write-Host "script aborted" -ForegroundColor Red
    return
}
catch {
    Write-Host "An unexpected error has occured. Script aborted" -ForegroundColor Red
    Write-Host $($Error[0].Exception.Message) -ForegroundColor Red
    Write-Host "script aborted" -ForegroundColor Red
    return
}

#Create the Kerberos Authentication Policy if required
if (($scope -eq "Tier-0") -or ($scope -eq "All-Tiers")){
    try {
        if ([bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.T0KerbAuthPolName)'")){
            Write-Host "Kerberos Authentication Policy $($config.T0KerbAuthPolName) already exists. Please validate the policy manual" -ForegroundColor Yellow
        } else {
            #create a Kerberos authentication policy, wher assinged users can logon to members of enterprise domain controllers
            #or member of the Tier 0 server group
            $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID($($Tier0ComputerGroup.SID))})))"
            New-ADAuthenticationPolicy -Name $config.T0KerbAuthPolName`
                                       -Enforce `
                                       -UserTGTLifetimeMins $DefaultTGTLifeTime `
                                       -UserAllowedToAuthenticateFrom $AllowToAutenticateFromSDDL `
                                       -ProtectedFromAccidentalDeletion $true `
                                       -Description $DescriptionTier0CKerberosAuthenticationPolicy
            Write-Host "Tier 0 Kerberos Authentication Policy sucessfully created"                             
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Host "Can't find group $($Error[0].CategoryInfo.TargetName). Script aborted" -ForegroundColor Red 
        Write-Host "script aborted" -ForegroundColor Red
        return
    }
    catch [System.UnauthorizedAccessException]{
        Write-Host "Enterprise Administrator Privileges required to create Kerberos Authentication Policy" -ForegroundColor Red
        Write-Host $($Error[0].Exception.Message) -ForegroundColor Red
        Write-Host "script aborted " -ForegroundColor Red
        return
    }
}
if (($scope -eq "Tier-1") -or ($scope -eq "All-Tiers")){
    try {
        if ([bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.T1KerbAuthPolName)'")){
            Write-Host "Kerberos Authentication Policy $($config.T1KerbAuthPolName)) already exists. Please validate the policy manual" -ForegroundColor Yellow
        } else {
            #create a Kerberos authentication policy, wher assinged users can logon to members of enterprise domain controllers
            #or member of the Tier 0 server group
            $AllowToAutenticateFromSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;(((Member_of {SID(ED)}) || (Member_of_any {SID($($Tier0ComputerGroup.SID))})) || (Member_of_any {SID($($Tier1ComputerGroup.SID))})))"
            New-ADAuthenticationPolicy -Name $config.T1KerbAuthPolName `
                                       -Enforce `
                                       -UserTGTLifetimeMins $DefaultTGTLifeTime `
                                       -Description $DescriptionTier1CKerberosAuthenticationPolicy `
                                       -UserAllowedToAuthenticateFrom $AllowToAutenticateFromSDDL `
                                       -ProtectedFromAccidentalDeletion $true 
            Write-Host "Tier 1 Kerberos Authentication Policy successfully created"                             
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Host "Can't find group $($Error[0].CategoryInfo.TargetName). Script aborted" -ForegroundColor Red 
        Write-Host "script aborted" -ForegroundColor Red
        exit
    }
    catch [System.UnauthorizedAccessException]{
        Write-Host "Enterprise Administrator Privileges required to create Kerberos Authentication Policy" -ForegroundColor Red
        Write-Host $($Error[0].Exception.Message) -ForegroundColor Red
        Write-Host "script aborted " -ForegroundColor Red
        exit
    }
}
#create the GMSA if the Tier Level isolation works in Mulit-Domain-Domain Forest mode
$strReadHost = Read-Host "Group Managed Service AccountName ($DefaultGMSAName)"
if ($strReadHost -eq '') {$strReadHost = $DefaultGMSAName}
$GMSAName = $strReadHost
if ($null -eq (Get-ADServiceAccount -Filter "name -eq '$GMSAName'")){
    if (![bool](Get-KdsRootKey)){
        Write-Host "KDS Rootkey is missing." -ForegroundColor Red
        Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
    }
    New-GMSA -GMSAName $GMSAName -AllowTOLogon (Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-516") -Description $DescriptionGMSA
}
$oGMSA = Get-ADServiceAccount -Filter "name -eq '$GMSAName'"
$ForestRootDomain = (Get-ADForest).RootDomain
$EAdminsGroup = Get-ADGroup -Identity "$((Get-ADDomain -server (Get-ADForest).RootDomain).DomainSid)-519" -Properties Members -Server $ForestRootDomain
try {
    if ($EAdminsGroup.Members -notcontains $oGMSA.DistinguishedName){
        Add-ADGroupMember $EAdminsGroup -Members $oGMSA -Server $ForestRootDomain
        Write-Host "The group $($oGMSA.Name) is added to the Enterprise Admins group" -ForegroundColor Yellow
    }
}
catch{
    Write-Host "The group $($oGMSA.Name) is not added to the Enterprise Admins group. Please add the group manually" -ForegroundColor Yellow
}
try{
    Copy-Item .\TierLevelComputerManagement.ps1 $ScriptTarget -ErrorAction Stop
    Copy-Item .\TierLevelUserManagement.ps1 $ScriptTarget -ErrorAction Stop    
} 
catch{
    Write-Host "can not copy the script file to $ScriptTarget" -ForegroundColor Red
}
try {
    $config | ConvertTo-Json | Out-File $ConfigFile 
}
catch {
    Write-Host "Can not write the config file"
    return
}
#region group policy
#read the schedule task template from the current directory
try {

    $ScheduleTaskRaw = Get-Content "$PWD\GPO\{$GPOBackupID}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Raw -ErrorAction Stop
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace("#ScriptPath", $ScriptTarget) 
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace("#GMSAName", $GMSAName)
    [XML]$ScheduleTaskXML = $ScheduleTaskRaw
    switch ($scope){ 
        "Tier-0" {
            #Disalbe the Tier 0 server management tasks. We will only manage the Tier 1 server and user management tasks
            $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{D9E485BC-145A-47BC-B6C0-A3457662E26A}'}
            $Task.disabled = "1"  
            #Disableing user context task         
            $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{832DD5A2-5AA7-4F99-8663-0D4855E5DA56}'}
            $Task.disabled = "1"
          }
        "Tier-1" {
            #Disabling Tier 0 server management tasks. We will only manage the Tier 1 server and user management tasks
            $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{B1168190-7E2C-4177-9391-B1FFBCDF4774}'}
            $Task.disabled = "1"
            #Disableing user context task
            $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{832DD5A2-5AA7-4F99-8663-0D4855E5DA56}'}
            $Task.disabled = "1"
          }
    }
    if ($GMSAName -eq ""){
        $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{832DD5A2-5AA7-4F99-8663-0D4855E5DA56}'}
        $Task.disabled = "1" #disable the user context task if no GMSA is used. This task is used to manage the user context for the Tier 0 / Tier 1 users
    }
    $ScheduleTaskXML.Save("$PWD\GPO\{$GPOBackupID}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml")
    Import-GPO -BackupId $GPOBackupID -Path "$PWD\GPO" -CreateIfNeeded -TargetName $GPOName
    $oGPO = Get-GPO -Name $GPOName
    $LinkedTieringGP = (Get-GPInheritance -Target (Get-ADDomain).DomainControllersContainer).GpoLinks | Where-Object {$_.GpoId -eq "$($oGPO.ID)"}
    if ($Null -eq $LinkedTieringGP){
        $oGPO | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled Yes
        Write-Host "$GPOName Group Policy is linked to Domain Controllers OU" -ForegroundColor Yellow -BackgroundColor Blue
        Write-Host "Do not forget to enable user management tasks" -ForegroundColor Yellow
        Write-Host "ONCE all Tier 0 server are members of the $($config.Tier0ComputerGroup) group AND have been rebooted you are ready to enable the 'Tier 0 User Management' Scheduled Task. Also, be sure to have a proper Breakglass account and process in place."
    } else {
        if (!$LinkedTieringGP.Enabled){
            Write-Host "$GPOName group policy is linked to $((Get-ADDomain).DomainControllersContainer)" -ForegroundColor Yellow
            Write-Host "Validate the status for the Schedule tasks before you enbaled the group policy link" -ForegroundColor Yellow
        }
    }
    #Enable Claim Support on Domain Controllers. 
    #Write this setting to the default domain controller policy  
    foreach ($domain in $config.Domains){
        $RegKey = Get-GPRegistryValue -Domain $domain -Guid $DefaultDomainControllerPolicy -Key $KDCEnableClaim.Key  -ErrorAction SilentlyContinue
        if ( $RegKey.value -ne 1){
            Set-GPRegistryValue @KDCEnableClaim -Domain $domain -Guid $DefaultDomainControllerPolicy 
        }
        $RegKey = Get-GPRegistryValue -Domain $Domain -Guid $DefaultDomainControllerPolicy -key $ClientKerberosAmoring.Key  -ErrorAction SilentlyContinue
        if ($RegKey.value -ne 1){
            Set-GPRegistryValue @ClientKerberosAmoring -Domain $domain -Guid $DefaultDomainControllerPolicy 
        }
        $RegKey = Get-GPRegistryValue -Domain $Domain -Guid $DefaultDomainPolicy -key $ClientKerberosAmoring.Key -ErrorAction SilentlyContinue
        if ($RegKey.value -ne 1){
            Set-GPRegistryValue @ClientKerberosAmoring -Domain $domain -Guid $DefaultDomainPolicy 
        }
    }
} 
catch{
    Write-Host $error[0]
}
#endregion 