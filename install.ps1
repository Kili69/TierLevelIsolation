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
    This script installes the Kerberos Tier Level isolation
.OUTPUTS 
    None

#>
[CmdletBinding (SupportsShouldProcess)]
param (
    #Tier Level 
    [Parameter(Mandatory = $false)]
    [ValidateSet("Tier-0", "Tier-1", "All-Tiers")]
    $scope = "All-Tiers"
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
function CreateOU {
    [CmdletBinding ( SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string]$OUPath,
        [Parameter (Mandatory)]
        [string]$DomainDNS
    )
    try {
        Write-Debug "CreateOU called the $OUPath $DomainDNS"
        #load the OU path into array to create the entire path step by step
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        #normalize OU remove 
        Write-Debug "Starting createOU $OUPath $DomainDNS"
        $OUPath = [regex]::Replace($OUPath, "\s?,\s?", ",")
        if ($OUPath.Contains("DC=")) {
            $OUPath = [regex]::Match($OUPath, "((CN|OU)=[^,]+,)+")
            $OUPath = $OUPath.Substring(0, $OUPath.Length - 1)
        }
        Write-Debug "Normalized OUPath $OUPath"
        $aryOU = $OUPath.Split(",")
        $BuildOUPath = ""
        #walk through the entire domain 
        For ($i = $aryOU.Count; $i -ne 0; $i--) {
            #to create the Organizational unit the string OU= must be removed to the native name
            $OUName = $aryOU[$i - 1].Replace("OU=", "")
            #if this is the first run of the for loop the OU must in the root. The searbase paramenter is not required 
            if ($i -eq $aryOU.Count) {
                #create the OU if it doesn|t exists in the domain root. 
                if ([bool](Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchScope OneLevel -server $DomainDNS)) {
                    Write-Debug "OU=$OUName,$DomainDN already exists no actions needed"
                }
                else {
                    Write-Host "$OUName doesn't exist in $OUPath. Creating OU" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Server $DomainDNS                        
                }
            }
            else {
                #create the sub ou if required
                if ([bool](Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase "$BuildOUPath$DomainDN" -Server $DomainDNS)) {
                    Write-Debug "$OUName,$OUPath already exists no action needed" 
                }
                else {
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
        Write-Host "A error occured while create OU Structure"
        Write-Host $Error[0].CategoryInfo.GetType()
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

function IsMemberOfEnterpriseAdmins{
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($currentUser.Groups -like "*-519"){
        return $true
    } else {
        return $false
    }
}


#####################################################################################################################################################################################
#region  Constanst and default value
#####################################################################################################################################################################################
#The current domain contains the relevant Tier level groups
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$CurrentDomainDN  = (Get-ADDomain).DistinguishedName

#This Description will be added to the Tier 0 / Tier 1 Commputers group if it will be created during this setup. This Description can't be changed during the setup. 
#But i can be changed after the setup
$DescriptionT0ComputerGroup = "This group contains all Tier 0 member computer. This group will be used for the Kerberos Authentication Policy claim"
$DescriptionT1ComputerGroup = "This group contains any Tier 1 member computer. This group will be used for the Kerberos Authentication Policy claim"
#This Description will be added to the Group Managemd Service Account if it is required in teh multi-domain forest mode. This Description can't be changed during the setup. 
#But i can be changed after the setup 
$DescriptionGMSA = "This Group Managed service account is used to manage user accounts and groups impacted by the Tier Level Model"
#This Description will be added to the Tier 0 / Tier 1 Kerberos Authentication Policy if they doesn't exists.This Description can't be changed during the setup. 
#But i can be changed after the setup
$DescriptionTier0CKerberosAuthenticationPolicy = "..."
$DescriptionTier1CKerberosAuthenticationPolicy = "..."

#Default values for the Kerberos Authenticaiton policy
$DefaultT0KerbAuthPolName = "Tier 0 restriction"
$DefaultT1KerbAuthPolName = "Tier 1 restriction"
#Default path of the Tier Level users OU
$DefaultT0Users = "OU=User,OU=Tier 0,OU=Admin"
$DefaultT1Users = "OU=User,OU=Tier 1,OU=Admin"
#Default path of the Tier Level users OU
$DefaultT0Computers = "OU=Computers,OU=Tier 0,OU=Admin"
$DefaultT1Computers = "OU=Computers,OU=Tier 1,OU=Admin"
#Default name of the Claim groups
$DefaultT0ComputerGroupName = "Tier 0 Computers"
$DefaultT1ComputerGroupName = "Tier 1 Computers"
$DefaultTGTLifeTime = 240
#Default Name of the Group Managed Service account 
$DefaultGMSAName = "TierLevel-mgmt"
#Default script location path
$ScriptTarget              = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts"
#Default FQDN configuration file path
$ConfigFile                = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\Tiering.config"

#constantes
$TaskSchedulerXML          = "ScheduledTasks.xml"
$ComputerManagementScript  = "TierLevelComputer.ps1"
$UserManagementScript      = "TierlevelUser.ps1"
$GPOName = "Tier Level Isolation"

$RegExOUPattern = "((OU|CN)=[^,]+,)*(OU|CN)=[^,]+$"
$RegExDNDomain = "(DC=[^,]+,)*DC=.+$"

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

#Inital configuration object
$config = New-Object psobject
$config | Add-Member -MemberType NoteProperty -Name Tier0ComputerPath   -Value @()
$config | Add-Member -MemberType NoteProperty -Name Tier1ComputerPath   -Value @()
$config | Add-Member -MemberType NoteProperty -Name Tier0ComputerGroup  -Value $DefaultT0ComputerGroupName
$config | Add-Member -MemberType NoteProperty -Name Tier1ComputerGroup  -Value $DefaultT1ComputerGroupName
$config | Add-Member -MemberType NoteProperty -Name Tier0UsersPath      -Value @()
$config | Add-Member -MemberType NoteProperty -Name tier1UsersPath      -Value @()
$config | Add-Member -MemberType NoteProperty -Name T0KerbAuthPolName   -Value $DefaultT0KerbAuthPolName
$config | Add-Member -MemberType NoteProperty -Name T1KerbAuthPolName   -Value $DefaultT1KerbAuthPolName
$config | Add-Member -MemberType NoteProperty -Name Domains             -Value @()
$config | Add-Member -MemberType NoteProperty -Name scope               -Value $scope   


#########################################################################################################
# Main program start here
#########################################################################################################

#This script requires the Active Director and Group Policy Powershell Module. The script terminal if one
#of the module is missing
try{
    Import-Module ActiveDirectory
    Import-Module GroupPolicy  
} 
catch {
    Write-Host "Failed to load the neede Powerhsell module" -ForegroundColor Red
    Write-Host "validate the Active Directory and Group Policy Powershell modules are installed"
    exit
}

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
if (((Get-ADForest).Domains.count -eq 1) -or ($SingleDomain)){
    $SingleDomain = $true
    $config.Domains += $CurrentDomainDNS
} else {
    $strReadHost = Read-Host "Do you want to enable the mulit-forest mode ([y]es / No)"
    if (($strReadHost -eq '') -or ($strReadHost -like "y*")){
        $SingleDomain = $false
        Write-Host "Forest Mode is enabled"
        $config.Domains += (Get-ADForest).Domains
    } else {
        $SingleDomain = $true
        Write-Host "Tierl Level isolation will be integrated on the current domain $CurrentDomainDNS"
        $config.Domains += $CurrentDomainDNS
    }
}


#Define Tier 0 Paramters
if (($scope -eq "Tier-0") -or ( $scope -eq "All-Tiers") ){
    Write-Host "Tier 0 isolation paramter "
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 user OU ($DefaultT0Users)"
        if ($strReadHost -eq '') {$strReadHost = $DefaultT0Users}
        if ($config.Tier0UsersPath -notcontains $strReadHost){
            $config.Tier0UsersPath += $strReadHost
        }
        $strReadHost = Read-Host "Do you want to add another Tier 0 user OU (y/[n])"
    } while ($strReadHost -like "y*")
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 computer OU ($defaultT0Computers)"
        if ($strReadHost -eq '') {$strReadHost = $DefaultT0Computers}
        if ($config.Tier0ComputerPath -notcontains $strReadHost){
            $config.Tier0ComputerPath += $strReadHost
            $strReadHost = Read-Host "Do you want to add anther Tier 0 computer OU (y/[n])"
        } 
    }while ($strReadHost -like "y*")
    $strReadHost = Read-Host "Provide the Tier 0 Kerberos Authentication policy name ($DefaultT0KerbAuthPolName)"
    if ($strReadHost -eq '') {$strReadHost = $DefaultT0KerbAuthPolName}
    $config.T0KerbAuthPolName = $strReadHost
}
$strReadHost = Read-Host "Provide the Tier 0 Computer Group name ($DefaultT0ComputerGroupName)"
if ($strReadHost -eq ''){$strReadHost = $DefaultT0ComputerGroupName}
$config.Tier0ComputerGroup = $strReadHost

if (($scope -eq "Tier-1") -or ( $scope -eq "All-Tiers")){
    Write-Host "Tier 1 isolation paramter "
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 user OU ($DefaultT1Users)"
        if ($strReadHost -eq '') {$strReadHost = $DefaultT1Users}
        if ($config.Tier1UsersPath -notcontains $strReadHost){
            $config.Tier1UsersPath += $strReadHost
        }
        $strReadHost = Read-Host "Do you want to add another Tier 1 user OU (y/[n])"
    } while ($strReadHost -like "y*")
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 computer OU ($DefaultT1Computers)"
        if ($strReadHost -eq '') {$strReadHost = $DefaultT1Computers}
        if ($config.Tier1ComputerPath -notcontains $strReadHost){
            $config.Tier1ComputerPath += $strReadHost
            $strReadHost = Read-Host "Do you want to add another Tier 0 computer OU (y/[n])"
        } 
    }while ($strReadHost -like "y*")
    $strReadHost = Read-Host "Provide the Tier 1 Kerberos Authentication policy name ($DefaultT1KerbAuthPolName)"
    if ($strReadHost -eq '') {$strReadHost = $DefaultT1KerbAuthPolName}
    $config.T1KerbAuthPolName = $strReadHost
}
#endregion

#region OU validation / creation
foreach ($domain in $config.Domains){
    $DomainDN = (Get-ADDomain).DistinguishedName
    if (($scope -eq "Tier-0") -or ($scope -eq "All-Tiers")){
        foreach ($OU in $config.Tier0ComputerPath){
            if ($OU -like "*DC=*"){
                if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                    CreateOU -OUPath "$OU" -DomainDNS $domain
                }
            } else {
                CreateOU -OUPath "$OU,$DomainDN" -DomainDNS $domain
            }
        }
    }
    if (($scope -eq "Tier-1") -or ($scope -eq "All-Tiers")){
        foreach ($OU in $config.tier1UsersPath){
            if ($OU -like "*DC=*"){
                if ([regex]::Match($OU,$RegExDNDomain).Value -eq $DomainDN){
                    createOU -OUPath $OU -DomainDNS $domain
                }
            } else {
                CreateOU -OUPath "$OU,$DomainDN" -DomainDNS $domain
            }
        }
    }
}
#endregion
#Tier 0 computers group is needed in any scope
$Tier0ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier0ComputerGroup)'"
$Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'" 
if ($Null -eq $Tier0ComputerGroup ){
    $Tier0ComputerGroup = New-ADGroup -Name $config.Tier0ComputerGroup -GroupScope Universal -Description $DescriptionT0ComputerGroup
}
if (($null -eq $Tier1ComputerGroup ) -and (($scope -eq "Tier-1") -or ($scope -eq "All-Tiers"))){
    $Tier1ComputerGroup = New-ADGroup -Name $config.Tier1ComputerGroup -GroupScope Universal -Description $DescriptionT1ComputerGroup
}
if (($scope -eq "Tier-0") -or ($scope -eq "All-Tiers")){
    try {
        if ([bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.T0KerbAuthPolName)'")){
            Write-Host "Kerberos Authentication Policy $($config.T0KerbAuthPolName)) already exists. Please validate the policy manual" -ForegroundColor Yellow
        } else {
            #create a Kerberos authentication policy, wher assinged users can logon to members of enterprise domain controllers
            #or member of the Tier 0 computers group
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
            #or member of the Tier 0 computers group
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
#create the GMSA if the Tier Level isolation works in Mulit-Domain Forest mode
if ($config.Domains.Count -gt 1){
    $strReadHost = Read-Host "Group Managed Service AccountName ($DefaultGMSAName)"
    if ($strReadHost -eq '') {$strReadHost = $DefaultGMSAName}
    if ($null -eq (Get-ADServiceAccount -Filter "name -eq '$strReadHost'")){
        if (![bool](Get-KdsRootKey)){
            Write-Host "KDS Rootkey is missing." -ForegroundColor Red
            Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
        }
        New-GMSA -GMSAName $strReadHost -AllowTOLogon (Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-516") -Description $DescriptionGMSA
    }
}
Copy-Item .\TierLevelComputerManagement.ps1 $ScriptTarget -ErrorAction Stop
Copy-Item .\TierLevelUserManagement.ps1 $ScriptTarget -ErrorAction Stop
$config | ConvertTo-Json | Out-File $ConfigFile 
#region group policy
#read the schedule task template from the current directory
[string]$ScheduleTaskRaw = Get-Content ".\ScheduledTasksTemplate.xml" -ErrorAction SilentlyContinue
if ($null -eq $ScheduleTaskRaw ){
    Write-Host "Missing .\ScheduleTaskTemplate.xml file. Configuration of the schedule tasks terminated" -ForegroundColor Red
    return
}


try {
    #Enable Claim Support on Domain Controllers. 
    #Write this setting to the default domain controller policy  
    foreach ($domain in $config.Domains){
        Set-GPRegistryValue @KDCEnableClaim        -Domain $domain -Guid $DefaultDomainControllerPolicy
        Set-GPRegistryValue @ClientKerberosAmoring -Domain $domain -Guid $DefaultDomainControllerPolicy
        Set-GPRegistryValue @ClientKerberosAmoring -Domain $domain -Guid $DefaultDomainPolicy
    }
    #Create new Group Policy if required to manage Tier level isolation
    $oGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($null -eq $oGPO){
        $oGPO = New-gpo -Name $GPOName -Comment "Tier Level enforcement group policy. " -ErrorAction SilentlyContinue
        $CSEGuid = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
        Set-ADObject -Identity "CN={$($oGPO.Id.Guid)},CN=Policies,CN=System,$CurrentDomainDN" -Add @{'gPCMachineExtensionNames' = $CSEGuid}
    }
    $GPPath = "\\$((Get-ADDomain).DNSRoot)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{$($oGPO.ID)}\Machine\Preferences\ScheduledTasks"
    if (!(Test-Path "$GPPath")){
        New-Item -ItemType Directory $GPPath | Out-Null
    }
    $GPPRAW = Get-Content ".\$TaskSchedulerXML"
    $GPPRAW.Replace($ComputerManagementScript, "$ScriptTarget\$ComputerManagementScript")
    $GPPRAW.Replace($UserComputerManagementScript, "$ScriptTarget\$UserManagementScript")
    $GPPRAW | Out-File "$GPPath\$TaskSchedulerXML"
    $oGPO | New-GPLink -Target (Get-ADDomain).DomainControllersContainer -LinkEnabled $true
    Write-Host "Tier Level User Management Group Policy is linked to Domain Controllers OU but not activated" -ForegroundColor Yellow -BackgroundColor Blue
    Write-Host "Validate the group policy and enable" -ForegroundColor Yellow
    if ($config.Domains.Count -gt 1){
        $UdpateGMSACommand = "`$principal = New-ScheduledTaskPrincipal -LogonType Password -UserId '$GmsaName`$';Set-ScheduledTask 'Tier 0 User Management' -Principal `$principal"
        $ScheduleTaskRaw = $ScheduleTaskRaw.Replace('$InstallTask', $UdpateGMSACommand)        
    } else {
        [XML]$ScheduleTaskXML = Get-Content "$GPPath\$TaksSchedulterXML"
        $GMSAChangeNodeTier0 = $ScheduleTaskXML.SelectSingleNode("//TaskV2[@name='Change Tier 0 User Management']")
        $GMSAChangeNodeTier1 = $ScheduleTaskXML.SelectSingleNode("//TaskV2[@name='Change Tier 0 User Management']")
        $ScheduleTaskXML.ScheduledTasks.RemoveChild($GMSAChangeNodeTier0)
        $ScheduleTaskXML.ScheduledTasks.RemoveChild($GMSAChangeNodeTier1)
        $ScheduleTaskXML.Save("$GPPath\$TaksSchedulterXML")    

    }
} 
catch{

}
#endregion 