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
    Installs and configures Active Directory Tier Level isolation.

.DESCRIPTION
    Installs the Tier Level isolation PowerShell module and interactively configures the
    selected Tier 0 and Tier 1 components. Depending on the selected scope, the script:

    - Creates or validates the configured organizational unit structures.
    - Creates universal server groups and protects them with adminCount.
    - Creates enforced Kerberos authentication policies.
    - Creates a group managed service account (gMSA) and grants its required membership.
    - Copies the management scripts, module, and configuration into SYSVOL.
    - Creates a reusable module ZIP package in the current user's Documents directory.
    - Imports and links the Tier Level Isolation Group Policy Object (GPO).
    - Optionally enables Kerberos claims and armoring through Group Policy.

    Every execution creates a uniquely named transcript in the Windows temporary directory.
    The transcript contains installation metadata, prompts, console output, verbose cmdlet
    output, warnings, errors, completion status, and duration.

.PARAMETER InstallPSModuleOnly
    Installs or updates only the TierLevelIsolation PowerShell module under the system-wide
    Windows PowerShell module directory and creates its reusable ZIP package. No Active Directory
    isolation objects are created.

.PARAMETER AdvancedSetupMode
    Displays additional configuration prompts for Protected Users membership and the debug-log
    directory used by the scheduled management scripts. This does not change the location of the
    installation transcript.

.PARAMETER InstallationParameters
    A PowerShell object that supplies every installation choice without interactive prompts. The
    object can contain InstallPSModuleOnly, AdvancedSetupMode, ContinueWithoutEnterpriseAdmin,
    Domains, Scope, Tier0, Tier1, ProtectedUsers, LogPath, PrivilegedGroupsCleanUp, GMSAName, and
    EnableClaimSupport. Tier0 and Tier1 are nested objects containing UserPaths,
    ServiceAccountPaths, ComputerPaths, KerberosAuthenticationPolicyName, and ComputerGroupName.
    Missing properties use values from an existing configuration or the documented defaults.

.INPUTS
    Prompts the user to select one or more forest domains.

    Displays a numbered domain list and accepts one or more comma-separated indices. Existing
    configured domains are preselected; when no defaults are supplied, pressing Enter selects all.

    DNS names available for selection.
    .\install.ps1
    DNS names selected when the user presses Enter without entering a value.
    Runs the interactive installation with standard setup options.
    System.String[]. The selected domain DNS names.
.EXAMPLE
    .\install.ps1 -AdvancedSetupMode


    Displays all forest domains and returns the user's selection.
.EXAMPLE
    .\install.ps1 -InstallPSModuleOnly

    Installs or updates only the TierLevelIsolation PowerShell module.

.EXAMPLE
    $Parameters = [pscustomobject]@{
        AdvancedSetupMode = $true
        ContinueWithoutEnterpriseAdmin = $false
        Domains = @("contoso.com")
        Scope = "All-Tiers"
        Tier0 = [pscustomobject]@{
            UserPaths = @("OU=Admins,OU=Tier 0,OU=Admin")
            ServiceAccountPaths = @("OU=Service Accounts,OU=Tier 0,OU=Admin")
            ComputerPaths = @("OU=Server,OU=Tier 0,OU=Admin")
            KerberosAuthenticationPolicyName = "Tier 0 restriction"
            ComputerGroupName = "Tier 0 computer"
        }
        Tier1 = [pscustomobject]@{
            UserPaths = @("OU=Admins,OU=Tier 1,OU=Admin")
            ServiceAccountPaths = @("OU=Service Accounts,OU=Tier 1,OU=Admin")
            ComputerPaths = @("OU=Server,OU=Tier 1,OU=Admin")
            KerberosAuthenticationPolicyName = "Tier 1 restriction"
            ComputerGroupName = "Tier 1 server"
        }
        ProtectedUsers = "All-Tiers"
        LogPath = "C:\Logs\TierLevelIsolation"
        PrivilegedGroupsCleanUp = $true
        GMSAName = "TierLevel-mgmt"
        EnableClaimSupport = $true
    }
    .\install.ps1 -InstallationParameters $Parameters

    Performs a complete non-interactive installation using a nested PowerShell object.

.NOTES
    Requirements:
    - Windows PowerShell with the ActiveDirectory and GroupPolicy modules.
    - Appropriate Active Directory, SYSVOL, authentication-policy, and GPO permissions.
    - Enterprise Admin membership is recommended and required for some forest-wide operations.

    Important: This script changes security-sensitive Active Directory and Group Policy settings.
    Test the installation in a non-production forest and maintain a tested break-glass process.

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
    Version 0.2.20250625
        [Stephen Shkardoon]
        Added GMSA validation. The script will not accept GMSA names longer than 15 characters.
    Version 0.2.20250714
        Fixing an error if only Tier 0 is implemented
    Version 0.2.20250923
        [Kili69]
        The administration can decide to enable Kerberos claim support manually. The script will display a warning message
    Version 0.2.20251014
        [Kili69]
        Updated links to Microsoft Docs
        Please refer to https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-policy-and-claims
        and https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-armoring-for-privileged-accounts
        for more information about claim support and Kerberos armoring
    Version 0.2.20260120
        [Kili69]
        Fixed a bug in the selection of the Tier-Level
    Version 0.2.20260306
    Version 0.2.20260825.1
        Protected Users configuration is only shown in advanced setup mode
    Version 0.2.20260825.2
        Added debug log path configuration to advanced setup mode
    Version 0.2.20260825.3
        Display the current domain during OU validation
        Use values from an existing configuration as setup defaults
    Version 0.2.20260828.1
        Added a detailed installation transcript with a unique file name to the temporary directory
    Version 0.2.20260828.2
        Added complete comment-based help and detailed inline documentation
    Version 0.2.20260828.3
        Added a reusable PowerShell module ZIP package to the Documents directory
    Version 0.2.20260828.4
        Added complete non-interactive parameterization through a PowerShell object
        Corrected scope-aware OU processing for all computer, user, and service-account paths
    Version 0.2.20260828.5
        Standardized Tier 0 terminology as Tier 0 computer

#>
param(
    [switch]$InstallPSModuleOnly,
    [switch]$AdvancedSetupMode,
    [Parameter()]
    [ValidateNotNull()]
    [psobject]$InstallationParameters
)
<#
.SYNOPSIS 
    Creates an organizational unit path in a specified domain.
.DESCRIPTION
    Creates every missing OU component from the domain root toward the leaf OU. The function
    accepts a relative OU path or a full distinguished name. A full distinguished name must
    belong to the domain specified by DomainDNS.
.PARAMETER OUPath 
    Relative OU path, such as OU=Server,OU=Tier 0,OU=Admin, or a complete distinguished name.
.PARAMETER DomainDNS
    DNS name of the target Active Directory domain, such as contoso.com.
.EXAMPLE
    New-TierLevelOU -OUPath "OU=Test,OU=Demo" -DomainDNS "contoso.com"

    Creates OU=Demo at the domain root and OU=Test below OU=Demo when either OU is missing.
.OUTPUTS
    System.Boolean. Returns $true when the path exists or was created successfully; otherwise $false.
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
        # Resolve the authoritative domain DN and reject a full DN belonging to another domain.
        $DomainDN = (Get-ADDomain -Server $DomainDNS).DistinguishedName
        if ($OUPath -like "*dc=*"){
            if ($OUPath -notlike "*$domainDN"){
                return $false
            } else {
                $OUPath = [regex]::Match($OUPath, "^(.*?)(?i)(?=,dc=)").Value
            }
        }
        # Normalize separators and strip the domain suffix before processing individual RDNs.
        $OUPath = [regex]::Replace($OUPath, "\s?,\s?", ",")
        if ($OUPath.Contains("DC=")) {
            $OUPath = [regex]::Match($OUPath, "((CN|OU)=[^,]+,)+")
            $OUPath = $OUPath.Substring(0, $OUPath.Length - 1)
        }
        $aryOU = $OUPath.Split(",")
        $BuildOUPath = ""
        # Walk from the highest parent OU to the requested leaf and create missing components.
        For ($i = $aryOU.Count; $i -ne 0; $i--) {
            # New-ADOrganizationalUnit expects the OU name without the OU= prefix.
            $OUName = $aryOU[$i - 1].Replace("OU=", "")
            # The first component is searched at the domain root. Later components use their
            # already validated parent path as SearchBase.
            if ($i -eq $aryOU.Count) {
                if ([bool]!(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchScope OneLevel -server $DomainDNS)) {
                    Write-Host "$OUName doesn't exist in $OUPath. Creating OU" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Server $DomainDNS                        
                }
            }
            else {
                if ([bool]!(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -SearchBase "$BuildOUPath$DomainDN" -Server $DomainDNS)) {
                    Write-Host "$OUPath,$DomainDN doesn't exist. Creating" -ForegroundColor Green
                    New-ADOrganizationalUnit -Name $OUName -Path "$BuildOUPath$DomainDN" -Server $DomainDNS
                }
            }
            # Extend the parent path for the next, more specific OU component.
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
    Creates the group managed service account when it does not exist.
.DESCRIPTION
    Ensures that a KDS root key exists, resolves the principals that may retrieve the managed
    password, and creates the requested gMSA with AES-256 Kerberos encryption. Existing accounts
    are left unchanged.
.PARAMETER GMSAName
    Name of the gMSA. The caller must ensure that the resulting sAMAccountName is no longer than
    15 characters.
.PARAMETER AllowTOLogon
    Semicolon-separated computer names permitted to retrieve the managed password. When omitted,
    the domain controllers are used.
.PARAMETER Description
    Description stored on the new Active Directory service account object.
.EXAMPLE
    New-GMSA -GMSAName "TierLevel-mgmt" -Description "Tier management account"

    Creates the service account when missing and permits domain controllers to retrieve its
    managed password.
.OUTPUTS
    System.Boolean. Returns $true when the gMSA exists or is created successfully; otherwise $false.
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
        # A KDS root key is mandatory for generating gMSA passwords.
        if (![bool](Get-KdsRootKey)) {
            Write-Host "KDS Rootkey is missing." -ForegroundColor Red
            Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
        }
        # Keep existing service accounts unchanged so reruns remain idempotent.
        if ([bool](Get-ADServiceAccount -Filter "Name -eq '$GMSAName'")) {
            return $true
        }
        # Build the principals allowed to retrieve the managed password. If no explicit computer
        # list is available, authorize all domain controllers.
        $aryAllowToLogon = @()
        if ($aryAllowToLogon -ne "") {
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
        # Require AES-256 Kerberos encryption for the newly created account.
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
    Tests whether the current identity is an Enterprise Admin.
.DESCRIPTION
    Examines the current Windows access token for a group SID ending in RID 519, the well-known
    Enterprise Admins RID in the forest root domain.
.OUTPUTS
    System.Boolean. Returns $true when the current token contains Enterprise Admins; otherwise $false.
.EXAMPLE
    IsMemberOfEnterpriseAdmins

    Returns the Enterprise Admin membership state of the current Windows identity.
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
.PARAMETER DefaultDomains
    Domains selected by default when the user does not provide any input.
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
        [string[]]$Domains,
        [Parameter (Mandatory = $false, Position = 1)]
        [string[]]$DefaultDomains = @()
    )
    $DefaultDomainIndices = @(
        for ($i = 0; $i -lt $Domains.Count; $i++) {
            if ($DefaultDomains -contains $Domains[$i]) {
                $i
            }
        }
    )
    $DefaultSelection = if ($DefaultDomainIndices.Count -gt 0) { $DefaultDomainIndices -join "," } else { $Domains.Count }
    # Continue prompting until at least one valid domain index has been selected.
    do {
        # The index after the final domain represents the convenient "all domains" option.
        For ($i = 0; $i -lt $Domains.count; $i++){
            Write-Host "[$i] $($Domains[$i])"
        }
        Write-Host "[$($i)] all domains"
        $strReadIndex  = Read-Host "Select domains (you can select multiple domain separated by ',' [$DefaultSelection])"
        if ($strReadIndex -eq '') {
            $strReadIndex = $DefaultSelection
        }
        $SelectedDomains = @()
        try {           
            foreach ($DomainIndex in $strReadIndex -split ","){
                # Integer conversion rejects nonnumeric input and routes it to the validation catch.
                $DomainIndex = [int]$DomainIndex.Trim()
                if ($DomainIndex -eq  $Domains.count){
                    return $Domains
                } else {
                    if ($DomainIndex -ge 0 -and $DomainIndex -le $Domains.Count){
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

<#
.SYNOPSIS
    Reads an optional property from an installation parameter object.
.DESCRIPTION
    Returns the named property value when present. Otherwise, it returns the supplied default.
    Unlike truthiness-based checks, this helper preserves valid values such as $false, zero, and
    an empty string.
.PARAMETER InputObject
    Object that may contain the requested property.
.PARAMETER Name
    Case-insensitive property name to read.
.PARAMETER DefaultValue
    Value returned when the input object or property is absent.
.OUTPUTS
    System.Object. The configured property value or its default.
#>
function Get-InstallationParameterValue {
    param(
        [AllowNull()]
        [psobject]$InputObject,
        [Parameter(Mandatory)]
        [string]$Name,
        [AllowNull()]
        [object]$DefaultValue
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $Property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        return $DefaultValue
    }

    return $Property.Value
}

#####################################################################################################################################################################################
#region Installation logging, constants, and default values
#####################################################################################################################################################################################
$ScriptVersion = "0.2.20260828.5"
$ObjectParameterMode = $PSBoundParameters.ContainsKey("InstallationParameters")
if ($ObjectParameterMode) {
    $InstallPSModuleOnly = [bool](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "InstallPSModuleOnly" -DefaultValue ([bool]$InstallPSModuleOnly))
    $AdvancedSetupMode = [bool](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "AdvancedSetupMode" -DefaultValue ([bool]$AdvancedSetupMode))
}

# Create a collision-resistant transcript name. Milliseconds, process ID, and a GUID allow
# concurrent executions on the same computer without overwriting another installation log.
$InstallationStartTime = Get-Date
$InstallationStatus = "Incomplete"
$PreviousVerbosePreference = $VerbosePreference
$LogTimestamp = $InstallationStartTime.ToString("yyyyMMdd-HHmmssfff")
$LogIdentifier = [guid]::NewGuid().ToString("N")
$LogFileName = "TierLevelIsolation-Installation-$LogTimestamp-$env:COMPUTERNAME-PID$PID-$LogIdentifier.log"
$InstallationLogFile = Join-Path ([System.IO.Path]::GetTempPath()) $LogFileName
$TranscriptStarted = $false

# The installation is intentionally aborted when no transcript can be created. This guarantees
# that every security-sensitive change made by this script has a corresponding audit trail.
try {
    Start-Transcript -Path $InstallationLogFile -IncludeInvocationHeader -Force -ErrorAction Stop | Out-Null
    $TranscriptStarted = $true
}
catch {
    throw "The installation log could not be created at '$InstallationLogFile'. Installation aborted. $($_.Exception.Message)"
}

# The outer try/finally guarantees that the transcript is finalized even when an inner block uses
# return or exit. Verbose output is enabled for the duration of the installation to improve detail.
try {
    $VerbosePreference = "Continue"
    Write-Host "Installation log: $InstallationLogFile" -ForegroundColor Cyan
    Write-Host "Installation started: $($InstallationStartTime.ToString('yyyy-MM-dd HH:mm:ss.fff K'))" -ForegroundColor Cyan
    Write-Host "Script version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "Script path: $PSCommandPath" -ForegroundColor Cyan
    Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Cyan
    Write-Host "Process ID: $PID" -ForegroundColor Cyan
    Write-Host "PowerShell version: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor Cyan
    Write-Host "Operating system: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Cyan
    Write-Host "Parameters: InstallPSModuleOnly=$InstallPSModuleOnly; AdvancedSetupMode=$AdvancedSetupMode; ObjectParameterMode=$ObjectParameterMode" -ForegroundColor Cyan
    if ($ObjectParameterMode) {
        Write-Host "Installation parameter object:" -ForegroundColor Cyan
        Write-Host ($InstallationParameters | ConvertTo-Json -Depth 5)
    }
    Write-Host "Loading required Active Directory and Group Policy modules" -ForegroundColor Cyan
try{
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy  -ErrorAction Stop
} 
catch {
    Write-Host "Failed to load the required Powerhsell module" -ForegroundColor Red
    Write-Host "validate the Active Directory and Group Policy Powershell modules are installed" -ForegroundColor Red
    exit
}
# The current domain hosts the tier server groups. Changes are sent to the nearest domain
# controller so that group creation remains site-aware.
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
$CurrentDC        = (Get-ADDomainController -Discover -NextClosestSite ).HostName.Value

# Descriptions assigned to Active Directory objects created by this installer.
$DescriptionT0ComputerGroup = "This group contains all Tier 0 member computer. This group will be used for the Kerberos Authentication Policy claim"
$DescriptionT1ComputerGroup = "This group contains any Tier 1 member computer. This group will be used for the Kerberos Authentication Policy claim"
$DescriptionGMSA = "This Group Managed service account is used to manage user accounts and groups impacted by the Tier Level Model"
$DescriptionTier0CKerberosAuthenticationPolicy = "This policy aims to isolate Tier 0 systems to ensure the security and integrity of critical IT infrastructures. Users assigned this policy can only log in to computers that are members of the 'Enterprise Domain Controller' group or the 'Tier 0 computer' group. This ensures that only authorized users have access to the most sensitive systems within the organization."
$DescriptionTier1CKerberosAuthenticationPolicy = "This policy aims to isolate Tier 1 systems to ensure the security and integrity of IT infrastructures. Users assigned this policy can only log in to computers that are members of the 'Tier 1 Server' group or 'Enterprise Domain Controller' group or the 'Tier 0 computer' group. This ensures that only authorized users have access to the most sensitive systems within the organization."

# Defaults offered during interactive parameter collection. Existing configuration values take
# precedence, allowing the script to be rerun without requiring every value to be entered again.
$DefaultT0KerbAuthPolName = "Tier 0 restriction"
$DefaultT1KerbAuthPolName = "Tier 1 restriction"
$DefaultT0Users = "OU=Admins,OU=Tier 0,OU=Admin"
$DefaultT1Users = "OU=Admins,OU=Tier 1,OU=Admin"
$DefaultT0Computers          =           "OU=Server,OU=Tier 0,OU=Admin"
$DefaultT0ServiceAccountPath = "OU=Service Accounts,OU=Tier 0,OU=Admin"
$DefaultT1ServiceAccountPath = "OU=Service Accounts,OU=Tier 1,OU=Admin"
$DefaultT1Computers          =           "OU=Server,OU=Tier 1,OU=Admin"
# Default sAMAccountName values for the tier server claim groups.
$DefaultT0ComputerGroupName = "Tier 0 computer"
$DefaultT1ComputerGroupName = "Tier 1 server"
# Ticket-granting ticket lifetime applied to newly created authentication policies, in minutes.
$DefaultTGTLifeTime = 240
$DefaultGMSAName = "TierLevel-mgmt"

# Forest-wide deployment locations. Scripts and configuration are placed in SYSVOL so every
# domain controller and scheduled task can access a consistent copy.
$ScriptTarget              = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts"
$ModuleTarget              = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\PSModules\TierLevelIsolation"
$ConfigFile                = "$ScriptTarget\TierLevelIsolation.config"

# Identity and parsing constants used while importing the bundled GPO and validating full DNs.
$GPOName = "Tier Level Isolation"
$GPOBackupID = "68e9eff4-48c4-420d-a229-f1acd8c75c6b"
$RegExDNDomain = "(?i)(DC=[^,]+,)*DC=.+$"
# Well-known GPO identifiers present in every Active Directory domain.
$DefaultDomainControllerPolicy = "6AC1786C-016F-11D2-945F-00C04FB984F9"
$DefaultDomainPolicy = "31B2F340-016D-11D2-945F-00C04FB984F9"

# Registry policy settings required for Kerberos claims, compound authentication, and armoring.
# The KDC setting is written to the Default Domain Controllers Policy; the client setting is
# written to both the Default Domain Controllers Policy and the Default Domain Policy.
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

#endregion

#########################################################################################################
# Main program
#########################################################################################################

# Display the execution mode after prerequisite modules and installation logging are initialized.
Write-Host "Welcome to the Tier Level isolation setup script" -ForegroundColor Green
Write-Host "This script will prepare you active directory to protect Administrators with Kerberos Authentication Policies" -ForegroundColor Green 
Write-Host "Tier 0 / Tier 1 isolation setup script ($ScriptVersion)" -ForegroundColor Green

#region install TierLevelIsolation module
# Compare the bundled module manifest with the machine-wide installation. The module is copied only
# when it is missing or older. A portable ZIP is always refreshed in the current user's Documents
# directory so that the same module version can be installed on additional computers.
try{
    $ModulePath = Join-Path $Env:ProgramFiles\WindowsPowerShell\Modules "TierLevelIsolation"
    $SourceModuleManifest = Join-Path $PSScriptRoot "module\TierLevelIsolation.psd1"
    $TargetModuleManifest = Join-Path $ModulePath "TierLevelIsolation.psd1"
    $SourceModuleVersion = [version](Import-PowerShellDataFile $SourceModuleManifest).ModuleVersion
    $InstalledModuleVersion = if (Test-Path $TargetModuleManifest) {
        [version](Import-PowerShellDataFile $TargetModuleManifest).ModuleVersion
    } else {
        [version]'0.0'
    }
    if ($InstalledModuleVersion -lt $SourceModuleVersion) {
        Write-Host "Installing TierLevelIsolation module version $SourceModuleVersion" -ForegroundColor Green
        New-Item -Path $ModulePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Copy-Item -Path "$PSScriptRoot\module\*" -Destination $ModulePath -Force -Recurse -ErrorAction Stop
        Write-Host "The TierLevelIsolation module is installed or updated" -ForegroundColor Green
    } else {
        Write-Host "TierLevelIsolation module version $InstalledModuleVersion is already installed" -ForegroundColor Green
    }

    $DocumentsPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
    if ([string]::IsNullOrWhiteSpace($DocumentsPath) -or !(Test-Path -LiteralPath $DocumentsPath -PathType Container)) {
        throw "The Documents directory for the current user could not be found."
    }
    $ModuleArchivePath = Join-Path $DocumentsPath "TierLevelIsolation.zip"
    Compress-Archive -Path "$PSScriptRoot\module\*" -DestinationPath $ModuleArchivePath -CompressionLevel Optimal -Force -ErrorAction Stop
    Write-Host "The reusable PowerShell module package was created at $ModuleArchivePath" -ForegroundColor Cyan
    Write-Host "To use the module on another computer, copy the ZIP file there and extract its contents into a TierLevelIsolation folder under a PowerShell module path." -ForegroundColor Yellow

    if ($InstallPSModuleOnly){
        $InstallationStatus = "Completed"
        exit
    }
    Write-Host "Loading the TierLevelIsolation module" -ForegroundColor Green
    Import-Module $TargetModuleManifest -Force -ErrorAction Stop
} catch {
    Write-Host "Failed to install the TierLevelIsolation module" -ForegroundColor Red
    Write-Host $Error[0].Exception.Message -ForegroundColor Red
    exit
}
#endregion
#region Parameter collection
# Reuse the persisted configuration as the default for reruns. Configuration changes made by the
# module commands below are written to the shared configuration file in SYSVOL.
$ExistingInstallation = Test-Path -LiteralPath $ConfigFile -PathType Leaf
$ExistingConfiguration = Get-TierLevelIsolationConfiguration
if ($ExistingInstallation) {
    Write-Host "Existing Tier Level Isolation configuration found. Previous values are used as defaults." -ForegroundColor Green
}

# Some forest-wide operations require Enterprise Admin rights. The user may continue to inspect or
# perform operations permitted by delegated rights, but later changes can still fail individually.
if (!(IsMemberOfEnterpriseAdmins)){
    Write-Host "Enterprise Administrator privileges required to access to configuration partition" -ForegroundColor Yellow
    $ContinueWithoutEnterpriseAdmin = if ($ObjectParameterMode) {
        [bool](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "ContinueWithoutEnterpriseAdmin" -DefaultValue $false)
    } else {
        $strReadHost = Read-Host "Do you want to continue without Enterprise Administrator privileges y/[n]"
        $strReadHost -like "y*"
    }
    if (!$ContinueWithoutEnterpriseAdmin){
        Write-Host "aborting" -ForegroundColor Yellow
        return
    }
}
# Select the domains whose OU paths and Group Policy settings will be managed.
$ForestDomains = @((Get-ADForest).Domains)
if ($ObjectParameterMode) {
    $DefaultDomains = if ($ExistingConfiguration.Domains.Count -gt 0) { @($ExistingConfiguration.Domains) } else { $ForestDomains }
    $Domains = @(Get-InstallationParameterValue -InputObject $InstallationParameters -Name "Domains" -DefaultValue $DefaultDomains)
    if ($Domains.Count -eq 0) {
        throw "InstallationParameters.Domains must contain at least one domain."
    }
    $UnknownDomains = @($Domains | Where-Object { $ForestDomains -notcontains $_ })
    if ($UnknownDomains.Count -gt 0) {
        throw "InstallationParameters.Domains contains domains that are not in the current forest: $($UnknownDomains -join ', ')"
    }
} else {
    $Domains = Get-SelectedDomains -Domains $ForestDomains -DefaultDomains $ExistingConfiguration.Domains
}
$Domains  | Add-TierLevelIsolationDomain 


# Select the deployment scope. Tier0 and Tier1 are internal command values; All-Tiers enables both.
Write-Host "Scope-Level:"
Write-Host "[0] Tier-0"
Write-Host "[1] Tier-1"
Write-Host "[2] Tier 0 and Tier 1"
$DefaultScopeSelection = switch ($ExistingConfiguration.scope) {
    "Tier-0" { "0" }
    "Tier-1" { "1" }
    Default { "2" }
}
if ($ObjectParameterMode) {
    $DefaultScope = switch ($DefaultScopeSelection) {
        "0" { "Tier0" }
        "1" { "Tier1" }
        Default { "All-Tiers" }
    }
    $ConfiguredScope = [string](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "Scope" -DefaultValue $DefaultScope)
    $scope = switch ($ConfiguredScope) {
        { $_ -in @("Tier0", "Tier-0") } { "Tier0"; break }
        { $_ -in @("Tier1", "Tier-1") } { "Tier1"; break }
        "All-Tiers" { "All-Tiers"; break }
        Default { throw "InstallationParameters.Scope must be Tier0, Tier1, or All-Tiers." }
    }
} else {
    do{
        $strReadHost = Read-Host "Select which scope should be enabled ($DefaultScopeSelection)"
        if ($strReadHost -eq '') {
            $strReadHost = $DefaultScopeSelection
        }
        switch ($strReadHost) {
            "0" { $scope = "Tier0"; break }
            "1" { $scope = "Tier1"; break }
            "2" { $scope = "All-Tiers"; break }
            Default {
                $scope = ""
                Write-Host "Invalid selection. Please select 0, 1 or 2." -ForegroundColor Red
                break
            }
        }
    } while ($scope -eq '')
}
Set-TierLevelIsolationScope $scope

# Collect OU paths and authentication-policy names for each enabled tier. A path can be relative
# to each selected domain or a complete distinguished name that applies only to its matching domain.
if (($scope -eq "Tier0") -or ( $scope -eq "All-Tiers") ){
    Write-Host "Tier 0 isolation parameter "
    $Tier0UsersDefault = if ($ExistingConfiguration.Tier0UsersPath.Count -gt 0) { $ExistingConfiguration.Tier0UsersPath -join "; " } else { $DefaultT0Users }
    if ($ObjectParameterMode) {
        $Tier0Parameters = Get-InstallationParameterValue -InputObject $InstallationParameters -Name "Tier0" -DefaultValue $null
        $Tier0UserPathDefaults = if ($ExistingConfiguration.Tier0UsersPath.Count -gt 0) { @($ExistingConfiguration.Tier0UsersPath) } else { @($DefaultT0Users) }
        $Tier0ServiceAccountPathDefaults = if ($ExistingConfiguration.Tier0ServiceAccountPath.Count -gt 0) { @($ExistingConfiguration.Tier0ServiceAccountPath) } else { @($DefaultT0ServiceAccountPath) }
        $Tier0ComputerPathDefaults = if ($ExistingConfiguration.Tier0ComputerPath.Count -gt 0) { @($ExistingConfiguration.Tier0ComputerPath) } else { @($DefaultT0Computers) }
        foreach ($Path in @(Get-InstallationParameterValue -InputObject $Tier0Parameters -Name "UserPaths" -DefaultValue $Tier0UserPathDefaults)) {
            Add-TierLevelIsolationUserPath Tier0 $Path
        }
        foreach ($Path in @(Get-InstallationParameterValue -InputObject $Tier0Parameters -Name "ServiceAccountPaths" -DefaultValue $Tier0ServiceAccountPathDefaults)) {
            Add-TierLevelIsolationServiceAccountPath Tier0 $Path
        }
        foreach ($Path in @(Get-InstallationParameterValue -InputObject $Tier0Parameters -Name "ComputerPaths" -DefaultValue $Tier0ComputerPathDefaults)) {
            Add-TierLevelIsolationComputerPath Tier0 $Path
        }
        $Tier0KerberosPolicyDefault = if ($ExistingConfiguration.T0KerbAuthPolName) { $ExistingConfiguration.T0KerbAuthPolName } else { $DefaultT0KerbAuthPolName }
        $Tier0KerberosPolicyName = [string](Get-InstallationParameterValue -InputObject $Tier0Parameters -Name "KerberosAuthenticationPolicyName" -DefaultValue $Tier0KerberosPolicyDefault)
        if ([string]::IsNullOrWhiteSpace($Tier0KerberosPolicyName)) {
            throw "InstallationParameters.Tier0.KerberosAuthenticationPolicyName cannot be empty."
        }
        Set-TierLevelIsolationKerberosAuthenticationPolicy Tier0 $Tier0KerberosPolicyName -Force
    } else {
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 Admin OU ($Tier0UsersDefault)"
        if ($strReadHost -ne '') {
            Add-TierLevelIsolationUserPath Tier0 $strReadHost
        } elseif ($ExistingConfiguration.Tier0UsersPath.Count -eq 0) {
            Add-TierLevelIsolationUserPath Tier0 $DefaultT0Users
        }
        $strReadHost = Read-Host "Do you want to add another Tier 0 Admin OU (y/[n])"
    } while ($strReadHost -like "y*")
    $Tier0ServiceAccountPathDefault = if ($ExistingConfiguration.Tier0ServiceAccountPath.Count -gt 0) { $ExistingConfiguration.Tier0ServiceAccountPath -join "; " } else { $DefaultT0ServiceAccountPath }
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 service account OU ($Tier0ServiceAccountPathDefault)"
        if ($strReadHost -ne '') {
            Add-TierLevelIsolationServiceAccountPath Tier0 $strReadHost
        } elseif ($ExistingConfiguration.Tier0ServiceAccountPath.Count -eq 0) {
            Add-TierLevelIsolationServiceAccountPath Tier0 $DefaultT0ServiceAccountPath
        }
        $strReadHost = Read-Host "Do you want to add another Tier 0 service account OU (y/[n])"
    } while ($strReadHost -like "y*")
    $Tier0ComputersDefault = if ($ExistingConfiguration.Tier0ComputerPath.Count -gt 0) { $ExistingConfiguration.Tier0ComputerPath -join "; " } else { $DefaultT0Computers }
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 0 computer OU ($Tier0ComputersDefault)"
        if ($strReadHost -ne '') {
            Add-TierLevelIsolationComputerPath Tier0 $strReadHost
        } elseif ($ExistingConfiguration.Tier0ComputerPath.Count -eq 0) {
            Add-TierLevelIsolationComputerPath Tier0 $DefaultT0Computers
        }
        $strReadHost = Read-Host "Do you want to add another Tier 0 computer OU (y/[n])"
    }while ($strReadHost -like "y*")
    $Tier0KerberosPolicyDefault = if ($ExistingConfiguration.T0KerbAuthPolName) { $ExistingConfiguration.T0KerbAuthPolName } else { $DefaultT0KerbAuthPolName }
    $strReadHost = Read-Host "Provide the Tier 0 Kerberos Authentication policy name ($Tier0KerberosPolicyDefault)"
    if ($strReadHost -eq ''){$strReadHost = $Tier0KerberosPolicyDefault}
    Set-TierLevelIsolationKerberosAuthenticationPolicy Tier0 $strReadHost -Force
    }
}
if ($scope -eq "Tier1" -or $scope -eq "All-Tiers"){
    Write-Host "Tier 1 isolation parameter "
    $Tier1UsersDefault = if ($ExistingConfiguration.Tier1UsersPath.Count -gt 0) { $ExistingConfiguration.Tier1UsersPath -join "; " } else { $DefaultT1Users }
    if ($ObjectParameterMode) {
        $Tier1Parameters = Get-InstallationParameterValue -InputObject $InstallationParameters -Name "Tier1" -DefaultValue $null
        $Tier1UserPathDefaults = if ($ExistingConfiguration.Tier1UsersPath.Count -gt 0) { @($ExistingConfiguration.Tier1UsersPath) } else { @($DefaultT1Users) }
        $Tier1ServiceAccountPathDefaults = if ($ExistingConfiguration.Tier1ServiceAccountPath.Count -gt 0) { @($ExistingConfiguration.Tier1ServiceAccountPath) } else { @($DefaultT1ServiceAccountPath) }
        $Tier1ComputerPathDefaults = if ($ExistingConfiguration.Tier1ComputerPath.Count -gt 0) { @($ExistingConfiguration.Tier1ComputerPath) } else { @($DefaultT1Computers) }
        foreach ($Path in @(Get-InstallationParameterValue -InputObject $Tier1Parameters -Name "UserPaths" -DefaultValue $Tier1UserPathDefaults)) {
            Add-TierLevelIsolationUserPath Tier1 $Path
        }
        foreach ($Path in @(Get-InstallationParameterValue -InputObject $Tier1Parameters -Name "ServiceAccountPaths" -DefaultValue $Tier1ServiceAccountPathDefaults)) {
            Add-TierLevelIsolationServiceAccountPath Tier1 $Path
        }
        foreach ($Path in @(Get-InstallationParameterValue -InputObject $Tier1Parameters -Name "ComputerPaths" -DefaultValue $Tier1ComputerPathDefaults)) {
            Add-TierLevelIsolationComputerPath Tier1 $Path
        }
        $Tier1KerberosPolicyDefault = if ($ExistingConfiguration.T1KerbAuthPolName) { $ExistingConfiguration.T1KerbAuthPolName } else { $DefaultT1KerbAuthPolName }
        $Tier1KerberosPolicyName = [string](Get-InstallationParameterValue -InputObject $Tier1Parameters -Name "KerberosAuthenticationPolicyName" -DefaultValue $Tier1KerberosPolicyDefault)
        if ([string]::IsNullOrWhiteSpace($Tier1KerberosPolicyName)) {
            throw "InstallationParameters.Tier1.KerberosAuthenticationPolicyName cannot be empty."
        }
        Set-TierLevelIsolationKerberosAuthenticationPolicy Tier1 $Tier1KerberosPolicyName -Force
    } else {
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 Admin OU ($Tier1UsersDefault)"
        if ($strReadHost -ne '') {
            Add-TierLevelIsolationUserPath Tier1 $strReadHost
        } elseif ($ExistingConfiguration.Tier1UsersPath.Count -eq 0) {
            Add-TierLevelIsolationUserPath Tier1 $DefaultT1Users
        }
        $strReadHost = Read-Host "Do you want to add another Tier 1 Admin OU (y/[n])"
    } while ($strReadHost -like "y*")
    $Tier1ServiceAccountPathDefault = if ($ExistingConfiguration.Tier1ServiceAccountPath.Count -gt 0) { $ExistingConfiguration.Tier1ServiceAccountPath -join "; " } else { $DefaultT1ServiceAccountPath }
    do{
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 service account OU ($Tier1ServiceAccountPathDefault)"
        if ($strReadHost -ne '') {
            Add-TierLevelIsolationServiceAccountPath Tier1 $strReadHost
        } elseif ($ExistingConfiguration.Tier1ServiceAccountPath.Count -eq 0) {
            Add-TierLevelIsolationServiceAccountPath Tier1 $DefaultT1ServiceAccountPath
        }
        $strReadHost = Read-Host "Do you want to add another Tier 1 service account OU (y/[n])"
    } while ($strReadHost -like "y*")
    $Tier1ComputersDefault = if ($ExistingConfiguration.Tier1ComputerPath.Count -gt 0) { $ExistingConfiguration.Tier1ComputerPath -join "; " } else { $DefaultT1Computers }
    do {
        $strReadHost = Read-Host "Distinguishedname of the Tier 1 server OU ($Tier1ComputersDefault)"
        if ($strReadHost -ne '') {
            Add-TierLevelIsolationComputerPath Tier1 $strReadHost
        } elseif ($ExistingConfiguration.Tier1ComputerPath.Count -eq 0) {
            Add-TierLevelIsolationComputerPath Tier1 $DefaultT1Computers
        }
        $strReadHost = Read-Host "Do you want to add another Tier 1 server OU (y/[n])"
    }while ($strReadHost -like "y*")
    $Tier1KerberosPolicyDefault = if ($ExistingConfiguration.T1KerbAuthPolName) { $ExistingConfiguration.T1KerbAuthPolName } else { $DefaultT1KerbAuthPolName }
    $strReadHost = Read-Host "Provide the Tier 1 Kerberos Authentication policy name ($Tier1KerberosPolicyDefault)"
    if ($strReadHost -eq ''){$strReadHost = $Tier1KerberosPolicyDefault}
    Set-TierLevelIsolationKerberosAuthenticationPolicy Tier1 $strReadHost -force
    }
}
if ($scope -eq "Tier0" -or $scope -eq "All-Tiers"){
    Write-Host "Tier 0 computer group parameter "
    $Tier0ComputerGroupDefault = if ($ExistingConfiguration.Tier0ComputerGroup) { $ExistingConfiguration.Tier0ComputerGroup } else { $DefaultT0ComputerGroupName }
    if ($ObjectParameterMode) {
        $Tier0Parameters = Get-InstallationParameterValue -InputObject $InstallationParameters -Name "Tier0" -DefaultValue $null
        $Tier0ComputerGroupName = [string](Get-InstallationParameterValue -InputObject $Tier0Parameters -Name "ComputerGroupName" -DefaultValue $Tier0ComputerGroupDefault)
        if ([string]::IsNullOrWhiteSpace($Tier0ComputerGroupName)) {
            throw "InstallationParameters.Tier0.ComputerGroupName cannot be empty."
        }
    } else {
        $Tier0ComputerGroupName = Read-Host "Provide the Tier 0 computer samaccount group name ($Tier0ComputerGroupDefault)"
        if ($Tier0ComputerGroupName -eq ''){$Tier0ComputerGroupName = $Tier0ComputerGroupDefault}
    }
    Set-TierLevelIsolationComputerGroup Tier0 $Tier0ComputerGroupName -Force
}
if (($scope -eq "Tier1") -or ( $scope -eq "All-Tiers")){
    Write-Host "Tier 1 isolation parameter "
    $Tier1ComputerGroupDefault = if ($ExistingConfiguration.Tier1ComputerGroup) { $ExistingConfiguration.Tier1ComputerGroup } else { $DefaultT1ComputerGroupName }
    if ($ObjectParameterMode) {
        $Tier1Parameters = Get-InstallationParameterValue -InputObject $InstallationParameters -Name "Tier1" -DefaultValue $null
        $Tier1ComputerGroupName = [string](Get-InstallationParameterValue -InputObject $Tier1Parameters -Name "ComputerGroupName" -DefaultValue $Tier1ComputerGroupDefault)
        if ([string]::IsNullOrWhiteSpace($Tier1ComputerGroupName)) {
            throw "InstallationParameters.Tier1.ComputerGroupName cannot be empty."
        }
    } else {
        $Tier1ComputerGroupName = Read-Host "Provide the Tier 1 server samaccount group name ($Tier1ComputerGroupDefault)"
        if ($Tier1ComputerGroupName -eq ''){$Tier1ComputerGroupName = $Tier1ComputerGroupDefault}
    }
    Set-TierLevelIsolationComputerGroup Tier1 $Tier1ComputerGroupName -Force
}
# Advanced settings control ongoing account management by the scheduled scripts. LogPath belongs
# to those runtime scripts; it is independent from this installer's transcript in the temp folder.
if ($AdvancedSetupMode) {
    Write-Host "Do you want to manage protected users group with tiering?"
    Write-Host "[0] Tier-0 users will be added to protected users"
    Write-Host "[1] Tier-1 users will be added to protected users"
    Write-Host "[2] Tier-0 and Tier-1 users will be added to protected users"
    Write-Host "[3] Protected users will not be managed with Tiering"
    $DefaultProtectedUsersSelection = if (($ExistingConfiguration.ProtectedUsers -contains "Tier-0") -and ($ExistingConfiguration.ProtectedUsers -contains "Tier-1")) {
        "2"
    } elseif ($ExistingConfiguration.ProtectedUsers -contains "Tier-0") {
        "0"
    } elseif ($ExistingConfiguration.ProtectedUsers -contains "Tier-1") {
        "1"
    } else {
        "3"
    }
    if ($ObjectParameterMode) {
        $DefaultProtectedUsers = switch ($DefaultProtectedUsersSelection) {
            "0" { "Tier-0" }
            "1" { "Tier-1" }
            "2" { "All-Tiers" }
            Default { "None" }
        }
        $ProtectedUsersSelection = [string](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "ProtectedUsers" -DefaultValue $DefaultProtectedUsers)
        if ($ProtectedUsersSelection -notin @("Tier-0", "Tier-1", "All-Tiers", "None")) {
            throw "InstallationParameters.ProtectedUsers must be Tier-0, Tier-1, All-Tiers, or None."
        }
        Set-TierLevelProtectedUsersState $ProtectedUsersSelection
    } else {
        $strReadHost = Read-Host "Select protected users level [$DefaultProtectedUsersSelection]"
        if ($strReadHost -eq '') {
            $strReadHost = $DefaultProtectedUsersSelection
        }
        switch ($strReadHost) {
            "0" { Set-TierLevelProtectedUsersState "Tier-0" }
            "1" { Set-TierLevelProtectedUsersState "Tier-1" }
            "2" { Set-TierLevelProtectedUsersState "All-Tiers" }
            Default { Set-TierLevelProtectedUsersState "None" }
        }
    }

    if ($ObjectParameterMode) {
        $LogPathDefault = $ExistingConfiguration.LogPath
        $LogPath = [string](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "LogPath" -DefaultValue $LogPathDefault)
        if (![string]::IsNullOrWhiteSpace($LogPath) -and !(Test-Path -LiteralPath $LogPath -PathType Container)) {
            throw "InstallationParameters.LogPath '$LogPath' does not exist or is not accessible."
        }
    } else {
        do {
            $LogPathDefault = $ExistingConfiguration.LogPath
            $LogPathPrompt = if ([string]::IsNullOrWhiteSpace($LogPathDefault)) { "leave empty to use local AppData" } else { $LogPathDefault }
            $LogPath = Read-Host "Provide the debug log directory ($LogPathPrompt)"
            if ([string]::IsNullOrWhiteSpace($LogPath)) {
                $LogPath = $LogPathDefault
            }
            $LogPathIsValid = [string]::IsNullOrWhiteSpace($LogPath) -or (Test-Path -LiteralPath $LogPath -PathType Container)
            if (-not $LogPathIsValid) {
                Write-Host "The log directory '$LogPath' does not exist or is not accessible." -ForegroundColor Red
            }
        } while (-not $LogPathIsValid)
    }
    Set-DebugLogPath -LogPath $LogPath
}
# Privileged-group cleanup removes tier-managed users from incompatible privileged groups during
# subsequent management runs. Preserve the configured state during upgrades.
$DefaultPrivilegedGroupsCleanUp = if ($ExistingInstallation) { [System.Convert]::ToBoolean($ExistingConfiguration.PrivilegedGroupsCleanUp) } else { $true }
$DefaultPrivilegedGroupsCleanUpSelection = if ($DefaultPrivilegedGroupsCleanUp) { "y" } else { "n" }
if ($ObjectParameterMode) {
    $PrivilegedGroupsCleanUp = [bool](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "PrivilegedGroupsCleanUp" -DefaultValue $DefaultPrivilegedGroupsCleanUp)
} else {
    $strReadHost = Read-Host "Enable privileged Tier 0 group cleanup [Y/N] ($DefaultPrivilegedGroupsCleanUpSelection)"
    if ($strReadHost -eq '') {
        $strReadHost = $DefaultPrivilegedGroupsCleanUpSelection
    }
    $PrivilegedGroupsCleanUp = $strReadHost -notlike "n*"
}
Set-TierLevelPrivilegedGroupsCleanUpState $PrivilegedGroupsCleanUp
    
#endregion

#region OU validation / creation
# Process every configured OU category for every selected domain. Relative paths receive the
# current domain DN. Full DNs are created only when their DC components match the current domain,
# preventing an OU intended for one domain from being created in another domain.
$config = Get-TierLevelIsolationConfiguration
foreach ($domain in $config.Domains){
    Write-Host "Validating organizational units in domain $domain" -ForegroundColor Green
    $DomainDN = (Get-ADDomain -Server $domain).DistinguishedName
    $ConfiguredOUPaths = @()
    if ($scope -eq "Tier0" -or $scope -eq "All-Tiers") {
        $ConfiguredOUPaths += @($config.Tier0ComputerPath)
        $ConfiguredOUPaths += @($config.Tier0UsersPath)
        $ConfiguredOUPaths += @($config.Tier0ServiceAccountPath)
    }
    if ($scope -eq "Tier1" -or $scope -eq "All-Tiers") {
        $ConfiguredOUPaths += @($config.Tier1ComputerPath)
        $ConfiguredOUPaths += @($config.Tier1UsersPath)
        $ConfiguredOUPaths += @($config.Tier1ServiceAccountPath)
    }

    foreach ($OU in @($ConfiguredOUPaths | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($OU)) {
            continue
        }

        # A full DN applies only to its own domain. Relative paths are expanded for every selected domain.
        if ($OU -like "*DC=*") {
            if ([regex]::Match($OU, $RegExDNDomain).Value -ne $DomainDN) {
                continue
            }
            $TargetOUPath = $OU
        } else {
            $TargetOUPath = "$OU,$DomainDN"
        }

        if (!(New-TierLevelOU -OUPath $TargetOUPath -DomainDNS $domain)) {
            Write-Host "Can't create the OU $OU in $domain" -ForegroundColor Red
            Write-Host "script aborted" -ForegroundColor Red
            return
        }
    }
}
#endregion

# Resolve existing server claim groups before attempting creation. Each enabled tier gets a
# universal group whose SID is embedded in the authentication policy's access-control expression.
if ($scope -eq "Tier0" -or $scope -eq "All-Tiers"){
    $Tier0ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier0ComputerGroup)'" 
}
if ($scope -eq "Tier1" -or $scope -eq "All-Tiers"){
    $Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'"    
}

# A newly created universal group might not be immediately visible through a global catalog.
# Retry for up to 100 seconds to tolerate normal inter-DC replication latency.
$GroupWaitCounter = 0
try {
    if (($Null -eq $Tier0ComputerGroup) -and (($scope -eq "Tier0") -or ($scope -eq "All-Tiers"))){
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
    if (($null -eq $Tier1ComputerGroup ) -and (($scope -eq "Tier1") -or ($scope -eq "All-Tiers"))){
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

# Create enforced Kerberos authentication policies when missing. The SDDL conditional ACE uses:
# - SID(ED): the well-known Enterprise Domain Controllers group.
# - Member_of_any with the configured group SID: computers assigned to the permitted tier.
# Tier 0 users may authenticate to enterprise DCs or Tier 0 computers. Tier 1 users additionally
# receive access to Tier 1 servers. Existing policies are deliberately not overwritten.
if (($scope -eq "Tier0") -or ($scope -eq "All-Tiers")){
    try {
        if ([bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.T0KerbAuthPolName)'")){
            Write-Host "Kerberos Authentication Policy $($config.T0KerbAuthPolName) already exists. Please validate the policy manual" -ForegroundColor Yellow
        } else {
            # Conditional access expression for Enterprise DCs and Tier 0 computer-group members.
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
if (($scope -eq "Tier1") -or ($scope -eq "All-Tiers")){
    try {
        if ([bool](Get-ADAuthenticationPolicy -Filter "Name -eq '$($config.T1KerbAuthPolName)'")){
            Write-Host "Kerberos Authentication Policy $($config.T1KerbAuthPolName) already exists. Please validate the policy manual" -ForegroundColor Yellow
        } else {
            # Conditional access expression for Enterprise DCs, Tier 0, and Tier 1 server groups.
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
        Write-Host $($_.Exception.Message) -ForegroundColor Red
        Write-Host $($_.InvocationInfo.ScriptLineNumber) -ForegroundColor Yellow
        Write-Host "script aborted " -ForegroundColor Red
        exit
    }
}
# The scheduled account-management tasks run as this gMSA. The 15-character validation protects
# compatibility with the service account's sAMAccountName. Creating a KDS root key with a past
# effective time permits immediate use when the forest has no existing key.
if ($ObjectParameterMode) {
    $GMSAName = [string](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "GMSAName" -DefaultValue $DefaultGMSAName)
    if ([string]::IsNullOrWhiteSpace($GMSAName)) {
        $GMSAName = $DefaultGMSAName
    }
    if ($GMSAName.Length -gt 15) {
        throw "InstallationParameters.GMSAName '$GMSAName' is longer than the 15-character sAMAccountName limit."
    }
} else {
    $strReadHost = Read-Host "Group Managed Service AccountName ($DefaultGMSAName)"
    while ($strReadHost.Length -gt 15) {
        Write-Host "The service account has a samAccountName attribute of '$strReadHost' which is too long; the samAccountName attribute must not be longer than 15 characters."
        $strReadHost = Read-Host "Group Managed Service AccountName ($DefaultGMSAName)"
    }
    if ($strReadHost -eq '') {$strReadHost = $DefaultGMSAName}
    $GMSAName = $strReadHost
}
if ($null -eq (Get-ADServiceAccount -Filter "name -eq '$GMSAName'")){
    if (![bool](Get-KdsRootKey)){
        Write-Host "KDS Rootkey is missing." -ForegroundColor Red
        Write-Host "Creating KDS-Rootkey" -ForegroundColor Yellow
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
        Write-Host "KDS Rootkey created" -ForegroundColor Green
    }
    New-GMSA -GMSAName $GMSAName -AllowTOLogon (Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-516") -Description $DescriptionGMSA
}
$oGMSA = Get-ADServiceAccount -Filter "name -eq '$GMSAName'"
$ForestRootDomain = (Get-ADForest).RootDomain
$EAdminsGroup = Get-ADGroup -Identity "$((Get-ADDomain -server (Get-ADForest).RootDomain).DomainSid)-519" -Properties Members -Server $ForestRootDomain

# The management account needs forest-wide authority for the current scheduled-task design.
# Membership is added only when absent; a failure is reported for manual remediation.
try {
    if ($EAdminsGroup.Members -notcontains $oGMSA.DistinguishedName){
        Add-ADGroupMember $EAdminsGroup -Members $oGMSA -Server $ForestRootDomain
        Write-Host "The group $($oGMSA.Name) is added to the Enterprise Admins group" -ForegroundColor Yellow
    }
}
catch{
    Write-Host "The group $($oGMSA.Name) is not added to the Enterprise Admins group. Please add the group manually" -ForegroundColor Yellow
}

# Deploy the management scripts and module to SYSVOL so scheduled tasks use replicated content
# from a domain-accessible path. Existing module files are replaced by the bundled version.
try{
    Copy-Item .\TierLevelComputerManagement.ps1 $ScriptTarget -ErrorAction Stop
    Copy-Item .\TierLevelUserManagement.ps1 $ScriptTarget -ErrorAction Stop
    if (!(Test-Path $ModuleTarget)){
        New-Item -Path $ModuleTarget -ItemType Directory -ErrorAction Stop | Out-Null
    }
    Copy-Item -Path "$PSScriptRoot\module\*" -Destination $ModuleTarget -Force -Recurse -ErrorAction Stop
} 
catch{
    Write-Host "can not copy the script file to $ScriptTarget" -ForegroundColor Red
}
# Persist the final configuration consumed by the management scripts and module commands.
try {
    $config | ConvertTo-Json | Out-File $ConfigFile 
}
catch {
    Write-Host "Can not write the config file"
    return
}
#region group policy
# Load the bundled GPO scheduled-task template, replace deployment placeholders, disable tasks that
# are outside the selected scope, import the backup, and link the resulting GPO to the Domain
# Controllers OU. Task UIDs are stable identifiers from the bundled ScheduledTasks.xml template.
try {

    $ScheduleTaskRaw = Get-Content "$PWD\GPO\{$GPOBackupID}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Raw -ErrorAction Stop
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace("#ScriptPath", $ScriptTarget) 
    $ScheduleTaskRaw = $ScheduleTaskRaw.Replace("#GMSANAME", $GMSAName)
    [XML]$ScheduleTaskXML = $ScheduleTaskRaw
    switch ($scope){ 
        "Tier0" {
            # Tier 1 Computer Management task; not required by a Tier 0-only installation.
            $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{D9E485BC-145A-47BC-B6C0-A3457662E26A}'}
            $Task.disabled = "1"  
          }
        "Tier1" {
            # Tier 0 Computer Management task; not required by a Tier 1-only installation.
            $Task = $ScheduleTaskXML.ScheduledTasks.TaskV2 | Where-Object {$_.UID -eq '{B1168190-7E2C-4177-9391-B1FFBCDF4774}'}
            $Task.disabled = "1"

          }
    }
    if ($GMSAName -eq ""){
        # Change User Context task; it cannot run when no gMSA identity is configured.
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
        Write-Host "ONCE all Tier 0 computers are members of the $($config.Tier0ComputerGroup) group AND have been rebooted you are ready to enable the 'Tier 0 User Management' Scheduled Task. Also, be sure to have a proper Breakglass account and process in place."
    } else {
        if (!$LinkedTieringGP.Enabled){
            Write-Host "$GPOName group policy is linked to $((Get-ADDomain).DomainControllersContainer)" -ForegroundColor Yellow
            Write-Host "Validate the status of the scheduled tasks before you enable the Group Policy link" -ForegroundColor Yellow
        }
    }
    # Kerberos authentication policies require claims, compound authentication, and armoring.
    # Apply the KDC setting to domain controllers and the client setting to all domain members.
    Write-Host "Enable claim support on domain controllers and clients" -ForegroundColor Green
    Write-Host "Claim support is required to use Kerberos Authentication Policies" -ForegroundColor Green
    Write-Host "If you continue with 'y' the script will enable claim support on domain controllers and clients via group policy in the Default Domain Controller Policy" -ForegroundColor Yellow
    Write-Host "and the Default Domain Policy" -ForegroundColor Yellow
    $EnableClaimSupport = if ($ObjectParameterMode) {
        [bool](Get-InstallationParameterValue -InputObject $InstallationParameters -Name "EnableClaimSupport" -DefaultValue $true)
    } else {
        $ReadKey = Read-Host "Do you want to enable claim support on domain controllers and clients ([y]/n)"
        $ReadKey -eq '' -or $ReadKey -like "y*"
    }
    if ($EnableClaimSupport){
        Write-Host "Enabling claim support on domain controllers and clients" -ForegroundColor Green
        foreach ($domain in $config.Domains){
            Write-Host "Enabling claim support in domain $domain" -ForegroundColor Green
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
    } else {
        Write-Host "Kerberos Claim support is not enabled. You must to enable claim support manually on domain controllers and clients" -ForegroundColor Yellow
        Write-Host "Please refer to https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-policy-and-claims" -ForegroundColor Yellow
        Write-Host "and https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-armoring-for-privileged-accounts" -ForegroundColor Yellow
        Write-Host "for more information about claim support and Kerberos armoring" -ForegroundColor Yellow
    }
} 
catch{
    Write-Host $error[0]
    $InstallationStatus = "Failed"
}
#endregion
if ($InstallationStatus -ne "Failed") {
    $InstallationStatus = "Completed"
}
}
finally {
    # Always restore the caller's verbosity preference and finalize the transcript. Early returns
    # retain the Incomplete status, while handled GPO failures are explicitly marked as Failed.
    $InstallationEndTime = Get-Date
    $InstallationDuration = $InstallationEndTime - $InstallationStartTime
    $VerbosePreference = $PreviousVerbosePreference
    Write-Host "Installation status: $InstallationStatus" -ForegroundColor Cyan
    Write-Host "Installation finished: $($InstallationEndTime.ToString('yyyy-MM-dd HH:mm:ss.fff K'))" -ForegroundColor Cyan
    Write-Host "Installation duration: $($InstallationDuration.ToString())" -ForegroundColor Cyan
    Write-Host "Installation log: $InstallationLogFile" -ForegroundColor Cyan
    if ($TranscriptStarted) {
        Stop-Transcript | Out-Null
    }
}