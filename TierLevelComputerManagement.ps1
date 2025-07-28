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
    Managing of Tier 0 and Tier 1 computer groups

.DESCRIPTION
    This PowerShell script is designed to manage computer objects within Tier 0 and Tier 1 computer groups in an Active Directory (AD) environment. It ensures that computer objects are correctly placed in their respective Organizational Units (OUs) and updates the membership of the Tier 0 and Tier 1 computer groups accordingly.


.OUTPUTS 
    None
.PARAMETER ConfigFile
    This is the full quaified path to the configuration file. If this parameter is empty, the script will
    search for the configuration in Active Directory or on the SYSVOL path
.PARAMETER scope
    defines which scope will be used. Possible scopes are:
    Tier-0 only the Tier 0 computer group will be managed
    Tier-1 only the Tier 1 computer group will be managed
    All-Tiers   the computer group for Tier 0 and Tier1 will be managed
.NOTES
    Version 20241220 
        Initial Version
    Version[AL] 20241223
        Documentation update
                The script creates a debug log in the user data app folder. This log file contains additional debug informations
        Important events are writte to the application log
    Version 0.2.20250304
        Provide logfile in the start message
    Version 0.2.20250314
        Documentation update
    Version 0.2.20250320
        Default configuration file change from tiering.json to TierLevelIsolation.config
    Version 0.2.20250329
        The script consumes the log path parameter from the configfile
    Version 0.2.20250623
        A errory fixed is the config file is not available or incorrect format
        New exit code added
    Version 0.2.20250625
        Removed inconsistency between this script and the TierLevelUserManagement.ps1 script reading the config file
    Version 0.2.20250714
        Fixed a bug in the scope parameter handling
    Version 0.2.20250716
        Fixed a false positive error message if the Tier 1 management is disabled
    Version 0.2.20250728
        Improved logging the log file contains the process ID of the script

    Exit codes:
        0x3E8 - a general error occured while readinb the configuration file
        0x3E9 - the configuration file is not available or has an incorrect format
        0x3EA - format error in the configuration file
        0x3EB - the configuration file is not available 
        0x3Ec - Can't find the computer group for the specified scope
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
    Write event to the event log and the debug log file
.DESCRIPTION
    This funtion will write all events to the log file. If the severity is debug the message will only be written to the debuig log file
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
        [Validateset('Error', 'Warning', 'Information', 'Debug') ]
        $Severity,
        #Event ID
        [Parameter (Mandatory = $true)]
        [int]$EventID
    )


    #Format the log message and write it to the log file
    $LogLine = "$(Get-Date -Format o),$($PID), [$Severity],[$EventID], $Message"
    Add-Content -Path $LogFile -Value $LogLine 
    #If the severity is not debug write the even to the event log and format the output
    switch ($Severity) {
        'Error' { 
            Write-Host $Message -ForegroundColor Red
            Add-Content -Path $LogFile -Value $Error[0].ScriptStackTrace 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Error -Message $Message 
        }
        'Warning' { 
            Write-Host $Message -ForegroundColor Yellow 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Warning -Message $Message
        }
        'Information' { 
            Write-Host $Message 
            Write-EventLog -LogName $eventLog -source $source -EventId $EventID -EntryType Information -Message $Message
        }
    }
}
<#
.SYNOPSIS
    Detect unexpected computer object in the member list of a group
.DESCRIPTION
    This function will search for computer objects in the member list of a group that are not located in the 
    expected OU's. The function will return a list of unexpected computer objects
.OUTPUTS
    A array of unexpected computers
.PARAMETER OUList
    A array of distunguished OU names
.PARAMETER MemberDNList
    A array Distinguished computer objects
.PARAMETER DomainDnsList
    A list of supported domain DNS names of the current forest
.EXAMPLE
    Get-UnexpectedComputerObjects -OUList @("OU=Computers,OU=Tier 0,OU=Admin","OU=Tier-1,DC=dev,DC=contoso,DC=com") ´
    -MemberDNList @("CN=MyServer,OU=Computers,OU=Tier 0,OU=Admin,DC=fabrikam,DC=com")
    this will return CN=MyServer,OU=Computers,OU=Tier 0,OU=Admin,DC=fabrikam,DC=com as result
#>
function Get-UnexpectedComputerObjects{
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $OUList,
        [Parameter (Mandatory = $true)]
        [string[]] $MemberDNList,
        [Parameter (Mandatory = $true)]
        [string[]] $DomainDnsList
    )
    $UnexpectedComputer = @() #result array 
    #The parameter OUList my contains the relative OU path. This array will be expanded to the full distinguished name
    $FQOuList = @() #list of all possible OU path
    foreach ($DomainRoot in $DomainDnsList){
        $DomainDN = (Get-ADDomain -Server $DomainRoot).DistinguishedName
        foreach ($OU in $OUList){
            if ($OU -notlike "*DC=*"){$OU = "$OU,$DomainDN"}
            if ($OU -like "*$DomainDN") {$FQOuList += $OU}
        }
    }
    #search for unexpected computer objects
    foreach ($Member in $MemberDNList ){
        #extract the OU path from the computer object
        $MemberOU = [regex]::Match($Member,"CN=[^,]+,(.*)").Groups[1].Value
        $found = $false
        #walk to all allowed OU's and check if the computer object is in one of the allowed OU's
        foreach ($OU in $FQOuList){
            if ($MemberOU -like "*$OU"){
                $found = $true
                break
            }
        }
        #if the computer object is not in one of the allowed OU's add it to the result array
        if (!$found) { $UnexpectedComputer += $Member }
    }    
    return $UnexpectedComputer
 }
#endregion

##############################################################################################################################
# Main program starts here
##############################################################################################################################

#region constantes
#Is the current domain DNS name.
$CurrentDomainDNS = (Get-ADDomain).DNSRoot
#The default configuration file is located in the SYSVOL path of the current domain
$DefaultConfigFile = "\\$CurrentDomainDNS\SYSVOL\$CurrentDomainDNS\scripts\TierLevelIsolation.config"
$config = $null #initialize the config variable
#The default path to the configuration in the Active Directory configuration partition
#$ADconfigurationPath = "CN=Tier Level Isolation,CN=Services,$((Get-ADRootDSE).configurationNamingContext)"
#endregion

#script Version 
$ScriptVersion = "0.2.20250728"
#validate the event source TierLevelIsolation is registered in the application log. If the registration failes
#the events will be written with the standard application event source to the event log. 
try {   
    $eventLog = "Application"
    $source = "TierLevelIsolation"
    # Check if the source exists; if not, create it
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $eventLog)
    }
}
catch {
    Write-EventLog -logname $eventLog -source "Application" -EventId 0 -EntryType Error -Message "The event source $source could not be created. The script will use the default event source Application"
    $source = "Application"
}
#using the next closest global catalog server
$GlobalCatalog = (Get-ADDomainController -Discover -Service GlobalCatalog -NextClosestSite ).HostName

#region read configuration
try{
    #if the configuration file is not set, the script will search for the configuration in the Active Directory configuration partition or on the default path
    #if the configuration is avaiable in the Active Directory configuration partition, the script will read the configuration from the AD
    #otherwise try to use the default configuration file
    if ($ConfigFile -eq '') {
<#        if ($null -ne (Get-ADObject -Filter "DistinguishedName -eq '$ADconfigurationPath'")){
            #Write-Log -Message "Read config from AD configuration partition" -Severity Debug -EventID 1002
            Write-host "AD config lesen noch implementieren" -ForegroundColor Red -BackgroundColor DarkGray
            return
        } else {
            #last resort if the configfile paramter is not available and no configuration is stored in the AD. check for the dafault configuration file
#>            if ($null -eq $config){
                if ((Test-Path -Path $DefaultConfigFile)){
                    $config = Get-Content $DefaultConfigFile | ConvertFrom-Json  
                    #Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 1101          
                } else {
                    Write-EventLog -LogName "Application" -source $source -Message "TierLevle Isolation Can't find the configuration in $DefaultConfigFile or Active Directory" -Severity Error -EventID 0
                    return 0xe7
                }
            }
        }
#    }
    else {  
        if (Test-Path -Path $ConfigFile){  
            $config = Get-Content $ConfigFile | ConvertFrom-Json 
            if ($null -eq $config) {
                Write-EventLog -LogName "Application" -source $source -Message "TierLevel Isolation Can't read the configuration file $ConfigFile" -EntryType Error -EventID 0
                Write-Output "An error occured while reading the configuration file $ConfigFile. The script will exit with code 0x3EB"
                return 0x3EB
            }
            Write-Log -Message "Read config from $ConfigFile" -Severity Debug -EventID 1101
        } else {
            Write-EventLog -LogName "Application" -source $source -Message "TierLevel Isolation Can't find the configuration file $ConfigFile" -EntryType Error -EventID 0
            write-output "An error occured while reading the configuration file $ConfigFile. The script will exit with code 0x3EA"
            return 0x3EA
        }
    }

}
catch {
    Write-EventLog -LogName "Application" -Source "Application" -Message "error reading configuration" -Severity Error -EventID 0
    Write-Output " An error occured while reading the configuration file $ConfigFile. The script will exit with code 0x3E8"
    return 0x3E8
}
#if the paramter $scope is set, it will overwrite the saved configuration
if ($null -eq $scope ){
    if ($config.scope -eq "Tier0"){
        $scope = "Tier-0"
    } elseif ($config.scope -eq "Tier1") {
        $scope = "Tier-1"
    } else {
        $scope = "All-Tiers"
    }
}

#endregion
#region Manage log file
[int]$MaxLogFileSize = 1048576 #Maximum size of the log file
if ($null -eq $config.LogPath -or $config.LogPath -eq ""){
    $LogFile = "$($env:LOCALAPPDATA)\$($MyInvocation.MyCommand).log" #Name and path of the log file
} else {
    $LogFile = "$($config.LogPath)\$($MyInvocation.MyCommand).log" #Name and path of the log file
}

#rename existing log files to *.sav if the currentlog file exceed the size of $MaxLogFileSize
if (Test-Path $LogFile) {
    if ((Get-Item $LogFile ).Length -gt $MaxLogFileSize) {
        if (Test-Path "$LogFile.sav") {
            Remove-Item "$LogFile.sav"
        }
        Rename-Item -Path $LogFile -NewName "$logFile.sav"
    }
}
#endregion
Write-Log -Message "Tier Isolation computer management $Scope version $ScriptVersion started. $($MyInvocation.Line) see $logFile " -Severity Information -EventID 1000
#region validate the Tier computer groups exist. If not terminal the script
if ($scope -eq "Tier-1" -and $config.scope -ne "Tier1"){
    Write-Log -Message "The TierLevelComputerManagement.ps1 script started with Tier 1 computer management scope. But the scope is disabled in the configuration file. The script will exit" -Severity Information -EventID 1205
    Write-Output "The script started with Tier 1 computer management scope. But the scope is disabled in the configuration file. The script will exit"
    return 0x0
}
try {
    $Tier0ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier0ComputerGroup)'" -Properties member
    if ($null -eq $Tier0ComputerGroup) {
        Write-Log "Tiering computer management: Can't find the Tier 0 computer group $($config.Tier0ComputerGroup) in the current domain. Script aborted" -Severity Error -EventID 1200
        Write-Output "can't fined the Tier 0 computer group $($config.Tier0ComputerGroup) in the current domain. Script aborted with 0x3EC"
        exit 0x3EC
    } else {
        Write-Log -Message "The group $($Tier0computerGroup.DistinguishedName) has $($Tier0computerGroup.Member.Count) members" -Severity Debug -EventID 1201
    }
    if ($config.scope -ne "Tier0"){
        $Tier1ComputerGroup = Get-ADGroup -Filter "SamAccountName -eq '$($config.Tier1ComputerGroup)'" -Properties member
        if ($null -eq $Tier1ComputerGroup){
            Write-Log -Message "Tiering computer management: Can't find the Tier 1 computer group $($config.Tier1ComputerGroup) in the current domain" -Severity Error -EventID 1202
        }
    }
}
catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
    Write-Log "The AD web service is not available" -Severity Error -EventID 1203
    Write-Output "The AD web service is not available. The script will exit with code 0x3E9"
    exit 0x3E9
}
#endregion
#region Add computer objects to the Tier 0 computer groups
$GroupUpdateRequired = $false #The flag is set to true if a computer object is added to the group
foreach ($Domain  in $config.Domains) {
    try{
        $DomainDN = (Get-ADDomain -Server $Domain).DistinguishedName  
        #region Tier0 computer group management     
        Foreach ($OU in $config.Tier0ComputerPath) {
            try{
                if ($OU -notlike "*,DC=*") { $OU = "$OU,$DomainDN" }
                if ($OU -like "*$DomainDN"){     
                    if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$OU'" -Server $Domain)) {
                        Write-Log "Missing the Tier 0 computer OU $OU" -Severity Warning  -EventID 1300
                    } else {
                        #validate the computer ain the Tier 0 OU are member of the tier 0 computers group
                        $T0computers = Get-ADComputer -Filter * -SearchBase $OU -Server $Domain
                        if ($null -eq $T0computers){
                        Write-Log -Message "No computer found in $OU" -Severity Debug -EventID 1305
                        } else {
                            if ($T0computers.GetType().Name -eq 'ADComputer'){
                            Write-Log -Message "Found 1 computer in $OU" -Severity Debug -EventID 1301
                            } else {
                            Write-Log -Message "Found $($T0computers.count) computers in $OU" -Severity Debug -EventID 1301
                            }
                            Foreach ($T0Computer in $T0computers) {
                                if ($Tier0ComputerGroup.member -notcontains $T0Computer.DistinguishedName ) {
                                $Tier0ComputerGroup.member += $T0Computer.DistinguishedName
                                $GroupUpdateRequired = $true
                                Write-Log "Adding $T0computer to $Tier0ComputerGroup" -Severity Information -EventID 1302
                                }
                            }
                            #Write update AD group if required
                            if ($GroupUpdateRequired) {
                                Set-ADGroup -Instance $Tier0ComputerGroup
                                Write-Log "Tier 0 computers $OU updated" -Severity Debug -EventID 1303
                                $GroupUpdateRequired = $false
                            }
                        }
                    }
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADException]{
                Write-Log "Working on $domain : Global catalog not updated. Wait for GP update $($Error[0].InvocationInfo.ScriptLineNumber)" -Severity Warning -EventID 1204
            }
            catch{
                Write-Log "A unexpected error has occured in line $($Error[0].InvocationInfo.ScriptLineNumber) while updating $Tier0ComputerGroup for domain $domain" -Severity Error -EventID 1003
            }
        }
        #endregion
        #Tier 1 group management
        if ($scope -ne "Tier-0"){
            try{
                $Tier1ComputerGroup = Get-ADGroup -Identity $config.Tier1ComputerGroup -Properties member
                $DomainDN = (Get-ADDomain -Server $Domain).DistinguishedName
                Foreach ($OU in $config.Tier1ComputerPath){
                    if ($OU -notlike "*,DC=*"){ $OU= "$OU,$DomainDN"}
                    if ($OU -like "*,$DomainDN"){
                        if ($null -eq (Get-ADObject -Filter "DistinguishedName -eq '$OU'" -Server $Domain)){
                                Write-Log "Missing Tier 1 computer OU $OU in $DomainDN" -Severity Warning -EventID 1400
                            } else {
                                Foreach ($Computer in (Get-ADComputer -Filter * -SearchBase $OU -Server $Domain)){
                                    if ($Tier1ComputerGroup.member -notcontains $computer.DistinguishedName){
                                        $Tier1ComputerGroup.member += $Computer.DistinguishedName
                                        $GroupUpdateRequired = $true
                                        Write-Log -Message "$computer added to $($config.Tier1ComputerGroup)" -Severity Information -EventID 1401
                                    }   
                                }
                                if ($GroupUpdateRequired){
                                    Set-ADGroup -Instance $Tier1ComputerGroup
                                    Write-Log -Message "Tier 0 computer group $OU updated" -Severity Debug -EventID 1405
                                    $GroupUpdateRequired = $false}
                            }
                        }
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADException]{
                Write-Log "Global catalog not updated while working on $domain . Wait for GP update $($Error[0].InvocationInfo.ScriptLineNumber)" -Severity Warning -EventID 1404
            }
            catch{
                Write-Log "A unexpected error has occured while managing Tier 1 computersgroups $($error[0]) on $domain" -Severity Error -EventID 1402
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Log "The AD WebService is down or not reachable for $domain script line $($error[0].InvocationInfo.ScriptLineNumber)" -Severity Error -EventID 1004
    }
}
# if the Tier 0 computer group is not empty, check if the computer objects are in the correct OU
if ($Tier0ComputerGroup.member.Count -gt 0){
    $ComputerObjectToRemove = @()
    $ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier0ComputerPath -MemberDNList $Tier0ComputerGroup.member -DomainDNSList $config.Domains
    Foreach ($DelComputerDN in $ComputerObjectToRemove){ 
        Write-Log -Message "Removing computer $DelComputerDN from $($Tier0computerGroup.DistinguishedName)" -Severity Warning -EventID 1304
        $DelComputer = Get-ADComputer -Filter "DistinguishedName -eq '$DelComputerDN'" -Server "$($GlobalCatalog[0]):3268"
        Remove-ADGroupMember -Identity $Tier0ComputerGroup -Members $DelComputer -Confirm:$false
    }
}
#if the scope is not Tier-0 and the Tier 1 computer group is not empty, check if the computer objects are in the correct OU
if (($scope -ne "Tier-0") -and ($Tier1ComputerGroup.member.count -gt 1)){
    $ComputerObjectToRemove = Get-UnexpectedComputerObjects -OUList $config.Tier1ComputerPath -MemberDNList $Tier1ComputerGroup.member -DomainDNSList $config.Domains
    Foreach ($DelComputerDN in $ComputerObjectToRemove){ 
        Write-Log -Message "Removing computer $DelComputerDN from $($Tier1computerGroup.DistinguishedName)" -Severity Warning -EventID 1403
        $DelComputer = Get-ADComputer -Filter "DistinguishedName -eq '$DelComputerDN'" -Server "$($GlobalCatalog[0]):3268"
        Remove-ADGroupMember -Identity $Tier1ComputerGroup -Members $DelComputerDN -Confirm:$false
    }
}
