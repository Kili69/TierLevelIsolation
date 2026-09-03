<#
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
#>

<#
.SYNOPSIS
    Validates Kerberos armoring configuration and FAST ticket issuance in an Active Directory forest.

.DESCRIPTION
    Validates that the local Windows client supports the commands required for Kerberos FAST. The
    script selects one writable domain controller per domain by default, creates a separate
    logon session, binds Kerberos requests to that controller, requests an LDAP service ticket for
    it, and verifies the FAST cache flag and issuing KDC. Use -TestAllDC to test every eligible
    domain controller.

    By default, the script prompts once for a non-privileged account from any domain in the forest.
    With -UseCurrentUser, the current logon session is used and its Kerberos ticket cache is purged
    during the test.

    Effective KDC and Kerberos client registry values on domain controllers are checked only when
    explicitly requested.

     Processing details:

     1. Prerequisite and target discovery
         The ActiveDirectory module supplies forest, domain, and domain-controller information. The
         local operating system, elevation state, klist.exe path, and required klist commands are
         validated before any ticket test starts. The target set contains every forest domain unless
         TargetDomain limits it to the local computer domain and one additional forest domain.
         Read-only controllers are excluded unless IncludeReadOnlyDomainControllers is specified.

     2. Optional configuration inspection
         CheckDomainControllerConfiguration reads the effective EnableCbacAndArmor value from the KDC
         and Kerberos client policy registry paths on each selected controller through the remote
         registry API. Missing values are treated as disabled. Registry access failures are captured
         per controller and do not prevent the ticket test from running.

     3. Controller-specific ticket acquisition
         klist add_bind directs Kerberos requests for a domain to the selected controller. Credential
         mode resolves the account to DOMAIN\user, creates an isolated Windows logon session, purges
         only that session's Kerberos cache, and requests ldap/<DC-FQDN>. Realm-specific mutexes
         protect the machine-wide binding cache during parallel tests. UseCurrentUser performs the
         same request in the caller's logon session and therefore purges that user's ticket cache;
         these tests run sequentially.

     4. Ticket validation
         The requested LDAP service-ticket block is selected from klist output. Cache Flags are parsed
         as a hexadecimal bit field; bit 0x40 indicates that the ticket was obtained through FAST.
         The Kdc Called value must also match the explicitly selected controller. This prevents a FAST
         ticket issued by a different KDC from being reported as a successful controller test.

     5. Result and cleanup
         A result is OK only when the ticket exists, FAST bit 0x40 is set, and the issuing KDC matches.
         A ticket from the expected KDC without FAST is False, while a ticket from another KDC is
         Warning. Parser, command, or ticket acquisition failures are Error. Bindings and temporary
         isolated-session files are removed,
         and current-user mode obtains a fresh home-domain TGT after its destructive cache tests. The
         script writes a color-coded summary, emits complete result objects with Verbose, and exits 0
         only when every requested check succeeds; otherwise it exits 1.

    Version 0.1.20260903.8

.NOTES
    Version history:
    0.1.20260903.8 - Added PassThru output objects containing domain and domain-controller armoring
                     statuses and centralized domain status aggregation.
    0.1.20260903.7 - Distinguished confirmed missing FAST as False, an unexpected issuing KDC as
                     Warning, and klist or validation failures as Error.
    0.1.20260903.6 - Wrapped status reasons before the console edge and separated DC labels from
                     reason text to prevent subsequent domain rows from appearing concatenated.
    0.1.20260903.5 - Added a usage example combining TargetDomain and TestAllDC.
    0.1.20260903.4 - Added armoring reasons for Warning and Error results to the normal output.
    0.1.20260903.3 - Added complete code documentation for Get-KerberosArmoringReason.
    0.1.20260903.2 - Added an explicit armoring-status reason that distinguishes missing FAST from
                     a ticket issued by a different KDC than the selected domain controller.
    0.1.20260903.1 - Clarified klist add_bind error 1722 as an unavailable RPC server and added
                     targeted DNS, firewall, RPC, and domain-controller connectivity guidance.
    0.1.20260902.14 - Added DC configuration status to the normal summary when the configuration
                      check is requested, independent of verbose output.
    0.1.20260902.13 - Correctly classified Windows Enterprise multi-session (ServerRdsh) as a client
                      instead of a server.
    0.1.20260902.12 - Added explicit Client, Server, or Domain Controller classification to verbose
                      local computer information.
    0.1.20260902.11 - Accepted a klist Kdc Called short host name when it matches the selected
                      domain controller FQDN.
    0.1.20260902.10 - Added the loaded ActiveDirectory module version to verbose startup output.
    0.1.20260902.9 - Omitted empty architecture fields from verbose output on Windows PowerShell 5.1.
    0.1.20260902.8 - Added local computer, operating-system, user, elevation, and PowerShell details
                     to verbose startup output.
    0.1.20260902.7 - Added inline data-flow documentation for function calls, key variables, and
                     essential processing blocks.
    0.1.20260902.6 - Completed parameter, output, side-effect, and error documentation for all
                     remaining functions.
    0.1.20260902.5 - Added detailed code documentation for Invoke-FastTicketTest and its temporary
                     isolated-session helper script.
    0.1.20260902.4 - Documented the local FAST support result object and operating-system gate.
    0.1.20260902.3 - Documented the script-level version, error handling, executable path, and
                     registry path variables.
     0.1.20260902.2 - Added a detailed technical description of discovery, ticket acquisition,
                            validation, cleanup, result status, and exit behavior.
    0.1.20260902.1 - Made Cache Flags parsing compatible with klist output that omits the
                     hexadecimal prefix for zero or the descriptive text after the flag value.
    0.1.20260901.4 - Resolved credential UPNs to down-level logon names before creating isolated
                     Windows logon sessions.
    0.1.20260901.3 - Protected controller bindings used by parallel credential tests with
                     realm-specific synchronization.
    0.1.20260901.2 - Moved klist add_bind to the elevated process and improved binding errors.
    0.1.20260901.1 - Used the Windows System32 klist.exe explicitly.
    0.1.20260831.1 - Corrected Kerberos armoring status evaluation for current-user tests.
    0.1.20260826.13 - Added explicit OK, Warning, and Error armoring status levels.
    0.1.20260826.12 - Added target-domain selection.
    0.1.20260826.10 - Improved domain-controller ticket testing and issuing-KDC validation.
    0.1.20260826.6 - Added Kerberos armoring validation and troubleshooting output.

.PARAMETER Credential
    Optional credential for one non-privileged account from any domain in the forest. The same
    account is used to request service tickets from every domain. If omitted, the script prompts
    once.

.PARAMETER UseCurrentUser
    Uses the current logon session for ticket tests. This purges all Kerberos tickets in the current
    session. Do not use this mode when existing Kerberos sessions must remain uninterrupted.

.PARAMETER CheckDomainControllerConfiguration
    Additionally checks the effective EnableCbacAndArmor registry values on every selected domain
    controller. This optional check requires permission to read the remote registry.

.PARAMETER TargetDomain
    Limits the test to the local computer domain and the specified domain in the current forest.
    Specify the DNS domain name. If the target is the local domain, it is tested only once. Without
    this parameter, every domain in the forest is tested.

.PARAMETER TestAllDC
    Tests every eligible domain controller. Without this parameter, only the first domain controller
    in each domain, sorted by host name, is tested. The compact output includes the domain controller
    name when this parameter is specified. Credential-based ticket tests run in parallel. Tests with
    -UseCurrentUser remain sequential because they share one Kerberos cache.

.PARAMETER ThrottleLimit
    Maximum number of parallel ticket tests when -TestAllDC is used with Credential. The default is
    8. This parameter has no effect with -UseCurrentUser.

.PARAMETER IncludeReadOnlyDomainControllers
    Includes read-only domain controllers. By default, only writable controllers are tested.

.PARAMETER PassThru
    Writes one structured object per tested domain controller to the success output stream. Each
    object contains the domain, aggregated domain status, domain controller, controller status, and
    controller reason. The color-coded host summary and process exit code remain unchanged.

.OUTPUTS
    PSCustomObject when PassThru is specified. A color-coded summary is written to the host. Detailed
    results for every domain controller are written to the verbose stream when -Verbose is specified.
    The script exits with code 1 if any check fails or cannot be completed, and with code 0 when all
    requested checks pass.

.EXAMPLE
    .\Test-KerberosArmoring.ps1 -UseCurrentUser

    Tests one writable domain controller per domain with the current user. The current Kerberos
    ticket cache is purged during this test.

.EXAMPLE
    .\Test-KerberosArmoring.ps1 -Credential (Get-Credential) -TestAllDC -Verbose

    Tests every writable domain controller in isolated logon sessions and displays per-controller
    details.

.EXAMPLE
    .\Test-KerberosArmoring.ps1 -UseCurrentUser -TargetDomain child.contoso.com

    Tests one writable domain controller in the local computer domain and in child.contoso.com.

.EXAMPLE
    .\Test-KerberosArmoring.ps1 -UseCurrentUser -TargetDomain child.contoso.com -TestAllDC

    Tests every writable domain controller in the local computer domain and in child.contoso.com.
    Tests run sequentially because they share the current user's Kerberos ticket cache.

.EXAMPLE
    $results = .\Test-KerberosArmoring.ps1 -UseCurrentUser -TestAllDC -PassThru
    $results | Export-Csv -Path .\KerberosArmoring.csv -NoTypeInformation

    Tests every writable domain controller and stores reusable result objects before exporting them
    to CSV. Host status output is displayed but is not included in the results variable.
#>
[CmdletBinding(DefaultParameterSetName = 'Credential')]
param(
    [Parameter(ParameterSetName = 'Credential')]
    [pscredential]$Credential,

    [Parameter(Mandatory = $true, ParameterSetName = 'CurrentUser')]
    [switch]$UseCurrentUser,

    [Parameter()]
    [switch]$CheckDomainControllerConfiguration,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetDomain,

    [Parameter()]
    [switch]$TestAllDC,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 8,

    [Parameter()]
    [switch]$IncludeReadOnlyDomainControllers,

    [Parameter()]
    [switch]$PassThru
)

# Current script release shown at startup and maintained in the comment-based help history.
$ScriptVersion = '0.1.20260903.8'
# Convert non-terminating PowerShell errors into terminating errors handled by the surrounding code.
$ErrorActionPreference = 'Stop'
# Use the operating system's Kerberos command-line utility instead of relying on PATH resolution.
$KlistPath = Join-Path $env:SystemRoot 'System32\klist.exe'
# Relative HKLM policy path containing the effective domain-controller Kerberos settings.
$KdcRegistryPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
# Relative HKLM policy path containing the effective Kerberos client settings.
$ClientRegistryPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
# Registry value used in both policy paths to enable claims, compound authentication, and armoring.
$RegistryValueName = 'EnableCbacAndArmor'

Write-Information "Test-KerberosArmoring.ps1 version $ScriptVersion" -InformationAction Continue

function Get-LocalComputerInformation {
    <#
    .SYNOPSIS
        Collects local runtime information for verbose diagnostic output.

    .DESCRIPTION
        Reads stable local .NET and Windows identity properties without querying Active Directory or
        a remote system. The returned values identify the computer, operating system, current user,
        Windows client or server role, process elevation, PowerShell host, and process architecture
        used to execute the test.

    .OUTPUTS
        PSCustomObject with ComputerName, OperatingSystem, WindowsSystemType, OSVersion, OSBuild,
        CurrentUser, UserDomain, IsElevated, PowerShellVersion, and PowerShellEdition properties.
        OSArchitecture and ProcessArchitecture are included only when the current .NET runtime
        provides values.

    .NOTES
        The main script calls this function only when verbose output is enabled. It does not change
        Kerberos tickets, bindings, registry values, or the current logon session.
    #>
    # WindowsIdentity supplies the effective process user. WindowsPrincipal evaluates the process
    # token so IsElevated reflects active administrator rights instead of group membership alone.
    $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = [Security.Principal.WindowsPrincipal]::new($windowsIdentity)
    $osVersion = [Environment]::OSVersion.Version
    $osArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    $processArchitecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
    # ProductType usually distinguishes client, server, and DC. Windows Enterprise multi-session is
    # the exception: it reports ServerNT while CurrentVersion identifies a Client/ServerRdsh edition.
    $windowsProductType = [Microsoft.Win32.Registry]::GetValue(
        'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions',
        'ProductType',
        $null
    )
    $currentVersionKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $windowsInstallationType = [Microsoft.Win32.Registry]::GetValue(
        $currentVersionKey,
        'InstallationType',
        $null
    )
    $windowsEditionId = [Microsoft.Win32.Registry]::GetValue(
        $currentVersionKey,
        'EditionID',
        $null
    )

    # A DC remains authoritative regardless of edition metadata. ServerRdsh takes precedence over
    # ServerNT because this is the supported Windows Enterprise multi-session client edition.
    $windowsSystemType = if ($windowsProductType -eq 'LanmanNT') {
        'Domain Controller'
    }
    elseif ($windowsEditionId -eq 'ServerRdsh') {
        'Client (Enterprise multi-session)'
    }
    elseif ($windowsInstallationType -eq 'Client' -or $windowsProductType -eq 'WinNT') {
        'Client'
    }
    elseif ($windowsProductType -eq 'ServerNT') {
        'Server'
    }
    else {
        'Unknown'
    }

    # Build the ordered output incrementally because Windows PowerShell 5.1 exposes the architecture
    # properties but can return empty values. Optional fields are added only when useful.
    $information = [ordered]@{
        ComputerName      = [Environment]::MachineName
        OperatingSystem   = [Runtime.InteropServices.RuntimeInformation]::OSDescription
        WindowsSystemType = $windowsSystemType
        OSVersion         = $osVersion.ToString()
        OSBuild           = $osVersion.Build
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$osArchitecture)) {
        $information['OSArchitecture'] = $osArchitecture
    }

    $information['CurrentUser'] = $windowsIdentity.Name
    $information['UserDomain'] = $env:USERDOMAIN
    $information['IsElevated'] = $windowsPrincipal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $information['PowerShellVersion'] = $PSVersionTable.PSVersion.ToString()
    $information['PowerShellEdition'] = $PSVersionTable.PSEdition
    if (-not [string]::IsNullOrWhiteSpace([string]$processArchitecture)) {
        $information['ProcessArchitecture'] = $processArchitecture
    }

    return [pscustomobject]$information
}

function Test-LocalFastSupport {
    <#
    .SYNOPSIS
        Verifies that the local operating system and klist.exe support the required FAST commands.

    .DESCRIPTION
        Performs the client-side prerequisite checks shared by every ticket test. It verifies that
        the script runs on Windows 8 / Windows Server 2012 or newer, that the current process is
        elevated, that System32 contains klist.exe, and that klist help advertises the get and
        add_bind commands. Expected validation failures are captured instead of being rethrown so
        the main script can present one consistent prerequisite error.

    .OUTPUTS
        PSCustomObject with Supported and Error properties. Supported is true only when every check
        succeeds. Error contains the first validation failure message and is otherwise null.

    .NOTES
        Elevation is required because later calls to klist add_bind modify the machine binding cache.
        This function checks capabilities only and does not modify Kerberos tickets or bindings.
    #>
    # Keep success state and any diagnostic message in one ordered object so the caller can report
    # a prerequisite failure without parsing exceptions. It defaults to unsupported and changes to
    # supported only after every check below succeeds; the catch block stores any failure in Error.
    $result = [ordered]@{
        Supported = $false
        Error     = $null
    }

    try {
        # Reject non-Windows platforms and Windows releases older than version 6.2 because the
        # Kerberos FAST support required by this script starts with Windows 8 / Windows Server 2012.
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT -or
            [System.Environment]::OSVersion.Version -lt [version]'6.2') {
            throw 'Kerberos FAST requires Windows 8, Windows Server 2012, or a newer Windows version.'
        }

        # WindowsIdentity identifies the account and token of this process. WindowsPrincipal wraps
        # that token so the following role test can verify effective, elevated administrator rights.
        $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $windowsPrincipal = [Security.Principal.WindowsPrincipal]::new($windowsIdentity)
        if (-not $windowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'klist add_bind requires an elevated process. Start PowerShell with Run as administrator and run the test again.'
        }

        if (-not (Test-Path -LiteralPath $KlistPath -PathType Leaf)) {
            throw "The Windows Kerberos utility was not found at '$KlistPath'."
        }

        # Capture stdout and stderr because klist help formatting and output streams vary by version.
        $klistHelp = (& $KlistPath '/?' 2>&1 | Out-String)
        # (?im) matches case-insensitively and treats every help line separately. ^\s* permits
        # indentation; the remaining tokens require the exact command syntax shown by klist /?.
        if ($klistHelp -notmatch '(?im)^\s*get\s+<SPN>' -or
            $klistHelp -notmatch '(?im)^\s*add_bind\s+<DOMAIN>\s+<DC>') {
            throw 'The installed klist.exe does not provide the get and add_bind commands.'
        }

        $result.Supported = $true
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return [pscustomobject]$result
}

function Get-RemoteRegistryValue {
    <#
    .SYNOPSIS
        Reads one value from the HKLM registry hive of a remote computer.

    .DESCRIPTION
        Opens the remote computer's HKEY_LOCAL_MACHINE hive through the .NET remote registry API,
        opens the requested relative subkey, and reads one value. This function is used only by the
        optional domain-controller configuration check. A missing registry key or value is returned
        as null so the caller can evaluate the effective setting. Connection, authorization, and
        remote-registry service failures are allowed to propagate to the caller.

    .PARAMETER ComputerName
        DNS name or resolvable host name of the computer whose HKLM hive is queried.

    .PARAMETER SubKey
        Registry path relative to HKEY_LOCAL_MACHINE. It must not include the HKLM prefix.

    .PARAMETER ValueName
        Name of the registry value to read from SubKey.

    .OUTPUTS
        The registry value using its native .NET type, or null when the subkey or value does not
        exist.

    .NOTES
        The Remote Registry service and sufficient read permissions are required on ComputerName.
        Registry handles are disposed in the finally block even when reading fails.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$SubKey,

        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )

    # Keep both disposable handles outside try so finally can close whichever handles were created
    # before a connection, subkey lookup, or value read failed.
    $baseKey = $null
    $registryKey = $null
    try {
        # baseKey represents remote HKLM; registryKey narrows that handle to the requested policy
        # path. GetValue returns the native value or the supplied null default when it is absent.
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            $ComputerName
        )
        $registryKey = $baseKey.OpenSubKey($SubKey)
        if ($null -eq $registryKey) {
            return $null
        }

        return $registryKey.GetValue($ValueName, $null)
    }
    finally {
        if ($null -ne $registryKey) {
            $registryKey.Dispose()
        }
        if ($null -ne $baseKey) {
            $baseKey.Dispose()
        }
    }
}

function Invoke-FastTicketTest {
    <#
    .SYNOPSIS
        Tests one domain controller with the supplied forest account in an isolated logon session.

    .DESCRIPTION
        Resolves the supplied credential to a Windows DOMAIN\user identity and creates a temporary
        working directory that this identity can modify. A domain-specific named mutex serializes
        changes to the machine-wide Kerberos binding for the tested domain while still permitting
        tests for different domains to run concurrently.

        After klist add_bind maps the domain to the requested controller, the function writes and
        starts a temporary PowerShell helper under the supplied credential. This creates a separate
        Windows logon session with its own Kerberos ticket cache. The helper purges that isolated
        cache, requests the specified service ticket, finds the matching ticket in klist output,
        evaluates FAST cache flag 0x40, and verifies the Kdc Called value against DomainController.

        The helper catches ticket-test failures and serializes its result to JSON because output from
        a process started with alternate credentials is not used as the data channel. The parent
        process waits for completion, validates the process and result file, deserializes the JSON,
        and returns it as a PSCustomObject. Temporary files and synchronization resources are always
        released. Machine-wide bindings are retained until all credential tests have completed and
        are then removed by the script's main cleanup path.

    .PARAMETER DomainName
        DNS name of the Active Directory domain whose Kerberos requests are temporarily bound to the
        selected controller. It also determines the scope of the synchronization mutex.

    .PARAMETER DomainController
        Fully qualified DNS name of the domain controller that must issue the service ticket. The
        value is passed to klist add_bind and compared with the Kdc Called field in the cached ticket.

    .PARAMETER ServicePrincipal
        Service principal name to request and locate in the isolated Kerberos cache. The caller uses
        ldap/<DC-FQDN> so the selected domain's KDC must issue the final service ticket.

    .PARAMETER Credential
        Forest account used to create the isolated Windows logon session. It is resolved to a
        down-level DOMAIN\user name and needs permission to log on locally to the test computer.

    .OUTPUTS
        PSCustomObject with Success, TicketReceived, FastEnabled, CacheFlags, IssuingKdc,
        KdcConfirmed, Error, and RawOutput properties. Setup failures that prevent the helper from
        returning a result are raised as terminating errors.

    .NOTES
        klist add_bind modifies machine-wide state and therefore requires an elevated parent process.
        The helper itself intentionally runs as the non-privileged test credential.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipal,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential
    )

    $klistPath = Join-Path $env:SystemRoot 'System32\klist.exe'

    # Start-Process is more reliable with the Windows down-level logon name than with a UPN.
    # Resolve through the SID so alternate UPN suffixes and differing sAMAccountName values work.
    try {
        $credentialSid = ([Security.Principal.NTAccount]::new($Credential.UserName)).Translate(
            [Security.Principal.SecurityIdentifier]
        )
        $downLevelUserName = $credentialSid.Translate(
            [Security.Principal.NTAccount]
        ).Value
        $processCredential = [pscredential]::new(
            $downLevelUserName,
            $Credential.Password
        )
    }
    catch {
        throw "The credential identity '$($Credential.UserName)' could not be resolved to a Windows domain account. $($_.Exception.Message)"
    }

    # add_bind changes the machine binding cache and requires elevation. Apply it in this elevated
    # parent/job process instead of the alternate, intentionally non-privileged logon process.
    # A realm-specific mutex prevents concurrent TestAllDC workers from replacing one another's
    # binding while still allowing tests for different domains to proceed in parallel.
    $domainBytes = [Text.Encoding]::UTF8.GetBytes($DomainName.ToUpperInvariant())
    $hashProvider = [Security.Cryptography.SHA256]::Create()
    try {
        $domainHash = [Convert]::ToBase64String($hashProvider.ComputeHash($domainBytes)) `
            -replace '[^A-Za-z0-9]', ''
    }
    finally {
        $hashProvider.Dispose()
    }
    $bindingMutex = [Threading.Mutex]::new($false, "TierLevelIsolation-$domainHash")
    $mutexAcquired = $false

    # Use a unique directory as the controlled exchange point between identities. The parent writes
    # the helper here, and the alternate identity writes the JSON result into the same directory.
    $workingDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().Guid)
    $helperPath = Join-Path $workingDirectory 'Test-FastTicket.ps1'
    $resultPath = Join-Path $workingDirectory 'result.json'
    New-Item -Path $workingDirectory -ItemType Directory | Out-Null

    # The alternate logon identity needs access to the helper script and its JSON result file.
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $processCredential.UserName,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $directoryAcl = Get-Acl -LiteralPath $workingDirectory
    $directoryAcl.SetAccessRule($accessRule)
    Set-Acl -LiteralPath $workingDirectory -AclObject $directoryAcl

    # This generated script is the isolation boundary: all cache-destructive klist operations run in
    # the alternate logon session, while privileged machine binding remains in the parent process.
    $helperScript = @'
<#
.SYNOPSIS
    Requests and validates one Kerberos service ticket in an isolated Windows logon session.

.DESCRIPTION
    Purges only the helper process identity's Kerberos cache, requests ServicePrincipal, and selects
    the corresponding numbered ticket block from klist output. It reads FAST bit 0x40 from Cache
    Flags and confirms that Kdc Called matches DomainController. All operational failures are stored
    in the result object, which is written to ResultPath as JSON in the finally block.

.PARAMETER DomainName
    DNS domain associated with the request. The parent already established its controller binding;
    this value remains available as execution context for the isolated test.

.PARAMETER DomainController
    Expected issuing domain-controller FQDN used to validate the Kdc Called field.

.PARAMETER ServicePrincipal
    SPN passed to klist get and used to select the requested ticket from the cache.

.PARAMETER ResultPath
    Parent-provided JSON file path used to return structured data across the process boundary.

.OUTPUTS
    No pipeline output is required. The complete result is persisted as JSON at ResultPath.
#>
param(
    [Parameter(Mandatory = $true)][string]$DomainName,
    [Parameter(Mandatory = $true)][string]$DomainController,
    [Parameter(Mandatory = $true)][string]$ServicePrincipal,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

# Use the same explicit system utility as the parent, independent of the alternate user's PATH.
$klistPath = Join-Path $env:SystemRoot 'System32\klist.exe'
# Initialize a complete failure-safe result contract. Individual properties are populated as each
# validation stage succeeds, and Error receives the exception message if any stage fails.
$result = [ordered]@{
    Success       = $false
    TicketReceived = $false
    FastEnabled   = $false
    CacheFlags    = $null
    IssuingKdc    = $null
    KdcConfirmed  = $false
    Error         = $null
    RawOutput     = $null
}

try {
    # A clean cache ensures that this run cannot reuse a service ticket issued by another KDC.
    & $klistPath purge | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "klist purge failed with exit code $LASTEXITCODE." }

    $requestOutput = (& $klistPath get $ServicePrincipal 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "Service ticket request failed: $requestOutput" }

    $cacheOutput = (& $klistPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "klist failed: $cacheOutput" }

    # klist separates cached tickets into numbered blocks. Select only the requested LDAP ticket;
    # Windows may canonicalize ldap/DC to ldap/DC/domain in the cached Server value.
    # (?im) enables case-insensitive, line-based matching. The escaped SPN is treated literally;
    # (?:/[^\s@]+)? accepts the optional canonical domain suffix before the realm separator (@).
    $serverPattern = '(?im)^\s*Server:\s*' + [regex]::Escape($ServicePrincipal) +
        '(?:/[^\s@]+)?\s+@'
    # (?ms) lets ^ address each line and . span line breaks. Each match starts at "#<number>>"
    # and ends immediately before the next numbered ticket block or the end of the cache output.
    $ticketMatch = [regex]::Matches($cacheOutput, '(?ms)^\s*#\d+>.*?(?=^\s*#\d+>|\z)') |
        Where-Object { $_.Value -match $serverPattern } |
        Select-Object -First 1
    if ($null -eq $ticketMatch) { throw "The service ticket for '$ServicePrincipal' was not found in the cache." }

    $ticketOutput = $ticketMatch.Value
    $result.TicketReceived = $true
    $result.RawOutput = $ticketOutput.Trim()
    # Accept both the bare zero emitted for an empty flag set and hexadecimal values. The optional
    # textual flag names following "->" are not interpreted.
    $flagMatch = [regex]::Match(
        $ticketOutput,
        '(?im)^\s*Cache Flags:\s*(?:0x(?<Flags>[0-9a-f]{1,8})|(?<Flags>0))(?:\s*->.*)?\s*$'
    )
    if (-not $flagMatch.Success) { throw 'The service ticket cache flags could not be parsed.' }

    $cacheFlags = [Convert]::ToInt32($flagMatch.Groups['Flags'].Value, 16)
    $result.CacheFlags = ('0x{0:X}' -f $cacheFlags)
    # KERB_TICKET_CACHE_INFO_EX3 uses bit 0x40 to mark a ticket obtained through FAST.
    $result.FastEnabled = (($cacheFlags -band 0x40) -eq 0x40)
    # (?im) locates the Kdc Called line; capture group 1 reads the non-whitespace host name.
    $kdcMatch = [regex]::Match($ticketOutput, '(?im)^\s*Kdc Called:\s*(\S+)\s*$')
    $result.IssuingKdc = if ($kdcMatch.Success) { $kdcMatch.Groups[1].Value }
    # klist can report Kdc Called as either a short host name or an FQDN. Accept the short form only
    # when it exactly matches the first DNS label of the selected controller.
    $issuingKdcName = if ($kdcMatch.Success) { $kdcMatch.Groups[1].Value.TrimEnd('.') }
    $expectedKdcName = $DomainController.TrimEnd('.')
    $expectedKdcShortName = ($expectedKdcName -split '\.', 2)[0]
    $result.KdcConfirmed = $kdcMatch.Success -and (
        [string]::Equals(
            $issuingKdcName,
            $expectedKdcName,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        ($issuingKdcName -notmatch '\.' -and [string]::Equals(
                $issuingKdcName,
                $expectedKdcShortName,
                [System.StringComparison]::OrdinalIgnoreCase
            ))
    )
    $result.Success = $result.FastEnabled -and $result.KdcConfirmed
}
catch {
    $result.Error = $_.Exception.Message
}
finally {
    # JSON returns structured data without mixing the helper process output into the parent console.
    $result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
'@

    try {
        $mutexAcquired = $bindingMutex.WaitOne()
        $bindOutput = (& $klistPath add_bind $DomainName $DomainController 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            $hexExitCode = '0x{0:X8}' -f ([uint32]([int64]$LASTEXITCODE -band 0xFFFFFFFFL))
            if ($LASTEXITCODE -eq 1722) {
                throw "klist add_bind failed for domain '$DomainName' and DC '$DomainController': Windows error 1722 ($hexExitCode), RPC server unavailable. The failure occurred while creating the KDC binding, before the service-ticket request. Verify DC name resolution, network routing and firewall access (including the RPC endpoint mapper on TCP 135 and dynamic RPC ports), and that the DC and its RPC services are reachable. $bindOutput"
            }
            throw "klist add_bind failed with exit code $LASTEXITCODE ($hexExitCode). $bindOutput"
        }

        Set-Content -LiteralPath $helperPath -Value $helperScript -Encoding UTF8
        # Start a hidden, non-interactive Windows PowerShell process with the alternate credential.
        # LoadUserProfile creates the expected user environment, and Wait makes the JSON handoff
        # synchronous so the parent can validate the exit code before reading the result.
        $processParameters = @{
            FilePath         = 'powershell.exe'
            Credential       = $processCredential
            ArgumentList     = @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', ('"{0}"' -f $helperPath),
                '-DomainName', $DomainName,
                '-DomainController', $DomainController,
                '-ServicePrincipal', $ServicePrincipal,
                '-ResultPath', ('"{0}"' -f $resultPath)
            )
            LoadUserProfile  = $true
            Wait             = $true
            PassThru         = $true
            WindowStyle      = 'Hidden'
        }
        try {
            $process = Start-Process @processParameters
        }
        catch {
            $nativeError = if ($_.Exception.InnerException -is [ComponentModel.Win32Exception]) {
                " Windows error $($_.Exception.InnerException.NativeErrorCode)."
            }
            else {
                ''
            }
            throw "Windows could not create a logon session for '$downLevelUserName'.$nativeError Verify the password, account state, and local interactive-logon policy. $($_.Exception.Message)"
        }
        if ($process.ExitCode -ne 0) {
            throw "Ticket test process exited with code $($process.ExitCode)."
        }
        if (-not (Test-Path -LiteralPath $resultPath)) {
            throw 'Ticket test process did not create a result file.'
        }

        return Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    }
    finally {
        Remove-Item -LiteralPath $workingDirectory -Recurse -Force -ErrorAction SilentlyContinue
        if ($mutexAcquired) {
            $bindingMutex.ReleaseMutex()
        }
        $bindingMutex.Dispose()
    }
}

function Invoke-CurrentUserFastTicketTest {
    <#
    .SYNOPSIS
        Tests one domain controller in the current user's Kerberos logon session.

    .DESCRIPTION
        Uses the same ticket and KDC validation as Invoke-FastTicketTest, but operates directly on
        the current Windows logon session instead of creating an isolated process. It purges the
        current Kerberos cache, binds the domain to the selected controller, requests the supplied
        service ticket, and locates the matching numbered ticket block in klist output.

        Cache Flags bit 0x40 determines whether FAST protected the request. The Kdc Called field is
        compared with DomainController so a ticket from another KDC cannot satisfy the test. Runtime
        failures are captured in Error and returned with any partial result state. The domain binding
        cache is purged in the finally block.

    .PARAMETER DomainName
        DNS domain passed to klist add_bind for the duration of this controller test.

    .PARAMETER DomainController
        Fully qualified DNS name used for the domain binding and expected in Kdc Called.

    .PARAMETER ServicePrincipal
        SPN requested with klist get and selected from the current user's ticket cache.

    .OUTPUTS
        PSCustomObject with Success, TicketReceived, FastEnabled, CacheFlags, IssuingKdc,
        KdcConfirmed, and Error properties.

    .NOTES
        This function is destructive to the current user's Kerberos session because it purges all
        cached tickets before each test. The main script runs this mode sequentially and requests a
        fresh home-domain TGT after all tests finish.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipal
    )

    # klistPath selects the trusted system utility; result preserves partial progress if a later
    # command or parser step fails and is returned to the orchestration layer in all cases.
    $klistPath = Join-Path $env:SystemRoot 'System32\klist.exe'
    $result = [ordered]@{
        Success      = $false
        TicketReceived = $false
        FastEnabled  = $false
        CacheFlags   = $null
        IssuingKdc   = $null
        KdcConfirmed = $false
        Error        = $null
    }

    try {
        # Remove all tickets from the current logon session so an older ticket from another KDC
        # cannot produce a false positive for this controller-specific test.
        & $klistPath purge | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "klist purge failed with exit code $LASTEXITCODE."
        }

        # Bind this DNS domain to the selected DC before requesting the LDAP service ticket.
        $bindOutput = (& $klistPath add_bind $DomainName $DomainController 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            $hexExitCode = '0x{0:X8}' -f ([uint32]([int64]$LASTEXITCODE -band 0xFFFFFFFFL))
            if ($LASTEXITCODE -eq 1722) {
                throw "klist add_bind failed for domain '$DomainName' and DC '$DomainController': Windows error 1722 ($hexExitCode), RPC server unavailable. The failure occurred while creating the KDC binding, before the service-ticket request. Verify DC name resolution, network routing and firewall access (including the RPC endpoint mapper on TCP 135 and dynamic RPC ports), and that the DC and its RPC services are reachable. $bindOutput"
            }
            throw "klist add_bind failed with exit code $LASTEXITCODE ($hexExitCode). $bindOutput"
        }

        # requestOutput is retained for a useful native-command error. cacheOutput then captures the
        # complete ticket cache because klist get does not provide every field required below.
        $requestOutput = (& $klistPath get $ServicePrincipal 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "Service ticket request failed: $requestOutput"
        }

        $cacheOutput = (& $klistPath 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "klist failed: $cacheOutput"
        }

        # Match one complete cache entry and allow the canonical ldap/DC/domain SPN form.
        # (?im) enables case-insensitive, line-based matching. The escaped SPN is literal, while
        # (?:/[^\s@]+)? accepts the optional canonical domain suffix before the realm separator.
        $serverPattern = '(?im)^\s*Server:\s*' + [regex]::Escape($ServicePrincipal) +
            '(?:/[^\s@]+)?\s+@'
        # (?ms) starts a block at "#<number>>", spans its lines, and stops via lookahead before
        # the next numbered block. \z handles the final ticket at the absolute end of the output.
        $ticketMatch = [regex]::Matches($cacheOutput, '(?ms)^\s*#\d+>.*?(?=^\s*#\d+>|\z)') |
            Where-Object { $_.Value -match $serverPattern } |
            Select-Object -First 1
        if ($null -eq $ticketMatch) {
            throw "The service ticket for '$ServicePrincipal' was not found in the cache."
        }

        # ticketOutput isolates the requested service ticket. Subsequent parsers must not inspect
        # unrelated TGTs or service tickets that can carry different flags and issuing KDC values.
        $ticketOutput = $ticketMatch.Value
        $result.TicketReceived = $true
        # Accept both the bare zero emitted for an empty flag set and hexadecimal values. The
        # optional textual flag names following "->" are not interpreted.
        $flagMatch = [regex]::Match(
            $ticketOutput,
            '(?im)^\s*Cache Flags:\s*(?:0x(?<Flags>[0-9a-f]{1,8})|(?<Flags>0))(?:\s*->.*)?\s*$'
        )
        if (-not $flagMatch.Success) {
            throw 'The service ticket cache flags could not be parsed.'
        }

        $cacheFlags = [Convert]::ToInt32($flagMatch.Groups['Flags'].Value, 16)
        $result.CacheFlags = ('0x{0:X}' -f $cacheFlags)
        # Both FAST (0x40) and the expected issuing KDC are required for a successful test.
        $result.FastEnabled = (($cacheFlags -band 0x40) -eq 0x40)
        # Capture group 1 reads the host name from the line beginning with "Kdc Called:".
        $kdcMatch = [regex]::Match($ticketOutput, '(?im)^\s*Kdc Called:\s*(\S+)\s*$')
        $result.IssuingKdc = if ($kdcMatch.Success) { $kdcMatch.Groups[1].Value }
        # Accept either the selected controller FQDN or its exact short host name from klist.
        $issuingKdcName = if ($kdcMatch.Success) { $kdcMatch.Groups[1].Value.TrimEnd('.') }
        $expectedKdcName = $DomainController.TrimEnd('.')
        $expectedKdcShortName = ($expectedKdcName -split '\.', 2)[0]
        $result.KdcConfirmed = $kdcMatch.Success -and (
            [string]::Equals(
                $issuingKdcName,
                $expectedKdcName,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -or
            ($issuingKdcName -notmatch '\.' -and [string]::Equals(
                    $issuingKdcName,
                    $expectedKdcShortName,
                    [System.StringComparison]::OrdinalIgnoreCase
                ))
        )
        $result.Success = $result.FastEnabled -and $result.KdcConfirmed
    }
    catch {
        # Preserve any fields established before failure and add the diagnostic for final status.
        $result.Error = $_.Exception.Message
    }
    finally {
        # Remove the machine-wide binding even when ticket acquisition or parsing failed.
        & $klistPath purge_bind | Out-Null
    }

    return [pscustomobject]$result
}

function Invoke-ParallelFastTicketTest {
    <#
    .SYNOPSIS
        Runs credential-based domain-controller ticket tests in parallel Windows PowerShell jobs.

    .DESCRIPTION
        Each job calls Invoke-FastTicketTest, which creates a separate logon session and Kerberos
        cache. The throttle limits concurrent processes so large forests do not overload the client
        or domain controllers. Test cases are placed in a FIFO queue. Jobs are started until the
        throttle is reached, then completed jobs are received and removed before more work starts.

        The function body of Invoke-FastTicketTest is injected into each Windows PowerShell job
        because background jobs run in separate processes and do not inherit caller-defined
        functions. Each result includes the original work-item index so the main script can merge it
        into the correct controller result regardless of job completion order. Remaining jobs are
        stopped and removed if orchestration terminates unexpectedly.

    .PARAMETER TestCases
        Array of work items. Every item must provide Index, DomainName, DomainController, and
        ServicePrincipal properties.

    .PARAMETER Credential
        Forest credential forwarded to Invoke-FastTicketTest for every isolated logon session.

    .PARAMETER ThrottleLimit
        Maximum number of Windows PowerShell background jobs allowed to run concurrently.

    .OUTPUTS
        One PSCustomObject per test case with Index, Success, TicketReceived, FastEnabled,
        CacheFlags, IssuingKdc, KdcConfirmed, and Error properties. Results are emitted in job
        completion order and must be correlated through Index.

    .NOTES
        Parallelism is used only for credential mode. Invoke-FastTicketTest serializes machine-wide
        controller bindings per domain while allowing tests for different domains to overlap.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseUsingScopeModifierInNewRunspaces',
        '',
        Justification = 'Start-Job values are passed with ArgumentList and declared in its param block.'
    )]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$TestCases,

        [Parameter(Mandatory = $true)]
        [pscredential]$Credential,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit
    )

    # functionBody transports the function definition into isolated job processes. pendingTests is
    # a FIFO work queue; runningJobs tracks active jobs for throttling, receipt, and final cleanup.
    $functionBody = ${function:Invoke-FastTicketTest}.ToString()
    $pendingTests = [System.Collections.Generic.Queue[object]]::new()
    foreach ($testCase in $TestCases) {
        $pendingTests.Enqueue($testCase)
    }

    $runningJobs = @()
    try {
        while ($pendingTests.Count -gt 0 -or $runningJobs.Count -gt 0) {
            while ($pendingTests.Count -gt 0 -and $runningJobs.Count -lt $ThrottleLimit) {
                $testCase = $pendingTests.Dequeue()
                $runningJobs += Start-Job -ScriptBlock {
                    param(
                        [string]$FunctionBody,
                        [object]$TestCase,
                        [pscredential]$TestCredential
                    )

                    # Recreate the parent function in this job before invoking the assigned test.
                    Set-Item -Path Function:\Invoke-FastTicketTest `
                        -Value ([scriptblock]::Create($FunctionBody))
                    try {
                        # ticketResult is the isolated-session result. The worker adds Index so the
                        # caller can correlate results even though jobs complete out of order.
                        $ticketResult = Invoke-FastTicketTest -DomainName $TestCase.DomainName `
                            -DomainController $TestCase.DomainController `
                            -ServicePrincipal $TestCase.ServicePrincipal -Credential $TestCredential

                        [pscustomobject]@{
                            Index        = $TestCase.Index
                            Success      = [bool]$ticketResult.Success
                            TicketReceived = [bool]$ticketResult.TicketReceived
                            FastEnabled  = [bool]$ticketResult.FastEnabled
                            CacheFlags   = $ticketResult.CacheFlags
                            IssuingKdc   = $ticketResult.IssuingKdc
                            KdcConfirmed = [bool]$ticketResult.KdcConfirmed
                            Error        = $ticketResult.Error
                        }
                    }
                    catch {
                        [pscustomobject]@{
                            Index        = $TestCase.Index
                            Success      = $false
                            TicketReceived = $false
                            FastEnabled  = $false
                            CacheFlags   = $null
                            IssuingKdc   = $null
                            KdcConfirmed = $false
                            Error        = $_.Exception.Message
                        }
                    }
                } -ArgumentList $functionBody, $testCase, $Credential
            }

            # Wait for one job, emit its result to this function's pipeline, remove it from tracking,
            # and free its PowerShell job resources before another queued test is started.
            $completedJob = Wait-Job -Job $runningJobs -Any
            Receive-Job -Job $completedJob
            $runningJobs = @($runningJobs | Where-Object { $_.Id -ne $completedJob.Id })
            Remove-Job -Job $completedJob -Force
        }
    }
    finally {
        if ($runningJobs.Count -gt 0) {
            $runningJobs | Stop-Job -ErrorAction SilentlyContinue
            $runningJobs | Remove-Job -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-KerberosArmoringStatus {
    <#
    .SYNOPSIS
        Converts ticket validation fields into the final armoring status.

    .DESCRIPTION
        Applies the common status policy used by sequential and parallel tests. Any captured error
        or missing ticket is Error. A received ticket from a KDC other than the selected controller
        is Warning because FAST cannot be attributed to the intended DC. A ticket from the selected
        controller without FAST bit 0x40 is False. A ticket is OK only when FAST is present and the
        issuing KDC matches the selected controller.

    .PARAMETER TicketReceived
        Indicates whether the requested service ticket was found in the Kerberos cache.

    .PARAMETER FastEnabled
        Indicates whether Cache Flags contained FAST bit 0x40.

    .PARAMETER KdcConfirmed
        Indicates whether Kdc Called matched the selected domain controller.

    .PARAMETER ErrorMessage
        Optional diagnostic message from ticket acquisition or parsing. Any non-empty value forces
        Error status.

    .OUTPUTS
        String containing exactly OK, False, Warning, or Error.

    .NOTES
        This function is side-effect free and centralizes status semantics for all execution modes.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [bool]$TicketReceived,

        [Parameter(Mandatory = $true)]
        [bool]$FastEnabled,

        [Parameter(Mandatory = $true)]
        [bool]$KdcConfirmed,

        [Parameter()]
        [AllowNull()]
        [string]$ErrorMessage
    )

    # Operational errors have highest priority because incomplete validation cannot be a warning.
    if ($ErrorMessage) {
        return 'Error'
    }
    # A missing ticket without a more specific diagnostic still means validation could not run.
    if (-not $TicketReceived) {
        return 'Error'
    }
    # A different issuing KDC makes the selected controller's FAST state inconclusive.
    if (-not $KdcConfirmed) {
        return 'Warning'
    }
    # A ticket from the selected DC provides a definitive positive or negative FAST result.
    if (-not $FastEnabled) {
        return 'False'
    }
    return 'OK'
}

function Get-KerberosArmoringReason {
    <#
    .SYNOPSIS
        Explains which ticket-validation condition produced the armoring status.

    .DESCRIPTION
        Converts the detailed ticket-test evidence into a human-readable explanation. An operational
        error takes precedence over all other evidence. Without an error, the function distinguishes
        between a missing service ticket, successful FAST validation, a missing FAST cache flag, an
        issuing KDC that differs from the selected domain controller, and a combination of the last
        two conditions.

        This function complements Get-KerberosArmoringStatus. It does not calculate or change the
        status and does not perform network, Kerberos, or Active Directory operations.

    .PARAMETER TicketReceived
        Indicates whether the requested service ticket was found in the Kerberos ticket cache.

    .PARAMETER FastEnabled
        Indicates whether the parsed Cache Flags value contained FAST bit 0x40.

    .PARAMETER KdcConfirmed
        Indicates whether the Kdc Called value from the service ticket matched DomainController.

    .PARAMETER DomainController
        Fully qualified DNS name of the domain controller selected for the ticket test.

    .PARAMETER IssuingKdc
        KDC reported by the service ticket's Kdc Called field. A null or empty value is described as
        an unknown KDC when KdcConfirmed is false.

    .PARAMETER CacheFlags
        Formatted hexadecimal Cache Flags value, such as 0x0 or 0x40. A null or empty value is
        described as unknown when FAST is not enabled.

    .PARAMETER ErrorMessage
        Optional diagnostic captured during ticket acquisition or parsing. When supplied, it is
        returned as the reason regardless of the other validation fields.

    .OUTPUTS
        String describing the operational error or the combined ticket receipt, FAST use, and
        issuing-KDC validation result.

    .NOTES
        This function is side-effect free and is used for both sequential and parallel result paths.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [bool]$TicketReceived,

        [Parameter(Mandatory = $true)]
        [bool]$FastEnabled,

        [Parameter(Mandatory = $true)]
        [bool]$KdcConfirmed,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter()]
        [AllowNull()]
        [string]$IssuingKdc,

        [Parameter()]
        [AllowNull()]
        [string]$CacheFlags,

        [Parameter()]
        [AllowNull()]
        [string]$ErrorMessage
    )

    if ($ErrorMessage) {
        return "Ticket test failed: $ErrorMessage"
    }
    if (-not $TicketReceived) {
        return 'No service ticket was received.'
    }

    $issuingKdcText = if ($IssuingKdc) { "'$IssuingKdc'" } else { 'an unknown KDC' }
    if ($FastEnabled -and $KdcConfirmed) {
        return "FAST is enabled and the ticket was issued by the selected DC '$DomainController'."
    }
    if ($FastEnabled) {
        return "FAST is enabled, but the ticket was issued by $issuingKdcText instead of the selected DC '$DomainController'."
    }

    $cacheFlagsText = if ($CacheFlags) { $CacheFlags } else { 'unknown' }
    if ($KdcConfirmed) {
        return "The ticket was issued by the selected DC '$DomainController', but the FAST cache flag 0x40 is not set (Cache Flags: $cacheFlagsText)."
    }
    return "The FAST cache flag 0x40 is not set (Cache Flags: $cacheFlagsText), and the ticket was issued by $issuingKdcText instead of the selected DC '$DomainController'."
}

function Write-WrappedStatusReason {
    <#
    .SYNOPSIS
        Writes a status reason without reaching the console's automatic wrap boundary.

    .DESCRIPTION
        Wraps text at word boundaries using the current console window width. The first line uses
        Prefix and continuation lines use matching indentation. One column is reserved at the right
        edge because legacy Windows consoles can leave the cursor in a pending-wrap state when a
        line exactly fills the window. A width of 120 is used when host dimensions are unavailable.

    .PARAMETER Prefix
        Label and indentation written before the first line.

    .PARAMETER Text
        Status-reason text to wrap and write.

    .PARAMETER ForegroundColor
        Console color used for every output line.

    .OUTPUTS
        None. Wrapped text is written directly to the host.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingWriteHost',
        '',
        Justification = 'Write-Host is required to preserve the status color.'
    )]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [ConsoleColor]$ForegroundColor
    )

    try {
        $windowWidth = $Host.UI.RawUI.WindowSize.Width
    }
    catch {
        $windowWidth = 120
    }
    $lineWidth = [Math]::Max(40, $windowWidth - 1)
    $continuationPrefix = ' ' * $Prefix.Length
    $currentLine = $Prefix

    foreach ($word in ($Text -split '\s+')) {
        if ($currentLine.Length -gt $Prefix.Length -and
            $currentLine.Length + $word.Length + 1 -gt $lineWidth) {
            Write-Host $currentLine -ForegroundColor $ForegroundColor
            $currentLine = $continuationPrefix + $word
        }
        else {
            $separator = if ($currentLine.Length -gt $Prefix.Length) { ' ' } else { '' }
            $currentLine += $separator + $word
        }
    }

    Write-Host $currentLine -ForegroundColor $ForegroundColor
}

function Get-DomainKerberosArmoringStatus {
    <#
    .SYNOPSIS
        Aggregates domain-controller armoring statuses into one domain status.

    .DESCRIPTION
        Returns the most significant status present in a domain using the common priority Error,
        False, Warning, and OK. The function is shared by host formatting and PassThru output so
        both representations always report the same domain result.

    .PARAMETER Results
        Result objects for all tested domain controllers in one domain.

    .OUTPUTS
        String containing exactly Error, False, Warning, or OK.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results
    )

    if ($Results.KerberosArmoringStatus -contains 'Error') {
        return 'Error'
    }
    if ($Results.KerberosArmoringStatus -contains 'False') {
        return 'False'
    }
    if ($Results.KerberosArmoringStatus -contains 'Warning') {
        return 'Warning'
    }
    return 'OK'
}

function ConvertTo-KerberosArmoringOutput {
    <#
    .SYNOPSIS
        Converts detailed controller results into reusable pipeline objects.

    .DESCRIPTION
        Groups controller results by domain, calculates the aggregate domain status, and writes one
        object per controller. Repeating the domain status on every object keeps filtering, grouping,
        CSV export, and other pipeline operations straightforward.

    .PARAMETER Results
        Detailed controller result objects produced by the ticket tests.

    .OUTPUTS
        PSCustomObject with Domain, DomainKerberosArmoringStatus, DomainController,
        DomainControllerKerberosArmoringStatus, and DomainControllerKerberosArmoringReason.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results
    )

    foreach ($domainResults in ($Results | Group-Object Domain | Sort-Object Name)) {
        $domainStatus = Get-DomainKerberosArmoringStatus -Results $domainResults.Group
        foreach ($result in ($domainResults.Group | Sort-Object DomainController)) {
            [pscustomobject][ordered]@{
                Domain                                = $domainResults.Name
                DomainKerberosArmoringStatus           = $domainStatus
                DomainController                       = $result.DomainController
                DomainControllerKerberosArmoringStatus = $result.KerberosArmoringStatus
                DomainControllerKerberosArmoringReason = $result.KerberosArmoringReason
            }
        }
    }
}

function Write-TicketTestResult {
    <#
    .SYNOPSIS
        Writes the color-coded forest summary and optional per-controller details.

    .DESCRIPTION
        By default, one aggregated status is shown per domain. When ShowDomainController is set, one
        status row is shown per tested controller. Full result objects are sent to the verbose stream
        and therefore appear only with -Verbose. Domain aggregation uses the most severe contained
        status: Error takes precedence over False, followed by Warning and OK. Error and False are
        red, Warning is yellow, and OK is green. When ShowConfigurationStatus is set, the normal
        summary also contains the combined KDC and client policy status. Every non-OK armoring result
        includes its reason in normal output; successful results remain compact.

    .PARAMETER Results
        Controller result objects to group, sort, summarize, and optionally write in full to the
        verbose stream. Each object must contain Domain, DomainController, and
        KerberosArmoringStatus properties.

    .PARAMETER ShowDomainController
        Writes one status row per domain controller instead of one worst-case aggregate per domain.

    .PARAMETER ShowConfigurationStatus
        Adds DCConfigurationStatus to the normal summary. This is used when the caller requested the
        optional domain-controller configuration check and does not require verbose output.

    .OUTPUTS
        None. Human-readable status rows and non-success reasons are written to the host. Detailed
        formatted objects are written to the verbose stream.

    .NOTES
        Write-Host is intentional because this function owns presentation and requires per-status
        colors. The machine-readable success or failure signal is supplied separately by the script's
        process exit code.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingWriteHost',
        '',
        Justification = 'Write-Host is required to render status values in colors.'
    )]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter()]
        [switch]$ShowDomainController,

        [Parameter()]
        [switch]$ShowConfigurationStatus
    )

    Write-Host ''
    if ($ShowDomainController) {
        if ($ShowConfigurationStatus) {
            Write-Host ('{0,-35} {1,-45} {2,-24} {3}' -f 'Domain', 'DomainController',
                'KerberosArmoringStatus', 'DCConfigurationStatus')
            Write-Host ('{0,-35} {1,-45} {2,-24} {3}' -f ('-' * 35), ('-' * 45),
                ('-' * 22), ('-' * 21))
        }
        else {
            Write-Host ('{0,-35} {1,-45} {2}' -f 'Domain', 'DomainController', 'KerberosArmoringStatus')
            Write-Host ('{0,-35} {1,-45} {2}' -f ('-' * 35), ('-' * 45), ('-' * 22))
        }
    }
    else {
        if ($ShowConfigurationStatus) {
            Write-Host ('{0,-40} {1,-24} {2}' -f 'Domain', 'KerberosArmoringStatus',
                'DCConfigurationStatus')
            Write-Host ('{0,-40} {1,-24} {2}' -f ('-' * 40), ('-' * 22), ('-' * 21))
        }
        else {
            Write-Host ('{0,-40} {1}' -f 'Domain', 'KerberosArmoringStatus')
            Write-Host ('{0,-40} {1}' -f ('-' * 40), ('-' * 22))
        }
    }

    # domainResults contains one group per domain. It supports either detailed controller rows or a
    # single domain row whose status is the worst status among all controllers in that group.
    foreach ($domainResults in ($Results | Group-Object Domain | Sort-Object Name)) {
        if ($ShowDomainController) {
            foreach ($result in ($domainResults.Group | Sort-Object DomainController)) {
                $statusColor = switch ($result.KerberosArmoringStatus) {
                    'OK' { 'Green' }
                    'Warning' { 'Yellow' }
                    'False' { 'Red' }
                    default { 'Red' }
                }

                Write-Host ('{0,-35} {1,-45} ' -f $result.Domain, $result.DomainController) -NoNewline
                if ($ShowConfigurationStatus) {
                    $configurationStatusColor = switch ($result.DCConfigurationStatus) {
                        'OK' { 'Green' }
                        'Warning' { 'Yellow' }
                        default { 'Red' }
                    }
                    Write-Host ('{0,-24} ' -f $result.KerberosArmoringStatus) `
                        -ForegroundColor $statusColor -NoNewline
                    Write-Host $result.DCConfigurationStatus `
                        -ForegroundColor $configurationStatusColor
                }
                else {
                    Write-Host $result.KerberosArmoringStatus -ForegroundColor $statusColor
                }
                if ($result.KerberosArmoringStatus -ne 'OK') {
                    Write-WrappedStatusReason -Prefix '  Reason: ' `
                        -Text $result.KerberosArmoringReason -ForegroundColor $statusColor
                }
            }
        }
        else {
            $domainStatus = Get-DomainKerberosArmoringStatus -Results $domainResults.Group
            $statusColor = switch ($domainStatus) {
                'OK' { 'Green' }
                'Warning' { 'Yellow' }
                'False' { 'Red' }
                default { 'Red' }
            }

            Write-Host ('{0,-40} ' -f $domainResults.Name) -NoNewline
            if ($ShowConfigurationStatus) {
                $domainConfigurationStatus = if (
                    $domainResults.Group.DCConfigurationStatus -contains 'Error'
                ) {
                    'Error'
                }
                elseif ($domainResults.Group.DCConfigurationStatus -contains 'Warning') {
                    'Warning'
                }
                else {
                    'OK'
                }
                $configurationStatusColor = switch ($domainConfigurationStatus) {
                    'OK' { 'Green' }
                    'Warning' { 'Yellow' }
                    default { 'Red' }
                }
                Write-Host ('{0,-24} ' -f $domainStatus) -ForegroundColor $statusColor -NoNewline
                Write-Host $domainConfigurationStatus -ForegroundColor $configurationStatusColor
            }
            else {
                Write-Host $domainStatus -ForegroundColor $statusColor
            }

            foreach ($result in ($domainResults.Group |
                    Where-Object { $_.KerberosArmoringStatus -ne 'OK' } |
                    Sort-Object DomainController)) {
                Write-Host "  DC: $($result.DomainController)" -ForegroundColor $statusColor
                Write-WrappedStatusReason -Prefix '    Reason: ' `
                    -Text $result.KerberosArmoringReason -ForegroundColor $statusColor
            }
        }

        foreach ($result in $domainResults.Group) {
            Write-Verbose (($result | Format-List * | Out-String).TrimEnd())
        }
    }
}

# Phase 1: discover the forest and verify that this client can perform the required klist operations.
# Collect and render startup diagnostics only for -Verbose. Formatting the object as a list keeps
# property names visible and makes output from different computers straightforward to compare.
if ($VerbosePreference -ne [Management.Automation.ActionPreference]::SilentlyContinue) {
    $localComputerInformation = Get-LocalComputerInformation
    Write-Verbose "Local computer information:`n$(
        ($localComputerInformation | Format-List * | Out-String).TrimEnd()
    )"
}

# PassThru returns the exact module instance selected by PowerShell, ensuring the verbose message
# reports the loaded version rather than another ActiveDirectory version that may also be installed.
$activeDirectoryModule = Import-Module ActiveDirectory -PassThru -Verbose:$false
Write-Verbose "Active Directory module version $($activeDirectoryModule.Version) loaded."
# localFastSupport is the shared prerequisite result. Stop before AD discovery and ticket-cache
# changes when the client platform, elevation, or klist command set cannot support the test.
$localFastSupport = Test-LocalFastSupport
if (-not $localFastSupport.Supported) {
    Write-Error -Message "Kerberos FAST test prerequisite failed: $($localFastSupport.Error)" `
        -ErrorAction Continue
    exit 1
}

# forest defines the authoritative domain set. localDomain ensures a targeted run always includes
# the computer's domain; currentUserDomain is retained only to restore that user's TGT after testing.
$forest = Get-ADForest
$localDomain = (Get-ADDomain -Current LocalComputer).DNSRoot
$currentUserDomain = if ($UseCurrentUser) {
    (Get-ADDomain -Current LoggedOnUser).DNSRoot
}
# domainsToTest is the normalized execution scope consumed by the controller discovery loop.
$domainsToTest = if ($TargetDomain) {
    $resolvedTargetDomain = $forest.Domains |
        Where-Object { $_ -ieq $TargetDomain } |
        Select-Object -First 1
    if (-not $resolvedTargetDomain) {
        $validDomains = @($forest.Domains | Sort-Object) -join ', '
        Write-Warning "Target domain '$TargetDomain' cannot be tested."
        Write-Information "Current forest: $($forest.Name)" -InformationAction Continue
        Write-Information "Valid target domains: $validDomains" -InformationAction Continue
        exit 1
    }

    @($localDomain, $resolvedTargetDomain) | Select-Object -Unique
}
else {
    @($forest.Domains)
}
if (-not $UseCurrentUser -and $localFastSupport.Supported -and $null -eq $Credential) {
    # One credential is reused across domains; Kerberos referrals reach each target domain.
    $Credential = Get-Credential -Message 'Enter one non-privileged account from any domain in the forest for the FAST ticket tests.'
}

# Phase 2: request one LDAP service ticket per DC. A forest account can follow referrals to every
# trusted domain, while ldap/DC ensures that the target domain's KDC issues the final service ticket.
# parallelTests holds deferred TestAllDC credential work. results is the canonical per-controller
# collection populated immediately for sequential tests and updated later for parallel tests.
$parallelTests = [System.Collections.Generic.List[object]]::new()
$results = foreach ($domainName in $domainsToTest) {
    # domainControllers is sorted for deterministic default selection and output ordering.
    $domainControllers = @(Get-ADDomainController -Filter * -Server $domainName |
            Where-Object { $IncludeReadOnlyDomainControllers -or -not $_.IsReadOnly } |
            Sort-Object HostName)

    # The default keeps the forest-wide test fast and predictable. TestAllDC retains the full list.
    if (-not $TestAllDC) {
        $domainControllers = @($domainControllers | Select-Object -First 1)
    }

    foreach ($domainController in $domainControllers) {
        # servicePrincipal targets LDAP on this exact DC. result starts with conservative defaults
        # and becomes the single record used by configuration checks, ticket tests, and reporting.
        $servicePrincipal = 'ldap/{0}' -f $domainController.HostName
        $result = [ordered]@{
            Domain                  = $domainName
            DomainController        = $domainController.HostName
            ServicePrincipal        = $servicePrincipal
            IsReadOnly              = $domainController.IsReadOnly
            LocalClientFastSupported = $localFastSupport.Supported
            LocalClientSupportError = $localFastSupport.Error
            ConfigurationCheckRequested = [bool]$CheckDomainControllerConfiguration
            KdcArmorConfigured      = $null
            ClientArmorConfigured   = $null
            DCConfigurationStatus   = 'NotRequested'
            ConfigurationError      = $null
            TicketReceived          = $false
            FastEnabled             = $false
            KerberosArmoringStatus  = 'Error'
            KerberosArmoringReason  = $null
            FastCacheFlags          = $null
            IssuingKdc              = $null
            IssuingKdcConfirmed     = $false
            TicketTestError         = $null
        }

        if ($CheckDomainControllerConfiguration) {
            try {
                # Read the same policy value from the KDC and client policy paths. A numeric value
                # of at least 1 means armoring support is enabled for that role on this controller.
                $kdcValue = Get-RemoteRegistryValue -ComputerName $domainController.HostName `
                    -SubKey $KdcRegistryPath -ValueName $RegistryValueName
                $clientValue = Get-RemoteRegistryValue -ComputerName $domainController.HostName `
                    -SubKey $ClientRegistryPath -ValueName $RegistryValueName
                $result.KdcArmorConfigured = ($kdcValue -ge 1)
                $result.ClientArmorConfigured = ($clientValue -ge 1)
            }
            catch {
                $result.ConfigurationError = $_.Exception.Message
            }

            # Combine both policy values and any read error into the status shown in the normal
            # summary. Missing policy is a warning; an unreadable configuration is an error.
            $result.DCConfigurationStatus = if ($result.ConfigurationError) {
                'Error'
            }
            elseif ($result.KdcArmorConfigured -and $result.ClientArmorConfigured) {
                'OK'
            }
            else {
                'Warning'
            }
        }

        if (-not $localFastSupport.Supported) {
            $result.TicketTestError = $localFastSupport.Error
        }
        elseif ($UseCurrentUser) {
            # Run synchronously because every call shares and purges the caller's Kerberos cache.
            # ticketResult is then copied into the canonical controller result record.
            $ticketResult = Invoke-CurrentUserFastTicketTest -DomainName $domainName `
                -DomainController $domainController.HostName -ServicePrincipal $servicePrincipal
            $result.TicketReceived = [bool]$ticketResult.TicketReceived
            $result.FastEnabled = [bool]$ticketResult.FastEnabled
            $result.FastCacheFlags = $ticketResult.CacheFlags
            $result.IssuingKdc = $ticketResult.IssuingKdc
            $result.IssuingKdcConfirmed = [bool]$ticketResult.KdcConfirmed
            $result.TicketTestError = $ticketResult.Error
        }
        elseif ($null -eq $Credential) {
            $result.TicketTestError = 'No test credential was supplied.'
        }
        elseif ($TestAllDC) {
            # Defer credential-based all-DC work. Index provides stable correlation when parallel
            # jobs return in completion order instead of controller discovery order.
            $parallelTests.Add([pscustomobject]@{
                    Index            = $parallelTests.Count
                    DomainName       = $domainName
                    DomainController = $domainController.HostName
                    ServicePrincipal = $servicePrincipal
                })
        }
        else {
            try {
                # A single credential-mode test uses an isolated logon session immediately.
                $ticketResult = Invoke-FastTicketTest -DomainName $domainName `
                    -DomainController $domainController.HostName -ServicePrincipal $servicePrincipal `
                    -Credential $Credential
                $result.TicketReceived = [bool]$ticketResult.TicketReceived
                $result.FastEnabled = [bool]$ticketResult.FastEnabled
                $result.FastCacheFlags = $ticketResult.CacheFlags
                $result.IssuingKdc = $ticketResult.IssuingKdc
                $result.IssuingKdcConfirmed = [bool]$ticketResult.KdcConfirmed
                $result.TicketTestError = $ticketResult.Error
            }
            catch {
                $result.TicketTestError = $_.Exception.Message
            }
        }

        # Convert the detailed evidence and any diagnostic into the common four-value status.
        $result.KerberosArmoringStatus = Get-KerberosArmoringStatus `
            -TicketReceived $result.TicketReceived -FastEnabled $result.FastEnabled `
            -KdcConfirmed $result.IssuingKdcConfirmed -ErrorMessage $result.TicketTestError
        $result.KerberosArmoringReason = Get-KerberosArmoringReason `
            -TicketReceived $result.TicketReceived -FastEnabled $result.FastEnabled `
            -KdcConfirmed $result.IssuingKdcConfirmed `
            -DomainController $result.DomainController -IssuingKdc $result.IssuingKdc `
            -CacheFlags $result.FastCacheFlags -ErrorMessage $result.TicketTestError

        [pscustomobject]$result
    }
}

if ($parallelTests.Count -gt 0) {
    # parallelTicketResults contains worker output in completion order. Each Index points back to
    # its deferred test case so the corresponding canonical result can be located and updated.
    $parallelTicketResults = @(Invoke-ParallelFastTicketTest -TestCases $parallelTests `
            -Credential $Credential -ThrottleLimit $ThrottleLimit)
    foreach ($ticketResult in $parallelTicketResults) {
        $testCase = $parallelTests[[int]$ticketResult.Index]
        $result = $results | Where-Object {
            $_.Domain -eq $testCase.DomainName -and
            $_.DomainController -eq $testCase.DomainController
        } | Select-Object -First 1

        $result.TicketReceived = [bool]$ticketResult.TicketReceived
        $result.FastEnabled = [bool]$ticketResult.FastEnabled
        $result.FastCacheFlags = $ticketResult.CacheFlags
        $result.IssuingKdc = $ticketResult.IssuingKdc
        $result.IssuingKdcConfirmed = [bool]$ticketResult.KdcConfirmed
        $result.TicketTestError = $ticketResult.Error
        # Recalculate status only after every field from the parallel worker has been merged.
        $result.KerberosArmoringStatus = Get-KerberosArmoringStatus `
            -TicketReceived $result.TicketReceived -FastEnabled $result.FastEnabled `
            -KdcConfirmed $result.IssuingKdcConfirmed -ErrorMessage $result.TicketTestError
        $result.KerberosArmoringReason = Get-KerberosArmoringReason `
            -TicketReceived $result.TicketReceived -FastEnabled $result.FastEnabled `
            -KdcConfirmed $result.IssuingKdcConfirmed `
            -DomainController $result.DomainController -IssuingKdc $result.IssuingKdc `
            -CacheFlags $result.FastCacheFlags -ErrorMessage $result.TicketTestError
    }
}

if ($UseCurrentUser -and $localFastSupport.Supported) {
    # Leave the current user with a fresh home-domain TGT after the destructive cache tests.
    & $KlistPath purge_bind | Out-Null
    & $KlistPath purge | Out-Null
    & $KlistPath get "krbtgt/$currentUserDomain" | Out-Null
}
elseif ($localFastSupport.Supported) {
    # Credential-mode workers share the machine binding cache. Remove all temporary bindings only
    # after every worker has completed so parallel tests in other domains cannot lose their binding.
    & $KlistPath purge_bind | Out-Null
}

# Render the canonical result collection. TestAllDC switches from domain aggregation to DC rows;
# a requested configuration check adds its status even when verbose output is disabled.
Write-TicketTestResult -Results $results -ShowDomainController:$TestAllDC `
    -ShowConfigurationStatus:$CheckDomainControllerConfiguration

# PassThru emits one reusable success-stream object per controller. Write-Host summary records remain
# outside the success stream, so callers can assign or pipe these objects without parsing display text.
if ($PassThru) {
    ConvertTo-KerberosArmoringOutput -Results $results
}

# Phase 3: preserve a machine-readable process result even though the human-readable output is
# grouped by domain. Optional registry failures count only when that check was explicitly requested.
# failed contains every record that should make the process unsuccessful. Optional registry state
# participates only when explicitly requested, while ticket status is always enforced.
$failed = $results | Where-Object {
    -not $_.LocalClientFastSupported -or
    $_.KerberosArmoringStatus -ne 'OK' -or
    ($CheckDomainControllerConfiguration -and (
        -not $_.KdcArmorConfigured -or
        -not $_.ClientArmorConfigured -or
        $null -ne $_.ConfigurationError
    ))
}

if ($failed) {
    exit 1
}
exit 0