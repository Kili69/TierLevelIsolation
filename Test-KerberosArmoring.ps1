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

    Version 0.1.20260901.1

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

.OUTPUTS
    None. A color-coded summary is written to the host. Detailed results for every domain controller
    are written to the verbose stream when -Verbose is specified. The script exits with code 1 if
    any check fails or cannot be completed, and with code 0 when all requested checks pass.

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
    [switch]$IncludeReadOnlyDomainControllers
)

$ScriptVersion = '0.1.20260901.1'
$ErrorActionPreference = 'Stop'
$KlistPath = Join-Path $env:SystemRoot 'System32\klist.exe'
$KdcRegistryPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
$ClientRegistryPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
$RegistryValueName = 'EnableCbacAndArmor'

Write-Information "Test-KerberosArmoring.ps1 version $ScriptVersion" -InformationAction Continue

function Test-LocalFastSupport {
    <#
    .SYNOPSIS
        Verifies that the local operating system and klist.exe support the required FAST commands.

    .OUTPUTS
        PSCustomObject with Supported and Error properties.
    #>
    $result = [ordered]@{
        Supported = $false
        Error     = $null
    }

    try {
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT -or
            [System.Environment]::OSVersion.Version -lt [version]'6.2') {
            throw 'Kerberos FAST requires Windows 8, Windows Server 2012, or a newer Windows version.'
        }

        if (-not (Test-Path -LiteralPath $KlistPath -PathType Leaf)) {
            throw "The Windows Kerberos utility was not found at '$KlistPath'."
        }

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
        This function is used only by the optional domain-controller configuration check. A missing
        registry key or value is returned as null so the caller can evaluate the effective setting.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$SubKey,

        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )

    $baseKey = $null
    $registryKey = $null
    try {
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
        Creates a temporary helper script and starts it with the supplied credential. The helper has
        its own Kerberos cache, so purging tickets cannot affect the caller's logon session. Its
        structured result is returned through a temporary JSON file.
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

    $workingDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().Guid)
    $helperPath = Join-Path $workingDirectory 'Test-FastTicket.ps1'
    $resultPath = Join-Path $workingDirectory 'result.json'
    New-Item -Path $workingDirectory -ItemType Directory | Out-Null

    # The alternate logon identity needs access to the helper script and its JSON result file.
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Credential.UserName,
        [System.Security.AccessControl.FileSystemRights]::Modify,
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $directoryAcl = Get-Acl -LiteralPath $workingDirectory
    $directoryAcl.SetAccessRule($accessRule)
    Set-Acl -LiteralPath $workingDirectory -AclObject $directoryAcl

    $helperScript = @'
param(
    [Parameter(Mandatory = $true)][string]$DomainName,
    [Parameter(Mandatory = $true)][string]$DomainController,
    [Parameter(Mandatory = $true)][string]$ServicePrincipal,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

$klistPath = Join-Path $env:SystemRoot 'System32\klist.exe'
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

    # Bind target-realm Kerberos requests to the DC whose KDC behavior is under test.
    & $klistPath add_bind $DomainName $DomainController | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "klist add_bind failed with exit code $LASTEXITCODE." }

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
    # (?im) searches individual lines case-insensitively. Capture group 1 contains only the
    # hexadecimal digits after "0x"; the textual flag names following "->" are not interpreted.
    $flagMatch = [regex]::Match(
        $ticketOutput,
        '(?im)^\s*Cache Flags:\s*0x([0-9a-f]{1,4})\s*->.*$'
    )
    if (-not $flagMatch.Success) { throw 'The service ticket cache flags could not be parsed.' }

    $cacheFlags = [Convert]::ToInt32($flagMatch.Groups[1].Value, 16)
    $result.CacheFlags = ('0x{0:X}' -f $cacheFlags)
    # KERB_TICKET_CACHE_INFO_EX3 uses bit 0x40 to mark a ticket obtained through FAST.
    $result.FastEnabled = (($cacheFlags -band 0x40) -eq 0x40)
    # (?im) locates the Kdc Called line; capture group 1 reads the non-whitespace host name.
    $kdcMatch = [regex]::Match($ticketOutput, '(?im)^\s*Kdc Called:\s*(\S+)\s*$')
    $result.IssuingKdc = if ($kdcMatch.Success) { $kdcMatch.Groups[1].Value }
    # FAST alone is insufficient: the ticket must also have come from the explicitly bound DC.
    $result.KdcConfirmed = $kdcMatch.Success -and [string]::Equals(
        $kdcMatch.Groups[1].Value.TrimEnd('.'),
        $DomainController.TrimEnd('.'),
        [System.StringComparison]::OrdinalIgnoreCase
    )
    $result.Success = $result.FastEnabled -and $result.KdcConfirmed
}
catch {
    $result.Error = $_.Exception.Message
}
finally {
    & $klistPath purge_bind | Out-Null
    # JSON returns structured data without mixing the helper process output into the parent console.
    $result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
'@

    try {
        Set-Content -LiteralPath $helperPath -Value $helperScript -Encoding UTF8
        $processParameters = @{
            FilePath         = 'powershell.exe'
            Credential       = $Credential
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
        $process = Start-Process @processParameters
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
    }
}

function Invoke-CurrentUserFastTicketTest {
    <#
    .SYNOPSIS
        Tests one domain controller in the current user's Kerberos logon session.

    .DESCRIPTION
        Uses the same ticket and KDC validation as Invoke-FastTicketTest, but operates directly on
        the current cache. The cache is purged before every controller test.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipal
    )

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
        & $klistPath purge | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "klist purge failed with exit code $LASTEXITCODE."
        }

        & $klistPath add_bind $DomainName $DomainController | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "klist add_bind failed with exit code $LASTEXITCODE."
        }

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

        $ticketOutput = $ticketMatch.Value
        $result.TicketReceived = $true
        # Capture group 1 extracts one to four hexadecimal digits from the Cache Flags line.
        # (?im) makes the label case-insensitive and anchors the match to a single output line.
        $flagMatch = [regex]::Match(
            $ticketOutput,
            '(?im)^\s*Cache Flags:\s*0x([0-9a-f]{1,4})\s*->.*$'
        )
        if (-not $flagMatch.Success) {
            throw 'The service ticket cache flags could not be parsed.'
        }

        $cacheFlags = [Convert]::ToInt32($flagMatch.Groups[1].Value, 16)
        $result.CacheFlags = ('0x{0:X}' -f $cacheFlags)
        # Both FAST (0x40) and the expected issuing KDC are required for a successful test.
        $result.FastEnabled = (($cacheFlags -band 0x40) -eq 0x40)
        # Capture group 1 reads the host name from the line beginning with "Kdc Called:".
        $kdcMatch = [regex]::Match($ticketOutput, '(?im)^\s*Kdc Called:\s*(\S+)\s*$')
        $result.IssuingKdc = if ($kdcMatch.Success) { $kdcMatch.Groups[1].Value }
        $result.KdcConfirmed = $kdcMatch.Success -and [string]::Equals(
            $kdcMatch.Groups[1].Value.TrimEnd('.'),
            $DomainController.TrimEnd('.'),
            [System.StringComparison]::OrdinalIgnoreCase
        )
        $result.Success = $result.FastEnabled -and $result.KdcConfirmed
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
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
        or domain controllers. Results include the original work-item index for deterministic merge.
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

                    Set-Item -Path Function:\Invoke-FastTicketTest `
                        -Value ([scriptblock]::Create($FunctionBody))
                    try {
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

    if ($ErrorMessage) {
        return 'Error'
    }
    if ($TicketReceived -and $FastEnabled -and $KdcConfirmed) {
        return 'OK'
    }
    if ($TicketReceived) {
        return 'Warning'
    }
    return 'Error'
}

function Write-TicketTestResult {
    <#
    .SYNOPSIS
        Writes the color-coded forest summary and optional per-controller details.

    .DESCRIPTION
        By default, one aggregated status is shown per domain. When ShowDomainController is set, one
        status row is shown per tested controller. Full result objects are sent to the verbose stream
        and therefore appear only with -Verbose.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingWriteHost',
        '',
        Justification = 'Write-Host is required to render OK, Warning, and Error in status colors.'
    )]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter()]
        [switch]$ShowDomainController
    )

    Write-Host ''
    if ($ShowDomainController) {
        Write-Host ('{0,-35} {1,-45} {2}' -f 'Domain', 'DomainController', 'KerberosArmoringStatus')
        Write-Host ('{0,-35} {1,-45} {2}' -f ('-' * 35), ('-' * 45), ('-' * 22))
    }
    else {
        Write-Host ('{0,-40} {1}' -f 'Domain', 'KerberosArmoringStatus')
        Write-Host ('{0,-40} {1}' -f ('-' * 40), ('-' * 22))
    }

    foreach ($domainResults in ($Results | Group-Object Domain | Sort-Object Name)) {
        if ($ShowDomainController) {
            foreach ($result in ($domainResults.Group | Sort-Object DomainController)) {
                $statusColor = switch ($result.KerberosArmoringStatus) {
                    'OK' { 'Green' }
                    'Warning' { 'Yellow' }
                    default { 'Red' }
                }

                Write-Host ('{0,-35} {1,-45} ' -f $result.Domain, $result.DomainController) -NoNewline
                Write-Host $result.KerberosArmoringStatus -ForegroundColor $statusColor
            }
        }
        else {
            $domainStatus = if ($domainResults.Group.KerberosArmoringStatus -contains 'Error') {
                'Error'
            }
            elseif ($domainResults.Group.KerberosArmoringStatus -contains 'Warning') {
                'Warning'
            }
            else {
                'OK'
            }
            $statusColor = switch ($domainStatus) {
                'OK' { 'Green' }
                'Warning' { 'Yellow' }
                default { 'Red' }
            }

            Write-Host ('{0,-40} ' -f $domainResults.Name) -NoNewline
            Write-Host $domainStatus -ForegroundColor $statusColor
        }

        foreach ($result in $domainResults.Group) {
            Write-Verbose (($result | Format-List * | Out-String).TrimEnd())
        }
    }
}

# Phase 1: discover the forest and verify that this client can perform the required klist operations.
Import-Module ActiveDirectory -Verbose:$false
Write-Verbose 'Active Directory module loaded.'
$localFastSupport = Test-LocalFastSupport
$forest = Get-ADForest
$localDomain = (Get-ADDomain -Current LocalComputer).DNSRoot
$currentUserDomain = if ($UseCurrentUser) {
    (Get-ADDomain -Current LoggedOnUser).DNSRoot
}
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
    $Credential = Get-Credential -Message 'Enter one non-privileged account from any domain in the forest for the FAST ticket tests.'
}

# Phase 2: request one LDAP service ticket per DC. A forest account can follow referrals to every
# trusted domain, while ldap/DC ensures that the target domain's KDC issues the final service ticket.
$parallelTests = [System.Collections.Generic.List[object]]::new()
$results = foreach ($domainName in $domainsToTest) {
    $domainControllers = @(Get-ADDomainController -Filter * -Server $domainName |
            Where-Object { $IncludeReadOnlyDomainControllers -or -not $_.IsReadOnly } |
            Sort-Object HostName)

    # The default keeps the forest-wide test fast and predictable. TestAllDC retains the full list.
    if (-not $TestAllDC) {
        $domainControllers = @($domainControllers | Select-Object -First 1)
    }

    foreach ($domainController in $domainControllers) {
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
            ConfigurationError      = $null
            TicketReceived          = $false
            FastEnabled             = $false
            KerberosArmoringStatus  = 'Error'
            FastCacheFlags          = $null
            IssuingKdc              = $null
            IssuingKdcConfirmed     = $false
            TicketTestError         = $null
        }

        if ($CheckDomainControllerConfiguration) {
            try {
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
        }

        if (-not $localFastSupport.Supported) {
            $result.TicketTestError = $localFastSupport.Error
        }
        elseif ($UseCurrentUser) {
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
            $parallelTests.Add([pscustomobject]@{
                    Index            = $parallelTests.Count
                    DomainName       = $domainName
                    DomainController = $domainController.HostName
                    ServicePrincipal = $servicePrincipal
                })
        }
        else {
            try {
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

        $result.KerberosArmoringStatus = Get-KerberosArmoringStatus `
            -TicketReceived $result.TicketReceived -FastEnabled $result.FastEnabled `
            -KdcConfirmed $result.IssuingKdcConfirmed -ErrorMessage $result.TicketTestError

        [pscustomobject]$result
    }
}

if ($parallelTests.Count -gt 0) {
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
        $result.KerberosArmoringStatus = Get-KerberosArmoringStatus `
            -TicketReceived $result.TicketReceived -FastEnabled $result.FastEnabled `
            -KdcConfirmed $result.IssuingKdcConfirmed -ErrorMessage $result.TicketTestError
    }
}

if ($UseCurrentUser -and $localFastSupport.Supported) {
    # Leave the current user with a fresh home-domain TGT after the destructive cache tests.
    & $KlistPath purge_bind | Out-Null
    & $KlistPath purge | Out-Null
    & $KlistPath get "krbtgt/$currentUserDomain" | Out-Null
}

Write-TicketTestResult -Results $results -ShowDomainController:$TestAllDC

# Phase 3: preserve a machine-readable process result even though the human-readable output is
# grouped by domain. Optional registry failures count only when that check was explicitly requested.
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