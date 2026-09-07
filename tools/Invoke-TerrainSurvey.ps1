#Requires -Version 5.1
<#
.SYNOPSIS
    Surveys defended terrain and reconciles it against the recorded network map.

.DESCRIPTION
    The asset inventory and reality drift. SITE-DC is recorded at 10.20.1.2
    but answers on 10.20.1.11; there are others. Every negative finding
    written against a wrong address is worthless, so the map has to be true
    before the hunt conclusions built on it mean anything.

    This surveys the estate, compares what answered against what was recorded,
    and emits a typed discrepancy report:

        Confirmed    name and address agree
        IPMismatch   recorded name answers on a different address
        NameMismatch recorded address reports a different name
        Missing      recorded but nothing answered
        Unmapped     answered but not in the inventory
        DuplicateIP  two inventory entries claim one address

    Three escalating methods. Passive sends nothing to any target; Standard
    adds ICMP and reverse DNS; Active adds TCP service probes for role and OS
    inference. Default is Standard.

    Every packet-generating action is written to a deconfliction log. On a CPT
    engagement your own survey traffic will show up in somebody else's hunt —
    hand them the log so it gets ruled out instead of investigated.

.PARAMETER TerrainPath
    Recorded network map to reconcile against. Defaults to the psephos
    terrain file beside this script.

.PARAMETER Scope
    CIDRs to survey. Defaults to every segment CIDR in the terrain file.
    Networks larger than MaxPrefix are refused rather than expanded.

.PARAMETER Method
    Passive | Standard | Active. See DESCRIPTION.

.PARAMETER ExcludeAddress
    Addresses never contacted under any method. Off-limits hosts belong here.
    The CPT tooling enclave is excluded by default; it is not defended terrain.

.PARAMETER SelfTest
    Validates reconciliation, CIDR handling and exclusions offline against
    synthetic data. No network. Run this first.

.EXAMPLE
    .\Invoke-TerrainSurvey.ps1 -SelfTest

.EXAMPLE
    .\Invoke-TerrainSurvey.ps1 -Method Passive
    Reads ARP, DNS cache and Active Directory. Sends nothing to any target.

.EXAMPLE
    .\Invoke-TerrainSurvey.ps1 -Scope 10.20.1.0/24 -Method Active -Verbose

.EXAMPLE
    .\Invoke-TerrainSurvey.ps1 -EmitTerrain
    Writes a corrected terrain file alongside the report for import.

.NOTES
    Windows PowerShell 5.1 by design — the range client is Windows 10.
    Read-only. Nothing is written to any surveyed host.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TerrainPath,

    [string[]]$Scope,

    [ValidateSet('Passive', 'Standard', 'Active')]
    [string]$Method = 'Standard',

    [string[]]$ExcludeAddress = @(),

    [string[]]$ExcludeCidr = @('10.40.1.0/24', '10.40.2.0/24'),

    [ValidateRange(16, 32)]
    [int]$MaxPrefix = 22,

    [ValidateRange(1, 65535)]
    [int]$MaxHosts = 8192,

    [ValidateRange(0, 5000)]
    [int]$TimeoutMs = 400,

    [ValidateRange(1, 256)]
    [int]$Concurrency = 64,

    [string]$OutputPath = (Join-Path $PWD 'survey'),

    [string]$DomainController,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$EmitTerrain,

    [switch]$SelfTest
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

#region CONFIG — the only region you should need to edit in the field

# Probed only under -Method Active. Chosen to identify a role in one connect
# rather than to enumerate: OT protocols are included because the estate is
# mostly Linux OT and a PLC is not going to announce itself any other way.
$script:ProbePorts = [ordered]@{
    22    = 'SSH'
    25    = 'SMTP'
    53    = 'DNS'
    80    = 'HTTP'
    88    = 'Kerberos'
    135   = 'RPC'
    389   = 'LDAP'
    443   = 'HTTPS'
    445   = 'SMB'
    502   = 'Modbus'
    554   = 'RTSP'
    1883  = 'MQTT'
    3268  = 'GlobalCatalog'
    3389  = 'RDP'
    5432  = 'PostgreSQL'
    47808 = 'BACnet'
}

# Role inference from the open-port set. First match wins, so order matters:
# the most specific signature has to come before the generic one.
$script:RoleRules = @(
    @{ Role = 'Domain Controller'; All = @(88, 389) }
    @{ Role = 'Exchange / mail';   All = @(25);      Any = @(443, 80) }
    @{ Role = 'PLC (Modbus)';      All = @(502) }
    @{ Role = 'MQTT broker';       All = @(1883) }
    @{ Role = 'Camera (RTSP)';     All = @(554) }
    @{ Role = 'BAS controller';    All = @(47808) }
    @{ Role = 'File server (SMB)'; All = @(445);     Not = @(88) }
    @{ Role = 'Web server';        Any = @(80, 443) }
    @{ Role = 'Linux host (SSH)';  All = @(22) }
    @{ Role = 'RDP host';          All = @(3389) }
)

#endregion CONFIG

#region HELPERS

$script:Deconfliction = New-Object System.Collections.ArrayList

function Write-Deconfliction {
    <#
        Anything that puts a packet on the wire is recorded here. This file is
        the difference between a teammate ruling your survey out in ten seconds
        and spending an afternoon hunting it.
    #>
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$Detail = ''
    )
    $null = $script:Deconfliction.Add([pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            Source       = $env:COMPUTERNAME
            Operator     = $env:USERNAME
            Action       = $Action
            Target       = $Target
            Detail       = $Detail
        })
}

function ConvertTo-UInt32Address {
    param([Parameter(Mandatory)][string]$Address)
    $bytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32Address {
    param([Parameter(Mandatory)][uint32]$Value)
    $bytes = [System.BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).IPAddressToString
}

function Expand-Cidr {
    <#
        Usable host addresses in a CIDR. Refuses anything wider than MaxPrefix
        rather than expanding it — the SITE enclave is a /16, and quietly
        turning that into 65,534 pings is how a survey becomes an incident.
    #>
    param(
        [Parameter(Mandatory)][string]$Cidr,
        [int]$MaxPrefix = 22
    )
    if ($Cidr -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})\s*$') {
        throw "Not a CIDR: '$Cidr'"
    }
    $base = $Matches[1]
    $prefix = [int]$Matches[2]
    if ($prefix -lt $MaxPrefix) {
        throw ("Refusing to expand $Cidr — /$prefix is wider than /$MaxPrefix. " +
            'Narrow the scope or raise -MaxPrefix deliberately.')
    }
    if ($prefix -ge 31) { return @($base) }

    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
    $network = (ConvertTo-UInt32Address $base) -band $mask
    $broadcast = $network -bor (-bnot $mask)

    $out = New-Object System.Collections.ArrayList
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $null = $out.Add((ConvertFrom-UInt32Address $i))
    }
    return $out.ToArray()
}

function Test-AddressInCidr {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Cidr
    )
    if ($Cidr -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})\s*$') { return $false }
    $prefix = [int]$Matches[2]
    if ($prefix -eq 0) { return $true }
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
    return ((ConvertTo-UInt32Address $Address) -band $mask) -eq ((ConvertTo-UInt32Address $Matches[1]) -band $mask)
}

function Get-ShortName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    return ($Name -split '[.\s]')[0].Trim().ToLowerInvariant()
}

#endregion HELPERS

#region TERRAIN

function Import-Terrain {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "No terrain file at $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    $hosts = New-Object System.Collections.ArrayList
    foreach ($enclave in $raw.enclaves) {
        foreach ($segment in $enclave.segments) {
            foreach ($h in $segment.hosts) {
                $null = $hosts.Add([pscustomobject]@{
                        Name    = $h.name
                        Address = $h.ip
                        OS      = $h.os
                        Role    = $h.role
                        Enclave = $enclave.name
                        Segment = $segment.name
                        Cidr    = $segment.cidr
                    })
            }
        }
    }
    return [pscustomobject]@{
        Hosts    = $hosts.ToArray()
        Segments = @($raw.enclaves | ForEach-Object {
                $e = $_
                $e.segments | Where-Object { $_.cidr } | ForEach-Object {
                    [pscustomobject]@{ Enclave = $e.name; Segment = $_.name; Cidr = $_.cidr }
                }
            })
    }
}

#endregion TERRAIN

#region DISCOVERY

function Get-PassiveObservation {
    <#
        Neighbour cache, DNS client cache and Active Directory. None of this
        puts a packet on the wire toward a target, so it is safe to run during
        a live incident and is the right first pass.
    #>
    [CmdletBinding()]
    param([string]$DomainController, [System.Management.Automation.PSCredential]$Credential)

    $seen = @{}

    # --- neighbour / ARP cache -------------------------------------------
    try {
        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
            foreach ($n in Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue) {
                if ($n.State -in @('Reachable', 'Stale', 'Permanent') -and
                    $n.IPAddress -notmatch '^(0\.|127\.|224\.|255\.)') {
                    $seen[$n.IPAddress] = [pscustomobject]@{
                        Address = $n.IPAddress; Name = ''; Source = 'arp'; Mac = $n.LinkLayerAddress
                    }
                }
            }
        }
        else {
            foreach ($line in (& arp.exe -a 2>$null)) {
                if ($line -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\w+)') {
                    $seen[$Matches[1]] = [pscustomobject]@{
                        Address = $Matches[1]; Name = ''; Source = 'arp'; Mac = $Matches[2]
                    }
                }
            }
        }
    }
    catch { Write-Verbose "ARP enumeration unavailable: $($_.Exception.Message)" }

    # --- DNS client cache -------------------------------------------------
    try {
        if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
            foreach ($e in Get-DnsClientCache -ErrorAction SilentlyContinue) {
                if ($e.Type -eq 1 -and $e.Data -match '^\d{1,3}(\.\d{1,3}){3}$') {
                    $seen[$e.Data] = [pscustomobject]@{
                        Address = $e.Data; Name = $e.Entry; Source = 'dnscache'; Mac = ''
                    }
                }
            }
        }
    }
    catch { Write-Verbose "DNS cache unavailable: $($_.Exception.Message)" }

    # --- Active Directory computer objects --------------------------------
    # The highest-value passive source by a wide margin: the DC already knows
    # every domain-joined machine, and it is authoritative for the name.
    try {
        $root = if ($DomainController) { "LDAP://$DomainController" } else { 'LDAP://RootDSE' }
        $entry = if ($Credential) {
            New-Object System.DirectoryServices.DirectoryEntry(
                $root, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else {
            New-Object System.DirectoryServices.DirectoryEntry($root)
        }

        if (-not $DomainController) {
            $base = $entry.Properties['defaultNamingContext'].Value
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$base")
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = '(objectCategory=computer)'
        $searcher.PageSize = 500
        foreach ($p in @('name', 'dnshostname', 'operatingsystem', 'lastlogontimestamp')) {
            $null = $searcher.PropertiesToLoad.Add($p)
        }

        foreach ($r in $searcher.FindAll()) {
            $dns = if ($r.Properties['dnshostname']) { [string]$r.Properties['dnshostname'][0] } else { '' }
            $nm = if ($r.Properties['name']) { [string]$r.Properties['name'][0] } else { '' }
            $os = if ($r.Properties['operatingsystem']) { [string]$r.Properties['operatingsystem'][0] } else { '' }
            $key = "ad:$nm"
            $seen[$key] = [pscustomobject]@{
                Address = ''; Name = $(if ($dns) { $dns } else { $nm }); Source = 'ad'; Mac = ''; OS = $os
            }
        }
        Write-Verbose "Active Directory returned $($searcher.FindAll().Count) computer objects"
    }
    catch {
        Write-Verbose "Active Directory query unavailable: $($_.Exception.Message)"
    }

    return $seen.Values
}

function Invoke-IcmpSweep {
    <#
        Async ICMP across the scope. The TTL on the reply is a cheap and
        surprisingly reliable OS hint: 128 says Windows, 64 says Linux, and
        the OT estate here is predominantly Linux.
    #>
    [CmdletBinding()]
    param([string[]]$Addresses, [int]$TimeoutMs, [int]$Concurrency)

    $alive = New-Object System.Collections.ArrayList
    $index = 0

    while ($index -lt $Addresses.Count) {
        $batch = $Addresses[$index..([math]::Min($index + $Concurrency - 1, $Addresses.Count - 1))]
        $pending = @()

        foreach ($addr in $batch) {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $pending += [pscustomobject]@{
                Address = $addr
                Ping    = $ping
                Task    = $ping.SendPingAsync($addr, $TimeoutMs)
            }
        }

        foreach ($p in $pending) {
            try {
                $reply = $p.Task.GetAwaiter().GetResult()
                if ($reply.Status -eq 'Success') {
                    $ttl = 0
                    try { $ttl = $reply.Options.Ttl } catch { $ttl = 0 }
                    $osHint = ''
                    if ($ttl -gt 0) {
                        if ($ttl -gt 64) { $osHint = 'Windows' } else { $osHint = 'Linux/Unix' }
                    }
                    $null = $alive.Add([pscustomobject]@{
                            Address = $p.Address
                            Ttl     = $ttl
                            OSHint  = $osHint
                            Rtt     = $reply.RoundtripTime
                        })
                }
            }
            catch { Write-Verbose "ping $($p.Address): $($_.Exception.Message)" }
            finally { $p.Ping.Dispose() }
        }

        $index += $Concurrency
        Write-Progress -Activity 'ICMP sweep' -Status "$index / $($Addresses.Count)" `
            -PercentComplete ([math]::Min(100, 100 * $index / [math]::Max(1, $Addresses.Count)))
    }
    Write-Progress -Activity 'ICMP sweep' -Completed
    return $alive.ToArray()
}

function Resolve-AddressName {
    param([string]$Address)
    try {
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $r = Resolve-DnsName -Name $Address -Type PTR -DnsOnly -ErrorAction Stop
            $ptr = $r | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($ptr) { return $ptr.NameHost }
        }
        else {
            return ([System.Net.Dns]::GetHostEntry($Address)).HostName
        }
    }
    catch { Write-Verbose "no PTR for $Address" }
    return ''
}

function Invoke-PortProbe {
    <#
        TCP connect, not SYN — this is a defender's box, not a scanner, and a
        completed handshake is what the target's own logs will show anyway.
    #>
    param([string]$Address, [int]$TimeoutMs)

    $open = New-Object System.Collections.ArrayList
    foreach ($port in $script:ProbePorts.Keys) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($Address, $port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
                $client.EndConnect($async)
                $null = $open.Add($port)
            }
        }
        catch { }
        finally { $client.Close() }
    }
    return $open.ToArray()
}

function Get-RoleFromPorts {
    param([int[]]$Ports)
    if (-not $Ports -or $Ports.Count -eq 0) { return '' }
    foreach ($rule in $script:RoleRules) {
        $ok = $true
        if ($rule.ContainsKey('All')) {
            foreach ($p in $rule.All) { if ($Ports -notcontains $p) { $ok = $false; break } }
        }
        if ($ok -and $rule.ContainsKey('Any')) {
            $hit = $false
            foreach ($p in $rule.Any) { if ($Ports -contains $p) { $hit = $true; break } }
            if (-not $hit) { $ok = $false }
        }
        if ($ok -and $rule.ContainsKey('Not')) {
            foreach ($p in $rule.Not) { if ($Ports -contains $p) { $ok = $false; break } }
        }
        if ($ok) { return $rule.Role }
    }
    return ''
}

#endregion DISCOVERY

#region RECONCILE

function Test-IsGatewayAddress {
    <#
        First usable address in the segment. Almost always the router, and a
        router listed beside the workstations reads as an unexplained host.
    #>
    param([string]$Address, [string]$Cidr)
    if (-not $Address -or -not $Cidr) { return $false }
    if ($Cidr -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})\s*$') { return $false }
    $prefix = [int]$Matches[2]
    if ($prefix -ge 31) { return $false }
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
    $net = (ConvertTo-UInt32Address $Matches[1]) -band $mask
    return $Address -eq (ConvertFrom-UInt32Address ($net + 1))
}

<#
    PRESENCE vocabulary.

    Deliberately separate from Psephos's `verdict`, which records
    whether a host is compromised. Presence only records whether something
    answered and whether we know what it is.

      confirmed           answered at its recorded address
      relocated           answered, but on a different address than recorded
      unanswered          probed from this vantage point and nothing replied.
                          NOT "dead": it may be filtered, powered off, moved,
                          or simply not routable from where the survey ran
      excluded            deliberately not contacted. Says nothing about the
                          host, only about the scope
      out-of-scope        outside the surveyed range entirely
      alive-named         answered and resolved, but absent from the inventory
      alive-unidentified  answered, no name, no role. Worth a look.
      infrastructure      answered on the segment's gateway address
#>
$script:PresenceLabel = @{
    'confirmed'          = 'Confirmed at recorded address'
    'relocated'          = 'Alive at a different address than recorded'
    'unanswered'         = 'Probed, no response (filtered, off, moved, or not routable from here)'
    'excluded'           = 'Not contacted: excluded from the survey scope'
    'out-of-scope'       = 'Not contacted: outside the surveyed range'
    'alive-named'        = 'Alive and named, not in inventory'
    'alive-unidentified' = 'Alive but unidentified'
    'infrastructure'     = 'Alive, segment gateway'
}

function Remove-NonHostAddress {
    <#
        A /24's .0 and .255 are not hosts. They reach the observation set via
        the ARP and DNS caches rather than the sweep, which excludes them, so
        they have to be filtered here too. 10.20.1.255 was landing in the
        corrected map as a host.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Observed,
        [AllowEmptyCollection()][string[]]$Cidrs = @()
    )
    $bad = @{}
    foreach ($c in $Cidrs) {
        if ($c -notmatch '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})\s*$') { continue }
        $prefix = [int]$Matches[2]
        if ($prefix -ge 31 -or $prefix -lt 1) { continue }
        $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefix))
        $net = (ConvertTo-UInt32Address $Matches[1]) -band $mask
        $bad[(ConvertFrom-UInt32Address $net)] = $true
        $bad[(ConvertFrom-UInt32Address ($net -bor (-bnot $mask)))] = $true
    }
    return @($Observed | Where-Object { -not ($_.Address -and $bad.ContainsKey($_.Address)) })
}

function Compare-Terrain {
    <#
        Produces one row per discrepancy. Matching is by short name first and
        address second, because a name that answers on the wrong address is
        the failure mode we are actually chasing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Recorded,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Observed,
        # Addresses this run actually put a packet toward. Anything absent from
        # it was never checked, and must not be reported as silent.
        [AllowEmptyCollection()][string[]]$Contacted = @(),
        [AllowEmptyCollection()][string[]]$ExcludedCidr = @(),
        [AllowEmptyCollection()][string[]]$ExcludedAddress = @(),
        [switch]$Probed
    )

    $findings = New-Object System.Collections.ArrayList
    $obsByAddr = @{}
    $obsByName = @{}
    $contactedSet = @{}
    foreach ($c in $Contacted) { $contactedSet[$c] = $true }

    <#
        Why a recorded host produced nothing. Saying "no response" about an
        address the survey deliberately skipped is a false negative: it reads
        as though we looked. An on-range run reported 21 CPT tooling hosts as
        silent when they were in the default exclusion list all along.
    #>
    function Resolve-Silence([string]$Address) {
        if (-not $Probed) { return 'unsurveyed' }
        if ($Address -and $contactedSet.ContainsKey($Address)) { return 'unanswered' }
        if ($Address) {
            if ($ExcludedAddress -contains $Address) { return 'excluded' }
            foreach ($c in $ExcludedCidr) {
                if (Test-AddressInCidr -Address $Address -Cidr $c) { return 'excluded' }
            }
        }
        return 'out-of-scope'
    }

    foreach ($o in $Observed) {
        if ($o.Address) { $obsByAddr[$o.Address] = $o }
        $short = Get-ShortName $o.Name
        if ($short -and -not $obsByName.ContainsKey($short)) { $obsByName[$short] = $o }
    }

    # Inventory entries sharing one address are a defect in the inventory
    # itself, independent of anything the survey saw.
    $dupes = $Recorded | Where-Object { $_.Address } | Group-Object Address | Where-Object { $_.Count -gt 1 }
    foreach ($d in $dupes) {
        $null = $findings.Add([pscustomobject]@{
                Type            = 'DuplicateIP'
                Name            = ($d.Group.Name -join ' / ')
                RecordedAddress = $d.Name
                ObservedAddress = ''
                ObservedName    = ''
                Enclave         = $d.Group[0].Enclave
                Segment         = $d.Group[0].Segment
                Evidence        = 'inventory'
                Presence        = ''
                Detail          = "$($d.Count) inventory entries claim this address"
            })
    }

    $matchedAddresses = New-Object System.Collections.ArrayList

    foreach ($r in $Recorded) {
        $short = Get-ShortName $r.Name
        $byAddr = $null
        if ($r.Address -and $obsByAddr.ContainsKey($r.Address)) { $byAddr = $obsByAddr[$r.Address] }
        $byName = $null
        if ($short -and $obsByName.ContainsKey($short)) { $byName = $obsByName[$short] }

        if ($byAddr) {
            $obsShort = Get-ShortName $byAddr.Name
            $null = $matchedAddresses.Add($r.Address)
            if ($obsShort -and $short -and $obsShort -ne $short) {
                $null = $findings.Add([pscustomobject]@{
                        Type            = 'NameMismatch'
                        Name            = $r.Name
                        RecordedAddress = $r.Address
                        ObservedAddress = $byAddr.Address
                        ObservedName    = $byAddr.Name
                        Enclave         = $r.Enclave
                        Segment         = $r.Segment
                        Evidence        = $byAddr.Source
                        Presence        = 'confirmed'
                        Detail          = "address answers as '$($byAddr.Name)'"
                    })
            }
            else {
                $null = $findings.Add([pscustomobject]@{
                        Type            = 'Confirmed'
                        Name            = $r.Name
                        RecordedAddress = $r.Address
                        ObservedAddress = $byAddr.Address
                        ObservedName    = $byAddr.Name
                        Enclave         = $r.Enclave
                        Segment         = $r.Segment
                        Evidence        = $byAddr.Source
                        Presence        = 'confirmed'
                        Detail          = ''
                    })
            }
            continue
        }

        # The inventory records role labels ("DC", "File", "Web") while the
        # estate uses <ENCLAVE>-<ROLE> hostnames ("SITE-DC.example.test"). Without
        # this, the DC at .11 came back as Missing plus a separate Unmapped and
        # no correction was ever applied. Scoped to the host's own segment so
        # SITE "DC" cannot capture SITE2-DC.
        if (-not $byName -and $short -and $r.Cidr) {
            foreach ($o in $Observed) {
                if (-not $o.Address) { continue }
                if ($matchedAddresses -contains $o.Address) { continue }
                if (-not (Test-AddressInCidr -Address $o.Address -Cidr $r.Cidr)) { continue }
                $tokens = @((Get-ShortName $o.Name) -split '[-_]')
                if ($tokens -contains $short) { $byName = $o; break }
            }
        }

        if ($byName -and $byName.Address -and $byName.Address -ne $r.Address) {
            # The SITE-DC case: right host, wrong address on the map.
            $null = $matchedAddresses.Add($byName.Address)
            $null = $findings.Add([pscustomobject]@{
                    Type            = 'IPMismatch'
                    Name            = $r.Name
                    RecordedAddress = $r.Address
                    ObservedAddress = $byName.Address
                    ObservedName    = $byName.Name
                    Enclave         = $r.Enclave
                    Segment         = $r.Segment
                    Evidence        = $byName.Source
                    Presence        = 'relocated'
                    Detail          = "recorded $($r.Address), answers on $($byName.Address)"
                })
            continue
        }

        $silence = Resolve-Silence $r.Address
        $null = $findings.Add([pscustomobject]@{
                Type            = $(if ($silence -eq 'unanswered') { 'Missing' } else { 'NotChecked' })
                Name            = $r.Name
                RecordedAddress = $r.Address
                ObservedAddress = ''
                ObservedName    = ''
                Enclave         = $r.Enclave
                Segment         = $r.Segment
                Evidence        = ''
                Presence        = $silence
                Detail          = $script:PresenceLabel[$silence]
            })
    }

    foreach ($o in $Observed) {
        if (-not $o.Address) { continue }
        if ($matchedAddresses -contains $o.Address) { continue }
        $null = $findings.Add([pscustomobject]@{
                Type            = 'Unmapped'
                Name            = $o.Name
                RecordedAddress = ''
                ObservedAddress = $o.Address
                ObservedName    = $o.Name
                Enclave         = ''
                Segment         = ''
                Evidence        = $o.Source
                Presence        = $(if ($o.Name -and $o.Name -ne $o.Address) { 'alive-named' } else { 'alive-unidentified' })
                Detail          = $script:PresenceLabel[$(if ($o.Name -and $o.Name -ne $o.Address) { 'alive-named' } else { 'alive-unidentified' })]
            })
    }

    return $findings.ToArray()
}

#endregion RECONCILE

#region EMIT

function Write-JsonFile {
    <#
        Set-Content -Encoding UTF8 emits a BOM on Windows PowerShell 5.1, and
        JSON.parse rejects it outright, so Psephos could not load its
        own corrected map. Write UTF-8 without a BOM.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-Prop {
    param($Object, [string]$Name, $Default = '')
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function New-CorrectedTerrain {
    <#
        Patches the recorded map in place rather than rebuilding it.

        The first version of this assembled a fresh tree from the flattened
        host list, which silently dropped every segment that had no named
        host: all twelve SITE workstation ranges, the Enclave B transit
        segments, and the entire Management enclave. A "corrected" map that
        quietly loses terrain is worse than no map at all, so this now walks
        the original structure and only changes what the survey actually
        found evidence to change.

        Hosts discovered by the survey are placed into whichever segment CIDR
        contains them, which is how the client ranges finally get populated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Raw,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [string]$Stamp = ''
    )

    $fix = @{}
    foreach ($f in @($Findings | Where-Object { $_.Type -eq 'IPMismatch' -and $_.ObservedAddress })) {
        $fix["$($f.Name)|$($f.RecordedAddress)"] = $f.ObservedAddress
    }
    $unmapped = @($Findings | Where-Object { $_.Type -eq 'Unmapped' -and $_.ObservedAddress })
    $placed = @{}
    $corrections = 0

    $byRecorded = @{}
    foreach ($f in $Findings) {
        if ($f.Type -eq 'Unmapped' -or $f.Type -eq 'DuplicateIP') { continue }
        $pk = "$($f.Name)|$($f.RecordedAddress)"
        if (-not $byRecorded.ContainsKey($pk)) { $byRecorded[$pk] = (Get-Prop $f 'Presence' 'unsurveyed') }
    }

    $enclavesOut = New-Object System.Collections.ArrayList
    foreach ($e in $Raw.enclaves) {
        $segsOut = New-Object System.Collections.ArrayList

        foreach ($sg in (Get-Prop $e 'segments' @())) {
            $hostsOut = New-Object System.Collections.ArrayList

            foreach ($h in (Get-Prop $sg 'hosts' @())) {
                $name = Get-Prop $h 'name'
                $ip = Get-Prop $h 'ip'
                $key = "$name|$ip"
                if ($fix.ContainsKey($key)) { $ip = $fix[$key]; $corrections++ }

                # Whatever the survey concluded about this host, said plainly
                # on the host itself rather than only in a separate report.
                $pres = 'unsurveyed'
                $hit = $byRecorded["$name|$(Get-Prop $h 'ip')"]
                if ($hit) { $pres = $hit }

                $null = $hostsOut.Add([ordered]@{
                        name = $name
                        ip = $ip
                        os = (Get-Prop $h 'os')
                        role = (Get-Prop $h 'role')
                        kind = (Get-Prop $h 'kind')
                        source = 'inventory'
                        presence = $pres
                        presenceNote = $(if ($script:PresenceLabel.ContainsKey($pres)) { $script:PresenceLabel[$pres] } else { 'Not covered by this survey' })
                    })
            }

            # Survey discoveries land in the segment whose CIDR contains them.
            $cidr = Get-Prop $sg 'cidr'
            if ($cidr) {
                foreach ($u in $unmapped) {
                    if ($placed.ContainsKey($u.ObservedAddress)) { continue }
                    if (Test-AddressInCidr -Address $u.ObservedAddress -Cidr $cidr) {
                        $placed[$u.ObservedAddress] = $true
                        $nm = $u.ObservedName
                        if (-not $nm) { $nm = $u.ObservedAddress }
                        $pres = Get-Prop $u 'Presence' 'alive-unidentified'
                        # A router listed beside the workstations reads as an
                        # unexplained host, so name it for what it is.
                        if (Test-IsGatewayAddress -Address $u.ObservedAddress -Cidr $cidr) {
                            $pres = 'infrastructure'
                        }
                        $null = $hostsOut.Add([ordered]@{
                                name = $nm; ip = $u.ObservedAddress; os = ''
                                role = $(if ($pres -eq 'infrastructure') { 'Gateway' } else { '' })
                                kind = ''; source = 'survey'
                                presence = $pres
                                presenceNote = $script:PresenceLabel[$pres]
                            })
                    }
                }
            }

            # Empty segments are kept. A client range with no named host is
            # still terrain, and dropping it is how the workstations vanished.
            $null = $segsOut.Add([ordered]@{
                    name  = (Get-Prop $sg 'name')
                    cidr  = $cidr
                    note  = (Get-Prop $sg 'note')
                    hosts = @($hostsOut)
                })
        }

        $null = $enclavesOut.Add([ordered]@{
                key         = (Get-Prop $e 'key')
                name        = (Get-Prop $e 'name')
                cidr        = (Get-Prop $e 'cidr')
                description = (Get-Prop $e 'description')
                segments    = @($segsOut)
            })
    }

    # Discoveries that fall outside every known CIDR still need a home.
    $orphans = @($unmapped | Where-Object { -not $placed.ContainsKey($_.ObservedAddress) })
    if ($orphans.Count -gt 0) {
        $ohosts = New-Object System.Collections.ArrayList
        foreach ($o in $orphans) {
            $nm = $o.ObservedName
            if (-not $nm) { $nm = $o.ObservedAddress }
            $pres = Get-Prop $o 'Presence' 'alive-unidentified'
            $null = $ohosts.Add([ordered]@{
                    name = $nm; ip = $o.ObservedAddress; os = ''; role = ''; kind = ''
                    source = 'survey'; presence = $pres; presenceNote = $script:PresenceLabel[$pres]
                })
        }
        $null = $enclavesOut.Add([ordered]@{
                key = 'unmapped'; name = 'Unmapped'; cidr = ''
                description = 'Answered during survey, outside every known segment'
                segments = @([ordered]@{
                        name = 'discovered'; cidr = ''; note = 'Placed by survey, needs analyst review'
                        hosts = @($ohosts)
                    })
            })
    }

    Write-Verbose "applied $corrections address correction(s), placed $($placed.Count) discovered host(s)"
    return [ordered]@{
        source   = "Invoke-TerrainSurvey $Stamp (patched from $(Get-Prop $Raw 'source' 'recorded map'))"
        enclaves = @($enclavesOut)
    }
}

#endregion EMIT

#region SELFTEST

function Invoke-SelfTest {
    $failures = New-Object System.Collections.ArrayList
    function Assert([bool]$Condition, [string]$Message) {
        if ($Condition) { Write-Host "  PASS  $Message" -ForegroundColor Green }
        else { Write-Host "  FAIL  $Message" -ForegroundColor Red; $null = $failures.Add($Message) }
    }

    Write-Host "`nCIDR handling" -ForegroundColor Cyan
    $h = @(Expand-Cidr -Cidr '10.20.30.0/29' -MaxPrefix 22)
    Assert ($h.Count -eq 6) "a /29 expands to 6 usable hosts (got $($h.Count))"
    Assert ($h[0] -eq '10.20.30.1' -and $h[-1] -eq '10.20.30.6') 'first and last are .1 and .6'
    Assert (@(Expand-Cidr -Cidr '192.168.1.5/32').Count -eq 1) 'a /32 is a single address'

    $refused = $false
    try { $null = Expand-Cidr -Cidr '10.20.0.0/16' -MaxPrefix 22 } catch { $refused = $true }
    Assert $refused 'a /16 is refused rather than expanded to 65k pings'

    Assert (Test-AddressInCidr -Address '10.20.30.7' -Cidr '10.20.30.0/24') 'address inside CIDR detected'
    Assert (-not (Test-AddressInCidr -Address '10.20.31.7' -Cidr '10.20.30.0/24')) 'address outside CIDR rejected'
    Assert ((ConvertFrom-UInt32Address (ConvertTo-UInt32Address '203.0.113.25')) -eq '203.0.113.25') 'address round-trips'

    Write-Host "`nName handling" -ForegroundColor Cyan
    Assert ((Get-ShortName 'SITE-MAIL.example.test') -eq 'site-mail') 'domain suffix stripped and lowercased'
    Assert ((Get-ShortName '') -eq '') 'empty name is safe'

    Write-Host "`nRole inference" -ForegroundColor Cyan
    Assert ((Get-RoleFromPorts @(88, 389, 445)) -eq 'Domain Controller') 'DC beats file server on 445'
    Assert ((Get-RoleFromPorts @(445)) -eq 'File server (SMB)') 'SMB alone is a file server'
    Assert ((Get-RoleFromPorts @(502)) -eq 'PLC (Modbus)') 'Modbus identifies a PLC'
    Assert ((Get-RoleFromPorts @(554, 80)) -eq 'Camera (RTSP)') 'RTSP beats generic web'
    Assert ((Get-RoleFromPorts @()) -eq '') 'no ports yields no role'

    Write-Host "`nReconciliation" -ForegroundColor Cyan
    $recorded = @(
        [pscustomobject]@{ Name = 'DC'; Address = '10.20.1.2'; Enclave = 'SITE'; Segment = 'servers'; Cidr = '10.20.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'File'; Address = '10.20.1.5'; Enclave = 'SITE'; Segment = 'servers'; Cidr = '10.20.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'Web'; Address = '10.20.1.10'; Enclave = 'SITE'; Segment = 'servers'; Cidr = '10.20.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'ControlThings'; Address = '10.40.1.5'; Enclave = 'CPT'; Segment = 'internal'; Cidr = '10.40.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'Sift'; Address = '10.40.1.5'; Enclave = 'CPT'; Segment = 'internal'; Cidr = '10.40.1.0/24'; OS = ''; Role = '' }
    )
    $observed = @(
        [pscustomobject]@{ Name = 'SITE-DC.example.test'; Address = '10.20.1.11'; Source = 'ad' }
        [pscustomobject]@{ Name = 'File'; Address = '10.20.1.5'; Source = 'icmp' }
        [pscustomobject]@{ Name = 'Rogue'; Address = '10.20.1.99'; Source = 'icmp' }
    )
    # Contacted must be supplied: without it the comparison cannot honestly say
    # anything failed to answer, only that it was never checked.
    $f = @(Compare-Terrain -Recorded $recorded -Observed $observed -Probed `
            -Contacted @('10.20.1.2', '10.20.1.5', '10.20.1.10', '10.20.1.11', '10.20.1.99'))
    # PowerShell unrolls single-element arrays on return, so a helper that
    # returns the collection would hand back a scalar with no .Count under
    # StrictMode. Return the integer instead.
    function CountOf([string]$t) { return @($f | Where-Object { $_.Type -eq $t }).Count }

    $ipMismatch = @($f | Where-Object { $_.Type -eq 'IPMismatch' })
    Assert ($ipMismatch.Count -eq 1) 'the DC address discrepancy is found'
    Assert ($ipMismatch[0].RecordedAddress -eq '10.20.1.2' -and
        $ipMismatch[0].ObservedAddress -eq '10.20.1.11') 'it reports both the recorded and the real address'
    Assert ((CountOf 'Confirmed') -eq 1) 'the host that agrees is confirmed'
    Assert ((CountOf 'Missing') -ge 1) 'a host that never answered is reported missing'
    Assert ((CountOf 'Unmapped') -eq 1) 'an address absent from the inventory is flagged'
    Assert ((CountOf 'DuplicateIP') -eq 1) 'two entries on one address are flagged'
    Assert (-not ($f | Where-Object { $_.Type -eq 'Unmapped' -and $_.ObservedAddress -eq '10.20.1.11' })) `
        'the relocated DC is not double-reported as unmapped'

    Write-Host "`nNot contacted is not the same as no response" -ForegroundColor Cyan
    # An on-range run reported 21 CPT tooling hosts as silent when they were in
    # the default exclusion list and had never been probed at all.
    $recS = @(
        [pscustomobject]@{ Name = 'Kali'; Address = '10.40.1.4'; Enclave = 'CPT'
            Segment = 'internal'; Cidr = '10.40.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'Web'; Address = '10.20.1.10'; Enclave = 'SITE'
            Segment = 'servers'; Cidr = '10.20.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'Far'; Address = '10.20.20.5'; Enclave = 'OT'
            Segment = 'services'; Cidr = '10.20.20.0/24'; OS = ''; Role = '' }
    )
    $fS = @(Compare-Terrain -Recorded $recS -Observed @() -Probed `
            -Contacted @('10.20.1.10') -ExcludedCidr @('10.40.1.0/24'))
    $pres = @{}
    foreach ($x in $fS) { $pres[$x.Name] = $x.Presence }
    Assert ($pres['Web'] -eq 'unanswered') 'a probed host that stayed silent is unanswered'
    Assert ($pres['Kali'] -eq 'excluded') 'an excluded host is not claimed to have been checked'
    Assert ($pres['Far'] -eq 'out-of-scope') 'a host outside the scope is reported as such'
    Assert ((@($fS | Where-Object { $_.Type -eq 'Missing' })).Count -eq 1) `
        'only the genuinely silent host counts as Missing'

    # Passive probes nothing, so it may not claim anything is silent.
    $fP = @(Compare-Terrain -Recorded $recS -Observed @())
    Assert ((@($fP | Where-Object { $_.Presence -eq 'unsurveyed' })).Count -eq 3) `
        'a passive run reports unsurveyed, never unanswered'

    Write-Host "`nName matching across conventions" -ForegroundColor Cyan
    # Confirmed against a real DC-side run: the inventory says "DC", the estate
    # answers as "SITE-DC.example.test". Before this, the DC came back as Missing
    # plus a separate Unmapped and no correction was ever applied.
    $rec2 = @(
        [pscustomobject]@{ Name = 'DC'; Address = '10.20.1.2'; Enclave = 'SITE'
            Segment = 'servers'; Cidr = '10.20.1.0/24'; OS = ''; Role = '' }
        [pscustomobject]@{ Name = 'DC'; Address = '10.21.8.250'; Enclave = 'Enclave B'
            Segment = 'domain servers'; Cidr = '10.21.8.0/24'; OS = ''; Role = '' }
    )
    $obs2 = @(
        [pscustomobject]@{ Name = 'SITE-DC.example.test'; Address = '10.20.1.11'; Source = 'ad' }
    )
    $f2 = @(Compare-Terrain -Recorded $rec2 -Observed $obs2 -Probed `
            -Contacted @('10.20.1.2', '10.20.1.11', '10.21.8.250'))
    $m2 = @($f2 | Where-Object { $_.Type -eq 'IPMismatch' })
    Assert ($m2.Count -eq 1) 'a <ENCLAVE>-<ROLE> hostname matches its role-label inventory entry'
    Assert ($m2[0].ObservedAddress -eq '10.20.1.11') 'and reports the real address'
    Assert (@($f2 | Where-Object { $_.Type -eq 'Unmapped' }).Count -eq 0) `
        'the matched host is not also reported as unmapped'
    Assert (@($f2 | Where-Object { $_.Type -eq 'Missing' -and $_.Enclave -eq 'Enclave B' }).Count -eq 1) `
        'the Enclave B DC is NOT captured by the SITE match'

    Write-Host "`nNetwork and broadcast addresses" -ForegroundColor Cyan
    $obs3 = @(
        [pscustomobject]@{ Name = ''; Address = '10.20.1.255'; Source = 'arp' }
        [pscustomobject]@{ Name = ''; Address = '10.20.1.0'; Source = 'arp' }
        [pscustomobject]@{ Name = 'real'; Address = '10.20.1.11'; Source = 'icmp' }
    )
    $kept = @(Remove-NonHostAddress -Observed $obs3 -Cidrs @('10.20.1.0/24'))
    Assert ($kept.Count -eq 1) "broadcast and network addresses dropped (kept $($kept.Count))"
    Assert ($kept[0].Address -eq '10.20.1.11') 'the real host survives'
    Assert (@(Remove-NonHostAddress -Observed $obs3 -Cidrs @()).Count -eq 3) `
        'with no CIDRs supplied nothing is dropped'

    Write-Host "`nCorrected map" -ForegroundColor Cyan
    # The first implementation rebuilt this from a flattened host list and
    # silently dropped every segment with no named host. These assertions
    # exist so that cannot happen again unnoticed.
    $rawJson = @'
{ "source": "test",
  "enclaves": [
    { "key": "diad", "name": "SITE", "cidr": "10.20.0.0/16", "description": "Air Defense network",
      "segments": [
        { "name": "servers", "cidr": "10.20.1.0/24", "note": "",
          "hosts": [ { "name": "DC", "ip": "10.20.1.2", "os": "Windows Server", "role": "", "kind": "win" } ] },
        { "name": "clients", "cidr": "10.20.2.0/24", "note": "Windows 10 client range", "hosts": [] }
      ] },
    { "key": "management", "name": "Management", "cidr": "192.168.3.0/24", "description": "Out-of-band",
      "segments": [] }
  ] }
'@
    $raw = $rawJson | ConvertFrom-Json
    # Shaped as Compare-Terrain emits them, Presence included: that is the
    # contract New-CorrectedTerrain consumes.
    $emitFindings = @(
        [pscustomobject]@{ Type = 'IPMismatch'; Name = 'DC'; RecordedAddress = '10.20.1.2'
            ObservedAddress = '10.20.1.11'; ObservedName = 'SITE-DC.example.test'; Presence = 'relocated' }
        [pscustomobject]@{ Type = 'Unmapped'; Name = ''; RecordedAddress = ''
            ObservedAddress = '10.20.2.37'; ObservedName = 'SITE-WS-1-3'; Presence = 'alive-named' }
        [pscustomobject]@{ Type = 'Unmapped'; Name = ''; RecordedAddress = ''
            ObservedAddress = '203.0.113.9'; ObservedName = ''; Presence = 'alive-unidentified' }
    )
    $out = New-CorrectedTerrain -Raw $raw -Findings $emitFindings -Stamp 'test'

    $outEnc = @($out.enclaves)
    Assert ($outEnc.Count -eq 3) "enclaves preserved plus Unmapped (got $($outEnc.Count))"
    Assert ($null -ne ($outEnc | Where-Object { $_.name -eq 'Management' })) 'a host-less enclave survives'

    $diad = $outEnc | Where-Object { $_.name -eq 'SITE' }
    Assert (@($diad.segments).Count -eq 2) 'a segment with no named hosts survives'
    Assert ($diad.cidr -eq '10.20.0.0/16') 'enclave CIDR preserved'
    Assert ($diad.description -eq 'Air Defense network') 'enclave description preserved'

    $clients = @($diad.segments) | Where-Object { $_.name -eq 'clients' }
    Assert ($clients.note -eq 'Windows 10 client range') 'segment note preserved'

    $servers = @($diad.segments) | Where-Object { $_.name -eq 'servers' }
    Assert ((@($servers.hosts)[0]).ip -eq '10.20.1.11') 'the DC address correction is applied'
    Assert ((@($servers.hosts)[0]).name -eq 'DC') 'the corrected host keeps its name'

    $ws = @($clients.hosts) | Where-Object { $_.ip -eq '10.20.2.37' }
    Assert ($null -ne $ws) 'a discovered host lands in the segment whose CIDR contains it'
    Assert ($ws.source -eq 'survey') 'discovered hosts are marked as survey-sourced'

    $unmappedEnc = $outEnc | Where-Object { $_.name -eq 'Unmapped' }
    Assert ($null -ne $unmappedEnc) 'a discovery outside every CIDR still gets a home'
    Assert ((@((@($unmappedEnc.segments)[0]).hosts)[0]).ip -eq '203.0.113.9') 'the orphan is the out-of-scope address'

    # 1 recorded host + 2 discoveries, each appearing exactly once.
    Write-Host "`nPresence annotation" -ForegroundColor Cyan
    $allHosts = @($outEnc | ForEach-Object { $_.segments } | ForEach-Object { $_.hosts })
    Assert (@($allHosts | Where-Object { -not $_.presence }).Count -eq 0) 'every host carries a presence value'
    Assert (@($allHosts | Where-Object { -not $_.presenceNote }).Count -eq 0) 'every host carries a readable note'

    $dcOut = $allHosts | Where-Object { $_.name -eq 'DC' }
    Assert ($dcOut.presence -eq 'relocated') 'the moved DC is annotated relocated'

    $ws = $allHosts | Where-Object { $_.ip -eq '10.20.2.37' }
    Assert ($ws.presence -eq 'alive-named') 'a named discovery is alive-named'

    $orphan = $allHosts | Where-Object { $_.ip -eq '203.0.113.9' }
    Assert ($orphan.presence -eq 'alive-unidentified') 'an unnamed discovery is alive but unidentified'
    Assert ($orphan.presenceNote -eq 'Alive but unidentified') 'and says so in plain words'

    # A gateway beside the workstations reads as an unexplained host.
    $gwFindings = @(
        [pscustomobject]@{ Type = 'Unmapped'; Name = ''; RecordedAddress = ''
            ObservedAddress = '10.20.2.1'; ObservedName = ''; Presence = 'alive-unidentified' }
    )
    $gwOut = New-CorrectedTerrain -Raw $raw -Findings $gwFindings -Stamp 'test'
    $gw = @($gwOut.enclaves | ForEach-Object { $_.segments } | ForEach-Object { $_.hosts }) |
        Where-Object { $_.ip -eq '10.20.2.1' }
    Assert ($gw.presence -eq 'infrastructure') 'the first usable address is tagged infrastructure'
    Assert ($gw.role -eq 'Gateway') 'and given a Gateway role'
    Assert (Test-IsGatewayAddress -Address '10.20.30.1' -Cidr '10.20.30.0/24') 'gateway detection works on a /24'
    Assert (-not (Test-IsGatewayAddress -Address '10.20.30.25' -Cidr '10.20.30.0/24')) 'a workstation is not a gateway'

    $allOut = @($outEnc | ForEach-Object { $_.segments } | ForEach-Object { $_.hosts })
    Assert ($allOut.Count -eq 3) "no host is lost or duplicated (got $($allOut.Count))"
    Assert (@($allOut.ip | Sort-Object -Unique).Count -eq 3) 'no address appears twice'

    Write-Host "`nExclusions" -ForegroundColor Cyan
    $excluded = @(Select-SurveyTarget -Addresses @('10.40.1.15', '10.20.1.5', '10.40.2.201') `
        -ExcludeAddress @('10.40.2.201') -ExcludeCidr @('10.40.1.0/24'))
    Assert ($excluded -notcontains '10.40.1.15') 'tooling CIDR excluded'
    Assert ($excluded -notcontains '10.40.2.201') 'off-limits address excluded'
    Assert ($excluded -contains '10.20.1.5') 'defended terrain retained'

    Write-Host ''
    if ($failures.Count -eq 0) {
        Write-Host "Self-test passed." -ForegroundColor Green
        return 0
    }
    Write-Host "$($failures.Count) self-test failure(s)." -ForegroundColor Red
    return 1
}

#endregion SELFTEST

#region MAIN

function Select-SurveyTarget {
    <#
        The exclusion gate. Every address that will be contacted passes through
        here, so an off-limits host cannot be reached by any code path.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Addresses,
        [string[]]$ExcludeAddress = @(),
        [string[]]$ExcludeCidr = @()
    )
    $out = New-Object System.Collections.ArrayList
    foreach ($a in $Addresses) {
        if ($ExcludeAddress -contains $a) { continue }
        $skip = $false
        foreach ($c in $ExcludeCidr) {
            if (Test-AddressInCidr -Address $a -Cidr $c) { $skip = $true; break }
        }
        if (-not $skip) { $null = $out.Add($a) }
    }
    return $out.ToArray()
}

if ($SelfTest) { exit (Invoke-SelfTest) }

if (-not $TerrainPath) {
    $TerrainPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'terrain\terrain.json'
}

Write-Host ''
Write-Host '  Terrain Survey' -ForegroundColor Cyan
Write-Host "  method   $Method"
Write-Host "  terrain  $TerrainPath"

$terrain = Import-Terrain -Path $TerrainPath
Write-Host "  recorded $($terrain.Hosts.Count) hosts across $($terrain.Segments.Count) segments"

if (-not $Scope) { $Scope = @($terrain.Segments.Cidr | Sort-Object -Unique) }

$targets = New-Object System.Collections.ArrayList
foreach ($cidr in $Scope) {
    try { foreach ($a in (Expand-Cidr -Cidr $cidr -MaxPrefix $MaxPrefix)) { $null = $targets.Add($a) } }
    catch { Write-Warning $_.Exception.Message }
}
$targets = Select-SurveyTarget -Addresses $targets.ToArray() -ExcludeAddress $ExcludeAddress -ExcludeCidr $ExcludeCidr

# The cap bounds how much traffic a sweep can generate, so it only applies to
# methods that generate any. Passive reads local caches and AD; blocking it on
# scope size would refuse a completely safe operation.
if ($Method -ne 'Passive' -and $targets.Count -gt $MaxHosts) {
    throw ("Scope expands to $($targets.Count) addresses, over -MaxHosts $MaxHosts. " +
        'Narrow -Scope or raise -MaxHosts deliberately.')
}
Write-Host "  scope    $($targets.Count) addresses after exclusions"
Write-Host ''

$observed = @{}

# --- passive ------------------------------------------------------------
Write-Host 'Passive sources (no traffic to targets)...' -ForegroundColor Cyan
foreach ($p in (Get-PassiveObservation -DomainController $DomainController -Credential $Credential)) {
    $key = if ($p.Address) { $p.Address } else { "name:$(Get-ShortName $p.Name)" }
    $observed[$key] = $p
}
Write-Host "  $($observed.Count) observations from ARP, DNS cache and Active Directory"

# --- standard and active ------------------------------------------------
if ($Method -ne 'Passive') {
    if ($PSCmdlet.ShouldProcess("$($targets.Count) addresses", "ICMP sweep")) {
        Write-Deconfliction -Action 'ICMP sweep' -Target ($Scope -join ',') -Detail "$($targets.Count) addresses"
        Write-Host 'ICMP sweep...' -ForegroundColor Cyan

        foreach ($a in (Invoke-IcmpSweep -Addresses $targets -TimeoutMs $TimeoutMs -Concurrency $Concurrency)) {
            $name = Resolve-AddressName -Address $a.Address
            $existing = $null
            if ($observed.ContainsKey($a.Address)) { $existing = $observed[$a.Address] }
            $observed[$a.Address] = [pscustomobject]@{
                Address = $a.Address
                Name    = $(if ($name) { $name } elseif ($existing) { $existing.Name } else { '' })
                Source  = 'icmp'
                Mac     = $(if ($existing -and $existing.PSObject.Properties['Mac']) { $existing.Mac } else { '' })
                OS      = $a.OSHint
                Ttl     = $a.Ttl
                Ports   = @()
                Role    = ''
            }
        }
        $live = @($observed.Values | Where-Object { $_.Source -eq 'icmp' })
        Write-Host "  $($live.Count) hosts answered"

        if ($Method -eq 'Active') {
            if ($PSCmdlet.ShouldProcess("$($live.Count) live hosts", 'TCP service probe')) {
                Write-Deconfliction -Action 'TCP connect probe' -Target ($live.Address -join ',') `
                    -Detail "ports: $($script:ProbePorts.Keys -join ',')"
                Write-Host 'Service probe...' -ForegroundColor Cyan
                $n = 0
                foreach ($h in $live) {
                    $n++
                    Write-Progress -Activity 'Service probe' -Status $h.Address `
                        -PercentComplete (100 * $n / [math]::Max(1, $live.Count))
                    $ports = Invoke-PortProbe -Address $h.Address -TimeoutMs $TimeoutMs
                    $h.Ports = $ports
                    $h.Role = Get-RoleFromPorts -Ports $ports
                }
                Write-Progress -Activity 'Service probe' -Completed
                Write-Host "  probed $($live.Count) hosts"
            }
        }
    }
}

# --- reconcile ----------------------------------------------------------
Write-Host ''
Write-Host 'Reconciling against the recorded map...' -ForegroundColor Cyan
$observedList = Remove-NonHostAddress -Observed @($observed.Values) -Cidrs @($terrain.Segments.Cidr | Sort-Object -Unique)
$findings = Compare-Terrain -Recorded $terrain.Hosts -Observed $observedList `
    -Contacted $targets -ExcludedCidr $ExcludeCidr -ExcludedAddress $ExcludeAddress `
    -Probed:($Method -ne 'Passive')

$summary = $findings | Group-Object Type | Sort-Object Name
foreach ($g in $summary) {
    $colour = switch ($g.Name) {
        'Confirmed' { 'Green' }
        'IPMismatch' { 'Red' }
        'NameMismatch' { 'Red' }
        'DuplicateIP' { 'Yellow' }
        'Unmapped' { 'Yellow' }
        default { 'Gray' }
    }
    Write-Host ("  {0,-14} {1}" -f $g.Name, $g.Count) -ForegroundColor $colour
}

Write-Host ''
Write-Host 'Presence:' -ForegroundColor Cyan
foreach ($g in ($findings | Where-Object { $_.Presence } | Group-Object Presence | Sort-Object Count -Descending)) {
    $label = $script:PresenceLabel[$g.Name]
    if (-not $label) { $label = $g.Name }
    $colour = switch ($g.Name) {
        'confirmed' { 'Green' }
        'relocated' { 'Red' }
        'alive-unidentified' { 'Yellow' }
        'alive-named' { 'Yellow' }
        default { 'Gray' }
    }
    Write-Host ("  {0,4}  {1}" -f $g.Count, $label) -ForegroundColor $colour
}

$corrections = @($findings | Where-Object { $_.Type -in @('IPMismatch', 'NameMismatch') })
if ($corrections.Count -gt 0) {
    Write-Host ''
    Write-Host 'Corrections needed:' -ForegroundColor Red
    foreach ($c in $corrections) {
        Write-Host ("  {0,-22} {1,-16} -> {2}" -f $c.Name, $c.RecordedAddress, $c.ObservedAddress)
    }
}

# --- output -------------------------------------------------------------
if (-not (Test-Path -LiteralPath $OutputPath)) {
    $null = New-Item -ItemType Directory -Path $OutputPath -Force
}
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')

$reportPath = Join-Path $OutputPath "terrain-discrepancies-$stamp.csv"
$findings | Sort-Object Type, Name | Export-Csv -LiteralPath $reportPath -NoTypeInformation -Encoding UTF8

$observedPath = Join-Path $OutputPath "survey-observed-$stamp.json"
Write-JsonFile -Path $observedPath -Text (@($observed.Values) | ConvertTo-Json -Depth 6)

$deconPath = Join-Path $OutputPath "deconfliction-$stamp.csv"
if ($script:Deconfliction.Count -gt 0) {
    $script:Deconfliction | Export-Csv -LiteralPath $deconPath -NoTypeInformation -Encoding UTF8
}

Write-Host ''
Write-Host "  discrepancies  $reportPath"
Write-Host "  observations   $observedPath"
if ($script:Deconfliction.Count -gt 0) {
    Write-Host "  deconfliction  $deconPath" -ForegroundColor Yellow
    Write-Host '                 hand this to the hunt cell so your own traffic is ruled out' -ForegroundColor Yellow
}

if ($EmitTerrain) {
    $raw = Get-Content -LiteralPath $TerrainPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $corrected = New-CorrectedTerrain -Raw $raw -Findings $findings -Stamp $stamp
    $terrainOut = Join-Path $OutputPath "terrain-corrected-$stamp.json"
    Write-JsonFile -Path $terrainOut -Text ($corrected | ConvertTo-Json -Depth 10)

    $segIn = @($raw.enclaves | ForEach-Object { $_.segments }).Count
    $segOut = @($corrected.enclaves | ForEach-Object { $_.segments }).Count
    Write-Host "  corrected map  $terrainOut" -ForegroundColor Green
    Write-Host ("                 {0} enclaves, {1} segments preserved (was {2}/{3})" -f `
            @($corrected.enclaves).Count, $segOut, @($raw.enclaves).Count, $segIn) -ForegroundColor Green
    Write-Host '                 review it, then copy it over the profile terrain' -ForegroundColor Green
}

Write-Host ''

#endregion MAIN
