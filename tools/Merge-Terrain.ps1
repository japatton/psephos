#Requires -Version 5.1
<#
.SYNOPSIS
    Merges terrain surveys taken from different vantage points into one map.

.DESCRIPTION
    No single vantage point sees the whole estate. A run from the SITE domain
    controller enumerates every workstation range and sees nothing in OT; a run
    from the DIP sees OT and Enclave B and nothing of the SITE clients. Both are
    correct. Neither is complete.

    The governing rule is that a positive observation beats a negative one.
    A host that answered from anywhere is alive; silence from a different
    vantage point is a fact about routing, not about the host. So presence
    values are ranked and the strongest observation wins:

        relocated > confirmed = alive-named > alive-unidentified >
        infrastructure > evidence-only > unanswered > out-of-scope >
        excluded > unsurveyed

    Every host records which vantage point saw what, so a disagreement stays
    visible instead of being flattened away. A box that answers from the DIP
    but not from the DC is telling you something about the path between them.

    Analyst edits survive. Hand-entered FQDNs and roles are richer than
    anything the survey produces, so the longest qualified name and any
    non-empty role or OS are carried forward.

.PARAMETER Path
    Two or more corrected-terrain JSON files.

.PARAMETER Label
    Vantage point names, positionally matched to Path. Defaults to the
    timestamp in each file's source field.

.PARAMETER OutFile
    Where to write the merged map. Defaults to terrain-merged.json beside the
    first input.

.PARAMETER SelfTest
    Validates ranking, provenance and analyst-edit preservation offline.

.EXAMPLE
    .\Merge-Terrain.ps1 -Path dc.json,dip.json -Label 'SITE-DC','DIP' -OutFile merged.json

.NOTES
    Windows PowerShell 5.1. Read-only with respect to its inputs.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string[]]$Label = @(),
    [string]$OutFile,
    [switch]$SelfTest
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

#region CONFIG

<#
    Higher wins. The ordering encodes one judgement: anything that answered
    outranks anything that did not, and "we never looked" outranks nothing.

    relocated sits above confirmed because it carries strictly more
    information — the host answered AND the inventory is wrong about where.
#>
$script:PresenceRank = @{
    'relocated'          = 60
    'confirmed'          = 50
    'alive-named'        = 50
    'alive-unidentified' = 45
    'infrastructure'     = 40
    'evidence-only'      = 20
    'unanswered'         = 10
    'out-of-scope'       = 5
    'excluded'           = 2
    'unsurveyed'         = 0
}

$script:PresenceLabel = @{
    'confirmed'          = 'Confirmed at recorded address'
    'relocated'          = 'Alive at a different address than recorded'
    'unanswered'         = 'Probed, no response from any vantage point'
    'excluded'           = 'Not contacted: excluded from every survey scope'
    'out-of-scope'       = 'Not contacted: outside every surveyed range'
    'alive-named'        = 'Alive and named, not in inventory'
    'alive-unidentified' = 'Alive but unidentified'
    'infrastructure'     = 'Alive, segment gateway'
    'evidence-only'      = 'Named in evidence, not surveyed'
    'unsurveyed'         = 'No survey has covered it'
}

#endregion CONFIG

#region HELPERS

function Get-Prop {
    param($Object, [string]$Name, $Default = '')
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function Get-Rank {
    param([string]$Presence)
    if ($Presence -and $script:PresenceRank.ContainsKey($Presence)) { return $script:PresenceRank[$Presence] }
    return -1
}

function Test-IsRealHostAddress {
    <#
        Multicast, loopback and link-local are never hosts. A run picked up
        239.255.255.250 (SSDP) from the surveying box's own traffic.

        Public addresses are NOT filtered: 203.0.113.25 and 203.0.113.101 are
        the adversary C2 servers, and dropping public space to tidy the map
        would discard the most important entries in it.
    #>
    param([string]$Address)
    if (-not $Address) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $false }
    $o = $ip.GetAddressBytes()
    if ($o[0] -ge 224 -and $o[0] -le 239) { return $false }   # multicast
    if ($o[0] -eq 255) { return $false }                       # broadcast
    if ($o[0] -eq 127) { return $false }                       # loopback
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }    # link-local
    if ($o[0] -eq 0) { return $false }
    return $true
}

function Select-BetterName {
    <#
        A hand-entered FQDN outranks anything the survey produced, and both
        outrank a bare address standing in for a name.
    #>
    param([string]$A, [string]$B)
    $aIsAddr = $A -match '^\d{1,3}(\.\d{1,3}){3}$'
    $bIsAddr = $B -match '^\d{1,3}(\.\d{1,3}){3}$'
    if ($A -and -not $aIsAddr -and ($bIsAddr -or -not $B)) { return $A }
    if ($B -and -not $bIsAddr -and ($aIsAddr -or -not $A)) { return $B }
    if ($A -and $B) {
        # Both real names: prefer the qualified one, then the longer.
        if ($A.Contains('.') -and -not $B.Contains('.')) { return $A }
        if ($B.Contains('.') -and -not $A.Contains('.')) { return $B }
        if ($A.Length -ge $B.Length) { return $A }
        return $B
    }
    if ($A) { return $A }
    return $B
}

function Select-Richer { param([string]$A, [string]$B) if ($A) { return $A } return $B }

#endregion HELPERS

#region MERGE

function Merge-HostRecord {
    <#
        One host, as seen from several vantage points. Keeps the strongest
        presence, the richest identity, and a record of who saw what.
    #>
    param($Existing, $Incoming, [string]$Vantage)

    if ($null -eq $Existing) {
        return [ordered]@{
            name         = Get-Prop $Incoming 'name'
            ip           = Get-Prop $Incoming 'ip'
            os           = Get-Prop $Incoming 'os'
            role         = Get-Prop $Incoming 'role'
            kind         = Get-Prop $Incoming 'kind'
            source       = Get-Prop $Incoming 'source' 'inventory'
            presence     = Get-Prop $Incoming 'presence' 'unsurveyed'
            presenceNote = Get-Prop $Incoming 'presenceNote'
            observedFrom = @("$Vantage=$(Get-Prop $Incoming 'presence' 'unsurveyed')")
        }
    }

    $inPres = Get-Prop $Incoming 'presence' 'unsurveyed'
    $exPres = [string]$Existing.presence

    # Strongest observation wins. An answer from anywhere beats silence.
    if ((Get-Rank $inPres) -gt (Get-Rank $exPres)) {
        $Existing.presence = $inPres
        $Existing.presenceNote = $(
            if ($script:PresenceLabel.ContainsKey($inPres)) { $script:PresenceLabel[$inPres] }
            else { Get-Prop $Incoming 'presenceNote' })
        # A relocation carries the corrected address with it.
        if ($inPres -eq 'relocated') { $Existing.ip = Get-Prop $Incoming 'ip' }
    }

    $Existing.name = Select-BetterName $Existing.name (Get-Prop $Incoming 'name')
    $Existing.os = Select-Richer $Existing.os (Get-Prop $Incoming 'os')
    $Existing.role = Select-Richer $Existing.role (Get-Prop $Incoming 'role')
    $Existing.kind = Select-Richer $Existing.kind (Get-Prop $Incoming 'kind')
    if ((Get-Prop $Incoming 'source') -eq 'inventory') { $Existing.source = 'inventory' }

    $Existing.observedFrom = @($Existing.observedFrom) + @("$Vantage=$inPres")
    return $Existing
}

function Get-ShortHostName {
    <#
        An address standing in for a name is not a name. Splitting
        "10.21.2.16" on the dot yields "150", which every unnamed host in a
        /24 shares — a merge keyed on that collapsed 26 hosts into one and
        took the exfil destination with it. Return empty so the caller falls
        through to address matching.
    #>
    param([string]$Name)
    if (-not $Name) { return '' }
    $n = $Name.Trim()
    if (-not $n) { return '' }

    # An address is not a name.
    if ($n -match '^\d{1,3}(\.\d{1,3}){3}$') { return '' }

    # Multi-word inventory labels are whole names. Splitting them on
    # whitespace made "IP Cam 1".."IP Cam 6" all collapse to "ip", and
    # OpenPLC SubstationA/B/C to "openplc", losing ten real OT hosts.
    if ($n -match '\s') { return $n.ToLowerInvariant() }

    # Only a hostname gets its DNS domain stripped.
    return ($n -split '\.')[0].ToLowerInvariant()
}

function Find-HostKey {
    <#
        The existing entry this incoming host is the same box as, or $null for
        something new. Name wins over address so a shared address does not
        merge two distinct tools; address is the fallback so a rename does not
        split one host into two.
    #>
    param($Segment, $Incoming, [hashtable]$Claimed)

    $nm = Get-ShortHostName ([string](Get-Prop $Incoming 'name'))
    $ip = [string](Get-Prop $Incoming 'ip')
    $isInv = (Get-Prop $Incoming 'source') -eq 'inventory'

    <#
        Name matching is for inventory entries only. There it means "the same
        recorded host, possibly relocated" — SITE-DC at .2 and at .11.

        A survey discovery IS its address: two addresses that both resolve to
        www.bing.com are two endpoints behind a CDN, not one host, and merging
        them would erase a live address from the map.
    #>
    if ($nm -and $isInv) {
        foreach ($k in $Segment.hosts.Keys) {
            if ([string]$Segment.hosts[$k].source -ne 'inventory') { continue }
            $existingShort = Get-ShortHostName ([string]$Segment.hosts[$k].name)
            if ($existingShort -and $existingShort -eq $nm) { return $k }
        }
    }
    if ($ip) {
        foreach ($k in $Segment.hosts.Keys) {
            if ([string]$Segment.hosts[$k].ip -eq $ip -and -not $Claimed.ContainsKey($k)) { return $k }
        }
    }
    return $null
}

function Merge-Terrain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Maps,
        [Parameter(Mandatory)][string[]]$Vantages
    )

    $enclaves = [ordered]@{}
    $dropped = New-Object System.Collections.ArrayList

    for ($m = 0; $m -lt $Maps.Count; $m++) {
        $map = $Maps[$m]
        $vantage = $Vantages[$m]
        # Reset per file: one incoming host may claim one existing entry.
        $claimed = @{}

        foreach ($e in $map.enclaves) {
            $ek = [string](Get-Prop $e 'key' (Get-Prop $e 'name'))
            if (-not $enclaves.Contains($ek)) {
                $enclaves[$ek] = [ordered]@{
                    key = $ek; name = (Get-Prop $e 'name'); cidr = (Get-Prop $e 'cidr')
                    description = (Get-Prop $e 'description'); segments = [ordered]@{}
                }
            }
            $enc = $enclaves[$ek]
            $enc.cidr = Select-Richer $enc.cidr (Get-Prop $e 'cidr')
            $enc.description = Select-Richer $enc.description (Get-Prop $e 'description')

            foreach ($sg in (Get-Prop $e 'segments' @())) {
                $sk = "$(Get-Prop $sg 'name')|$(Get-Prop $sg 'cidr')"
                if (-not $enc.segments.Contains($sk)) {
                    $enc.segments[$sk] = [ordered]@{
                        name = (Get-Prop $sg 'name'); cidr = (Get-Prop $sg 'cidr')
                        note = (Get-Prop $sg 'note'); hosts = [ordered]@{}
                    }
                }
                $seg = $enc.segments[$sk]
                $seg.note = Select-Richer $seg.note (Get-Prop $sg 'note')

                foreach ($h in (Get-Prop $sg 'hosts' @())) {
                    $ip = [string](Get-Prop $h 'ip')
                    $nm = [string](Get-Prop $h 'name')

                    if ($ip -and -not (Test-IsRealHostAddress $ip)) {
                        $null = $dropped.Add("$ip ($nm) - not a host address")
                        continue
                    }

                    <#
                        Matching by name alone breaks when the analyst renames
                        a host in one file: "Exchange" and "SITE-MAIL.example.test"
                        are the same box. Matching by address alone breaks the
                        opposite way: ControlThings and Sift genuinely share
                        10.40.1.5 and must stay two hosts.

                        So: name first, then address among entries no incoming
                        host has already claimed this round.
                    #>
                    $key = Find-HostKey -Segment $seg -Incoming $h -Claimed $claimed
                    if (-not $key) {
                        $key = "h$($seg.hosts.Count)|$nm|$ip"
                    }
                    $claimed[$key] = $true
                    $seg.hosts[$key] = Merge-HostRecord $(
                        if ($seg.hosts.Contains($key)) { $seg.hosts[$key] } else { $null }
                    ) $h $vantage
                }
            }
        }
    }

    $out = [ordered]@{
        source   = "Merge-Terrain of $($Vantages -join ' + ')"
        vantages = @($Vantages)
        enclaves = @(foreach ($enc in $enclaves.Values) {
                [ordered]@{
                    key = $enc.key; name = $enc.name; cidr = $enc.cidr
                    description = $enc.description
                    segments = @(foreach ($seg in $enc.segments.Values) {
                            [ordered]@{
                                name = $seg.name; cidr = $seg.cidr; note = $seg.note
                                hosts = @(foreach ($h in $seg.hosts.Values) {
                                        $h.observedFrom = @($h.observedFrom | Sort-Object -Unique)
                                        $h
                                    })
                            }
                        })
                }
            })
    }
    return [pscustomobject]@{ Terrain = $out; Dropped = $dropped.ToArray() }
}

#endregion MERGE

#region SELFTEST

function Invoke-SelfTest {
    $fails = New-Object System.Collections.ArrayList
    function Assert([bool]$c, [string]$m) {
        if ($c) { Write-Host "  PASS  $m" -ForegroundColor Green }
        else { Write-Host "  FAIL  $m" -ForegroundColor Red; $null = $fails.Add($m) }
    }

    $mk = {
        param($hosts)
        [pscustomobject]@{ enclaves = @([pscustomobject]@{
                    key = 'diad'; name = 'SITE'; cidr = '10.20.0.0/16'; description = 'Air Defense'
                    segments = @([pscustomobject]@{
                            name = 'servers'; cidr = '10.20.1.0/24'; note = ''; hosts = $hosts
                        })
                }) }
    }

    Write-Host "`nPresence precedence" -ForegroundColor Cyan
    $A = & $mk @([pscustomobject]@{ name = 'Web'; ip = '10.20.1.10'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'confirmed'; presenceNote = 'x' })
    $B = & $mk @([pscustomobject]@{ name = 'Web'; ip = '10.20.1.10'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'unanswered'; presenceNote = 'y' })
    $r = Merge-Terrain -Maps @($B, $A) -Vantages @('DC', 'DIP')
    $web = $r.Terrain.enclaves[0].segments[0].hosts[0]
    Assert ($web.presence -eq 'confirmed') 'an answer from one vantage beats silence from another'
    Assert (@($web.observedFrom).Count -eq 2) 'both vantage points are recorded'
    Assert ((@($web.observedFrom) -join ',') -match 'DC=unanswered') 'the disagreement stays visible'

    $E = & $mk @([pscustomobject]@{ name = 'Kali'; ip = '10.40.1.4'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'excluded'; presenceNote = '' })
    $C = & $mk @([pscustomobject]@{ name = 'Kali'; ip = '10.40.1.4'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'confirmed'; presenceNote = '' })
    $r2 = Merge-Terrain -Maps @($E, $C) -Vantages @('DC', 'DIP')
    Assert ($r2.Terrain.enclaves[0].segments[0].hosts[0].presence -eq 'confirmed') `
        'a host excluded from one scope but seen from another is alive'

    Write-Host "`nRelocation carries its address" -ForegroundColor Cyan
    $R1 = & $mk @([pscustomobject]@{ name = 'DC'; ip = '10.20.1.2'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'unanswered'; presenceNote = '' })
    $R2 = & $mk @([pscustomobject]@{ name = 'DC'; ip = '10.20.1.11'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'relocated'; presenceNote = '' })
    $r3 = Merge-Terrain -Maps @($R1, $R2) -Vantages @('a', 'b')
    $dc = $r3.Terrain.enclaves[0].segments[0].hosts[0]
    Assert ($dc.presence -eq 'relocated') 'relocated outranks unanswered'
    Assert ($dc.ip -eq '10.20.1.11') 'and the corrected address comes with it'

    Write-Host "`nAnalyst edits survive" -ForegroundColor Cyan
    $P = & $mk @([pscustomobject]@{ name = 'SITE-MAIL.example.test'; ip = '10.20.1.12'; os = 'Windows Server'
            role = 'Exchange Server'; kind = 'win'; source = 'inventory'; presence = 'confirmed'; presenceNote = '' })
    $Q = & $mk @([pscustomobject]@{ name = 'Exchange'; ip = '10.20.1.12'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'unanswered'; presenceNote = '' })
    $r4 = Merge-Terrain -Maps @($Q, $P) -Vantages @('a', 'b')
    $ex = $r4.Terrain.enclaves[0].segments[0].hosts[0]
    Assert ($ex.name -eq 'SITE-MAIL.example.test') 'a hand-entered FQDN beats the inventory label'
    Assert ($ex.role -eq 'Exchange Server') 'a hand-entered role is not overwritten by blank'
    Assert ($ex.os -eq 'Windows Server') 'OS is carried forward'

    Write-Host "`nNon-host addresses" -ForegroundColor Cyan
    $M = & $mk @(
        [pscustomobject]@{ name = '239.255.255.250'; ip = '239.255.255.250'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-unidentified'; presenceNote = '' }
        [pscustomobject]@{ name = 'c2'; ip = '203.0.113.25'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-named'; presenceNote = '' }
    )
    $r5 = Merge-Terrain -Maps @($M) -Vantages @('a')
    $ips = @($r5.Terrain.enclaves[0].segments[0].hosts | ForEach-Object { $_.ip })
    Assert ($ips -notcontains '239.255.255.250') 'multicast is dropped'
    Assert ($ips -contains '203.0.113.25') 'public addresses are kept: the C2 servers live there'
    Assert (@($r5.Dropped).Count -eq 1) 'what was dropped is reported, not silent'

    Write-Host "`nTwo inventory hosts on one address" -ForegroundColor Cyan
    $D = & $mk @(
        [pscustomobject]@{ name = 'ControlThings'; ip = '10.40.1.5'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'confirmed'; presenceNote = '' }
        [pscustomobject]@{ name = 'Sift'; ip = '10.40.1.5'; os = ''; role = ''; kind = ''
            source = 'inventory'; presence = 'confirmed'; presenceNote = '' }
    )
    $r6 = Merge-Terrain -Maps @($D, $D) -Vantages @('a', 'b')
    Assert (@($r6.Terrain.enclaves[0].segments[0].hosts).Count -eq 2) `
        'both survive a merge rather than collapsing into one'

    Write-Host "`nUnnamed hosts in one subnet" -ForegroundColor Cyan
    # Bare addresses used as names all share a first dot-component. Keying on
    # that collapsed an entire /24 into a single host on real data.
    $bare = & $mk @(
        [pscustomobject]@{ name = '10.21.2.11'; ip = '10.21.2.11'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-unidentified'; presenceNote = '' }
        [pscustomobject]@{ name = '10.21.2.16'; ip = '10.21.2.16'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-unidentified'; presenceNote = '' }
        [pscustomobject]@{ name = '10.21.2.35'; ip = '10.21.2.35'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-unidentified'; presenceNote = '' }
    )
    $rb = Merge-Terrain -Maps @($bare, $bare) -Vantages @('a', 'b')
    $kept = @($rb.Terrain.enclaves[0].segments[0].hosts)
    Assert ($kept.Count -eq 3) "three unnamed hosts stay three (got $($kept.Count))"
    Assert (@($kept | ForEach-Object { $_.ip }) -contains '10.21.2.16') 'the exfil destination survives'
    Assert (@($kept | ForEach-Object { $_.ip } | Sort-Object -Unique).Count -eq 3) 'and none are duplicated'

    Assert ((Get-ShortHostName '10.21.2.16') -eq '') 'an address is not treated as a name'
    Assert ((Get-ShortHostName 'SITE-MAIL.example.test') -eq 'site-mail') 'a real hostname still shortens'

    Write-Host "`nMulti-word inventory names" -ForegroundColor Cyan
    $ot = & $mk @(
        [pscustomobject]@{ name = 'IP Cam 1'; ip = '10.20.40.10'; os = 'Ubuntu'; role = ''; kind = 'nix'
            source = 'inventory'; presence = 'confirmed'; presenceNote = '' }
        [pscustomobject]@{ name = 'IP Cam 2'; ip = '10.20.40.20'; os = 'Ubuntu'; role = ''; kind = 'nix'
            source = 'inventory'; presence = 'confirmed'; presenceNote = '' }
        [pscustomobject]@{ name = 'OpenPLC SubstationA'; ip = '10.125.10.110'; os = 'Ubuntu'; role = 'PLC'
            kind = 'nix'; source = 'inventory'; presence = 'confirmed'; presenceNote = '' }
        [pscustomobject]@{ name = 'OpenPLC SubstationB'; ip = '10.125.10.111'; os = 'Ubuntu'; role = 'PLC'
            kind = 'nix'; source = 'inventory'; presence = 'confirmed'; presenceNote = '' }
    )
    $ro = Merge-Terrain -Maps @($ot, $ot) -Vantages @('a', 'b')
    $keptOt = @($ro.Terrain.enclaves[0].segments[0].hosts)
    Assert ($keptOt.Count -eq 4) "multi-word names stay distinct (got $($keptOt.Count))"
    Assert ((Get-ShortHostName 'IP Cam 1') -ne (Get-ShortHostName 'IP Cam 2')) 'IP Cam 1 and 2 are different hosts'
    Assert ((Get-ShortHostName 'OpenPLC SubstationA') -ne (Get-ShortHostName 'OpenPLC SubstationB')) `
        'OpenPLC A and B are different hosts'
    Assert ((Get-ShortHostName 'SITE-MAIL.example.test') -eq 'site-mail') 'an FQDN still loses its domain'

    Write-Host "`nNothing is lost" -ForegroundColor Cyan
    # The merge is a union. Anything in an input and not in the output is a bug
    # unless it was explicitly reported as dropped.
    $u1 = & $mk @(
        [pscustomobject]@{ name = 'www.bing.com'; ip = '203.0.113.200'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-named'; presenceNote = '' }
        [pscustomobject]@{ name = 'www.bing.com'; ip = '203.0.113.201'; os = ''; role = ''; kind = ''
            source = 'survey'; presence = 'alive-named'; presenceNote = '' }
    )
    $ru = Merge-Terrain -Maps @($u1) -Vantages @('a')
    Assert (@($ru.Terrain.enclaves[0].segments[0].hosts).Count -eq 2) `
        'two addresses sharing one resolved name stay two hosts'

    Write-Host "`nStructure" -ForegroundColor Cyan
    $S1 = [pscustomobject]@{ enclaves = @([pscustomobject]@{ key = 'a'; name = 'A'; cidr = ''; description = ''
                segments = @([pscustomobject]@{ name = 's1'; cidr = '10.0.0.0/24'; note = 'keep me'; hosts = @() }) }) }
    $S2 = [pscustomobject]@{ enclaves = @([pscustomobject]@{ key = 'b'; name = 'B'; cidr = ''; description = ''
                segments = @([pscustomobject]@{ name = 's2'; cidr = '10.0.1.0/24'; note = ''; hosts = @() }) }) }
    $r7 = Merge-Terrain -Maps @($S1, $S2) -Vantages @('a', 'b')
    Assert (@($r7.Terrain.enclaves).Count -eq 2) 'enclaves from both files are kept'
    Assert ($r7.Terrain.enclaves[0].segments[0].note -eq 'keep me') 'empty segments and their notes survive'

    Write-Host ''
    if ($fails.Count -eq 0) { Write-Host 'Self-test passed.' -ForegroundColor Green; return 0 }
    Write-Host "$($fails.Count) failure(s)." -ForegroundColor Red
    return 1
}

#endregion SELFTEST

#region MAIN

if ($SelfTest) { exit (Invoke-SelfTest) }

if (-not $Path -or $Path.Count -lt 2) { throw 'Give at least two files with -Path.' }

$maps = @()
$vantages = @()
for ($i = 0; $i -lt $Path.Count; $i++) {
    $raw = Get-Content -LiteralPath $Path[$i] -Raw -Encoding UTF8 | ConvertFrom-Json
    $maps += $raw
    $v = if ($i -lt $Label.Count -and $Label[$i]) { $Label[$i] }
    elseif ((Get-Prop $raw 'source') -match '(\d{8}-\d{6})') { $Matches[1] }
    else { "file$($i + 1)" }
    $vantages += $v
    Write-Host "  $v  <- $($Path[$i])"
}

$result = Merge-Terrain -Maps $maps -Vantages $vantages
$merged = $result.Terrain

$allHosts = @($merged.enclaves | ForEach-Object { $_.segments } | ForEach-Object { $_.hosts })
Write-Host ''
Write-Host "  merged $($allHosts.Count) hosts across $(@($merged.enclaves).Count) enclaves" -ForegroundColor Cyan

Write-Host ''
Write-Host 'Presence after merge:' -ForegroundColor Cyan
foreach ($g in ($allHosts | ForEach-Object { [pscustomobject]$_ } |
        Group-Object presence | Sort-Object Count -Descending)) {
    $colour = switch ($g.Name) {
        'confirmed' { 'Green' } 'relocated' { 'Red' }
        'alive-unidentified' { 'Yellow' } 'alive-named' { 'Yellow' }
        default { 'Gray' }
    }
    Write-Host ("  {0,4}  {1}" -f $g.Count, $g.Name) -ForegroundColor $colour
}

$upgraded = @($allHosts | ForEach-Object { [pscustomobject]$_ } | Where-Object {
        $seen = @($_.observedFrom)
        $seen.Count -gt 1 -and ($seen -join ',') -match '(unanswered|excluded|out-of-scope)' -and
        (Get-Rank $_.presence) -ge 40
    })
if ($upgraded.Count -gt 0) {
    Write-Host ''
    Write-Host "  $($upgraded.Count) host(s) recovered by a second vantage point:" -ForegroundColor Green
    foreach ($h in ($upgraded | Select-Object -First 12)) {
        Write-Host ("    {0,-34} {1,-16} {2}" -f $h.name, $h.ip, ($h.observedFrom -join '  '))
    }
    if ($upgraded.Count -gt 12) { Write-Host "    ... and $($upgraded.Count - 12) more" }
}

if ($result.Dropped.Count -gt 0) {
    Write-Host ''
    Write-Host '  Dropped as not-a-host:' -ForegroundColor Yellow
    foreach ($d in $result.Dropped) { Write-Host "    $d" -ForegroundColor Yellow }
}

if (-not $OutFile) { $OutFile = Join-Path (Split-Path -Parent $Path[0]) 'terrain-merged.json' }
[System.IO.File]::WriteAllText($OutFile, ($merged | ConvertTo-Json -Depth 12),
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host ''
Write-Host "  merged map  $OutFile" -ForegroundColor Green
Write-Host ''

#endregion MAIN
