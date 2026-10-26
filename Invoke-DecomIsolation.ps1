#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Isolates a server from its local subnet ahead of decommissioning.

.DESCRIPTION
    Detects the local IPv4 subnet, then creates two Windows Firewall rules
    (Inbound + Outbound) that BLOCK the whole subnet EXCEPT:
      - the default gateway
      - the DNS server(s) configured on the interface
      - the DHCP server (if the interface uses DHCP)
      - this server's own IP
      - any extra IPs passed via -AdditionalAllowedIPs (e.g. a jump box)

    Windows Firewall block rules always win over allow rules, so instead of
    "block subnet + allow exceptions" the script builds the block rule's
    RemoteAddress as IP ranges that skip the exempt addresses.

    Traffic to addresses OUTSIDE the local subnet (internet, RMM, other
    routed subnets) is not affected.

    All rules are created in the firewall group "Decom Isolation" so they are
    easy to find in wf.msc. Reverse with:  .\Invoke-DecomIsolation.ps1 -Remove

.PARAMETER InterfaceAlias
    Optional. Skip the interface prompt by naming the interface (e.g. "Ethernet0").

.PARAMETER AdditionalAllowedIPs
    Optional. Extra local IPs to keep reachable (e.g. an admin jump box).

.PARAMETER IncludeAPIPA
    Optional. Also list interfaces with 169.254.x.x (APIPA) addresses, which
    are skipped by default. Mainly useful for lab testing on isolated switches.

.PARAMETER Force
    Skip the final "type YES" confirmation.

.PARAMETER Remove
    Remove the isolation rules created by this script.

.EXAMPLE
    .\Invoke-DecomIsolation.ps1 -WhatIf
    Shows what would be created without changing anything.

.EXAMPLE
    .\Invoke-DecomIsolation.ps1 -AdditionalAllowedIPs 10.0.0.50

.EXAMPLE
    .\Invoke-DecomIsolation.ps1 -Remove
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Apply')]
param(
    [Parameter(ParameterSetName = 'Apply')]
    [string]$InterfaceAlias,

    [Parameter(ParameterSetName = 'Apply')]
    [string[]]$AdditionalAllowedIPs = @(),

    [Parameter(ParameterSetName = 'Apply')]
    [switch]$IncludeAPIPA,

    [Parameter(ParameterSetName = 'Apply')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Remove', Mandatory)]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$RuleGroup  = 'Decom Isolation'
$RulePrefix = 'DECOM-ISOLATE'

#region Helpers
function ConvertTo-UInt32IP {
    param([string]$IP)
    $bytes = ([System.Net.IPAddress]::Parse($IP)).GetAddressBytes()
    [Array]::Reverse($bytes)
    [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32IP {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-MaskUInt32 {
    param([int]$PrefixLength)
    if ($PrefixLength -le 0) { return [uint32]0 }
    $all = [uint64]4294967295
    [uint32](($all -shl (32 - $PrefixLength)) -band $all)
}

function Test-IPv4 {
    param([string]$IP)
    $parsed = $null
    [System.Net.IPAddress]::TryParse($IP, [ref]$parsed) -and $parsed.AddressFamily -eq 'InterNetwork'
}
#endregion

#region Remove mode
if ($Remove) {
    $rules = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "No '$RuleGroup' firewall rules found. Nothing to remove." -ForegroundColor Yellow
        return
    }
    $rules | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
    if ($PSCmdlet.ShouldProcess("$($rules.Count) rule(s) in group '$RuleGroup'", 'Remove')) {
        $rules | Remove-NetFirewallRule
        Write-Host "Isolation rules removed. LAN connectivity restored." -ForegroundColor Green
    }
    return
}
#endregion

#region Collect interfaces
$candidates = @(
    foreach ($cfg in (Get-NetIPConfiguration | Where-Object { $_.IPv4Address })) {
        foreach ($addr in $cfg.IPv4Address) {
            if ($addr.IPAddress -like '127.*') { continue }
            if ($addr.IPAddress -like '169.254.*' -and -not $IncludeAPIPA) { continue }
            [pscustomobject]@{
                InterfaceAlias = $cfg.InterfaceAlias
                InterfaceIndex = $cfg.InterfaceIndex
                IPAddress      = $addr.IPAddress
                PrefixLength   = [int]$addr.PrefixLength
                SubnetMask     = ConvertFrom-UInt32IP (Get-MaskUInt32 $addr.PrefixLength)
                Gateway        = @($cfg.IPv4DefaultGateway | ForEach-Object NextHop)
                DnsServers     = @($cfg.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object ServerAddresses)
            }
        }
    }
)

if ($InterfaceAlias) {
    $candidates = @($candidates | Where-Object InterfaceAlias -eq $InterfaceAlias)
}

if ($candidates.Count -eq 0) {
    throw "No usable IPv4 interface found$(if ($InterfaceAlias) { " named '$InterfaceAlias'" })."
}
#endregion

#region Select interface
if ($candidates.Count -eq 1) {
    $sel = $candidates[0]
}
else {
    Write-Host "`nMultiple interfaces/IPs found:`n" -ForegroundColor Cyan
    $i = 0
    $candidates | ForEach-Object {
        [pscustomobject]@{
            '#'        = ($i++)
            Interface  = $_.InterfaceAlias
            IPAddress  = $_.IPAddress
            SubnetMask = "$($_.SubnetMask) (/$($_.PrefixLength))"
            Gateway    = ($_.Gateway -join ', ')
        }
    } | Format-Table -AutoSize | Out-Host

    do {
        $choice = Read-Host "Select the interface to isolate (0-$($candidates.Count - 1))"
        $valid  = $choice -match '^\d+$' -and [int]$choice -lt $candidates.Count
        if (-not $valid) { Write-Host 'Invalid selection.' -ForegroundColor Red }
    } until ($valid)
    $sel = $candidates[[int]$choice]
}
#endregion

#region DHCP server
$dhcpServer = $null
$nac = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($sel.InterfaceIndex)"
if ($nac.DHCPEnabled -and $nac.DHCPServer -and (Test-IPv4 $nac.DHCPServer)) {
    $dhcpServer = $nac.DHCPServer
}
#endregion

#region Build subnet and exemptions
$ipInt     = ConvertTo-UInt32IP $sel.IPAddress
$maskInt   = Get-MaskUInt32 $sel.PrefixLength
$network   = [uint32]([uint64]$ipInt -band [uint64]$maskInt)
$broadcast = [uint32]([uint64]$network + ([uint64]4294967295 - [uint64]$maskInt))

foreach ($ip in $AdditionalAllowedIPs) {
    if (-not (Test-IPv4 $ip)) { throw "AdditionalAllowedIPs: '$ip' is not a valid IPv4 address." }
}

$exemptList = [ordered]@{}
foreach ($gw  in $sel.Gateway)        { if (Test-IPv4 $gw)  { $exemptList[$gw]  = 'Gateway' } }
foreach ($dns in $sel.DnsServers)     { if (Test-IPv4 $dns) { $exemptList[$dns] = 'DNS' } }
if ($dhcpServer)                      { $exemptList[$dhcpServer] = 'DHCP' }
foreach ($ip  in $AdditionalAllowedIPs) { $exemptList[$ip] = 'Additional' }
$exemptList[$sel.IPAddress] = 'This server'

$exemptInts = @(
    $exemptList.Keys | ForEach-Object { ConvertTo-UInt32IP $_ } |
        Where-Object { $_ -ge $network -and $_ -le $broadcast } |
        Sort-Object -Unique
)

# Build block ranges covering the subnet minus the exempt IPs
$ranges = New-Object System.Collections.Generic.List[string]
$start  = [uint64]$network
foreach ($e in $exemptInts) {
    if ([uint64]$e -gt $start) {
        $end = [uint64]$e - 1
        if ($start -eq $end) { $ranges.Add((ConvertFrom-UInt32IP $start)) }
        else { $ranges.Add("$(ConvertFrom-UInt32IP $start)-$(ConvertFrom-UInt32IP $end)") }
    }
    $start = [uint64]$e + 1
}
if ($start -le [uint64]$broadcast) {
    if ($start -eq [uint64]$broadcast) { $ranges.Add((ConvertFrom-UInt32IP $broadcast)) }
    else { $ranges.Add("$(ConvertFrom-UInt32IP $start)-$(ConvertFrom-UInt32IP $broadcast)") }
}

if ($ranges.Count -eq 0) { throw 'Nothing left to block after exemptions. Check the subnet.' }
#endregion

#region Summary
Write-Host "`n=== Decommission isolation plan ===" -ForegroundColor Cyan
Write-Host ("Interface : {0}" -f $sel.InterfaceAlias)
Write-Host ("Server IP : {0}" -f $sel.IPAddress)
Write-Host ("Subnet    : {0}/{1}  ({2})" -f (ConvertFrom-UInt32IP $network), $sel.PrefixLength, $sel.SubnetMask)
Write-Host "`nAllowed (not blocked):" -ForegroundColor Green
$exemptList.GetEnumerator() | ForEach-Object {
    $inSubnet = (ConvertTo-UInt32IP $_.Key) -ge $network -and (ConvertTo-UInt32IP $_.Key) -le $broadcast
    "  {0,-16} {1}{2}" -f $_.Key, $_.Value, $(if (-not $inSubnet) { '  (outside subnet - unaffected anyway)' })
} | Out-Host
if (-not $dhcpServer) { Write-Host '  (No DHCP server - interface is statically configured)' -ForegroundColor DarkGray }
Write-Host "`nBlocked ranges (inbound + outbound):" -ForegroundColor Red
$ranges | ForEach-Object { "  $_" } | Out-Host

# Warnings
if ($env:SESSIONNAME -like 'RDP-*') {
    Write-Warning 'You appear to be connected over RDP. If you are connecting from an IP on this subnet, your session WILL drop. Use -AdditionalAllowedIPs for your jump box, or work via RMM/console.'
}
$profiles = Get-NetFirewallProfile -PolicyStore ActiveStore
$disabled = @($profiles | Where-Object { "$($_.Enabled)" -eq 'False' })
if ($disabled) {
    Write-Warning ("Windows Firewall is DISABLED on profile(s): {0}. The rules will have no effect on those profiles until the firewall is enabled." -f ($disabled.Name -join ', '))
}
$noLocal = @($profiles | Where-Object { "$($_.AllowLocalFirewallRules)" -eq 'False' })
if ($noLocal) {
    Write-Warning ("Group Policy blocks local firewall rules on profile(s): {0}. These rules will be ignored on those profiles." -f ($noLocal.Name -join ', '))
}

$existing = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
if ($existing) { Write-Warning "Existing '$RuleGroup' rules found - they will be replaced." }
#endregion

#region Apply
if (-not $Force -and -not $WhatIfPreference) {
    $confirm = Read-Host "`nType YES to apply these rules"
    if ($confirm -ne 'YES') { Write-Host 'Aborted. No changes made.' -ForegroundColor Yellow; return }
}

if ($PSCmdlet.ShouldProcess("$($sel.IPAddress) / subnet $(ConvertFrom-UInt32IP $network)/$($sel.PrefixLength)", 'Create LAN isolation firewall rules')) {
    if ($existing) { $existing | Remove-NetFirewallRule }

    $desc = "Decommission isolation created $(Get-Date -Format 'yyyy-MM-dd HH:mm') by $env:USERNAME. Remove with Invoke-DecomIsolation.ps1 -Remove or delete/disable in wf.msc."
    foreach ($dir in 'Inbound', 'Outbound') {
        New-NetFirewallRule -DisplayName "$RulePrefix - Block LAN $dir" `
            -Group $RuleGroup `
            -Direction $dir `
            -Action Block `
            -RemoteAddress $ranges.ToArray() `
            -Profile Any `
            -Description $desc | Out-Null
    }

    Get-NetFirewallRule -Group $RuleGroup | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
    Write-Host "Isolation applied. To reverse: .\Invoke-DecomIsolation.ps1 -Remove  (or disable the '$RuleGroup' rules in wf.msc)" -ForegroundColor Green
}
#endregion
