<#
.SYNOPSIS
    Malware Analysis Victim VM - Firewall, Defender, Network
.DESCRIPTION
    Malware Analysis Victim VM - Firewall, Defender, Network
.PARAMETER DHCP
    When true, set network to dhcp
#>
[CmdletBinding()]

Param(
    [switch]
    $DHCP = $false
)

New-Module -ScriptBlock {

    # Disable Firewall
    Function Disable-Firewall {
        Write-Host "Disabling Firewall..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
    }

    # Disable Windows Defender Cloud
    Function Disable-DefenderCloud {
        Write-Host "Disabling Windows Defender Cloud..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
    }

    # Disable Windows Defender
    Function Disable-Defender {
        Write-Host "Disabling Windows Defender..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
    }

    Export-ModuleMember -Function Disable-Firewall,Disable-DefenderCloud,Disable-Defender
}

Disable-Firewall
Disable-DefenderCloud
Disable-Defender

$wmi = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IpEnabled = 'true'"
if ($wmi -eq $null) {
    write-output "error: no active network adapter found"
    if($myinvocation.mycommand.commandtype -eq 'Script') { return } else { exit -1 }
}

if ($DHCP) {
    $wmi.EnableDHCP()
    $wmi.RenewDHCPLease()
} else {
    #--- IP settings ---
    write-output "Configuring Static IP"
    $IPv4Address = "192.168.12.2"
    $IPv4Mask = "255.255.255.0"
    $IPv4Gateway = "192.168.12.1"
    $IPv4DNS = "192.168.12.1"

    $wmi.EnableStatic($IPv4Address, $IPv4Mask)
    $wmi.SetGateways($IPv4Gateway, 1)
    $wmi.SetDNSServerSearchOrder($IPv4DNS)
}
