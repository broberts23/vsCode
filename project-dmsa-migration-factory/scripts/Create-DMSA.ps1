param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$HostName,

    [Parameter(Mandatory = $true)]
    [string]$DomainDnsName,

    [Parameter(Mandatory = $false)]
    [string]$SupersededAccount
)

Import-Module ActiveDirectory -ErrorAction Stop

$shortName = $HostName -replace "\..*$", ""

try {
    $principal = Get-ADComputer -Identity $shortName -ErrorAction Stop
}
catch {
    try {
        $principal = Get-ADComputer -Identity "$shortName$" -ErrorAction Stop
    }
    catch {
        throw "AD computer $shortName not found: $_"
    }
}

$existing = Get-ADServiceAccount -Identity $Name -ErrorAction SilentlyContinue

if ($existing) {
    Set-ADServiceAccount -Identity $Name -PrincipalsAllowedToRetrieveManagedPassword $principal -ErrorAction Stop
    "dMSA $Name already exists; retrieval principal updated for $shortName$"
    return
}

$TargetDNS = "$Name.$DomainDnsName"

New-ADServiceAccount `
    -Name $Name `
    -DNSHostName $TargetDNS `
    -CreateDelegatedServiceAccount `
    -PrincipalsAllowedToRetrieveManagedPassword $principal `
    -KerberosEncryptionType AES256 `
    -ErrorAction Stop

Set-ADServiceAccount -Identity $Name -Replace @{ "msDS-DelegatedMSAState" = 3 } -ErrorAction Stop
Add-ADGroupMember -Identity "dMSA-Service-Hosts" -Members "$Name$" -ErrorAction Stop

if ($SupersededAccount) {
    Start-ADServiceAccountMigration -Identity $Name -SupersededAccount $SupersededAccount -Server localhost -ErrorAction Stop
    "dMSA $Name created superseding $SupersededAccount"
}
else {
    "dMSA $Name created as standalone"
}