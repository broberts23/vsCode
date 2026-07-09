param(
    [Parameter(Mandatory = $true)]
    [string]$Identity,

    [Parameter(Mandatory = $true)]
    [string]$SupersededAccount
)

Import-Module ActiveDirectory -ErrorAction Stop

Undo-ADServiceAccountMigration -Identity $Identity -SupersededAccount $SupersededAccount -Server localhost -ErrorAction Stop
"Migration undone: dMSA $Identity no longer supersedes $SupersededAccount"