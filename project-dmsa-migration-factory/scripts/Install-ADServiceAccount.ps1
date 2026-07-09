param(
    [Parameter(Mandatory = $true)]
    [string]$Name
)

Import-Module ActiveDirectory -ErrorAction Stop
Install-ADServiceAccount -Identity $Name -Confirm:$false -ErrorAction Stop
"AD service account $Name installed"
