# PowerShell profile for Azure Functions
#
# Keep this file lightweight. Use it for shared initialization if needed.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try {
	Import-Module -Name GovernanceAutomation -Force -ErrorAction Stop
}
catch {
	# If the module isn't present (e.g., during partial deployments), keep the worker alive.
	Write-Warning "Failed to import GovernanceAutomation module: $($_.Exception.Message)"
}
