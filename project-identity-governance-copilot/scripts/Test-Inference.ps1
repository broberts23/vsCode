#!/usr/bin/env pwsh
#Requires -Version 7.4

# This wrapper keeps the smoke test simple: collect one prompt and pass it to the Python entry point.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Prompt,

    [Parameter()]
    [string]$PythonCommand = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
# The Python script uses `argparse`, so the prompt is passed as a standard `--prompt` command-line argument.
& $PythonCommand (Join-Path $projectRoot 'src/app.py') '--prompt' $Prompt