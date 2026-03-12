#Requires -Version 5.1
<#
.SYNOPSIS
    Common test bootstrap for MDEValidator Pester tests.

.DESCRIPTION
    Provides shared module import and setup for all test files.
    All test files should dot-source this file and call Initialize-MDEValidatorTest
    inside a BeforeAll block before running any test assertions.

    MockBuilders.ps1 is auto-loaded at file scope so mock helper functions
    (New-MpPreferenceMock, New-MpComputerStatusMock, etc.) are available in
    the test's BeforeAll scope without a separate dot-source line.

.EXAMPLE
    BeforeAll {
        . $PSScriptRoot/../Helpers/TestBootstrap.ps1
        Initialize-MDEValidatorTest
    }
#>

# Auto-load mock builder helpers at file scope.
# This file is dot-sourced from test files' BeforeAll blocks.
# $PSScriptRoot may not resolve correctly in all PowerShell/Pester version
# combinations when dot-sourced from within Pester 5 BeforeAll, so we use
# a fallback chain to reliably locate MockBuilders.ps1.
$_mockBuildersPath = if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot 'MockBuilders.ps1'))) {
    Join-Path $PSScriptRoot 'MockBuilders.ps1'
} elseif ($PSCommandPath) {
    Join-Path (Split-Path $PSCommandPath -Parent) 'MockBuilders.ps1'
} elseif ($MyInvocation.MyCommand.Path) {
    Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) 'MockBuilders.ps1'
} elseif ($MyInvocation.MyCommand.ScriptBlock -and $MyInvocation.MyCommand.ScriptBlock.File) {
    Join-Path (Split-Path $MyInvocation.MyCommand.ScriptBlock.File -Parent) 'MockBuilders.ps1'
} elseif ($MyInvocation.ScriptName) {
    # Caller is at Tests/{Public,Private}/X.Tests.ps1, so Helpers is ../Helpers/
    Join-Path (Split-Path $MyInvocation.ScriptName -Parent) '..' 'Helpers' 'MockBuilders.ps1'
} else {
    throw 'TestBootstrap: Cannot locate MockBuilders.ps1 — all path resolution methods failed.'
}
. $_mockBuildersPath

function Initialize-MDEValidatorTest {
    <#
    .SYNOPSIS
        Imports the MDEValidator module with -Force for a clean test session.

    .DESCRIPTION
        Resolves the module manifest path relative to this bootstrap file.
        Uses $MyInvocation.MyCommand.ScriptBlock.File to reliably locate the
        bootstrap file's directory, regardless of $PSScriptRoot availability
        in Pester BeforeAll execution contexts.

    .OUTPUTS
        [PSModuleInfo] The imported module object returned by Get-Module.

    .EXAMPLE
        BeforeAll {
            . $PSScriptRoot/../Helpers/TestBootstrap.ps1
            Initialize-MDEValidatorTest
        }
    #>
    param()

    # Use the function's own source file location instead of $PSScriptRoot.
    # $PSScriptRoot can be empty or resolve to the wrong directory when called
    # from within Pester 5 BeforeAll blocks after dot-sourcing.
    $bootstrapDir = if ($MyInvocation.MyCommand.ScriptBlock -and $MyInvocation.MyCommand.ScriptBlock.File) {
        Split-Path $MyInvocation.MyCommand.ScriptBlock.File -Parent
    } elseif ($_mockBuildersPath) {
        Split-Path $_mockBuildersPath -Parent
    } else {
        $PSScriptRoot
    }
    $manifestPath = Resolve-Path (Join-Path $bootstrapDir '..\..\MDEValidator\MDEValidator.psd1')
    Import-Module $manifestPath -Force -ErrorAction Stop
    Get-Module MDEValidator
}
