#Requires -Version 5.1
<#
.SYNOPSIS
    Common test bootstrap for MDEValidator Pester tests.

.DESCRIPTION
    Provides shared module import and setup for all test files.
    Test files should dot-source this file, MockBuilders.ps1 (if needed),
    and call Initialize-MDEValidatorTest inside a BeforeAll block.

    MockBuilders.ps1 must be dot-sourced directly in the test file's BeforeAll
    so the mock helper functions stay in the test scope. Dot-sourcing inside
    Initialize-MDEValidatorTest would create them in a child scope that is
    destroyed when the function returns.

.EXAMPLE
    BeforeAll {
        . $PSScriptRoot/../Helpers/TestBootstrap.ps1
        . $PSScriptRoot/../Helpers/MockBuilders.ps1   # only if test uses mock builders
        Initialize-MDEValidatorTest
    }
#>

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
            . $PSScriptRoot/../Helpers/MockBuilders.ps1
            Initialize-MDEValidatorTest
        }
    #>
    param()

    $bootstrapDir = Split-Path $MyInvocation.MyCommand.ScriptBlock.File -Parent
    $manifestPath = Resolve-Path (Join-Path $bootstrapDir '..\..\MDEValidator\MDEValidator.psd1')
    Import-Module $manifestPath -Force -ErrorAction Stop
    Get-Module MDEValidator
}
