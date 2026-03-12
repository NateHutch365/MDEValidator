#Requires -Version 5.1
<#
.SYNOPSIS
    Common test bootstrap for MDEValidator Pester tests.

.DESCRIPTION
    Provides shared module import and setup for all test files.
    All test files should dot-source this file and call Initialize-MDEValidatorTest
    inside a BeforeAll block before running any test assertions.

.EXAMPLE
    BeforeAll {
        . $PSScriptRoot/../Helpers/TestBootstrap.ps1
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
            Initialize-MDEValidatorTest
        }
    #>
    param()

    # Use the function's own source file location instead of $PSScriptRoot.
    # $PSScriptRoot can be empty or resolve to the wrong directory when called
    # from within Pester 5 BeforeAll blocks after dot-sourcing.
    $bootstrapDir = Split-Path $MyInvocation.MyCommand.ScriptBlock.File -Parent
    $manifestPath = Resolve-Path (Join-Path $bootstrapDir '..\..\MDEValidator\MDEValidator.psd1')
    Import-Module $manifestPath -Force -ErrorAction Stop
    Get-Module MDEValidator
}
