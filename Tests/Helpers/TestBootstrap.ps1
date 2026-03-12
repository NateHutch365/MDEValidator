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

    # Resolve bootstrap directory from the function source file itself.
    # This avoids file-scope context differences in CI vs local Pester runs.
    $bootstrapDir = Split-Path $MyInvocation.MyCommand.ScriptBlock.File -Parent

    # Load mock helper builders at call time (inside BeforeAll) so the helpers
    # are available in each test file scope without relying on file-scope state.
    $mockBuildersPath = Join-Path $bootstrapDir 'MockBuilders.ps1'
    . $mockBuildersPath

    $manifestPath = Resolve-Path (Join-Path $bootstrapDir '..\..\MDEValidator\MDEValidator.psd1')
    Import-Module $manifestPath -Force -ErrorAction Stop
    Get-Module MDEValidator
}
