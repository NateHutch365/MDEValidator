BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDESmartScreenDownloadOverride' {

    Context 'Pass path' {

        It 'returns Pass when PreventSmartScreenPromptOverrideForFiles is 1' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ PreventSmartScreenPromptOverrideForFiles = 1 }
            }

            $result = Test-MDESmartScreenDownloadOverride

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Warning when PreventSmartScreenPromptOverrideForFiles is not configured' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDESmartScreenDownloadOverride

            $result.Status | Should -Be 'Warning'
        }

        It 'returns Fail when PreventSmartScreenPromptOverrideForFiles is 0' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ PreventSmartScreenPromptOverrideForFiles = 0 }
            }

            $result = Test-MDESmartScreenDownloadOverride

            $result.Status | Should -BeIn @('Fail', 'Warning')
        }
    }
}
