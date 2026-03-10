BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDESmartScreenPromptOverride' {

    Context 'Pass path' {

        It 'returns Pass when SmartScreen prompt override prevention is enabled (1)' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ PreventSmartScreenPromptOverride = 1 }
            }

            $result = Test-MDESmartScreenPromptOverride

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when SmartScreen prompt override prevention is disabled (0)' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ PreventSmartScreenPromptOverride = 0 }
            }

            $result = Test-MDESmartScreenPromptOverride

            $result.Status | Should -Be 'Fail'
        }

        It 'returns Fail when SmartScreen prompt override registry key is not configured' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDESmartScreenPromptOverride

            $result.Status | Should -Be 'Fail'
        }
    }
}
