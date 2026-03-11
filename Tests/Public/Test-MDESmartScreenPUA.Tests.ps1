BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDESmartScreenPUA' {

    Context 'Pass path' {

        It 'returns Pass when SmartScreen PUA blocking is enabled (1)' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ SmartScreenPuaEnabled = 1 }
            }

            $result = Test-MDESmartScreenPUA

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Warning when SmartScreen PUA blocking is disabled (0)' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ SmartScreenPuaEnabled = 0 }
            }

            $result = Test-MDESmartScreenPUA

            $result.Status | Should -BeIn @('Warning', 'Fail')
        }

        It 'returns Warning when SmartScreen PUA registry key is not configured' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDESmartScreenPUA

            $result.Status | Should -BeIn @('Warning', 'Fail')
        }
    }
}
