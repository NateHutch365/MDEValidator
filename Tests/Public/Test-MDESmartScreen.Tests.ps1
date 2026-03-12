BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESmartScreen' {

    Context 'Pass path' {

        It 'returns Pass when SmartScreen is enabled via Group Policy' {
            Mock Test-Path -ModuleName MDEValidator {
                param($Path)
                $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ SmartScreenEnabled = 1 }
            }

            $result = Test-MDESmartScreen

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when SmartScreen is disabled' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ SmartScreenEnabled = 0 }
            }

            $result = Test-MDESmartScreen

            $result.Status | Should -Be 'Fail'
        }

        It 'returns Warning when SmartScreen registry key is not found' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDESmartScreen

            $result.Status | Should -BeIn @('Warning', 'Fail')
        }
    }
}
