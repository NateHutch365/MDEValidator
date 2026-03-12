BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEOnboardingStatus' {

    Context 'Pass path' {

        It 'returns Pass when Sense is running and OnboardingState is 1' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Running' -StartType 'Automatic'
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ OnboardingState = 1 }
            }

            $result = Test-MDEOnboardingStatus

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when Sense service is not installed' {
            Mock Get-Service -ModuleName MDEValidator { $null }

            $result = Test-MDEOnboardingStatus

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-Service -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Fail when Sense service is not running' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Stopped' -StartType 'Manual'
            }

            $result = Test-MDEOnboardingStatus

            $result.Status | Should -Be 'Fail'
        }
    }
}
