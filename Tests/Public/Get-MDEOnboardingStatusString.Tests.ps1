BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Get-MDEOnboardingStatusString' {

    Context 'Onboarded' {

        It 'returns Onboarded when Sense is running and registry confirms state 1' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Running' -StartType 'Automatic'
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ OnboardingState = 1 }
            }

            $result = Get-MDEOnboardingStatusString

            $result | Should -Be 'Onboarded'
        }
    }

    Context 'Not Onboarded' {

        It 'returns Not Onboarded when Sense service does not exist' {
            Mock Get-Service -ModuleName MDEValidator { $null }

            $result = Get-MDEOnboardingStatusString

            $result | Should -Be 'Not Onboarded'
        }

        It 'returns Not Onboarded when Sense service is stopped' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Stopped' -StartType 'Manual'
            }

            $result = Get-MDEOnboardingStatusString

            $result | Should -BeLike 'Not Onboarded*'
        }
    }

    Context 'Partially Onboarded' {

        It 'returns Partially Onboarded when registry key is not found' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Running' -StartType 'Automatic'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Get-MDEOnboardingStatusString

            $result | Should -BeLike 'Partially Onboarded*'
        }
    }
}
