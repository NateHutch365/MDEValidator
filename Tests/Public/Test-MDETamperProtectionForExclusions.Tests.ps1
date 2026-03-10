BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDETamperProtectionForExclusions' {

    Context 'Pass path' {

        It 'returns Pass when all requirements are met for Intune-managed device' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $true -AMProductVersion '4.18.24040.4'
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ManagedDefenderProductType = 6
                    TPExclusions               = 1
                }
            }

            $result = Test-MDETamperProtectionForExclusions

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when Tamper Protection is not enabled' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $false -AMProductVersion '4.18.24040.4'
            }

            $result = Test-MDETamperProtectionForExclusions

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
