BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDETamperProtection' {

    Context 'Pass path' {

        It 'returns Pass when Tamper Protection is enabled' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $true
            }

            $result = Test-MDETamperProtection

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when Tamper Protection is disabled' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $false
            }

            $result = Test-MDETamperProtection

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
