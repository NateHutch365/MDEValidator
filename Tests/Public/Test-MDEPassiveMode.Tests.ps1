BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEPassiveMode' {

    Context 'Pass path' {

        It 'returns Pass when device is running in Active Mode' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Normal'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Warning when device is running in Passive Mode' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Passive Mode'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            $result.Status | Should -Be 'Warning'
        }
    }
}
