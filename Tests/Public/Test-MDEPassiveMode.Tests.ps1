BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEPassiveMode' {

    Context 'Pass path — Active Mode' {

        It 'returns Pass for Passive Mode check when device is running in Active Mode' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Normal'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            ($result | Where-Object TestName -eq 'Passive Mode / EDR Block Mode').Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass for AM Running Mode check when AMRunningMode is Normal' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Normal'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            ($result | Where-Object TestName -eq 'AM Running Mode').Status | Should -Be 'Pass'
        }
    }

    Context 'Warning path — Passive Mode' {

        It 'returns Warning for Passive Mode check when device is running in Passive Mode' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Passive Mode'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            ($result | Where-Object TestName -eq 'Passive Mode / EDR Block Mode').Status | Should -Be 'Warning'
        }

        It 'returns Warning for AM Running Mode check when AMRunningMode is not Normal' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Passive Mode'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            ($result | Where-Object TestName -eq 'AM Running Mode').Status | Should -Be 'Warning'
        }
    }

    Context 'MpComputerStatus snapshot parameter' {

        It 'uses the supplied snapshot without calling Get-MpComputerStatus' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Passive Mode'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }
            $snapshot = New-MpComputerStatusMock -AMRunningMode 'Normal'

            $result = Test-MDEPassiveMode -MpComputerStatus $snapshot

            ($result | Where-Object TestName -eq 'AM Running Mode').Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 0 -Exactly
        }

        It 'self-queries Get-MpComputerStatus when no snapshot is supplied' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AMRunningMode 'Normal'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPassiveMode

            ($result | Where-Object TestName -eq 'AM Running Mode').Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
