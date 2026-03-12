BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDERealTimeScanDirection' {

    Context 'Pass path' {

        It 'returns Pass when real-time scan direction is bi-directional (0)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -RealTimeScanDirection 0
            }

            $result = Test-MDERealTimeScanDirection

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Warning when real-time scan monitors incoming files only (1)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -RealTimeScanDirection 1
            }

            $result = Test-MDERealTimeScanDirection

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Warning when real-time scan monitors outgoing files only (2)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -RealTimeScanDirection 2
            }

            $result = Test-MDERealTimeScanDirection

            $result.Status | Should -Be 'Warning'
        }
    }
}
