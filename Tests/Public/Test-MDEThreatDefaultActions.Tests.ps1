BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEThreatDefaultActions' {

    Context 'Pass path' {

        It 'returns Pass when all threat default actions are set to Quarantine (2)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock `
                    -LowThreatDefaultAction 2 `
                    -ModerateThreatDefaultAction 2 `
                    -HighThreatDefaultAction 2 `
                    -SevereThreatDefaultAction 2
            }
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $true
            }

            $result = Test-MDEThreatDefaultActions

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when any threat action is set to NoAction (9)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock `
                    -LowThreatDefaultAction 9 `
                    -ModerateThreatDefaultAction 2 `
                    -HighThreatDefaultAction 2 `
                    -SevereThreatDefaultAction 2
            }
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $true
            }

            $result = Test-MDEThreatDefaultActions

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Fail when any threat action is set to Allow (6)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock `
                    -LowThreatDefaultAction 2 `
                    -ModerateThreatDefaultAction 6 `
                    -HighThreatDefaultAction 2 `
                    -SevereThreatDefaultAction 2
            }
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -IsTamperProtected $true
            }

            $result = Test-MDEThreatDefaultActions

            $result.Status | Should -Be 'Fail'
        }
    }
}
