BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEFileHashComputation' {

    Context 'Pass path' {

        It 'returns Pass when file hash computation is enabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -EnableFileHashComputation $true
            }

            $result = Test-MDEFileHashComputation

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Warning when file hash computation is disabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -EnableFileHashComputation $false
            }

            $result = Test-MDEFileHashComputation

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
