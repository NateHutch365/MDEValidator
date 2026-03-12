BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESignatureUpdateInterval' {

    Context 'Pass path' {

        It 'returns Pass when signature update interval is 1 hour' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureUpdateInterval 1
            }

            $result = Test-MDESignatureUpdateInterval

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when signature update interval is 4 hours' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureUpdateInterval 4
            }

            $result = Test-MDESignatureUpdateInterval

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when signature update interval is 0 (disabled)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureUpdateInterval 0
            }

            $result = Test-MDESignatureUpdateInterval

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
