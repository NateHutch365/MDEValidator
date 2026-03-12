BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESampleSubmission' {

    Context 'Pass path' {

        It 'returns Pass when sample submission is set to Send all samples (3)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SubmitSamplesConsent 3
            }

            $result = Test-MDESampleSubmission

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when sample submission is Never send (2)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SubmitSamplesConsent 2
            }

            $result = Test-MDESampleSubmission

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
