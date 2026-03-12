BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDECloudExtendedTimeout' {

    Context 'Pass path' {

        It 'returns Pass when cloud extended timeout is in optimal range (50)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudExtendedTimeout 50
            }

            $result = Test-MDECloudExtendedTimeout

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when cloud extended timeout is 41' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudExtendedTimeout 41
            }

            $result = Test-MDECloudExtendedTimeout

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when cloud extended timeout is not configured (0)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudExtendedTimeout 0
            }

            $result = Test-MDECloudExtendedTimeout

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Fail when cloud extended timeout is too low (10)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudExtendedTimeout 10
            }

            $result = Test-MDECloudExtendedTimeout

            $result.Status | Should -Be 'Fail'
        }
    }
}
