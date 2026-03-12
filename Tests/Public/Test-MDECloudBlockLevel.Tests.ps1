BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDECloudBlockLevel' {

    Context 'Pass path' {

        It 'returns Pass when cloud block level is High (2)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudBlockLevel 2
            }

            $result = Test-MDECloudBlockLevel

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when cloud block level is High+ (4)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudBlockLevel 4
            }

            $result = Test-MDECloudBlockLevel

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when cloud block level is Default (0)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudBlockLevel 0
            }

            $result = Test-MDECloudBlockLevel

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Fail when cloud block level is Moderate (1)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -CloudBlockLevel 1
            }

            $result = Test-MDECloudBlockLevel

            $result.Status | Should -Be 'Fail'
        }
    }
}
