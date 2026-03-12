BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDECloudProtection' {

    Context 'Pass path' {

        It 'returns Pass when cloud protection is enabled at Advanced level' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -MAPSReporting 2
            }

            $result = Test-MDECloudProtection

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when cloud protection is enabled at Basic level' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -MAPSReporting 1
            }

            $result = Test-MDECloudProtection

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when cloud protection is disabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -MAPSReporting 0
            }

            $result = Test-MDECloudProtection

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
