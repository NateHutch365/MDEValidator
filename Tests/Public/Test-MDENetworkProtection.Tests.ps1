BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDENetworkProtection' {

    Context 'Pass path' {

        It 'returns Pass when network protection is enabled in Block mode (1)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -EnableNetworkProtection 1
            }

            $result = Test-MDENetworkProtection

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when network protection is disabled (0)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -EnableNetworkProtection 0
            }

            $result = Test-MDENetworkProtection

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
