BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDETroubleshootingMode' {

    Context 'Pass path' {

        It 'returns Pass when troubleshooting mode is disabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -TroubleshootingMode 'Disabled'
            }

            $result = Test-MDETroubleshootingMode

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Warning when troubleshooting mode is enabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -TroubleshootingMode 'Enabled'
            }

            $result = Test-MDETroubleshootingMode

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
