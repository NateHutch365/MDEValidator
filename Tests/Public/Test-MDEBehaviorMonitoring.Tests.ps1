BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEBehaviorMonitoring' {

    Context 'Pass path' {

        It 'returns Pass when behavior monitoring is enabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableBehaviorMonitoring $false
            }

            $result = Test-MDEBehaviorMonitoring

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when behavior monitoring is disabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableBehaviorMonitoring $true
            }

            $result = Test-MDEBehaviorMonitoring

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
