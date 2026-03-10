BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDERealTimeProtection' {

    Context 'Pass path' {

        It 'returns Pass when real-time monitoring is enabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableRealtimeMonitoring $false
            }

            $result = Test-MDERealTimeProtection

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when real-time monitoring is disabled' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableRealtimeMonitoring $true
            }

            $result = Test-MDERealTimeProtection

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
