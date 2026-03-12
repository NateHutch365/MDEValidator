BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEDisableCatchupQuickScan' {

    Context 'Pass path' {

        It 'returns Pass when catchup quick scan is enabled (DisableCatchupQuickScan = false)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableCatchupQuickScan $false
            }

            $result = Test-MDEDisableCatchupQuickScan

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when catchup quick scan is disabled (DisableCatchupQuickScan = true)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableCatchupQuickScan $true
            }

            $result = Test-MDEDisableCatchupQuickScan

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
