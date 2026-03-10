BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEPolicyRegistryVerification' {

    Context 'Pass path' {

        It 'returns Pass sub-test result when registry value is found' {
            Mock Get-MDEManagementType -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEPolicySettingConfig -ModuleName MDEValidator {
                [PSCustomObject]@{
                    Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
                    SettingName = 'DisableRealtimeMonitoring'
                    DisplayName = 'Real-Time Protection'
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ DisableRealtimeMonitoring = 0 }
            }

            $result = Test-MDEPolicyRegistryVerification -ParentTestName 'Real-Time Protection' `
                -SettingKey 'RealTimeProtection' -IsApplicableToSSM $true

            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -BeIn @('Pass', 'Info')
        }
    }

    Context 'Fail path' {

        It 'returns Warning or Fail when registry setting is not configured' {
            Mock Get-MDEManagementType -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEPolicySettingConfig -ModuleName MDEValidator {
                [PSCustomObject]@{
                    Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
                    SettingName = 'DisableRealtimeMonitoring'
                    DisplayName = 'Real-Time Protection'
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPolicyRegistryVerification -ParentTestName 'Real-Time Protection' `
                -SettingKey 'RealTimeProtection' -IsApplicableToSSM $true

            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -BeIn @('Warning', 'Fail', 'Info')
        }
    }
}
