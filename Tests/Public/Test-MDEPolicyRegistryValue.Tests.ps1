BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEPolicyRegistryValue' {

    Context 'Registry value found' {

        It 'returns Found true when registry setting exists at correct path' {
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

            $result = Test-MDEPolicyRegistryValue -SettingKey 'RealTimeProtection'

            $result.Found | Should -Be $true
            $result.ManagementType | Should -Be 'GPO'
        }
    }

    Context 'Registry value not found' {

        It 'returns Found false when registry path does not exist' {
            Mock Get-MDEManagementType -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEPolicySettingConfig -ModuleName MDEValidator {
                [PSCustomObject]@{
                    Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
                    SettingName = 'DisableRealtimeMonitoring'
                    DisplayName = 'Real-Time Protection'
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEPolicyRegistryValue -SettingKey 'RealTimeProtection'

            $result.Found | Should -Be $false
        }
    }
}
