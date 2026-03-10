BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDEPolicySettingConfig' {

    Context 'Intune management' {

        It 'returns Policy Manager path and AllowRealtimeMonitoring for RealTimeProtection' {
            $result = Get-MDEPolicySettingConfig -SettingKey 'RealTimeProtection' -ManagementType 'Intune'

            $result.Path | Should -BeLike '*Policy Manager*'
            $result.SettingName | Should -Be 'AllowRealtimeMonitoring'
        }

        It 'returns Policy Manager path and AllowCloudProtection for CloudProtection' {
            $result = Get-MDEPolicySettingConfig -SettingKey 'CloudProtection' -ManagementType 'Intune'

            $result.Path | Should -BeLike '*Policy Manager*'
            $result.SettingName | Should -Be 'AllowCloudProtection'
        }
    }

    Context 'GPO management' {

        It 'returns standard path and DisableRealtimeMonitoring for RealTimeProtection' {
            $result = Get-MDEPolicySettingConfig -SettingKey 'RealTimeProtection' -ManagementType 'GPO'

            $result.Path | Should -Not -BeLike '*Policy Manager*'
            $result.SettingName | Should -Be 'DisableRealtimeMonitoring'
        }

        It 'returns DisplayName for all settings' {
            $result = Get-MDEPolicySettingConfig -SettingKey 'NetworkProtection' -ManagementType 'GPO'

            $result.DisplayName | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SecuritySettingsManagement' {

        It 'returns config for BehaviorMonitoring' {
            $result = Get-MDEPolicySettingConfig -SettingKey 'BehaviorMonitoring' -ManagementType 'SecuritySettingsManagement'

            $result | Should -Not -BeNullOrEmpty
            $result.SettingName | Should -Not -BeNullOrEmpty
        }
    }
}
