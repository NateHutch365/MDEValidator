BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDEPolicyRegistryPath' {

    Context 'Intune management' {

        It 'returns Policy Manager path for Intune' {
            $result = Get-MDEPolicyRegistryPath -ManagementType 'Intune'

            $result | Should -BeLike '*Policy Manager*'
        }
    }

    Context 'Non-Intune management types' {

        It 'returns standard Windows Defender path for SecuritySettingsManagement' {
            $result = Get-MDEPolicyRegistryPath -ManagementType 'SecuritySettingsManagement'

            $result | Should -Not -BeLike '*Policy Manager*'
            $result | Should -BeLike '*Windows Defender*'
        }

        It 'returns standard Windows Defender path for SCCM' {
            $result = Get-MDEPolicyRegistryPath -ManagementType 'SCCM'

            $result | Should -Not -BeLike '*Policy Manager*'
        }

        It 'returns standard Windows Defender path for GPO' {
            $result = Get-MDEPolicyRegistryPath -ManagementType 'GPO'

            $result | Should -Not -BeLike '*Policy Manager*'
        }

        It 'returns standard Windows Defender path for None' {
            $result = Get-MDEPolicyRegistryPath -ManagementType 'None'

            $result | Should -Not -BeLike '*Policy Manager*'
        }
    }
}
