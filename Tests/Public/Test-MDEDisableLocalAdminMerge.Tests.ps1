BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEDisableLocalAdminMerge' {

    Context 'Pass path' {

        It 'returns Pass when DisableLocalAdminMerge is 1 in registry' {
            Mock Get-MDEManagementType -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEPolicySettingConfig -ModuleName MDEValidator {
                [PSCustomObject]@{
                    Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
                    SettingName = 'DisableLocalAdminMerge'
                    DisplayName = 'Disable Local Admin Merge'
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ DisableLocalAdminMerge = 1 }
            }

            $result = Test-MDEDisableLocalAdminMerge

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Warning when DisableLocalAdminMerge is 0' {
            Mock Get-MDEManagementType -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEPolicySettingConfig -ModuleName MDEValidator {
                [PSCustomObject]@{
                    Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
                    SettingName = 'DisableLocalAdminMerge'
                    DisplayName = 'Disable Local Admin Merge'
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ DisableLocalAdminMerge = 0 }
            }

            $result = Test-MDEDisableLocalAdminMerge

            $result.Status | Should -BeIn @('Fail', 'Warning')
        }

        It 'returns Warning when setting is not configured' {
            Mock Get-MDEManagementType -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEPolicySettingConfig -ModuleName MDEValidator {
                [PSCustomObject]@{
                    Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
                    SettingName = 'DisableLocalAdminMerge'
                    DisplayName = 'Disable Local Admin Merge'
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-MDEManagedDefenderProductType -ModuleName MDEValidator {
                [PSCustomObject]@{ IsManagedForExclusions = $false }
            }

            $result = Test-MDEDisableLocalAdminMerge

            $result.Status | Should -BeIn @('Warning', 'Info')
        }
    }
}
