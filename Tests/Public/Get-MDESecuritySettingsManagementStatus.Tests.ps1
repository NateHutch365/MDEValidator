BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDESecuritySettingsManagementStatus' {

    Context 'ManagedDefenderProductType present' {

        It 'returns Intune Only when ManagedDefenderProductType is 6' {
            Mock Get-MDEManagedDefenderProductType -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ManagedDefenderProductType = 6
                    ManagementType             = 'Intune Only'
                    IsManagedForExclusions     = $true
                }
            }

            $result = Get-MDESecuritySettingsManagementStatus

            $result | Should -BeLike '*Intune*'
        }
    }

    Context 'Fallback to SenseCM EnrollmentStatus' {

        It 'returns Security Settings Management when EnrollmentStatus is 1' {
            Mock Get-MDEManagedDefenderProductType -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ManagedDefenderProductType = $null
                    ManagementType             = 'Unknown'
                    IsManagedForExclusions     = $false
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ EnrollmentStatus = 1 }
            }

            $result = Get-MDESecuritySettingsManagementStatus

            $result | Should -Be 'Security Settings Management'
        }

        It 'returns Intune when EnrollmentStatus is 3' {
            Mock Get-MDEManagedDefenderProductType -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ManagedDefenderProductType = $null
                    ManagementType             = 'Unknown'
                    IsManagedForExclusions     = $false
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ EnrollmentStatus = 3 }
            }

            $result = Get-MDESecuritySettingsManagementStatus

            $result | Should -Be 'Intune'
        }
    }

    Context 'No management detected' {

        It 'uses fallback detection when SenseCM key is absent' {
            Mock Get-MDEManagedDefenderProductType -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ManagedDefenderProductType = $null
                    ManagementType             = 'Unknown'
                    IsManagedForExclusions     = $false
                }
            }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-MDEManagementTypeFallback -ModuleName MDEValidator { 'Not Configured' }

            $result = Get-MDESecuritySettingsManagementStatus

            $result | Should -Not -BeNullOrEmpty
        }
    }
}
