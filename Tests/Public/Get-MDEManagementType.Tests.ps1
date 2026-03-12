BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDEManagementType' {

    Context 'Intune-only (ManagedDefenderProductType 6)' {

        It 'returns Intune when ManagedDefenderProductType is 6' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ ManagedDefenderProductType = 6 }
            }

            $result = Get-MDEManagementType

            $result | Should -Be 'Intune'
        }
    }

    Context 'Security Settings Management via EnrollmentStatus' {

        It 'returns SecuritySettingsManagement when EnrollmentStatus is 1' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator -ParameterFilter {
                $Path -like '*Windows Defender*'
            } {
                [PSCustomObject]@{}
            }
            Mock Get-ItemProperty -ModuleName MDEValidator -ParameterFilter {
                $Path -like '*SenseCM*'
            } {
                [PSCustomObject]@{ EnrollmentStatus = 1 }
            }

            $result = Get-MDEManagementType

            $result | Should -Be 'SecuritySettingsManagement'
        }
    }

    Context 'No management configured' {

        It 'returns GPO or None when registry keys are absent' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Get-MDEManagementType

            $result | Should -Not -BeNullOrEmpty
        }
    }
}
