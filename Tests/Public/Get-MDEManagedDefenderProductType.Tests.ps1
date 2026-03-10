BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Get-MDEManagedDefenderProductType' {

    Context 'Intune-only managed (value 6)' {

        It 'returns Intune management type when ManagedDefenderProductType is 6' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ ManagedDefenderProductType = 6 }
            }

            $result = Get-MDEManagedDefenderProductType

            $result.ManagedDefenderProductType | Should -Be 6
            $result.ManagementType | Should -BeLike '*Intune*'
            $result.IsManagedForExclusions | Should -Be $true
        }
    }

    Context 'No management registry key' {

        It 'returns Unknown when no registry values are present' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Get-MDEManagedDefenderProductType

            $result.ManagedDefenderProductType | Should -Be $null
            $result.ManagementType | Should -BeLike '*Unknown*'
            $result.IsManagedForExclusions | Should -Be $false
        }
    }

    Context 'Co-managed (value 7 with EnrollmentStatus 3)' {

        It 'returns co-managed type when ManagedDefenderProductType is 7 and EnrollmentStatus is 3' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator -ParameterFilter {
                $Path -like '*Windows Defender*' -and $Path -notlike '*SenseCM*'
            } {
                [PSCustomObject]@{ ManagedDefenderProductType = 7 }
            }
            Mock Get-ItemProperty -ModuleName MDEValidator -ParameterFilter {
                $Path -like '*SenseCM*'
            } {
                [PSCustomObject]@{ EnrollmentStatus = 3 }
            }

            $result = Get-MDEManagedDefenderProductType

            $result.ManagedDefenderProductType | Should -Be 7
        }
    }
}
