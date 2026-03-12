BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDEOperatingSystemInfo' {

    Context 'Valid OS registry data' {

        It 'returns full OS string with product name, version, and build' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ProductName    = 'Windows 11 Enterprise'
                    DisplayVersion = '23H2'
                    CurrentBuild   = '22631'
                    UBR            = 3737
                }
            }

            $result = Get-MDEOperatingSystemInfo

            $result | Should -BeLike '*Windows 11 Enterprise*'
            $result | Should -BeLike '*23H2*'
            $result | Should -BeLike '*22631*'
        }

        It 'returns string without version when DisplayVersion is absent' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ProductName  = 'Windows Server 2022'
                    CurrentBuild = '20348'
                    UBR          = 1000
                }
            }

            $result = Get-MDEOperatingSystemInfo

            $result | Should -BeLike '*Windows Server 2022*'
        }
    }

    Context 'Registry path not found' {

        It 'returns Unknown OS when registry path does not exist' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Get-MDEOperatingSystemInfo

            $result | Should -Be 'Unknown OS'
        }
    }
}
