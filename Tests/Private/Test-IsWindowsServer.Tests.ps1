BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-IsWindowsServer' {

    Context 'Server OS detection via InstallationType' {

        It 'returns true when InstallationType is Server' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty {
                    [PSCustomObject]@{ InstallationType = 'Server'; ProductName = 'Windows Server 2022' }
                }

                $result = Test-IsWindowsServer
                $result | Should -Be $true
            }
        }

        It 'returns true when InstallationType is Server Core' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty {
                    [PSCustomObject]@{ InstallationType = 'Server Core'; ProductName = 'Windows Server 2022 Core' }
                }

                $result = Test-IsWindowsServer
                $result | Should -Be $true
            }
        }

        It 'returns false when InstallationType is Client' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty {
                    [PSCustomObject]@{ InstallationType = 'Client'; ProductName = 'Windows 11 Pro' }
                }

                $result = Test-IsWindowsServer
                $result | Should -Be $false
            }
        }
    }

    Context 'Fallback to ProductName when InstallationType missing' {

        It 'returns true when ProductName starts with Windows Server' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty {
                    [PSCustomObject]@{ ProductName = 'Windows Server 2019 Standard' }
                }

                $result = Test-IsWindowsServer
                $result | Should -Be $true
            }
        }

        It 'returns false when ProductName is a client OS' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty {
                    [PSCustomObject]@{ ProductName = 'Windows 10 Pro' }
                }

                $result = Test-IsWindowsServer
                $result | Should -Be $false
            }
        }
    }

    Context 'Error handling' {

        It 'returns false when registry path does not exist' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $false }

                $result = Test-IsWindowsServer
                $result | Should -Be $false
            }
        }

        It 'returns false when Get-ItemProperty throws' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty { throw 'Registry access denied' }

                $result = Test-IsWindowsServer
                $result | Should -Be $false
            }
        }

        It 'returns a boolean value' {
            InModuleScope MDEValidator {
                Mock Test-Path { return $true }
                Mock Get-ItemProperty {
                    [PSCustomObject]@{ InstallationType = 'Client'; ProductName = 'Windows 11' }
                }

                $result = Test-IsWindowsServer
                $result | Should -BeOfType [bool]
            }
        }
    }
}
