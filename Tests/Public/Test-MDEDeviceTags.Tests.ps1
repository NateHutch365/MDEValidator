BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEDeviceTags' {

    Context 'Tag configured' {

        It 'returns Info status when device tag is set' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ Group = 'Finance-Laptops' }
            }

            $result = Test-MDEDeviceTags

            $result.Status | Should -Be 'Info'
            $result.Message | Should -BeLike '*Finance-Laptops*'
        }
    }

    Context 'No tag configured' {

        It 'returns Info status when no tag is set (registry path absent)' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEDeviceTags

            $result.Status | Should -Be 'Info'
            $result.Message | Should -BeLike '*No locally configured*'
        }

        It 'returns Info status when tag registry value is empty' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ Group = '' }
            }

            $result = Test-MDEDeviceTags

            $result.Status | Should -Be 'Info'
        }
    }
}
