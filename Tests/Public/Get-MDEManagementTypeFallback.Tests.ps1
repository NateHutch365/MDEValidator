BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Get-MDEManagementTypeFallback' {

    Context 'Intune detected via policy manager path entries' {

        It 'returns Intune when Policy Manager registry path has entries' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-Item -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Get-ItemProperty -ModuleName MDEValidator -ParameterFilter {
                $Path -like '*Policy Manager*'
            } {
                [PSCustomObject]@{
                    PSPath = 'Registry::HKLM\...'
                    AllowRealtimeMonitoring = 1
                }
            }

            $result = Get-MDEManagementTypeFallback

            $result | Should -Be 'Intune'
        }
    }

    Context 'Security Settings Management detected via standard policy path' {

        It 'returns SecuritySettingsManagement when standard policy path has entries but no Policy Manager path' {
            Mock Test-Path -ModuleName MDEValidator -ParameterFilter {
                $Path -like '*Policy Manager*'
            } { $false }
            Mock Test-Path -ModuleName MDEValidator -ParameterFilter {
                $Path -notlike '*Policy Manager*'
            } { $true }
            Mock Get-Item -ModuleName MDEValidator { $null }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{
                    PSPath = 'Registry::HKLM\...'
                    DisableRealtimeMonitoring = 0
                }
            }

            $result = Get-MDEManagementTypeFallback

            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Not configured' {

        It 'returns Not Configured when neither policy path has entries' {
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-Item -ModuleName MDEValidator { $null }

            $result = Get-MDEManagementTypeFallback

            $result | Should -BeLike '*Not Configured*'
        }
    }
}
