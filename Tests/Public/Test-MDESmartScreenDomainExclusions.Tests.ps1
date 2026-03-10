BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDESmartScreenDomainExclusions' {

    Context 'No exclusions configured (Pass)' {

        It 'returns Pass when SmartScreenAllowListDomains registry key is absent' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDESmartScreenDomainExclusions

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Domain exclusions configured (Warning)' {

        It 'returns Warning when allow-list domains are present' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{
                    PSPath = 'Registry::HKLM\...'
                    '1'    = 'contoso.com'
                    '2'    = 'fabrikam.com'
                }
            }

            $result = Test-MDESmartScreenDomainExclusions

            $result.Status | Should -Be 'Warning'
        }
    }
}
