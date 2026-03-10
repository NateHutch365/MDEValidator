BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDESmartScreenAppRepExclusions' {

    Context 'No exclusions configured (Pass)' {

        It 'returns Pass when no AppRep exclusions registry keys exist' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDESmartScreenAppRepExclusions

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Exclusions configured (Warning)' {

        It 'returns Warning when ExemptSmartScreenDownloadWarnings JSON value is set' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{
                    ExemptSmartScreenDownloadWarnings = '[{"file_extension":"msi","domains":["contoso.com"]}]'
                }
            }

            $result = Test-MDESmartScreenAppRepExclusions

            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'Registry path exists but no exclusion value' {

        It 'returns Pass when registry key exists but ExemptSmartScreenDownloadWarnings is null' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{}
            }

            $result = Test-MDESmartScreenAppRepExclusions

            $result.Status | Should -Be 'Pass'
        }
    }
}
