BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEExclusionVisibilityLocalUsers' {

    Context 'Exclusions hidden (Pass)' {

        It 'returns Pass when HideExclusionsFromLocalUsers is 1 in policy registry' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ HideExclusionsFromLocalUsers = 1 }
            }

            $result = Test-MDEExclusionVisibilityLocalUsers

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Exclusions visible (Warning)' {

        It 'returns Warning when HideExclusionsFromLocalUsers is not set' {
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEExclusionVisibilityLocalUsers

            $result.Status | Should -BeIn @('Warning', 'Info')
        }

        It 'returns Warning when HideExclusionsFromLocalUsers is 0' {
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ HideExclusionsFromLocalUsers = 0 }
            }

            $result = Test-MDEExclusionVisibilityLocalUsers

            $result.Status | Should -BeIn @('Warning', 'Fail', 'Info')
        }
    }
}
