BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEExclusionVisibilityLocalAdmins' {

    Context 'Exclusions hidden (Pass)' {

        It 'returns Pass when HideExclusionsFromLocalAdmins is 1 in policy registry' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -HideExclusionsFromLocalAdmins $true
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ HideExclusionsFromLocalAdmins = 1 }
            }

            $result = Test-MDEExclusionVisibilityLocalAdmins

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Exclusions visible (Fail/Warning)' {

        It 'returns Warning when HideExclusionsFromLocalAdmins is not configured' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock
            }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEExclusionVisibilityLocalAdmins

            $result.Status | Should -BeIn @('Warning', 'Info')
        }
    }
}
