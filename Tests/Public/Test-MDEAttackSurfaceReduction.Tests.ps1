BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEAttackSurfaceReduction' {

    Context 'Pass path' {

        It 'returns Pass when ASR rules are configured with Block action' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock `
                    -AttackSurfaceReductionRules_Ids @('56a863a9-875e-4185-98a7-b882c64b5ce5', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550') `
                    -AttackSurfaceReductionRules_Actions @(1, 1)
            }

            $result = Test-MDEAttackSurfaceReduction

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when no ASR rules are configured' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -AttackSurfaceReductionRules_Ids @() -AttackSurfaceReductionRules_Actions @()
            }

            $result = Test-MDEAttackSurfaceReduction

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
