BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESignatureUpdateFallbackOrder' {

    Context 'Pass path' {

        It 'returns Pass when fallback order matches recommended value' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when fallback order is not configured' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                [PSCustomObject]@{
                    SignatureFallbackOrder = $null
                }
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
