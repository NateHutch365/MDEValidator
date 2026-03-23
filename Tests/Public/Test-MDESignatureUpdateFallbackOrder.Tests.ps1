BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESignatureUpdateFallbackOrder' {

    Context 'Pass path' {

        It 'returns Pass when fallback order matches recommended value' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MicrosoftUpdateServer|MMPC|InternalDefinitionUpdateServer'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when InternalDefinitionUpdateServer is absent but order is correct' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MicrosoftUpdateServer|MMPC'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when additional sources are present but order is correct' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MicrosoftUpdateServer|MMPC|InternalDefinitionUpdateServer|FileShares'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Warning path' {

        It 'returns Warning when MMPC appears before MicrosoftUpdateServer' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Warning when MicrosoftUpdateServer is missing' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MMPC|InternalDefinitionUpdateServer'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Warning when MMPC is missing' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -SignatureFallbackOrder 'MicrosoftUpdateServer|InternalDefinitionUpdateServer'
            }

            $result = Test-MDESignatureUpdateFallbackOrder

            $result.Status | Should -Be 'Warning'
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
