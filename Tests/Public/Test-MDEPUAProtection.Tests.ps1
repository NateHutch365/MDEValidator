BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEPUAProtection' {

    Context 'Pass path' {

        It 'returns Pass when PUAProtection is 1 (Enabled)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -PUAProtection 1
            }

            $result = Test-MDEPUAProtection

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Warning path' {

        It 'returns Warning when PUAProtection is 6 (Audit)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -PUAProtection 6
            }

            $result = Test-MDEPUAProtection

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when PUAProtection is 0 (Disabled)' {
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -PUAProtection 0
            }

            $result = Test-MDEPUAProtection

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Fail when Get-MpPreference throws' {
            Mock Get-MpPreference -ModuleName MDEValidator { throw 'Defender unavailable' }

            $result = Test-MDEPUAProtection

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}

Describe 'Test-MDEPUAProtection — PSScriptAnalyzer compliance' {

    It 'reports zero Error or Warning violations (QA-02)' {
        if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer not installed locally (enforced by CI pipeline PSSA step)'
        }

        $scriptPath   = (Resolve-Path (Join-Path $PSScriptRoot '..\..\MDEValidator\Public\Test-MDEPUAProtection.ps1')).Path
        $settingsPath = (Resolve-Path (Join-Path $PSScriptRoot '..\..\.PSScriptAnalyzerSettings.psd1')).Path

        $violations = Invoke-ScriptAnalyzer `
            -Path     $scriptPath `
            -Settings $settingsPath `
            -Severity @('Error', 'Warning')

        if ($violations) {
            $violations | ForEach-Object { Write-Host "Line $($_.Line): [$($_.RuleName)] $($_.Message)" -ForegroundColor Yellow }
        }

        $violations | Should -BeNullOrEmpty
    }
}