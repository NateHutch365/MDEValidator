BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDENISEnabled' {

    Context 'Pass path' {

        It 'returns Pass when NISEnabled is true' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -NISEnabled $true
            }

            $result = Test-MDENISEnabled

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Warning path' {

        It 'returns Warning when NISEnabled is false' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -NISEnabled $false
            }

            $result = Test-MDENISEnabled

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when Get-MpComputerStatus throws' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator { throw 'Defender unavailable' }

            $result = Test-MDENISEnabled

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}

Describe 'Test-MDENISEnabled — PSScriptAnalyzer compliance' {

    It 'reports zero Error or Warning violations (QA-02)' {
        if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer not installed locally (enforced by CI pipeline PSSA step)'
        }

        $scriptPath   = (Resolve-Path (Join-Path $PSScriptRoot '..\..\MDEValidator\Public\Test-MDENISEnabled.ps1')).Path
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
