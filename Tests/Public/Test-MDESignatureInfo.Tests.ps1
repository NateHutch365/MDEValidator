BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESignatureInfo' {

    Context 'Info path' {

        It 'returns Info for Antivirus Signature Version' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureVersion '1.1.24040.4' `
                    -AntivirusSignatureLastUpdated ([datetime]'2026-04-08 12:00:00')
            }

            $result = Test-MDESignatureInfo

            ($result | Where-Object TestName -eq 'Antivirus Signature Version').Status | Should -Be 'Info'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'surfaces the signature version string in the message' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureVersion '1.1.24040.4' `
                    -AntivirusSignatureLastUpdated ([datetime]'2026-04-08 12:00:00')
            }

            $result = Test-MDESignatureInfo

            ($result | Where-Object TestName -eq 'Antivirus Signature Version').Message | Should -Match '1\.1\.24040\.4'
        }

        It 'returns Info for Antivirus Signature Last Updated' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureVersion '1.1.24040.4' `
                    -AntivirusSignatureLastUpdated ([datetime]'2026-04-08 12:00:00')
            }

            $result = Test-MDESignatureInfo

            ($result | Where-Object TestName -eq 'Antivirus Signature Last Updated').Status | Should -Be 'Info'
        }

        It 'surfaces the last-updated date in the message' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureVersion '1.1.24040.4' `
                    -AntivirusSignatureLastUpdated ([datetime]'2026-04-08 12:00:00')
            }

            $result = Test-MDESignatureInfo

            ($result | Where-Object TestName -eq 'Antivirus Signature Last Updated').Message | Should -Match '2026-04-08'
        }
    }

    Context 'Null path — version property is null' {

        It 'returns Info with Unknown when AntivirusSignatureVersion is null' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                [PSCustomObject]@{
                    AntivirusSignatureVersion      = $null
                    AntivirusSignatureLastUpdated = [datetime]'2026-04-08 12:00:00'
                }
            }

            $result = Test-MDESignatureInfo

            $versionResult = $result | Where-Object TestName -eq 'Antivirus Signature Version'
            $versionResult.Status | Should -Be 'Info'
            $versionResult.Message | Should -Match 'Unknown'
        }

        It 'returns Info with Unknown when AntivirusSignatureLastUpdated is null' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                [PSCustomObject]@{
                    AntivirusSignatureVersion      = '1.1.24040.4'
                    AntivirusSignatureLastUpdated = $null
                }
            }

            $result = Test-MDESignatureInfo

            $lastUpdatedResult = $result | Where-Object TestName -eq 'Antivirus Signature Last Updated'
            $lastUpdatedResult.Status | Should -Be 'Info'
            $lastUpdatedResult.Message | Should -Match 'Unknown'
        }
    }
}

Describe 'Test-MDESignatureInfo — PSScriptAnalyzer compliance' {

    It 'reports zero Error or Warning violations (QA-02)' {
        if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer not installed locally (enforced by CI pipeline PSSA step)'
        }

        $scriptPath   = (Resolve-Path (Join-Path $PSScriptRoot '..\..\MDEValidator\Public\Test-MDESignatureInfo.ps1')).Path
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
