BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDESignatureAge' {

    Context 'Pass path — 0 days old' {

        It 'returns Pass for Antivirus Signature Age when age is 0 days' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 0 -AntispywareSignatureAge 0
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Pass'
            Should -Invoke Get-MpComputerStatus -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass for Antispyware Signature Age when age is 0 days' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 0 -AntispywareSignatureAge 0
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Pass'
        }
    }

    Context 'Pass path — 1 day old' {

        It 'returns Pass for both signatures when age is 1 day' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 1 -AntispywareSignatureAge 1
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Pass'
            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Pass'
        }
    }

    Context 'Warning path — 2 days old' {

        It 'returns Warning for both signatures when age is 2 days' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 2 -AntispywareSignatureAge 2
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Warning'
            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Warning'
        }
    }

    Context 'Warning path — 3 days old' {

        It 'returns Warning for both signatures when age is 3 days' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 3 -AntispywareSignatureAge 3
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Warning'
            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Warning'
        }
    }

    Context 'Fail path — more than 3 days old' {

        It 'returns Fail for both signatures when age is 4 days' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 4 -AntispywareSignatureAge 4
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Fail'
            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Fail'
        }

        It 'returns Fail for both signatures when age is 30 days' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                New-MpComputerStatusMock -AntivirusSignatureAge 30 -AntispywareSignatureAge 30
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Fail'
            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Fail'
        }
    }

    Context 'Null path — age property is null' {

        It 'returns Warning for Antivirus Signature Age when age is null' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                [PSCustomObject]@{
                    AntivirusSignatureAge   = $null
                    AntispywareSignatureAge = 0
                }
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antivirus Signature Age').Status | Should -Be 'Warning'
        }

        It 'returns Warning for Antispyware Signature Age when age is null' {
            Mock Get-MpComputerStatus -ModuleName MDEValidator {
                [PSCustomObject]@{
                    AntivirusSignatureAge   = 0
                    AntispywareSignatureAge = $null
                }
            }

            $result = Test-MDESignatureAge

            ($result | Where-Object TestName -eq 'Antispyware Signature Age').Status | Should -Be 'Warning'
        }
    }
}

Describe 'Test-MDESignatureAge — PSScriptAnalyzer compliance' {

    It 'reports zero Error or Warning violations (QA-02)' {
        if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer not installed locally (enforced by CI pipeline PSSA step)'
        }

        $scriptPath   = (Resolve-Path (Join-Path $PSScriptRoot '..\..\MDEValidator\Public\Test-MDESignatureAge.ps1')).Path
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
