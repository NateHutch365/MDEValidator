BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEOnboardingStatus' {

    Context 'Pass path' {

        It 'returns Pass when Sense is running and OnboardingState is 1' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Running' -StartType 'Automatic'
            }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ OnboardingState = 1; OrgId = '00000000-0000-0000-0000-000000000001' }
            }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            ($result | Where-Object TestName -eq 'MDE Onboarding Status')[0].Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when Sense service is not installed' {
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            ($result | Where-Object TestName -eq 'MDE Onboarding Status')[0].Status | Should -Be 'Fail'
        }

        It 'returns Fail when Sense service is not running' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Stopped' -StartType 'Manual'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            ($result | Where-Object TestName -eq 'MDE Onboarding Status')[0].Status | Should -Be 'Fail'
        }
    }

    Context 'DiagTrack service check' {

        It 'returns Pass when DiagTrack service is running' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'DiagTrack' -Status 'Running' -DisplayName 'Connected User Experiences and Telemetry'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            $diagResult = $result | Where-Object TestName -eq 'Connected User Experiences and Telemetry Service'
            $diagResult.Status | Should -Be 'Pass'
        }

        It 'returns Warning when DiagTrack service is stopped' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'Sense' -Status 'Running' -StartType 'Automatic'
            }
            Mock Get-Service -ModuleName MDEValidator -ParameterFilter { $Name -eq 'DiagTrack' } {
                New-ServiceMock -Name 'DiagTrack' -Status 'Stopped' -StartType 'Manual'
            }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            $diagResult = $result | Where-Object TestName -eq 'Connected User Experiences and Telemetry Service'
            $diagResult.Status | Should -Be 'Warning'
        }

        It 'returns Warning when DiagTrack service is not installed' {
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            $diagResult = $result | Where-Object TestName -eq 'Connected User Experiences and Telemetry Service'
            $diagResult.Status | Should -Be 'Warning'
        }
    }

    Context 'OrgId registry check' {

        It 'returns Info with GUID when OrgId is present' {
            $testGuid = '12345678-abcd-efgh-ijkl-0123456789ab'
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ OnboardingState = 0; OrgId = $testGuid }
            }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            $orgResult = $result | Where-Object TestName -eq 'MDE Organization ID'
            $orgResult.Status | Should -Be 'Info'
            $orgResult.Message | Should -BeLike "*$testGuid*"
        }

        It 'returns Warning when OrgId registry property is absent' {
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ OnboardingState = 0 }
            }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            $orgResult = $result | Where-Object TestName -eq 'MDE Organization ID'
            $orgResult.Status | Should -Be 'Warning'
        }

        It 'returns Warning when MDE registry key does not exist' {
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'No WDATPOnboarding events' }

            $result = Test-MDEOnboardingStatus

            $orgResult = $result | Where-Object TestName -eq 'MDE Organization ID'
            $orgResult.Status | Should -Be 'Warning'
        }
    }

    Context 'WDATPOnboarding event log check' {

        It 'returns Pass with event count and timestamp when events are found' {
            $fakeTime = [datetime]'2026-03-15 10:30:00'
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator {
                New-WinEventMock -Count 5 -LatestTimeCreated $fakeTime
            }

            $result = Test-MDEOnboardingStatus

            $evtResult = $result | Where-Object TestName -eq 'WDATPOnboarding Event Log'
            $evtResult.Status | Should -Be 'Pass'
            $evtResult.Message | Should -BeLike '*5 event(s)*'
            $evtResult.Message | Should -BeLike "*$fakeTime*"
        }

        It 'returns Warning when no WDATPOnboarding events exist' {
            Mock Get-Service -ModuleName MDEValidator { $null }
            Mock Test-Path -ModuleName MDEValidator { $false }
            Mock Get-WinEvent -ModuleName MDEValidator { throw 'The RPC server is unavailable' }

            $result = Test-MDEOnboardingStatus

            $evtResult = $result | Where-Object TestName -eq 'WDATPOnboarding Event Log'
            $evtResult.Status | Should -Be 'Warning'
        }
    }
}

Describe 'Test-MDEOnboardingStatus — PSScriptAnalyzer compliance' {

    It 'reports zero Error or Warning violations (QA-02)' {
        if (-not (Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer not installed locally (enforced by CI pipeline PSSA step)'
        }

        $scriptPath   = (Resolve-Path (Join-Path $PSScriptRoot '..\..\MDEValidator\Public\Test-MDEOnboardingStatus.ps1')).Path
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
