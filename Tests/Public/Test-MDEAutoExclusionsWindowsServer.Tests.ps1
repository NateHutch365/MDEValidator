BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-MDEAutoExclusionsWindowsServer' {

    Context 'Pass path' {

        It 'returns NotApplicable when not running on Windows Server' {
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $false }

            $result = Test-MDEAutoExclusionsWindowsServer

            $result.Status | Should -Be 'NotApplicable'
            Should -Invoke Test-IsWindowsServer -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when on Windows Server and auto exclusions are disabled' {
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $true }
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableAutoExclusions $true
            }

            $result = Test-MDEAutoExclusionsWindowsServer

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Warning when on Windows Server and auto exclusions are enabled' {
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $true }
            Mock Get-MpPreference -ModuleName MDEValidator {
                New-MpPreferenceMock -DisableAutoExclusions $false
            }

            $result = Test-MDEAutoExclusionsWindowsServer

            $result.Status | Should -Be 'Warning'
            Should -Invoke Get-MpPreference -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
