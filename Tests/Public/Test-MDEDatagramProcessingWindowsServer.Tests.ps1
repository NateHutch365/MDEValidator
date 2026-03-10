BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEDatagramProcessingWindowsServer' {

    Context 'Pass path' {

        It 'returns NotApplicable when not running on Windows Server' {
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $false }

            $result = Test-MDEDatagramProcessingWindowsServer

            $result.Status | Should -Be 'NotApplicable'
            Should -Invoke Test-IsWindowsServer -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Pass when on Windows Server and AllowDatagramProcessingOnWinServer is 1' {
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $true }
            Mock Test-Path -ModuleName MDEValidator { $true }
            Mock Get-ItemProperty -ModuleName MDEValidator {
                [PSCustomObject]@{ AllowDatagramProcessingOnWinServer = 1 }
            }

            $result = Test-MDEDatagramProcessingWindowsServer

            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Fail path' {

        It 'returns Fail when on Windows Server and registry key is not configured' {
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $true }
            Mock Test-Path -ModuleName MDEValidator { $false }

            $result = Test-MDEDatagramProcessingWindowsServer

            $result.Status | Should -Be 'Fail'
            Should -Invoke Test-IsWindowsServer -ModuleName MDEValidator -Times 1 -Exactly
        }
    }
}
