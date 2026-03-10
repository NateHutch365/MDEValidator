BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEServiceStatus' {

    Context 'Pass path' {

        It 'returns Pass when WinDefend is Running and start type is Automatic' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'WinDefend' -Status 'Running' -StartType 'Automatic'
            }

            $result = Test-MDEServiceStatus

            $result.Status | Should -Be 'Pass'
            Should -Invoke Get-Service -ModuleName MDEValidator -Times 2 -Exactly
        }
    }

    Context 'Fail path' {

        It 'returns Fail when WinDefend is Stopped' {
            Mock Get-Service -ModuleName MDEValidator {
                New-ServiceMock -Name 'WinDefend' -Status 'Stopped' -StartType 'Automatic'
            }

            $result = Test-MDEServiceStatus

            $result.Status | Should -Be 'Fail'
            Should -Invoke Get-Service -ModuleName MDEValidator -Times 1 -Exactly
        }

        It 'returns Fail when WinDefend service is not found' {
            Mock Get-Service -ModuleName MDEValidator { throw 'Service not found' }

            $result = Test-MDEServiceStatus

            $result.Status | Should -Be 'Fail'
        }
    }
}
