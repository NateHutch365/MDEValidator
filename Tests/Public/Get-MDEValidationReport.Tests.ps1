BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Get-MDEValidationReport' {

    Context 'Object output format' {

        It 'returns array of validation result objects' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @(
                    [PSCustomObject]@{ TestName = 'Service Status'; Status = 'Pass' }
                )
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise 23H2' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'Intune' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Onboarded' }

            $result = Get-MDEValidationReport -OutputFormat Object

            $result | Should -Not -BeNullOrEmpty
            $result[0].Status | Should -Be 'Pass'
        }
    }

    Context 'Console output format' {

        It 'executes without error for Console format' {
            Mock Test-MDEConfiguration -ModuleName MDEValidator {
                @([PSCustomObject]@{ TestName = 'Service Status'; Status = 'Pass'; Message = 'OK' })
            }
            Mock Get-MDEOperatingSystemInfo -ModuleName MDEValidator { 'Windows 11 Enterprise' }
            Mock Get-MDESecuritySettingsManagementStatus -ModuleName MDEValidator { 'GPO' }
            Mock Get-MDEOnboardingStatusString -ModuleName MDEValidator { 'Not Onboarded' }

            { Get-MDEValidationReport -OutputFormat Console } | Should -Not -Throw
        }
    }
}
