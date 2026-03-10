BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Write-ValidationResult' {

    Context 'Return type and shape' {

        It 'returns a PSCustomObject' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result | Should -BeOfType [PSCustomObject]
            }
        }

        It 'result includes TestName property matching the provided value' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'Check-SomeSetting' -Status 'Pass'
                $result.TestName | Should -Be 'Check-SomeSetting'
            }
        }

        It 'result includes Status property matching the provided value' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Fail'
                $result.Status | Should -Be 'Fail'
            }
        }

        It 'result includes Message property' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result.PSObject.Properties.Name | Should -Contain 'Message'
            }
        }

        It 'result includes Recommendation property' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result.PSObject.Properties.Name | Should -Contain 'Recommendation'
            }
        }

        It 'result includes Timestamp property' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result.PSObject.Properties.Name | Should -Contain 'Timestamp'
            }
        }
    }

    Context 'Status values' {

        It 'accepts Pass status' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result.Status | Should -Be 'Pass'
            }
        }

        It 'accepts Fail status' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Fail'
                $result.Status | Should -Be 'Fail'
            }
        }

        It 'accepts Warning status' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Warning'
                $result.Status | Should -Be 'Warning'
            }
        }

        It 'accepts Info status' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Info'
                $result.Status | Should -Be 'Info'
            }
        }

        It 'accepts NotApplicable status' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'NotApplicable'
                $result.Status | Should -Be 'NotApplicable'
            }
        }
    }

    Context 'Optional parameters' {

        It 'stores provided Message value' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Fail' -Message 'Something went wrong'
                $result.Message | Should -Be 'Something went wrong'
            }
        }

        It 'stores provided Recommendation value' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Fail' -Recommendation 'Enable the setting'
                $result.Recommendation | Should -Be 'Enable the setting'
            }
        }

        It 'defaults Message to empty string when not provided' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result.Message | Should -Be ''
            }
        }

        It 'defaults Recommendation to empty string when not provided' {
            InModuleScope MDEValidator {
                $result = Write-ValidationResult -TestName 'SomeTest' -Status 'Pass'
                $result.Recommendation | Should -Be ''
            }
        }
    }
}
