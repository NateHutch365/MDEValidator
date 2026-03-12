BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
}

Describe 'Test-IsElevated' {

    Context 'Return type contract' {

        It 'returns a boolean value' {
            InModuleScope MDEValidator {
                $result = Test-IsElevated
                $result | Should -BeOfType [bool]
            }
        }

        It 'does not throw when called' {
            InModuleScope MDEValidator {
                { Test-IsElevated } | Should -Not -Throw
            }
        }
    }

    Context 'Elevated session (mocked)' {

        It 'returns true when WindowsPrincipal reports Administrator role' {
            InModuleScope MDEValidator {
                # Mock New-Object to return a fake principal that reports elevated
                Mock New-Object {
                    $fakePrincipal = [PSCustomObject]@{}
                    Add-Member -InputObject $fakePrincipal -MemberType ScriptMethod -Name IsInRole -Value {
                        param([Security.Principal.WindowsBuiltInRole]$role)
                        return $true
                    }
                    return $fakePrincipal
                } -ParameterFilter { $TypeName -eq 'Security.Principal.WindowsPrincipal' }

                $result = Test-IsElevated
                $result | Should -Be $true
            }
        }
    }

    Context 'Non-elevated session (mocked)' {

        It 'returns false when WindowsPrincipal reports non-Administrator role' {
            InModuleScope MDEValidator {
                Mock New-Object {
                    $fakePrincipal = [PSCustomObject]@{}
                    Add-Member -InputObject $fakePrincipal -MemberType ScriptMethod -Name IsInRole -Value {
                        param([Security.Principal.WindowsBuiltInRole]$role)
                        return $false
                    }
                    return $fakePrincipal
                } -ParameterFilter { $TypeName -eq 'Security.Principal.WindowsPrincipal' }

                $result = Test-IsElevated
                $result | Should -Be $false
            }
        }
    }
}
