#Requires -Modules Pester
<#
.SYNOPSIS
    Pester tests for MDEValidator module.

.DESCRIPTION
    Unit tests for the MDEValidator PowerShell module functions.
#>

BeforeAll {
    # Import the module
    $modulePath = Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1'
    Import-Module $modulePath -Force
}

Describe 'MDEValidator Module' {
    Context 'Module Import' {
        It 'Should import the module without errors' {
            { Import-Module (Join-Path $PSScriptRoot '..' 'MDEValidator' 'MDEValidator.psm1') -Force } | Should -Not -Throw
        }
        
        It 'Should export Test-MDEConfiguration function' {
            Get-Command -Name 'Test-MDEConfiguration' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Get-MDEValidationReport function' {
            Get-Command -Name 'Get-MDEValidationReport' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEServiceStatus function' {
            Get-Command -Name 'Test-MDEServiceStatus' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDERealTimeProtection function' {
            Get-Command -Name 'Test-MDERealTimeProtection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDECloudProtection function' {
            Get-Command -Name 'Test-MDECloudProtection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESampleSubmission function' {
            Get-Command -Name 'Test-MDESampleSubmission' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEBehaviorMonitoring function' {
            Get-Command -Name 'Test-MDEBehaviorMonitoring' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEOnboardingStatus function' {
            Get-Command -Name 'Test-MDEOnboardingStatus' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDENetworkProtection function' {
            Get-Command -Name 'Test-MDENetworkProtection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEAttackSurfaceReduction function' {
            Get-Command -Name 'Test-MDEAttackSurfaceReduction' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Test-MDEServiceStatus' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEServiceStatus
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Windows Defender Service Status'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Test-MDERealTimeProtection' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDERealTimeProtection
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Real-Time Protection'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Test-MDECloudProtection' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDECloudProtection
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Cloud-Delivered Protection'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
    }
    
    Context 'Test-MDESampleSubmission' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESampleSubmission
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Automatic Sample Submission'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
    }
    
    Context 'Test-MDEBehaviorMonitoring' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEBehaviorMonitoring
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Behavior Monitoring'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
    }
    
    Context 'Test-MDEOnboardingStatus' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEOnboardingStatus
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'MDE Onboarding Status'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
    }
    
    Context 'Test-MDENetworkProtection' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDENetworkProtection
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Network Protection'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
    }
    
    Context 'Test-MDEAttackSurfaceReduction' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEAttackSurfaceReduction
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Attack Surface Reduction Rules'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
    }
    
    Context 'Test-MDEConfiguration' {
        It 'Should return an array of results' {
            $results = Test-MDEConfiguration
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -BeGreaterThan 0
        }
        
        It 'Should include all basic tests when called without parameters' {
            $results = Test-MDEConfiguration
            $testNames = $results.TestName
            $testNames | Should -Contain 'Windows Defender Service Status'
            $testNames | Should -Contain 'Real-Time Protection'
            $testNames | Should -Contain 'Cloud-Delivered Protection'
            $testNames | Should -Contain 'Automatic Sample Submission'
            $testNames | Should -Contain 'Behavior Monitoring'
            $testNames | Should -Contain 'Network Protection'
            $testNames | Should -Contain 'Attack Surface Reduction Rules'
        }
        
        It 'Should include onboarding test when -IncludeOnboarding is specified' {
            $results = Test-MDEConfiguration -IncludeOnboarding
            $testNames = $results.TestName
            $testNames | Should -Contain 'MDE Onboarding Status'
        }
    }
    
    Context 'Get-MDEValidationReport' {
        It 'Should return results when OutputFormat is Object' {
            $results = Get-MDEValidationReport -OutputFormat Object
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -BeGreaterThan 0
        }
        
        It 'Should create HTML file when OutputFormat is HTML' {
            $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
            $tempPath = Join-Path $tempDir "MDETest_$(Get-Random).html"
            try {
                $outputPath = Get-MDEValidationReport -OutputFormat HTML -OutputPath $tempPath
                $outputPath | Should -Be $tempPath
                Test-Path $tempPath | Should -Be $true
                $htmlContent = Get-Content $tempPath -Raw
                $htmlContent | Should -Match 'MDE Configuration Validation Report'
            }
            finally {
                if (Test-Path $tempPath) {
                    Remove-Item $tempPath -Force
                }
            }
        }
    }
}
