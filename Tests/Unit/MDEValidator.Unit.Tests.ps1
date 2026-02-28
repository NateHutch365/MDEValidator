#Requires -Modules Pester

<#
.SYNOPSIS
    Comprehensive Pester 5.x unit tests for the MDEValidator module.

.DESCRIPTION
    Tests pass, fail, and warning paths for all core validation functions.
    Uses mock PSObjects passed via -MpPreference / -MpComputerStatus parameters
    where possible, and Pester Mock for functions that call Get-Service, Test-Path,
    or Get-ItemProperty directly.

    All tests run cross-platform — no real Windows cmdlets are invoked.
#>

BeforeAll {
    # Import the module under test
    $modulePath = Join-Path $PSScriptRoot '../../MDEValidator/MDEValidator.psm1'
    Import-Module $modulePath -Force
}

AfterAll {
    Remove-Module MDEValidator -ErrorAction SilentlyContinue
}

# ──────────────────────────────────────────────
# Protection Tests
# ──────────────────────────────────────────────

Describe 'Test-MDEServiceStatus' {
    BeforeAll {
        # Mock Get-Service so we never touch real services
        Mock Get-Service {
            [PSCustomObject]@{
                Name      = 'WinDefend'
                Status    = 'Running'
                StartType = 'Automatic'
            }
        }
    }

    Context 'WinDefend is Running and Automatic' {
        It 'Should return Pass' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'WinDefend'; Status = 'Running'; StartType = 'Automatic' }
            }
            $result = Test-MDEServiceStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Windows Defender Service Status'
        }
    }

    Context 'WinDefend is Running but Manual start type' {
        It 'Should return Warning' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'WinDefend'; Status = 'Running'; StartType = 'Manual' }
            }
            $result = Test-MDEServiceStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
            $result.TestName | Should -Be 'Windows Defender Service Status'
        }
    }

    Context 'WinDefend is Stopped' {
        It 'Should return Fail' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'WinDefend'; Status = 'Stopped'; StartType = 'Manual' }
            }
            $result = Test-MDEServiceStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'Get-Service throws (service not found)' {
        It 'Should return Fail' {
            Mock Get-Service { throw 'Service not found' }
            $result = Test-MDEServiceStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }
}

Describe 'Test-MDERealTimeProtection' {
    Context 'Real-time protection is enabled' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ DisableRealtimeMonitoring = $false }
            $result = Test-MDERealTimeProtection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Real-Time Protection'
        }
    }

    Context 'Real-time protection is disabled' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ DisableRealtimeMonitoring = $true }
            $result = Test-MDERealTimeProtection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Real-Time Protection'
        }
    }
}

Describe 'Test-MDECloudProtection' {
    Context 'MAPSReporting is Advanced (2)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ MAPSReporting = 2 }
            $result = Test-MDECloudProtection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Cloud-Delivered Protection'
        }
    }

    Context 'MAPSReporting is Basic (1)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ MAPSReporting = 1 }
            $result = Test-MDECloudProtection -MpPreference $mockPref
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'MAPSReporting is Disabled (0)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ MAPSReporting = 0 }
            $result = Test-MDECloudProtection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Cloud-Delivered Protection'
        }
    }
}

Describe 'Test-MDECloudBlockLevel' {
    Context 'CloudBlockLevel is High (2)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ CloudBlockLevel = 2 }
            $result = Test-MDECloudBlockLevel -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Cloud Block Level'
        }
    }

    Context 'CloudBlockLevel is High+ (4)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ CloudBlockLevel = 4 }
            $result = Test-MDECloudBlockLevel -MpPreference $mockPref
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'CloudBlockLevel is Zero Tolerance (6)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ CloudBlockLevel = 6 }
            $result = Test-MDECloudBlockLevel -MpPreference $mockPref
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'CloudBlockLevel is Default/Not Configured (0)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ CloudBlockLevel = 0 }
            $result = Test-MDECloudBlockLevel -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Cloud Block Level'
        }
    }

    Context 'CloudBlockLevel is Moderate (1)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ CloudBlockLevel = 1 }
            $result = Test-MDECloudBlockLevel -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'CloudBlockLevel is unknown value (99)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ CloudBlockLevel = 99 }
            $result = Test-MDECloudBlockLevel -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }
}

Describe 'Test-MDECloudExtendedTimeout' {
    Context 'CloudExtendedTimeout is 50 (optimal)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ CloudExtendedTimeout = 50 }
            $result = Test-MDECloudExtendedTimeout -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Cloud Extended Timeout'
        }
    }

    Context 'CloudExtendedTimeout is 41 (lower bound of optimal)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ CloudExtendedTimeout = 41 }
            $result = Test-MDECloudExtendedTimeout -MpPreference $mockPref
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'CloudExtendedTimeout is 30 (mid range)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ CloudExtendedTimeout = 30 }
            $result = Test-MDECloudExtendedTimeout -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'CloudExtendedTimeout is 0 (not configured)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ CloudExtendedTimeout = 0 }
            $result = Test-MDECloudExtendedTimeout -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Cloud Extended Timeout'
        }
    }

    Context 'CloudExtendedTimeout is 10 (low)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ CloudExtendedTimeout = 10 }
            $result = Test-MDECloudExtendedTimeout -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }
}

Describe 'Test-MDESampleSubmission' {
    Context 'SubmitSamplesConsent is Send All (3)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ SubmitSamplesConsent = 3 }
            $result = Test-MDESampleSubmission -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Automatic Sample Submission'
        }
    }

    Context 'SubmitSamplesConsent is Safe samples only (1)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ SubmitSamplesConsent = 1 }
            $result = Test-MDESampleSubmission -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'SubmitSamplesConsent is Always Prompt (0)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ SubmitSamplesConsent = 0 }
            $result = Test-MDESampleSubmission -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'SubmitSamplesConsent is Never send (2)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ SubmitSamplesConsent = 2 }
            $result = Test-MDESampleSubmission -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }
}

Describe 'Test-MDEBehaviorMonitoring' {
    Context 'Behavior monitoring is enabled' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ DisableBehaviorMonitoring = $false }
            $result = Test-MDEBehaviorMonitoring -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Behavior Monitoring'
        }
    }

    Context 'Behavior monitoring is disabled' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ DisableBehaviorMonitoring = $true }
            $result = Test-MDEBehaviorMonitoring -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Behavior Monitoring'
        }
    }
}

Describe 'Test-MDENetworkProtection' {
    Context 'Network protection is Enabled/Block (1)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ EnableNetworkProtection = 1 }
            $result = Test-MDENetworkProtection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Network Protection'
        }
    }

    Context 'Network protection is Disabled (0)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ EnableNetworkProtection = 0 }
            $result = Test-MDENetworkProtection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'Network protection is Audit mode (2)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ EnableNetworkProtection = 2 }
            $result = Test-MDENetworkProtection -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }
}

# ──────────────────────────────────────────────
# Tamper Protection Tests
# ──────────────────────────────────────────────

Describe 'Test-MDETamperProtection' {
    Context 'Tamper Protection is enabled' {
        It 'Should return Pass' {
            $mockStatus = [PSCustomObject]@{
                IsTamperProtected       = $true
                TamperProtectionSource  = 'ATP'
            }
            $result = Test-MDETamperProtection -MpComputerStatus $mockStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Tamper Protection'
        }
    }

    Context 'Tamper Protection is disabled' {
        It 'Should return Fail' {
            $mockStatus = [PSCustomObject]@{
                IsTamperProtected       = $false
                TamperProtectionSource  = ''
            }
            $result = Test-MDETamperProtection -MpComputerStatus $mockStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Tamper Protection'
        }
    }
}

Describe 'Test-MDETamperProtectionForExclusions' {
    # This function also reads the registry; mock those paths so it works cross-platform.
    BeforeAll {
        Mock Test-Path { $false }
        Mock Get-ItemProperty { $null }
    }

    Context 'Tamper Protection is disabled (prerequisite fails)' {
        It 'Should return Fail' {
            $mockStatus = [PSCustomObject]@{
                IsTamperProtected  = $false
                AMProductVersion   = '4.18.2301.1'
            }
            $result = Test-MDETamperProtectionForExclusions -MpComputerStatus $mockStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Tamper Protection for Exclusions'
        }
    }

    Context 'Tamper Protection is enabled but platform version is null' {
        It 'Should return Fail' {
            $mockStatus = [PSCustomObject]@{
                IsTamperProtected  = $true
                AMProductVersion   = $null
            }
            $result = Test-MDETamperProtectionForExclusions -MpComputerStatus $mockStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }
}

# ──────────────────────────────────────────────
# ASR Tests
# ──────────────────────────────────────────────

Describe 'Test-MDEAttackSurfaceReduction' {
    Context 'ASR rules configured with Block actions' {
        It 'Should return Pass when rules are in Block mode' {
            $mockPref = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids     = @(
                    '56a863a9-875e-4185-98a7-b882c64b5ce5',
                    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
                )
                AttackSurfaceReductionRules_Actions = @(1, 1)
            }
            $result = Test-MDEAttackSurfaceReduction -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Attack Surface Reduction Rules'
        }
    }

    Context 'ASR rules in Audit mode only' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids     = @(
                    '56a863a9-875e-4185-98a7-b882c64b5ce5'
                )
                AttackSurfaceReductionRules_Actions = @(2)
            }
            $result = Test-MDEAttackSurfaceReduction -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'ASR rules all disabled' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids     = @(
                    '56a863a9-875e-4185-98a7-b882c64b5ce5'
                )
                AttackSurfaceReductionRules_Actions = @(0)
            }
            $result = Test-MDEAttackSurfaceReduction -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'No ASR rules configured' {
        It 'Should return Fail when Ids is null' {
            $mockPref = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids     = $null
                AttackSurfaceReductionRules_Actions = $null
            }
            $result = Test-MDEAttackSurfaceReduction -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }

        It 'Should return Fail when Ids is empty array' {
            $mockPref = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids     = @()
                AttackSurfaceReductionRules_Actions = @()
            }
            $result = Test-MDEAttackSurfaceReduction -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'Mixed ASR rule actions with at least one Block' {
        It 'Should return Pass when at least one rule is in Block mode' {
            $mockPref = [PSCustomObject]@{
                AttackSurfaceReductionRules_Ids     = @(
                    '56a863a9-875e-4185-98a7-b882c64b5ce5',
                    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
                    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
                )
                AttackSurfaceReductionRules_Actions = @(1, 2, 0)
            }
            $result = Test-MDEAttackSurfaceReduction -MpPreference $mockPref
            $result.Status | Should -Be 'Pass'
        }
    }
}

# ──────────────────────────────────────────────
# Onboarding Tests
# ──────────────────────────────────────────────

Describe 'Test-MDEOnboardingStatus' {
    BeforeAll {
        Mock Get-Service { $null }
        Mock Test-Path { $false }
        Mock Get-ItemProperty { $null }
    }

    Context 'Device is fully onboarded' {
        It 'Should return Pass when SENSE is running and OnboardingState=1' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'Sense'; Status = 'Running' }
            } -ParameterFilter { $Name -eq 'Sense' }

            Mock Test-Path { $true } -ParameterFilter {
                $Path -like '*Windows Advanced Threat Protection*'
            }

            Mock Get-ItemProperty {
                [PSCustomObject]@{ OnboardingState = 1 }
            } -ParameterFilter {
                $Path -like '*Windows Advanced Threat Protection*'
            }

            $result = Test-MDEOnboardingStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'MDE Onboarding Status'
        }
    }

    Context 'SENSE service is not installed' {
        It 'Should return Fail' {
            Mock Get-Service { $null } -ParameterFilter { $Name -eq 'Sense' }

            $result = Test-MDEOnboardingStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'SENSE is running but OnboardingState is not 1' {
        It 'Should return Warning' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'Sense'; Status = 'Running' }
            } -ParameterFilter { $Name -eq 'Sense' }

            Mock Test-Path { $true } -ParameterFilter {
                $Path -like '*Windows Advanced Threat Protection*'
            }

            Mock Get-ItemProperty {
                [PSCustomObject]@{ OnboardingState = 0 }
            } -ParameterFilter {
                $Path -like '*Windows Advanced Threat Protection*'
            }

            $result = Test-MDEOnboardingStatus
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'SENSE is running but registry key does not exist' {
        It 'Should return Warning' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'Sense'; Status = 'Running' }
            } -ParameterFilter { $Name -eq 'Sense' }

            Mock Test-Path { $false } -ParameterFilter {
                $Path -like '*Windows Advanced Threat Protection*'
            }

            $result = Test-MDEOnboardingStatus
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'SENSE service exists but is not running' {
        It 'Should return Fail' {
            Mock Get-Service {
                [PSCustomObject]@{ Name = 'Sense'; Status = 'Stopped' }
            } -ParameterFilter { $Name -eq 'Sense' }

            $result = Test-MDEOnboardingStatus
            $result.Status | Should -Be 'Fail'
        }
    }
}

# ──────────────────────────────────────────────
# SmartScreen Tests
# ──────────────────────────────────────────────

Describe 'Test-MDESmartScreen' {
    BeforeAll {
        Mock Test-Path { $false }
        Mock Get-ItemProperty { $null }
    }

    Context 'SmartScreen is enabled via Group Policy' {
        It 'Should return Pass when SmartScreenEnabled=1' {
            Mock Test-Path { $true } -ParameterFilter {
                $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            }

            Mock Get-ItemProperty {
                [PSCustomObject]@{ SmartScreenEnabled = 1 }
            } -ParameterFilter {
                $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            }

            $result = Test-MDESmartScreen
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Edge SmartScreen'
        }
    }

    Context 'SmartScreen is disabled via Group Policy' {
        It 'Should return Fail when SmartScreenEnabled=0' {
            Mock Test-Path { $true } -ParameterFilter {
                $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            }

            Mock Get-ItemProperty {
                [PSCustomObject]@{ SmartScreenEnabled = 0 }
            } -ParameterFilter {
                $Path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            }

            $result = Test-MDESmartScreen
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }
}

# ──────────────────────────────────────────────
# Scan and Updates Tests
# ──────────────────────────────────────────────

Describe 'Test-MDEDisableCatchupQuickScan' {
    Context 'Catchup Quick Scan is enabled (DisableCatchupQuickScan=$false)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ DisableCatchupQuickScan = $false }
            $result = Test-MDEDisableCatchupQuickScan -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Catchup Quick Scan'
        }
    }

    Context 'Catchup Quick Scan is disabled (DisableCatchupQuickScan=$true)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ DisableCatchupQuickScan = $true }
            $result = Test-MDEDisableCatchupQuickScan -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
            $result.TestName | Should -Be 'Catchup Quick Scan'
        }
    }
}

Describe 'Test-MDERealTimeScanDirection' {
    Context 'RealTimeScanDirection is bi-directional (0)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ RealTimeScanDirection = 0 }
            $result = Test-MDERealTimeScanDirection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Real Time Scan Direction'
        }
    }

    Context 'RealTimeScanDirection is incoming only (1)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ RealTimeScanDirection = 1 }
            $result = Test-MDERealTimeScanDirection -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'RealTimeScanDirection is outgoing only (2)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ RealTimeScanDirection = 2 }
            $result = Test-MDERealTimeScanDirection -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'RealTimeScanDirection is null' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ RealTimeScanDirection = $null }
            $result = Test-MDERealTimeScanDirection -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }
}

Describe 'Test-MDESignatureUpdateFallbackOrder' {
    Context 'Recommended fallback order is configured' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{
                SignatureFallbackOrder = 'MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer'
            }
            $result = Test-MDESignatureUpdateFallbackOrder -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Signature Update Fallback Order'
        }
    }

    Context 'Non-recommended fallback order is configured' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{
                SignatureFallbackOrder = 'MicrosoftUpdateServer|MMPC'
            }
            $result = Test-MDESignatureUpdateFallbackOrder -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'Fallback order is empty' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ SignatureFallbackOrder = '' }
            $result = Test-MDESignatureUpdateFallbackOrder -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'Fallback order is null' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ SignatureFallbackOrder = $null }
            $result = Test-MDESignatureUpdateFallbackOrder -MpPreference $mockPref
            $result.Status | Should -Be 'Fail'
        }
    }
}

Describe 'Test-MDESignatureUpdateInterval' {
    Context 'Interval is 1 hour (optimal)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ SignatureUpdateInterval = 1 }
            $result = Test-MDESignatureUpdateInterval -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'Signature Update Interval'
        }
    }

    Context 'Interval is 4 hours (upper optimal)' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ SignatureUpdateInterval = 4 }
            $result = Test-MDESignatureUpdateInterval -MpPreference $mockPref
            $result.Status | Should -Be 'Pass'
        }
    }

    Context 'Interval is 12 hours (less frequent)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ SignatureUpdateInterval = 12 }
            $result = Test-MDESignatureUpdateInterval -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'Interval is 24 hours (boundary)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ SignatureUpdateInterval = 24 }
            $result = Test-MDESignatureUpdateInterval -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'Interval is 0 (disabled)' {
        It 'Should return Fail' {
            $mockPref = [PSCustomObject]@{ SignatureUpdateInterval = 0 }
            $result = Test-MDESignatureUpdateInterval -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Fail'
        }
    }

    Context 'Interval is >24 (invalid)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ SignatureUpdateInterval = 48 }
            $result = Test-MDESignatureUpdateInterval -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }
}

Describe 'Test-MDEFileHashComputation' {
    Context 'File hash computation is enabled' {
        It 'Should return Pass' {
            $mockPref = [PSCustomObject]@{ EnableFileHashComputation = $true }
            $result = Test-MDEFileHashComputation -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Pass'
            $result.TestName | Should -Be 'File Hash Computation'
        }
    }

    Context 'File hash computation is disabled' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ EnableFileHashComputation = $false }
            $result = Test-MDEFileHashComputation -MpPreference $mockPref
            $result | Should -Not -BeNullOrEmpty
            $result.Status | Should -Be 'Warning'
        }
    }

    Context 'File hash computation is null (not configured)' {
        It 'Should return Warning' {
            $mockPref = [PSCustomObject]@{ EnableFileHashComputation = $null }
            $result = Test-MDEFileHashComputation -MpPreference $mockPref
            $result.Status | Should -Be 'Warning'
        }
    }
}

# ──────────────────────────────────────────────
# Validation Result Shape Tests
# ──────────────────────────────────────────────

Describe 'Validation Result Object Shape' {
    It 'Every result should have TestName, Status, Message, Recommendation, Timestamp' {
        $mockPref = [PSCustomObject]@{ DisableRealtimeMonitoring = $false }
        $result = Test-MDERealTimeProtection -MpPreference $mockPref

        $result.PSObject.Properties.Name | Should -Contain 'TestName'
        $result.PSObject.Properties.Name | Should -Contain 'Status'
        $result.PSObject.Properties.Name | Should -Contain 'Message'
        $result.PSObject.Properties.Name | Should -Contain 'Recommendation'
        $result.PSObject.Properties.Name | Should -Contain 'Timestamp'
    }

    It 'Timestamp should be in yyyy-MM-dd HH:mm:ss format' {
        $mockPref = [PSCustomObject]@{ DisableRealtimeMonitoring = $false }
        $result = Test-MDERealTimeProtection -MpPreference $mockPref

        $result.Timestamp | Should -Match '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$'
    }

    It 'Status should be a valid value' {
        $mockPref = [PSCustomObject]@{ DisableRealtimeMonitoring = $false }
        $result = Test-MDERealTimeProtection -MpPreference $mockPref

        $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
    }
}
