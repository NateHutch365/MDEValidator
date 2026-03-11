BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest

    . "$PSScriptRoot/../Helpers/MockBuilders.ps1"
}

Describe 'Test-MDEConfiguration' {

    Context 'Basic run (no flags)' {

        It 'returns an array of validation result objects' {
            Mock Test-MDEServiceStatus -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Service Status'; Status = 'Pass' }
            }
            Mock Test-MDEPassiveMode -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Passive Mode'; Status = 'Pass' }
            }
            Mock Test-MDERealTimeProtection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Real-Time Protection'; Status = 'Pass' }
            }
            Mock Test-MDECloudProtection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Cloud Protection'; Status = 'Pass' }
            }
            Mock Test-MDECloudBlockLevel -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Cloud Block Level'; Status = 'Pass' }
            }
            Mock Test-MDECloudExtendedTimeout -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Cloud Extended Timeout'; Status = 'Pass' }
            }
            Mock Test-MDEBehaviorMonitoring -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Behavior Monitoring'; Status = 'Pass' }
            }
            Mock Test-MDENetworkProtection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Network Protection'; Status = 'Pass' }
            }
            Mock Test-MDESampleSubmission -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Sample Submission'; Status = 'Pass' }
            }
            Mock Test-MDETamperProtection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Tamper Protection'; Status = 'Pass' }
            }
            Mock Test-MDETamperProtectionForExclusions -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Tamper Protection for Exclusions'; Status = 'Pass' }
            }
            Mock Test-MDEFileHashComputation -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'File Hash Computation'; Status = 'Pass' }
            }
            Mock Test-MDEAttackSurfaceReduction -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'ASR'; Status = 'Pass' }
            }
            Mock Test-MDEThreatDefaultActions -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Threat Default Actions'; Status = 'Pass' }
            }
            Mock Test-MDEDisableCatchupQuickScan -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Disable Catchup Quick Scan'; Status = 'Pass' }
            }
            Mock Test-MDERealTimeScanDirection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Real-Time Scan Direction'; Status = 'Pass' }
            }
            Mock Test-MDESignatureUpdateInterval -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Signature Update Interval'; Status = 'Pass' }
            }
            Mock Test-MDESignatureUpdateFallbackOrder -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Signature Fallback Order'; Status = 'Pass' }
            }
            Mock Test-MDEDisableLocalAdminMerge -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Disable Local Admin Merge'; Status = 'Pass' }
            }
            Mock Test-MDEExclusionVisibilityLocalAdmins -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Exclusion Visibility Admins'; Status = 'Pass' }
            }
            Mock Test-MDEExclusionVisibilityLocalUsers -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Exclusion Visibility Users'; Status = 'Pass' }
            }
            Mock Test-MDETroubleshootingMode -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Troubleshooting Mode'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreen -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreenPromptOverride -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen Prompt Override'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreenDownloadOverride -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen Download Override'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreenPUA -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen PUA'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreenAppRepExclusions -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen AppRep Exclusions'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreenDomainExclusions -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen Domain Exclusions'; Status = 'Pass' }
            }
            Mock Test-MDEDeviceTags -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Device Tags'; Status = 'Info' }
            }
            Mock Test-IsElevated -ModuleName MDEValidator { $true }
            Mock Test-MDENetworkProtectionWindowsServer -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Network Protection WS'; Status = 'Pass' }
            }
            Mock Test-MDEAutoExclusionsWindowsServer -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Auto Exclusions WS'; Status = 'Pass' }
            }
            Mock Test-MDEDatagramProcessingWindowsServer -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Datagram WS'; Status = 'Pass' }
            }
            Mock Test-IsWindowsServer -ModuleName MDEValidator { $false }

            $result = Test-MDEConfiguration

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
        }
    }
}
