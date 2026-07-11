BeforeAll {
    . "$PSScriptRoot/../Helpers/TestBootstrap.ps1"
    Initialize-MDEValidatorTest
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
            Mock Get-MpPreference -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Get-MpComputerStatus -ModuleName MDEValidator { [PSCustomObject]@{} }
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
            Mock Test-MDEAntiSpywareEnabled -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Anti-Spyware Protection'; Status = 'Pass' }
            }
            Mock Test-MDEIoavProtectionEnabled -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'IOAV Protection'; Status = 'Pass' }
            }
            Mock Test-MDENISEnabled -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Network Inspection System (NIS)'; Status = 'Pass' }
            }
            Mock Test-MDESignatureAge -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Antivirus Signature Age'; Status = 'Pass' }
                [PSCustomObject]@{ TestName = 'Antispyware Signature Age'; Status = 'Pass' }
            }
            Mock Test-MDESignatureInfo -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Antivirus Signature Version'; Status = 'Info' }
                [PSCustomObject]@{ TestName = 'Antivirus Signature Last Updated'; Status = 'Info' }
            }

            $result = Test-MDEConfiguration

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [PSCustomObject]
        }
    }

    Context '-Category filter' {

        BeforeAll {
            Mock Test-IsElevated -ModuleName MDEValidator { $true }
            Mock Get-MpPreference -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Get-MpComputerStatus -ModuleName MDEValidator { [PSCustomObject]@{} }
            
            # Provide return values for the two categories used in these tests
            Mock Test-MDEAttackSurfaceReduction -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Attack Surface Reduction Rules'; Category = 'ASR Rules'; Status = 'Pass' }
            }
            Mock Test-MDEServiceStatus -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Service Status'; Category = 'Device State'; Status = 'Pass' }
            }
            Mock Test-MDESmartScreen -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'SmartScreen'; Category = 'Network Protection'; Status = 'Pass' }
            }
        }

        It 'runs only ASR Rules tests and skips Device State tests' {
            Test-MDEConfiguration -Category 'ASR Rules' | Out-Null
            Should -Invoke Test-MDEAttackSurfaceReduction -Times 1 -ModuleName MDEValidator
            Should -Invoke Test-MDEServiceStatus -Times 0 -ModuleName MDEValidator
        }

        It 'returns only results from the requested category' {
            $result = Test-MDEConfiguration -Category 'ASR Rules'
            $result | Should -Not -BeNullOrEmpty
            $result | ForEach-Object { $_.Category | Should -Be 'ASR Rules' }
        }

        It 'runs tests from multiple categories when multiple values supplied' {
            Mock Test-MDETamperProtection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Tamper Protection'; Category = 'Tamper Protection'; Status = 'Pass' }
            }
            Mock Test-MDETamperProtectionForExclusions -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Tamper Protection for Exclusions'; Category = 'Tamper Protection'; Status = 'Pass' }
            }
            Mock Test-MDETroubleshootingMode -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Troubleshooting Mode'; Category = 'Tamper Protection'; Status = 'Pass' }
            }
            
            Test-MDEConfiguration -Category 'ASR Rules', 'Tamper Protection' | Out-Null
            Should -Invoke Test-MDEAttackSurfaceReduction -Times 1 -ModuleName MDEValidator
            Should -Invoke Test-MDETamperProtection -Times 1 -ModuleName MDEValidator
            Should -Invoke Test-MDESmartScreen -Times 0 -ModuleName MDEValidator
        }
    }

    Context '-ExcludeTest filter' {

        BeforeAll {
            Mock Test-IsElevated -ModuleName MDEValidator { $true }
            Mock Get-MpPreference -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Get-MpComputerStatus -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Test-MDETamperProtection -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Tamper Protection'; Category = 'Tamper Protection'; Status = 'Pass' }
            }
            Mock Test-MDETamperProtectionForExclusions -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Tamper Protection for Exclusions'; Category = 'Tamper Protection'; Status = 'Pass' }
            }
            Mock Test-MDETroubleshootingMode -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Troubleshooting Mode'; Category = 'Tamper Protection'; Status = 'Pass' }
            }
        }

        It 'removes results whose TestName matches the wildcard' {
            $result = Test-MDEConfiguration -Category 'Tamper Protection' -ExcludeTest '*Exclusion*'
            ($result | Where-Object { $_.TestName -like '*Exclusion*' }) | Should -BeNullOrEmpty
        }

        It 'retains results that do not match any ExcludeTest pattern' {
            $result = Test-MDEConfiguration -Category 'Tamper Protection' -ExcludeTest '*Exclusion*'
            ($result | Where-Object { $_.TestName -eq 'Tamper Protection' }) | Should -Not -BeNullOrEmpty
            ($result | Where-Object { $_.TestName -eq 'Troubleshooting Mode' }) | Should -Not -BeNullOrEmpty
        }

        It 'still invokes the test function even when all its results are excluded' {
            # -ExcludeTest filters post-invocation; the function is always called when its category runs
            Test-MDEConfiguration -Category 'Tamper Protection' -ExcludeTest '*Exclusion*' | Out-Null
            Should -Invoke Test-MDETamperProtectionForExclusions -Times 1 -ModuleName MDEValidator
        }

        It 'supports multiple ExcludeTest patterns' {
            $result = Test-MDEConfiguration -Category 'Tamper Protection' -ExcludeTest '*Exclusion*', 'Troubleshooting Mode'
            $result.Count | Should -Be 1
            $result[0].TestName | Should -Be 'Tamper Protection'
        }
    }

    Context 'Write-Progress' {

        It 'returns results without error (progress calls do not suppress output)' {
            Mock Test-IsElevated -ModuleName MDEValidator { $true }
            Mock Get-MpPreference -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Get-MpComputerStatus -ModuleName MDEValidator { [PSCustomObject]@{} }
            Mock Test-MDEAttackSurfaceReduction -ModuleName MDEValidator {
                [PSCustomObject]@{ TestName = 'Attack Surface Reduction Rules'; Category = 'ASR Rules'; Status = 'Pass' }
            }
            
            $result = Test-MDEConfiguration -Category 'ASR Rules'
            $result | Should -Not -BeNullOrEmpty
            $result[0].TestName | Should -Be 'Attack Surface Reduction Rules'
        }
    }
}
