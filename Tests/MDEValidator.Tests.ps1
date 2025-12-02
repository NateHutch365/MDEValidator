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
        
        It 'Should export Test-MDEThreatDefaultActions function' {
            Get-Command -Name 'Test-MDEThreatDefaultActions' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEExclusionVisibilityLocalAdmins function' {
            Get-Command -Name 'Test-MDEExclusionVisibilityLocalAdmins' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEExclusionVisibilityLocalUsers function' {
            Get-Command -Name 'Test-MDEExclusionVisibilityLocalUsers' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDECloudBlockLevel function' {
            Get-Command -Name 'Test-MDECloudBlockLevel' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Get-MDEOperatingSystemInfo function' {
            Get-Command -Name 'Get-MDEOperatingSystemInfo' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEPassiveMode function' {
            Get-Command -Name 'Test-MDEPassiveMode' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDETamperProtection function' {
            Get-Command -Name 'Test-MDETamperProtection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDECloudExtendedTimeout function' {
            Get-Command -Name 'Test-MDECloudExtendedTimeout' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEDisableCatchupQuickScan function' {
            Get-Command -Name 'Test-MDEDisableCatchupQuickScan' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDERealTimeScanDirection function' {
            Get-Command -Name 'Test-MDERealTimeScanDirection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESignatureUpdateFallbackOrder function' {
            Get-Command -Name 'Test-MDESignatureUpdateFallbackOrder' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Get-MDEOperatingSystemInfo' {
        It 'Should return a non-empty string' {
            $result = Get-MDEOperatingSystemInfo
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [string]
        }
        
        It 'Should return OS information or Unknown OS' {
            $result = Get-MDEOperatingSystemInfo
            # Either returns valid OS info (Windows/Ubuntu/etc) or "Unknown OS"
            $result | Should -Match '(Windows|Ubuntu|Linux|macOS|Unknown OS)'
        }
    }
    
    Context 'Test-MDEPassiveMode' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEPassiveMode
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Passive Mode / EDR Block Mode'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention passive mode or active mode in the message' {
            $result = Test-MDEPassiveMode
            $result.Message | Should -Match '(Passive|Active|EDR Block|Unable to determine)'
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
    
    Context 'Test-MDENetworkProtectionWindowsServer' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDENetworkProtectionWindowsServer
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Network Protection (Windows Server)'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDENetworkProtectionWindowsServer function' {
            Get-Command -Name 'Test-MDENetworkProtectionWindowsServer' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Windows Server or NotApplicable in the message' {
            $result = Test-MDENetworkProtectionWindowsServer
            $result.Message | Should -Match '(Windows Server|This check only applies|Unable to query)'
        }
    }
    
    Context 'Test-MDEDatagramProcessingWindowsServer' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEDatagramProcessingWindowsServer
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Datagram Processing (Windows Server)'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDEDatagramProcessingWindowsServer function' {
            Get-Command -Name 'Test-MDEDatagramProcessingWindowsServer' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Windows Server or NotApplicable in the message' {
            $result = Test-MDEDatagramProcessingWindowsServer
            $result.Message | Should -Match '(Windows Server|This check only applies|Unable to query)'
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
    
    Context 'Test-MDESmartScreen' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESmartScreen
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Edge SmartScreen'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDESmartScreen function' {
            Get-Command -Name 'Test-MDESmartScreen' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Test-MDESmartScreenPUA' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESmartScreenPUA
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Edge SmartScreen PUA Protection'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESmartScreenPUA function' {
            Get-Command -Name 'Test-MDESmartScreenPUA' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention SmartScreen PUA or error message in output' {
            $result = Test-MDESmartScreenPUA
            $result.Message | Should -Match '(SmartScreen PUA|Unable to query)'
        }
    }
    
    Context 'Test-MDESmartScreenPromptOverride' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESmartScreenPromptOverride
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Edge SmartScreen Prompt Override Prevention'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESmartScreenPromptOverride function' {
            Get-Command -Name 'Test-MDESmartScreenPromptOverride' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention SmartScreen prompt override or error message in output' {
            $result = Test-MDESmartScreenPromptOverride
            $result.Message | Should -Match '(SmartScreen prompt override|Unable to query)'
        }
    }
    
    Context 'Test-MDESmartScreenDownloadOverride' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESmartScreenDownloadOverride
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Edge SmartScreen Download Override Prevention'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESmartScreenDownloadOverride function' {
            Get-Command -Name 'Test-MDESmartScreenDownloadOverride' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention SmartScreen download override or error message in output' {
            $result = Test-MDESmartScreenDownloadOverride
            $result.Message | Should -Match '(SmartScreen download override|Unable to query)'
        }
    }
    
    Context 'Test-MDESmartScreenDomainExclusions' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESmartScreenDomainExclusions
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Edge SmartScreen Domain Exclusions'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESmartScreenDomainExclusions function' {
            Get-Command -Name 'Test-MDESmartScreenDomainExclusions' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention SmartScreen domain exclusions or error message in output' {
            $result = Test-MDESmartScreenDomainExclusions
            $result.Message | Should -Match '(SmartScreen domain exclusions|SmartScreen protection|Unable to query)'
        }
    }
    
    Context 'Test-MDEThreatDefaultActions' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEThreatDefaultActions
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Threat Default Actions'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDEThreatDefaultActions function' {
            Get-Command -Name 'Test-MDEThreatDefaultActions' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should include threat level details or error message in the message' {
            $result = Test-MDEThreatDefaultActions
            # Either contains threat levels when successful, or contains error info when Get-MpPreference is unavailable
            $result.Message | Should -Match '(Low|Moderate|High|Severe|Unable to query|threat default actions)'
        }
    }
    
    Context 'Test-MDEExclusionVisibilityLocalAdmins' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEExclusionVisibilityLocalAdmins
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Exclusion Visibility (Local Admins)'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDEExclusionVisibilityLocalAdmins function' {
            Get-Command -Name 'Test-MDEExclusionVisibilityLocalAdmins' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention local administrators in the message' {
            $result = Test-MDEExclusionVisibilityLocalAdmins
            $result.Message | Should -Match '(local administrators|administrators)'
        }
    }
    
    Context 'Test-MDEExclusionVisibilityLocalUsers' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEExclusionVisibilityLocalUsers
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Exclusion Visibility (Local Users)'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDEExclusionVisibilityLocalUsers function' {
            Get-Command -Name 'Test-MDEExclusionVisibilityLocalUsers' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention local users in the message' {
            $result = Test-MDEExclusionVisibilityLocalUsers
            $result.Message | Should -Match '(local users|users)'
        }
    }
    
    Context 'Test-MDECloudBlockLevel' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDECloudBlockLevel
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Cloud Block Level'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
        }
        
        It 'Should export Test-MDECloudBlockLevel function' {
            Get-Command -Name 'Test-MDECloudBlockLevel' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Cloud Block Level or error message in output' {
            $result = Test-MDECloudBlockLevel
            $result.Message | Should -Match '(Cloud Block Level|Unable to query)'
        }
    }
    
    Context 'Test-MDETamperProtection' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDETamperProtection
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Tamper Protection'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDETamperProtection function' {
            Get-Command -Name 'Test-MDETamperProtection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Tamper Protection or error message in output' {
            $result = Test-MDETamperProtection
            $result.Message | Should -Match '(Tamper Protection|Unable to query)'
        }
    }
    
    Context 'Test-MDECloudExtendedTimeout' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDECloudExtendedTimeout
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Cloud Extended Timeout'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDECloudExtendedTimeout function' {
            Get-Command -Name 'Test-MDECloudExtendedTimeout' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Cloud Extended Timeout or error message in output' {
            $result = Test-MDECloudExtendedTimeout
            $result.Message | Should -Match '(Cloud Extended Timeout|Unable to query)'
        }
    }
    
    Context 'Test-MDEDisableCatchupQuickScan' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEDisableCatchupQuickScan
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Catchup Quick Scan'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEDisableCatchupQuickScan function' {
            Get-Command -Name 'Test-MDEDisableCatchupQuickScan' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Catchup Quick Scan or error message in output' {
            $result = Test-MDEDisableCatchupQuickScan
            $result.Message | Should -Match '(Catchup Quick Scan|Unable to query)'
        }
    }
    
    Context 'Test-MDERealTimeScanDirection' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDERealTimeScanDirection
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Real Time Scan Direction'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDERealTimeScanDirection function' {
            Get-Command -Name 'Test-MDERealTimeScanDirection' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Real Time Scan Direction or error message in output' {
            $result = Test-MDERealTimeScanDirection
            $result.Message | Should -Match '(Real Time Scan Direction|Unable to query)'
        }
    }
    
    Context 'Test-MDESignatureUpdateFallbackOrder' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESignatureUpdateFallbackOrder
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Signature Update Fallback Order'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESignatureUpdateFallbackOrder function' {
            Get-Command -Name 'Test-MDESignatureUpdateFallbackOrder' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Signature Update Fallback Order or error message in output' {
            $result = Test-MDESignatureUpdateFallbackOrder
            $result.Message | Should -Match '(Signature Update Fallback Order|Unable to query)'
        }
    }
    
    Context 'Test-MDESignatureUpdateInterval' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDESignatureUpdateInterval
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Signature Update Interval'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDESignatureUpdateInterval function' {
            Get-Command -Name 'Test-MDESignatureUpdateInterval' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Signature Update Interval or error message in output' {
            $result = Test-MDESignatureUpdateInterval
            $result.Message | Should -Match '(Signature Update Interval|Unable to query)'
        }
    }
    
    Context 'Test-MDEDisableLocalAdminMerge' {
        It 'Should return a PSCustomObject with expected properties' {
            $result = Test-MDEDisableLocalAdminMerge
            $result | Should -Not -BeNullOrEmpty
            $result.TestName | Should -Be 'Disable Local Admin Merge'
            $result.Status | Should -BeIn @('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')
            $result.Message | Should -Not -BeNullOrEmpty
            $result.Timestamp | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-MDEDisableLocalAdminMerge function' {
            Get-Command -Name 'Test-MDEDisableLocalAdminMerge' -Module 'MDEValidator' | Should -Not -BeNullOrEmpty
        }
        
        It 'Should mention Disable Local Admin Merge or error message in output' {
            $result = Test-MDEDisableLocalAdminMerge
            $result.Message | Should -Match '(Disable Local Admin Merge|Local Admin|Unable to query)'
        }
    }
    
    Context 'Test-MDEConfiguration' {
        It 'Should return an array of results' {
            $results = Test-MDEConfiguration
            $results | Should -Not -BeNullOrEmpty
            @($results).Count | Should -BeGreaterThan 0
        }
        
        It 'Should include all basic tests when called without parameters' {
            $results = Test-MDEConfiguration
            $testNames = $results.TestName
            $testNames | Should -Contain 'Windows Defender Service Status'
            $testNames | Should -Contain 'Passive Mode / EDR Block Mode'
            $testNames | Should -Contain 'Real-Time Protection'
            $testNames | Should -Contain 'Cloud-Delivered Protection'
            $testNames | Should -Contain 'Cloud Block Level'
            $testNames | Should -Contain 'Cloud Extended Timeout'
            $testNames | Should -Contain 'Automatic Sample Submission'
            $testNames | Should -Contain 'Behavior Monitoring'
            $testNames | Should -Contain 'Network Protection'
            $testNames | Should -Contain 'Network Protection (Windows Server)'
            $testNames | Should -Contain 'Datagram Processing (Windows Server)'
            $testNames | Should -Contain 'Attack Surface Reduction Rules'
            $testNames | Should -Contain 'Threat Default Actions'
            $testNames | Should -Contain 'Tamper Protection'
            $testNames | Should -Contain 'Exclusion Visibility (Local Admins)'
            $testNames | Should -Contain 'Exclusion Visibility (Local Users)'
            $testNames | Should -Contain 'Edge SmartScreen'
            $testNames | Should -Contain 'Edge SmartScreen PUA Protection'
            $testNames | Should -Contain 'Edge SmartScreen Prompt Override Prevention'
            $testNames | Should -Contain 'Edge SmartScreen Download Override Prevention'
            $testNames | Should -Contain 'Edge SmartScreen Domain Exclusions'
            $testNames | Should -Contain 'Catchup Quick Scan'
            $testNames | Should -Contain 'Real Time Scan Direction'
            $testNames | Should -Contain 'Signature Update Fallback Order'
            $testNames | Should -Contain 'Signature Update Interval'
            $testNames | Should -Contain 'Disable Local Admin Merge'
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
