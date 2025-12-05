#Requires -Version 5.1
<#
.SYNOPSIS
    MDEValidator - Microsoft Defender for Endpoint Configuration Validation Module

.DESCRIPTION
    This module provides functions to validate Microsoft Defender for Endpoint (MDE)
    configurations and security settings on Windows endpoints.

.NOTES
    Author: MDEValidator Team
    Version: 1.0.0
#>

#region Helper Functions

function ConvertTo-HtmlEncodedString {
    <#
    .SYNOPSIS
        HTML-encodes a string to prevent XSS vulnerabilities.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InputString
    )
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }
    
    return [System.Net.WebUtility]::HtmlEncode($InputString)
}

function Write-ValidationResult {
    <#
    .SYNOPSIS
        Formats and outputs a validation result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')]
        [string]$Status,
        
        [Parameter()]
        [string]$Message = '',
        
        [Parameter()]
        [string]$Recommendation = ''
    )
    
    [PSCustomObject]@{
        TestName = $TestName
        Status = $Status
        Message = $Message
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Checks if the current PowerShell session is running with elevated privileges.
    #>
    [CmdletBinding()]
    param()
    
    # Only perform elevation check on Windows
    if ($IsWindows -or ([System.Environment]::OSVersion.Platform -eq 'Win32NT')) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            # If we can't determine elevation status, assume not elevated
            return $false
        }
    }
    
    # On non-Windows platforms, check if running as root
    if ($IsLinux -or $IsMacOS) {
        try {
            return (& id -u) -eq 0
        }
        catch {
            return $false
        }
    }
    
    return $false
}

function Test-IsWindowsServer {
    <#
    .SYNOPSIS
        Checks if the current operating system is Windows Server.
    .NOTES
        Uses the InstallationType registry value which is more reliable than pattern matching.
        InstallationType values: "Client" for workstation, "Server" or "Server Core" for servers.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get OS information from registry
        $osRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        
        if (-not (Test-Path $osRegPath)) {
            return $false
        }
        
        $osInfo = Get-ItemProperty -Path $osRegPath -ErrorAction Stop
        
        # Check InstallationType - more reliable than pattern matching ProductName
        # InstallationType is "Client" for workstation, "Server" or "Server Core" for servers
        if ($null -ne $osInfo.InstallationType) {
            if ($osInfo.InstallationType -eq 'Server' -or $osInfo.InstallationType -eq 'Server Core') {
                return $true
            }
            return $false
        }
        
        # Fallback: Check ProductName if InstallationType is not available
        # Use specific "Windows Server" pattern to avoid false positives like "Workstation"
        $productName = $osInfo.ProductName
        if ($productName -match '^Windows Server') {
            return $true
        }
        
        return $false
    }
    catch {
        return $false
    }
}

function Get-MDEManagementType {
    <#
    .SYNOPSIS
        Gets the management type for the device based on enrollment status.
    
    .DESCRIPTION
        Determines how the device is managed (Intune, Security Settings Management, SCCM, GPO, or None)
        based on the SenseCM EnrollmentStatus registry value.
    
    .OUTPUTS
        String containing the management type: 'Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', or 'None'
    
    .NOTES
        Registry location: HKLM\SOFTWARE\Microsoft\SenseCM
        EnrollmentStatus REG_DWORD values:
        0 = Failed / Not Successfully Enrolled -> GPO (fallback to GPO)
        1 = Enrolled to Security Settings Management
        2 = Not Enrolled (never enrolled) -> GPO (fallback to GPO)
        3 = Managed by Intune
        4 = Managed by Configuration Manager (SCCM)
    #>
    [CmdletBinding()]
    param()
    
    try {
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        if (-not (Test-Path $senseCmPath)) {
            return 'None'
        }
        
        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
        
        if ($null -eq $senseCmInfo -or $null -eq $senseCmInfo.EnrollmentStatus) {
            return 'None'
        }
        
        $enrollmentStatus = $senseCmInfo.EnrollmentStatus
        
        switch ($enrollmentStatus) {
            0 { return 'GPO' }           # Failed enrollment - default to GPO path (standard policy location)
            1 { return 'SecuritySettingsManagement' }
            2 { return 'GPO' }           # Never enrolled - default to GPO path (standard policy location)
            3 { return 'Intune' }
            4 { return 'SCCM' }
            default { return 'None' }
        }
    }
    catch {
        return 'None'
    }
}

function Get-MDEPolicyRegistryPath {
    <#
    .SYNOPSIS
        Gets the appropriate registry path for MDE policies based on management type.
    
    .DESCRIPTION
        Returns the registry path where MDE policy settings are stored based on how
        the device is managed.
    
    .PARAMETER ManagementType
        The management type: 'Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', or 'None'
    
    .OUTPUTS
        String containing the registry path for MDE policies.
    
    .NOTES
        Registry locations based on management type:
        - Security Settings Management, SCCM, GPO: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
        - Intune (MDM): HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', 'None')]
        [string]$ManagementType
    )
    
    # Intune uses a different registry path (Policy Manager subfolder)
    # All other management types use the standard Windows Defender policy path
    if ($ManagementType -eq 'Intune') {
        return 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    }
    
    # Standard policy path for SSM, SCCM, GPO, and unmanaged devices
    return 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
}

function Get-MDEPolicySettingConfig {
    <#
    .SYNOPSIS
        Gets the registry configuration for a policy setting based on management type.
    
    .DESCRIPTION
        Returns the correct registry path and setting name for a policy setting
        based on whether the device is managed by Intune or GPO/SSM/SCCM.
        
        Intune stores settings directly in Policy Manager with different key names.
        GPO/SSM/SCCM stores settings in subfolders with traditional key names.
    
    .PARAMETER SettingKey
        The logical setting key (e.g., 'RealTimeProtection', 'CloudProtection').
    
    .PARAMETER ManagementType
        The management type: 'Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', or 'None'
    
    .OUTPUTS
        PSCustomObject with properties:
        - Path: The full registry path for the setting
        - SettingName: The registry value name
        - DisplayName: Human-readable name for the setting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'RealTimeProtection',
            'CloudProtection',
            'CloudBlockLevel',
            'CloudExtendedTimeout',
            'SampleSubmission',
            'BehaviorMonitoring',
            'NetworkProtection',
            'AttackSurfaceReduction',
            'HideExclusionsFromLocalUsers',
            'HideExclusionsFromLocalAdmins',
            'CatchupQuickScan',
            'RealTimeScanDirection',
            'SignatureFallbackOrder',
            'SignatureUpdateInterval',
            'DisableLocalAdminMerge'
        )]
        [string]$SettingKey,
        
        [Parameter(Mandatory)]
        [ValidateSet('Intune', 'SecuritySettingsManagement', 'SCCM', 'GPO', 'None')]
        [string]$ManagementType
    )
    
    # Define the configuration mappings
    # 
    # Registry naming conventions differ between Intune and GPO:
    # - Intune (Policy Manager): Uses "Allow" prefix (e.g., AllowRealtimeMonitoring, AllowBehaviorMonitoring)
    #   where 1 = enabled and 0 = disabled
    # - GPO/SCCM/SSM: Uses "Disable" prefix (e.g., DisableRealtimeMonitoring, DisableBehaviorMonitoring)
    #   where 0 = enabled and 1 = disabled
    # This is due to the different CSP (Configuration Service Provider) implementations.
    
    $intuneBasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $gpoBasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    
    # Configuration: [SettingKey] = @{ Intune = @{Path, Name}; GPO = @{Path, Name}; DisplayName }
    $settingConfigs = @{
        'RealTimeProtection' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'AllowRealtimeMonitoring' }
            GPO = @{ Path = "$gpoBasePath\Real-Time Protection"; Name = 'DisableRealtimeMonitoring' }
            DisplayName = 'Real-Time Protection'
        }
        'CloudProtection' = @{
            # Note: "Spynet" is the legacy registry path name for Cloud Protection/MAPS
            # (Microsoft Active Protection Service). Microsoft still uses this path internally.
            Intune = @{ Path = $intuneBasePath; Name = 'AllowCloudProtection' }
            GPO = @{ Path = "$gpoBasePath\Spynet"; Name = 'SpynetReporting' }
            DisplayName = 'Cloud Protection (MAPS)'
        }
        'CloudBlockLevel' = @{
            Intune = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpCloudBlockLevel' }
            GPO = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpCloudBlockLevel' }
            DisplayName = 'Cloud Block Level'
        }
        'CloudExtendedTimeout' = @{
            Intune = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpBafsExtendedTimeout' }
            GPO = @{ Path = "$gpoBasePath\MpEngine"; Name = 'MpBafsExtendedTimeout' }
            DisplayName = 'Cloud Extended Timeout'
        }
        'SampleSubmission' = @{
            # Note: "Spynet" is the legacy registry path name for Cloud Protection/MAPS
            Intune = @{ Path = $intuneBasePath; Name = 'SubmitSamplesConsent' }
            GPO = @{ Path = "$gpoBasePath\Spynet"; Name = 'SubmitSamplesConsent' }
            DisplayName = 'Sample Submission'
        }
        'BehaviorMonitoring' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'AllowBehaviorMonitoring' }
            GPO = @{ Path = "$gpoBasePath\Real-Time Protection"; Name = 'DisableBehaviorMonitoring' }
            DisplayName = 'Behavior Monitoring'
        }
        'NetworkProtection' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'EnableNetworkProtection' }
            GPO = @{ Path = "$gpoBasePath\Windows Defender Exploit Guard\Network Protection"; Name = 'EnableNetworkProtection' }
            DisplayName = 'Network Protection'
        }
        'AttackSurfaceReduction' = @{
            # ASR rules verification: Intune stores rules in a combined ASRRules key,
            # while GPO uses ExploitGuard_ASR_Rules. Both indicate ASR is configured.
            Intune = @{ Path = $intuneBasePath; Name = 'ASRRules' }
            GPO = @{ Path = "$gpoBasePath\Windows Defender Exploit Guard\ASR"; Name = 'ExploitGuard_ASR_Rules' }
            DisplayName = 'Attack Surface Reduction Rules'
        }
        'HideExclusionsFromLocalUsers' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'HideExclusionsFromLocalUsers' }
            GPO = @{ Path = "$gpoBasePath\Exclusions"; Name = 'HideExclusionsFromLocalUsers' }
            DisplayName = 'Hide Exclusions From Local Users'
        }
        'HideExclusionsFromLocalAdmins' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'HideExclusionsFromLocalAdmins' }
            GPO = @{ Path = "$gpoBasePath\Exclusions"; Name = 'HideExclusionsFromLocalAdmins' }
            DisplayName = 'Hide Exclusions From Local Admins'
        }
        'CatchupQuickScan' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'DisableCatchupQuickScan' }
            GPO = @{ Path = "$gpoBasePath\Scan"; Name = 'DisableCatchupQuickScan' }
            DisplayName = 'Catchup Quick Scan'
        }
        'RealTimeScanDirection' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'RealTimeScanDirection' }
            GPO = @{ Path = "$gpoBasePath\Real-Time Protection"; Name = 'RealTimeScanDirection' }
            DisplayName = 'Real-Time Scan Direction'
        }
        'SignatureFallbackOrder' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'SignatureUpdateFallbackOrder' }
            GPO = @{ Path = "$gpoBasePath\Signature Updates"; Name = 'FallbackOrder' }
            DisplayName = 'Signature Fallback Order'
        }
        'SignatureUpdateInterval' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'SignatureUpdateInterval' }
            GPO = @{ Path = "$gpoBasePath\Signature Updates"; Name = 'SignatureUpdateInterval' }
            DisplayName = 'Signature Update Interval'
        }
        'DisableLocalAdminMerge' = @{
            Intune = @{ Path = $intuneBasePath; Name = 'DisableLocalAdminMerge' }
            GPO = @{ Path = $gpoBasePath; Name = 'DisableLocalAdminMerge' }
            DisplayName = 'Disable Local Admin Merge'
        }
    }
    
    $config = $settingConfigs[$SettingKey]
    if ($null -eq $config) {
        return $null
    }
    
    # Determine which configuration to use based on management type
    $pathConfig = if ($ManagementType -eq 'Intune') {
        $config.Intune
    } else {
        # GPO, SSM, SCCM, and None all use the GPO path structure
        $config.GPO
    }
    
    return [PSCustomObject]@{
        Path = $pathConfig.Path
        SettingName = $pathConfig.Name
        DisplayName = $config.DisplayName
    }
}

function Test-MDEPolicyRegistryValue {
    <#
    .SYNOPSIS
        Tests if a policy registry value exists and matches expected value.
    
    .DESCRIPTION
        Verifies that a Windows Defender policy setting exists in the correct
        registry location based on the device's management type.
    
    .PARAMETER SettingKey
        The logical setting key (e.g., 'RealTimeProtection'). When provided,
        the function automatically determines the correct path and setting name
        based on the management type.
    
    .PARAMETER SettingName
        The name of the setting to verify (e.g., 'DisableRealtimeMonitoring').
        Used for backward compatibility. Ignored if SettingKey is provided.
    
    .PARAMETER ExpectedValue
        The expected value for the setting.
    
    .PARAMETER SubPath
        Optional subpath under the main policy path (e.g., 'Real-Time Protection').
        Used for backward compatibility. Ignored if SettingKey is provided.
    
    .OUTPUTS
        PSCustomObject with properties:
        - Found: Boolean indicating if the registry value was found
        - Value: The actual value found (if any)
        - Path: The full registry path checked
        - ManagementType: The detected management type
        - SettingName: The registry value name that was checked
    
    .NOTES
        This function checks the appropriate registry location based on the
        detected management type (Intune vs Security Settings Management/GPO/SCCM).
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SettingKey,
        
        [Parameter()]
        [string]$SettingName,
        
        [Parameter()]
        $ExpectedValue = $null,
        
        [Parameter()]
        [string]$SubPath = ''
    )
    
    $managementType = Get-MDEManagementType
    
    # If SettingKey is provided, use the new configuration-based approach
    if (-not [string]::IsNullOrEmpty($SettingKey)) {
        $config = Get-MDEPolicySettingConfig -SettingKey $SettingKey -ManagementType $managementType
        if ($null -ne $config) {
            $fullPath = $config.Path
            $actualSettingName = $config.SettingName
        } else {
            # Fallback to old behavior if config not found
            $basePath = Get-MDEPolicyRegistryPath -ManagementType $managementType
            $fullPath = $basePath
            $actualSettingName = $SettingName
        }
    } else {
        # Backward compatibility: use the old SubPath approach
        $basePath = Get-MDEPolicyRegistryPath -ManagementType $managementType
        $fullPath = if ([string]::IsNullOrEmpty($SubPath)) {
            $basePath
        } else {
            Join-Path $basePath $SubPath
        }
        $actualSettingName = $SettingName
    }
    
    $result = [PSCustomObject]@{
        Found = $false
        Value = $null
        Path = $fullPath
        ManagementType = $managementType
        SettingName = $actualSettingName
    }
    
    try {
        if (Test-Path $fullPath) {
            $regValue = Get-ItemProperty -Path $fullPath -Name $actualSettingName -ErrorAction SilentlyContinue
            if ($null -ne $regValue -and $null -ne $regValue.$actualSettingName) {
                $result.Found = $true
                $result.Value = $regValue.$actualSettingName
            }
        }
    }
    catch {
        # Registry path or value not accessible
        $result.Found = $false
    }
    
    return $result
}

function Test-MDEPolicyRegistryVerification {
    <#
    .SYNOPSIS
        Performs registry verification sub-test for an MDE setting.
    
    .DESCRIPTION
        Creates a sub-test result that verifies whether a policy setting exists
        in the correct registry location based on management type.
    
    .PARAMETER ParentTestName
        The name of the parent test (e.g., 'Real-Time Protection').
    
    .PARAMETER SettingKey
        The logical setting key (e.g., 'RealTimeProtection'). When provided,
        the function automatically determines the correct path, setting name,
        and display name based on the management type.
    
    .PARAMETER SettingName
        The registry setting name to verify (deprecated, use SettingKey instead).
    
    .PARAMETER SettingDisplayName
        Human-readable name for the setting (deprecated, use SettingKey instead).
    
    .PARAMETER SubPath
        Optional subpath under the main policy path (deprecated, use SettingKey instead).
    
    .PARAMETER ExpectedValue
        The expected value for the setting (optional).
    
    .PARAMETER IsApplicableToSSM
        Whether this setting is applicable to Security Settings Management.
        Default is $true. Set to $false for settings not supported by SSM.
    
    .OUTPUTS
        PSCustomObject with validation results for the registry verification sub-test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ParentTestName,
        
        [Parameter()]
        [string]$SettingKey,
        
        [Parameter()]
        [string]$SettingName,
        
        [Parameter()]
        [string]$SettingDisplayName,
        
        [Parameter()]
        [string]$SubPath = '',
        
        [Parameter()]
        $ExpectedValue = $null,
        
        [Parameter()]
        [bool]$IsApplicableToSSM = $true
    )
    
    $testName = "$ParentTestName - Policy Registry Verification"
    
    $managementType = Get-MDEManagementType
    
    # Check if this test is applicable based on management type
    if ($managementType -eq 'None') {
        return Write-ValidationResult -TestName $testName -Status 'Info' `
            -Message "Policy registry verification skipped - device management type could not be determined."
    }
    
    # Check if SSM-incompatible test on SSM-managed device
    if (-not $IsApplicableToSSM -and $managementType -eq 'SecuritySettingsManagement') {
        return Write-ValidationResult -TestName $testName -Status 'NotApplicable' `
            -Message "This setting cannot be enforced via Security Settings Management. Only Antivirus, ASR, EDR, and Firewall policies are supported."
    }
    
    # Use SettingKey if provided, otherwise fall back to legacy parameters
    if (-not [string]::IsNullOrEmpty($SettingKey)) {
        $regResult = Test-MDEPolicyRegistryValue -SettingKey $SettingKey -ExpectedValue $ExpectedValue
        # Get the display name from the configuration
        $config = Get-MDEPolicySettingConfig -SettingKey $SettingKey -ManagementType $managementType
        $displayName = if ($null -ne $config) { $config.DisplayName } else { $SettingKey }
    } else {
        $regResult = Test-MDEPolicyRegistryValue -SettingName $SettingName -SubPath $SubPath -ExpectedValue $ExpectedValue
        $displayName = $SettingDisplayName
    }
    
    if ($regResult.Found) {
        $valueInfo = if ($null -ne $ExpectedValue) {
            $matchStatus = if ($regResult.Value -eq $ExpectedValue) { "matches expected" } else { "differs from expected" }
            "Value: $($regResult.Value) ($matchStatus value: $ExpectedValue)"
        } else {
            "Value: $($regResult.Value)"
        }
        
        return Write-ValidationResult -TestName $testName -Status 'Pass' `
            -Message "Policy registry entry verified. $displayName found at $($regResult.Path)\$($regResult.SettingName). $valueInfo. Management type: $($regResult.ManagementType)."
    } else {
        $recommendation = @"
The policy registry entry for $displayName was not found at $($regResult.Path)\$($regResult.SettingName).
This may indicate:
- The policy has not been deployed via $($regResult.ManagementType)
- The policy is configured locally but not via management tools
- There may be a sync issue with the management platform
Verify the policy is correctly configured in your management solution ($($regResult.ManagementType)).
"@
        
        return Write-ValidationResult -TestName $testName -Status 'Warning' `
            -Message "Policy registry entry not found. Expected $displayName at $($regResult.Path)\$($regResult.SettingName). Management type: $($regResult.ManagementType)." `
            -Recommendation $recommendation
    }
}

#endregion

#region Public Functions

function Get-MDEOperatingSystemInfo {
    <#
    .SYNOPSIS
        Gets the operating system version and build information.
    
    .DESCRIPTION
        Retrieves detailed information about the Windows operating system including
        the product name, version (e.g., 22H2, 25H2), and build number.
    
    .EXAMPLE
        Get-MDEOperatingSystemInfo
        
        Returns a string like "Windows 10 Professional Version 22H2 19045.6575"
    
    .OUTPUTS
        String containing the OS name, version, and build information.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get OS information from registry
        $osRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        
        if (-not (Test-Path $osRegPath)) {
            return "Unknown OS"
        }
        
        $osInfo = Get-ItemProperty -Path $osRegPath -ErrorAction Stop
        
        # Get product name (e.g., "Windows 10 Pro", "Windows 11 Enterprise", "Windows Server 2022")
        $productName = $osInfo.ProductName
        
        # Get display version (e.g., "22H2", "25H2")
        $displayVersion = $osInfo.DisplayVersion
        
        # Get current build number and UBR (Update Build Revision)
        $currentBuild = $osInfo.CurrentBuild
        $ubr = $osInfo.UBR
        
        # Construct the full build string
        $fullBuild = if ($null -ne $currentBuild -and $null -ne $ubr) {
            "$currentBuild.$ubr"
        } elseif ($null -ne $currentBuild) {
            $currentBuild
        } else {
            ""
        }
        
        # Build the output string
        $osString = $productName
        
        if (-not [string]::IsNullOrEmpty($displayVersion)) {
            $osString += " Version $displayVersion"
        }
        
        if (-not [string]::IsNullOrEmpty($fullBuild)) {
            $osString += " $fullBuild"
        }
        
        return $osString
    }
    catch {
        return "Unknown OS"
    }
}

function Get-MDESecuritySettingsManagementStatus {
    <#
    .SYNOPSIS
        Gets the device management status for MDE policy settings.
    
    .DESCRIPTION
        Retrieves the device management status from the SenseCM registry key.
        If the SenseCM key is not found, falls back to detecting management type
        based on Windows Defender policy registry paths:
        - Access denied to HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager = Intune
          (HideExclusionsFromLocalAdmins restricts SYSTEM access, only settable via Intune)
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager (with entries) = Intune
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender (with entries) = Security Settings Management
    
    .EXAMPLE
        Get-MDESecuritySettingsManagementStatus
        
        Returns a string like "Intune" or "Security Settings Management" 
        depending on the management status.
    
    .OUTPUTS
        String containing the device management status.
    
    .NOTES
        Primary Registry location: HKLM\SOFTWARE\Microsoft\SenseCM
        EnrollmentStatus REG_DWORD values and their return strings:
        0 = "Failed / Not Successfully Enrolled"
        1 = "Security Settings Management"
        2 = "Not Enrolled (never enrolled)"
        3 = "Intune"
        4 = "Configuration Manager (SCCM)"
        
        Fallback detection:
        - Access denied to Policy Manager path indicates Intune management
          (HideExclusionsFromLocalAdmins cannot be set via SSM or locally)
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager (with entries) = Intune
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender (with entries) = Security Settings Management
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get Security Settings Management enrollment status from registry
        $senseCmPath = 'HKLM:\SOFTWARE\Microsoft\SenseCM'
        
        if (-not (Test-Path $senseCmPath)) {
            # SenseCM key not found - use fallback detection based on policy registry paths
            return Get-MDEManagementTypeFallback
        }
        
        $senseCmInfo = Get-ItemProperty -Path $senseCmPath -ErrorAction SilentlyContinue
        
        if ($null -eq $senseCmInfo -or $null -eq $senseCmInfo.EnrollmentStatus) {
            # EnrollmentStatus not set - use fallback detection
            return Get-MDEManagementTypeFallback
        }
        
        $enrollmentStatus = $senseCmInfo.EnrollmentStatus
        
        # Map enrollment status values to human-readable strings
        switch ($enrollmentStatus) {
            0 { return "Failed / Not Successfully Enrolled" }
            1 { return "Security Settings Management" }
            2 { return "Not Enrolled (never enrolled)" }
            3 { return "Intune" }
            4 { return "Configuration Manager (SCCM)" }
            default { return "Unknown Status ($enrollmentStatus)" }
        }
    }
    catch {
        return "Error retrieving status"
    }
}

function Get-MDEManagementTypeFallback {
    <#
    .SYNOPSIS
        Detects management type based on Windows Defender policy registry paths.
    
    .DESCRIPTION
        Fallback detection when SenseCM registry key is not available.
        Checks for the presence of policy entries in registry paths to determine
        if the device is managed by Intune or Security Settings Management.
        
        Additional detection logic: When HideExclusionsFromLocalAdmins is enabled via Intune,
        it restricts access (including SYSTEM) to the Policy Manager registry path. Since this
        setting cannot be enforced via Security Settings Management, if access is denied to 
        the Policy Manager path, the device is Intune managed.
    
    .OUTPUTS
        String containing the detected management type.
    
    .NOTES
        Detection logic:
        1. If access to HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager is denied -> Intune
           (HideExclusionsFromLocalAdmins restricts SYSTEM access, only settable via Intune)
        2. If HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager has entries -> Intune
        3. If HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender has entries -> Security Settings Management
        4. Otherwise -> Not Configured
        
        HideExclusionsFromLocalAdmins cannot be set locally using Set-MpPreference or via 
        Security Settings Management, so access denial to the Policy Manager path reliably 
        indicates Intune management.
    #>
    [CmdletBinding()]
    param()
    
    # Pattern to filter out PowerShell automatic properties from registry entries
    $psAutoPropertiesPattern = '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
    
    $intunePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'
    $ssmPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    
    # First, check if access to the Intune Policy Manager path is denied
    # When HideExclusionsFromLocalAdmins is enabled via Intune, it restricts SYSTEM access
    # to this registry location. This setting cannot be enforced via Security Settings Management,
    # so access denial reliably indicates Intune management.
    try {
        # Attempt to access the Intune Policy Manager path with ErrorAction Stop
        # to catch access denied exceptions
        $null = Get-ItemProperty -Path $intunePolicyPath -ErrorAction Stop
    }
    catch {
        # Check if the error is an access denied / unauthorized exception
        $isAccessDenied = $_.Exception -is [System.UnauthorizedAccessException] -or
                          $_.Exception -is [System.Security.SecurityException] -or
                          ($_.Exception.InnerException -is [System.UnauthorizedAccessException]) -or
                          ($_.Exception.InnerException -is [System.Security.SecurityException])
        
        # Also check the error message for access denied indicators
        if (-not $isAccessDenied) {
            $errorMessage = $_.Exception.Message
            $isAccessDenied = $errorMessage -match 'access.*(denied|not allowed)|unauthorized|permission'
        }
        
        if ($isAccessDenied) {
            # Access denied to Policy Manager path indicates Intune management
            # because HideExclusionsFromLocalAdmins (which causes this restriction)
            # can only be set via Intune, not via Security Settings Management or locally
            return "Intune"
        }
        # If error is not access denied (e.g., path doesn't exist), continue with normal detection
    }
    
    try {
        # Check for Intune policy entries first (more specific path)
        if (Test-Path $intunePolicyPath) {
            $intuneEntries = Get-ItemProperty -Path $intunePolicyPath -ErrorAction SilentlyContinue
            if ($null -ne $intuneEntries) {
                # Check if there are any values (excluding PSPath, PSParentPath, etc.)
                $valueNames = @($intuneEntries.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch $psAutoPropertiesPattern } |
                    Select-Object -ExpandProperty Name)
                if ($valueNames.Count -gt 0) {
                    return "Intune"
                }
            }
        }
        
        # Check for Security Settings Management / GPO policy entries
        if (Test-Path $ssmPolicyPath) {
            $ssmEntries = Get-ItemProperty -Path $ssmPolicyPath -ErrorAction SilentlyContinue
            # Check if any subkeys exist - limit to first result for efficiency
            $hasSubKeys = $null -ne (Get-ChildItem -Path $ssmPolicyPath -ErrorAction SilentlyContinue | Select-Object -First 1)
            
            if ($null -ne $ssmEntries) {
                # Check if there are any values (excluding PSPath, PSParentPath, etc.)
                $valueNames = @($ssmEntries.PSObject.Properties | 
                    Where-Object { $_.Name -notmatch $psAutoPropertiesPattern } |
                    Select-Object -ExpandProperty Name)
                if ($valueNames.Count -gt 0 -or $hasSubKeys) {
                    return "Security Settings Management"
                }
            }
            elseif ($hasSubKeys) {
                return "Security Settings Management"
            }
        }
        
        return "Not Configured"
    }
    catch {
        return "Not Configured"
    }
}

function Test-MDEPassiveMode {
    <#
    .SYNOPSIS
        Tests if the device is in Passive Mode or EDR in Block Mode.
    
    .DESCRIPTION
        Checks whether Microsoft Defender Antivirus is running in Passive Mode
        (when another antivirus is the primary AV) or if EDR in Block Mode is enabled.
        Both modes should generate warnings as they indicate non-standard configurations.
    
    .EXAMPLE
        Test-MDEPassiveMode
        
        Tests if the device is in Passive Mode or EDR in Block Mode.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Passive Mode: Defender runs alongside another AV, with limited real-time protection.
        EDR in Block Mode: Allows Defender to take remediation actions even when in passive mode.
        
        Detection methods:
        - Primary: Get-MpComputerStatus AMRunningMode property (Normal, Passive, EDR Block Mode, SxS Passive Mode)
        - Registry fallback for Passive Mode: HKLM:\SOFTWARE\Microsoft\Windows Defender\PassiveMode = 1
        - Registry for EDR Block Mode behavior: HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\PassiveModeBehavior = 1
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Passive Mode / EDR Block Mode'
    
    try {
        $isPassiveMode = $false
        $isEDRBlockMode = $false
        
        # Check for Passive Mode via Get-MpComputerStatus if available
        try {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
            if ($null -ne $mpStatus.AMRunningMode) {
                # AMRunningMode can be: Normal, Passive, EDR Block Mode, SxS Passive Mode
                $runningMode = $mpStatus.AMRunningMode
                if ($runningMode -match 'Passive') {
                    $isPassiveMode = $true
                }
                if ($runningMode -match 'EDR Block') {
                    $isEDRBlockMode = $true
                }
            }
        }
        catch {
            # Get-MpComputerStatus may not be available on non-Windows systems or if Defender is not installed
            # Fall back to registry checks below
        }
        
        # Check registry for Passive Mode indicator
        $passiveModeRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
        if (Test-Path $passiveModeRegPath) {
            $defenderReg = Get-ItemProperty -Path $passiveModeRegPath -ErrorAction SilentlyContinue
            if ($null -ne $defenderReg.PassiveMode -and $defenderReg.PassiveMode -eq 1) {
                $isPassiveMode = $true
            }
        }
        
        # Check for EDR Block Mode configuration
        # EDR Block Mode is when passive mode is forced but block mode behavior is enabled
        $atpPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
        $featuresPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        
        $forcePassiveMode = $null
        $passiveModeBehavior = $null
        
        if (Test-Path $atpPolicyPath) {
            $atpPolicy = Get-ItemProperty -Path $atpPolicyPath -ErrorAction SilentlyContinue
            if ($null -ne $atpPolicy.ForceDefenderPassiveMode) {
                $forcePassiveMode = $atpPolicy.ForceDefenderPassiveMode
            }
        }
        
        if (Test-Path $featuresPath) {
            $features = Get-ItemProperty -Path $featuresPath -ErrorAction SilentlyContinue
            if ($null -ne $features.PassiveModeBehavior) {
                $passiveModeBehavior = $features.PassiveModeBehavior
            }
        }
        
        # EDR Block Mode detection via registry
        # EDR Block Mode allows Defender to perform remediation even when in passive mode
        # It's enabled when PassiveModeBehavior = 1 (block mode behavior is on) AND 
        # the device is in passive mode (either detected via AMRunningMode or PassiveMode registry)
        if ($passiveModeBehavior -eq 1 -and $isPassiveMode) {
            $isEDRBlockMode = $true
        }
        
        # Determine the result
        if ($isEDRBlockMode) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Device is running in EDR Block Mode. Defender is in passive mode but can take remediation actions via EDR." `
                -Recommendation "EDR Block Mode is typically used when third-party antivirus is primary. Verify this is intentional and ensure the third-party AV provides adequate protection."
        } elseif ($isPassiveMode) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Device is running in Passive Mode. Microsoft Defender Antivirus is not the primary antivirus solution." `
                -Recommendation "Passive Mode means another antivirus is active. Verify the third-party AV provides adequate protection, or consider enabling EDR Block Mode for additional remediation capabilities."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Device is running in Active Mode. Microsoft Defender Antivirus is the primary antivirus solution."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to determine Passive Mode / EDR Block Mode status: $_" `
            -Recommendation "Ensure you have appropriate permissions to query Windows Defender status."
    }
}

function Test-MDEServiceStatus {
    <#
    .SYNOPSIS
        Tests the status of the Windows Defender service.
    
    .DESCRIPTION
        Checks if the Windows Defender Antivirus Service (WinDefend) is running
        and configured to start automatically.
    
    .EXAMPLE
        Test-MDEServiceStatus
        
        Tests if the Windows Defender service is running properly.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Windows Defender Service Status'
    
    try {
        $service = Get-Service -Name 'WinDefend' -ErrorAction Stop
        
        if ($service.Status -eq 'Running') {
            $startType = (Get-Service -Name 'WinDefend').StartType
            if ($startType -eq 'Automatic') {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Windows Defender service is running and set to start automatically."
            } else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Windows Defender service is running but start type is '$startType'." `
                    -Recommendation "Set the service to start automatically for optimal protection."
            }
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Windows Defender service is not running. Current status: $($service.Status)" `
                -Recommendation "Start the Windows Defender service and ensure it's set to start automatically."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Windows Defender service: $_" `
            -Recommendation "Verify that Windows Defender is installed on this system."
    }
}

function Test-MDERealTimeProtection {
    <#
    .SYNOPSIS
        Tests if real-time protection is enabled.
    
    .DESCRIPTION
        Checks the real-time protection status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDERealTimeProtection
        
        Tests if real-time protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Real-Time Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        if ($mpPreference.DisableRealtimeMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Real-time protection is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Real-time protection is disabled." `
                -Recommendation "Enable real-time protection via Group Policy or 'Set-MpPreference -DisableRealtimeMonitoring `$false'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query real-time protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}

function Test-MDECloudProtection {
    <#
    .SYNOPSIS
        Tests if cloud-delivered protection is enabled.
    
    .DESCRIPTION
        Checks the cloud-delivered protection (MAPS) status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDECloudProtection
        
        Tests if cloud-delivered protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Cloud-Delivered Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # MAPSReporting: 0 = Disabled, 1 = Basic, 2 = Advanced
        if ($mpPreference.MAPSReporting -ge 1) {
            $level = switch ($mpPreference.MAPSReporting) {
                1 { 'Basic' }
                2 { 'Advanced' }
                default { 'Unknown' }
            }
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Cloud-delivered protection is enabled at '$level' level."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Cloud-delivered protection is disabled." `
                -Recommendation "Enable cloud-delivered protection via Group Policy or 'Set-MpPreference -MAPSReporting 2' for advanced protection."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query cloud-delivered protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDESampleSubmission {
    <#
    .SYNOPSIS
        Tests if automatic sample submission is enabled.
    
    .DESCRIPTION
        Checks the automatic sample submission status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDESampleSubmission
        
        Tests if automatic sample submission is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Automatic Sample Submission'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # SubmitSamplesConsent: 0 = Always Prompt, 1 = Send safe samples, 2 = Never send, 3 = Send all samples
        if ($mpPreference.SubmitSamplesConsent -eq 3) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Automatic sample submission is enabled: 'Send all samples automatically'."
        } elseif ($mpPreference.SubmitSamplesConsent -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Safe samples only'." `
                -Recommendation "Consider enabling 'Send all samples automatically' for better threat detection via 'Set-MpPreference -SubmitSamplesConsent 3'."
        } elseif ($mpPreference.SubmitSamplesConsent -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Automatic sample submission is set to 'Always Prompt'." `
                -Recommendation "Consider enabling automatic sample submission for better threat detection via 'Set-MpPreference -SubmitSamplesConsent 3'."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Automatic sample submission is disabled." `
                -Recommendation "Enable automatic sample submission via Group Policy or 'Set-MpPreference -SubmitSamplesConsent 3'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query sample submission status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEBehaviorMonitoring {
    <#
    .SYNOPSIS
        Tests if behavior monitoring is enabled.
    
    .DESCRIPTION
        Checks the behavior monitoring status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDEBehaviorMonitoring
        
        Tests if behavior monitoring is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Behavior Monitoring'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        if ($mpPreference.DisableBehaviorMonitoring -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Behavior monitoring is enabled."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Behavior monitoring is disabled." `
                -Recommendation "Enable behavior monitoring via Group Policy or 'Set-MpPreference -DisableBehaviorMonitoring `$false'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query behavior monitoring status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEOnboardingStatus {
    <#
    .SYNOPSIS
        Tests the MDE onboarding status.
    
    .DESCRIPTION
        Checks if the device is properly onboarded to Microsoft Defender for Endpoint
        by verifying the SENSE service status and registry settings.
    
    .EXAMPLE
        Test-MDEOnboardingStatus
        
        Tests if the device is onboarded to MDE.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'MDE Onboarding Status'
    
    try {
        # Check for SENSE service (Microsoft Defender for Endpoint Service)
        $senseService = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
        
        if ($null -eq $senseService) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Microsoft Defender for Endpoint service (Sense) is not installed." `
                -Recommendation "Onboard the device to Microsoft Defender for Endpoint using the onboarding package from the Security Center."
            return
        }
        
        if ($senseService.Status -ne 'Running') {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Microsoft Defender for Endpoint service is not running. Status: $($senseService.Status)" `
                -Recommendation "Start the SENSE service and verify the onboarding configuration."
            return
        }
        
        # Check onboarding state in registry
        $onboardingPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
        if (Test-Path $onboardingPath) {
            $onboardingState = Get-ItemProperty -Path $onboardingPath -Name 'OnboardingState' -ErrorAction SilentlyContinue
            
            if ($onboardingState.OnboardingState -eq 1) {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Device is successfully onboarded to Microsoft Defender for Endpoint."
            } else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Device appears to be partially onboarded. OnboardingState: $($onboardingState.OnboardingState)" `
                    -Recommendation "Re-run the onboarding script or check the device status in the Security Center."
            }
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "MDE onboarding registry key not found, but SENSE service is running." `
                -Recommendation "Verify the device's onboarding status in the Microsoft 365 Defender portal."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query MDE onboarding status: $_" `
            -Recommendation "Ensure you have appropriate permissions and MDE is properly configured."
    }
}

function Test-MDENetworkProtection {
    <#
    .SYNOPSIS
        Tests if network protection is enabled.
    
    .DESCRIPTION
        Checks the network protection status of Windows Defender Antivirus.
    
    .EXAMPLE
        Test-MDENetworkProtection
        
        Tests if network protection is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Network Protection'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # EnableNetworkProtection: 0 = Disabled, 1 = Enabled (Block), 2 = Audit mode
        switch ($mpPreference.EnableNetworkProtection) {
            0 {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Network protection is disabled." `
                    -Recommendation "Enable network protection via Group Policy or 'Set-MpPreference -EnableNetworkProtection Enabled'."
            }
            1 {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Network protection is enabled in Block mode."
            }
            2 {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Network protection is in Audit mode only." `
                    -Recommendation "Consider enabling Block mode for full protection after validating Audit mode results."
            }
            default {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Network protection status is unknown: $($mpPreference.EnableNetworkProtection)" `
                    -Recommendation "Verify network protection configuration."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query network protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDENetworkProtectionWindowsServer {
    <#
    .SYNOPSIS
        Tests if Network Protection is properly configured for Windows Server.
    
    .DESCRIPTION
        Checks if the AllowNetworkProtectionOnWinServer and AllowNetworkProtectionDownLevel 
        registry keys are enabled for Windows Server operating systems. These settings are 
        required for Network Protection to function on Windows Server.
        
        For non-Server operating systems (e.g., Windows 10/11 Professional, Enterprise), 
        this check returns NotApplicable as these settings are only required on Server.
    
    .EXAMPLE
        Test-MDENetworkProtectionWindowsServer
        
        Tests if Network Protection is properly configured for Windows Server.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry locations:
        - HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection
          - AllowNetworkProtectionOnWinServer (REG_DWORD, 1 = enabled)
          - AllowNetworkProtectionDownLevel (REG_DWORD, 1 = enabled)
        
        Both settings must be set to 1 for Network Protection to work on Windows Server.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Network Protection (Windows Server)'
    
    # Check if running on Windows Server
    if (-not (Test-IsWindowsServer)) {
        Write-ValidationResult -TestName $testName -Status 'NotApplicable' `
            -Message "This check only applies to Windows Server operating systems."
        return
    }
    
    try {
        $networkProtectionPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        
        $allowOnWinServer = $null
        $allowDownLevel = $null
        
        if (Test-Path $networkProtectionPath) {
            $npSettings = Get-ItemProperty -Path $networkProtectionPath -ErrorAction SilentlyContinue
            $allowOnWinServer = $npSettings.AllowNetworkProtectionOnWinServer
            $allowDownLevel = $npSettings.AllowNetworkProtectionDownLevel
        }
        
        $issues = @()
        
        # Check AllowNetworkProtectionOnWinServer
        if ($null -eq $allowOnWinServer -or $allowOnWinServer -ne 1) {
            $issues += "AllowNetworkProtectionOnWinServer is not enabled"
        }
        
        # Check AllowNetworkProtectionDownLevel
        if ($null -eq $allowDownLevel -or $allowDownLevel -ne 1) {
            $issues += "AllowNetworkProtectionDownLevel is not enabled"
        }
        
        if ($issues.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Network Protection for Windows Server is properly configured. AllowNetworkProtectionOnWinServer and AllowNetworkProtectionDownLevel are both enabled."
        } else {
            $recommendation = @"
Deploy the following registry keys via Group Policy or another management tool:
- HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection
  - AllowNetworkProtectionDownLevel REG_DWORD 1
  - AllowNetworkProtectionOnWinServer REG_DWORD 1
"@
            
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Network Protection for Windows Server is not properly configured. Issues: $($issues -join '; ')." `
                -Recommendation $recommendation
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Network Protection Windows Server settings: $_" `
            -Recommendation "Ensure you have appropriate permissions to read Windows Defender registry settings."
    }
}

function Test-MDEDatagramProcessingWindowsServer {
    <#
    .SYNOPSIS
        Tests if Datagram Processing is properly configured for Windows Server.
    
    .DESCRIPTION
        Checks if the AllowDatagramProcessingOnWinServer registry key is enabled for 
        Windows Server operating systems. This setting is required for proper network 
        inspection functionality on Windows Server.
        
        For non-Server operating systems (e.g., Windows 10/11 Professional, Enterprise), 
        this check returns NotApplicable as this setting is only required on Server.
    
    .EXAMPLE
        Test-MDEDatagramProcessingWindowsServer
        
        Tests if Datagram Processing is properly configured for Windows Server.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Microsoft\Windows Defender\NIS\Consumers\IPS
          - AllowDatagramProcessingOnWinServer (REG_DWORD, 1 = enabled)
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Datagram Processing (Windows Server)'
    
    # Check if running on Windows Server
    if (-not (Test-IsWindowsServer)) {
        Write-ValidationResult -TestName $testName -Status 'NotApplicable' `
            -Message "This check only applies to Windows Server operating systems."
        return
    }
    
    try {
        $ipsPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\NIS\Consumers\IPS'
        
        $allowDatagramProcessing = $null
        
        if (Test-Path $ipsPath) {
            $ipsSettings = Get-ItemProperty -Path $ipsPath -ErrorAction SilentlyContinue
            $allowDatagramProcessing = $ipsSettings.AllowDatagramProcessingOnWinServer
        }
        
        if ($null -ne $allowDatagramProcessing -and $allowDatagramProcessing -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Datagram Processing for Windows Server is properly configured. AllowDatagramProcessingOnWinServer is enabled."
        } else {
            $recommendation = @"
Deploy the following registry key via Group Policy or another management tool:
- HKLM\SOFTWARE\Microsoft\Windows Defender\NIS\Consumers\IPS
  - AllowDatagramProcessingOnWinServer REG_DWORD 1
"@
            
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Datagram Processing for Windows Server is not enabled. AllowDatagramProcessingOnWinServer is not configured or disabled." `
                -Recommendation $recommendation
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Datagram Processing Windows Server settings: $_" `
            -Recommendation "Ensure you have appropriate permissions to read Windows Defender registry settings."
    }
}

function Test-MDEAttackSurfaceReduction {
    <#
    .SYNOPSIS
        Tests if Attack Surface Reduction (ASR) rules are configured.
    
    .DESCRIPTION
        Checks the Attack Surface Reduction rules status of Windows Defender Antivirus.
        Reports each rule by its human-readable name and enforcement setting.
    
    .EXAMPLE
        Test-MDEAttackSurfaceReduction
        
        Tests if ASR rules are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Attack Surface Reduction Rules'
    
    # Common ASR rule GUIDs and their descriptions
    $asrRuleNames = @{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet criteria'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
        'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    }
    
    # ASR rule action values and their human-readable names
    $asrActionNames = @{
        0 = 'Disabled'
        1 = 'Block'
        2 = 'Audit'
        6 = 'Warn'
    }
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $configuredRules = $mpPreference.AttackSurfaceReductionRules_Ids
        $ruleActions = $mpPreference.AttackSurfaceReductionRules_Actions
        
        if ($null -eq $configuredRules -or $configuredRules.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "No Attack Surface Reduction rules are configured." `
                -Recommendation "Configure ASR rules via Group Policy or Intune for enhanced protection."
            return
        }
        
        $enabledCount = 0
        $auditCount = 0
        $disabledCount = 0
        $warnCount = 0
        $ruleDetails = @()
        
        for ($i = 0; $i -lt $configuredRules.Count; $i++) {
            $ruleGuid = $configuredRules[$i].ToLower()
            $actionValue = if ($null -ne $ruleActions -and $i -lt $ruleActions.Count) { $ruleActions[$i] } else { $null }
            
            # Get human-readable rule name (fall back to GUID if unknown)
            $ruleName = if ($asrRuleNames.ContainsKey($ruleGuid)) { 
                $asrRuleNames[$ruleGuid] 
            } else { 
                "Unknown rule ($ruleGuid)" 
            }
            
            # Get human-readable action name
            $actionName = if ($null -ne $actionValue -and $asrActionNames.ContainsKey([int]$actionValue)) {
                $asrActionNames[[int]$actionValue]
            } else {
                'Unknown'
            }
            
            # Count actions
            if ($null -ne $actionValue) {
                switch ([int]$actionValue) {
                    0 { $disabledCount++ }
                    1 { $enabledCount++ }
                    2 { $auditCount++ }
                    6 { $warnCount++ }
                }
            }
            
            # Add to rule details with human-readable format
            $ruleDetails += "$ruleName ($actionName)"
        }
        
        $totalRules = $configuredRules.Count
        $summaryMessage = "ASR rules configured: $totalRules total ($enabledCount Block, $auditCount Audit, $warnCount Warn, $disabledCount Disabled)"
        
        # Build detailed message with rule names and actions, each on its own line
        $detailedRules = ($ruleDetails | ForEach-Object { "  - $_" }) -join "`n"
        $fullMessage = "$summaryMessage`nRules:`n$detailedRules"
        
        if ($enabledCount -gt 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message $fullMessage
        } elseif ($auditCount -gt 0 -or $warnCount -gt 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$fullMessage. No rules are in Block mode." `
                -Recommendation "Consider enabling Block mode for ASR rules after validating Audit mode results."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "$fullMessage. All configured rules are disabled." `
                -Recommendation "Enable ASR rules for enhanced protection against common attack techniques."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query ASR rules status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEThreatDefaultActions {
    <#
    .SYNOPSIS
        Tests the default actions configured for threat severity levels.
    
    .DESCRIPTION
        Checks the default actions (Quarantine, Remove, Ignore, etc.) configured for
        Low, Moderate, High, and Severe threat severity levels in Windows Defender.
    
    .EXAMPLE
        Test-MDEThreatDefaultActions
        
        Tests the default threat actions configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Threat action values:
        0 = Unknown (may indicate Tamper Protection is enabled)
        1 = Clean (repairs infected files)
        2 = Quarantine
        3 = Remove (deletes the file)
        6 = Allow (Ignore)
        8 = UserDefined
        9 = NoAction
        10 = Block
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Threat Default Actions'
    
    # Map action values to human-readable names
    # Note: Value 0 (Unknown) typically occurs when Tamper Protection is enabled,
    # as it prevents reading these settings for security purposes
    $actionNames = @{
        0 = 'Unknown'
        1 = 'Clean'
        2 = 'Quarantine'
        3 = 'Remove'
        6 = 'Allow'
        8 = 'UserDefined'
        9 = 'NoAction'
        10 = 'Block'
    }
    
    # Recommended actions for each threat level
    $recommendedActions = @{
        'LowThreatDefaultAction' = @(1, 2, 3)      # Clean, Quarantine or Remove
        'ModerateThreatDefaultAction' = @(1, 2, 3) # Clean, Quarantine or Remove
        'HighThreatDefaultAction' = @(1, 2, 3)     # Clean, Quarantine or Remove
        'SevereThreatDefaultAction' = @(1, 2, 3)   # Clean, Quarantine or Remove
    }
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $threatActions = @{
            'LowThreatDefaultAction' = $mpPreference.LowThreatDefaultAction
            'ModerateThreatDefaultAction' = $mpPreference.ModerateThreatDefaultAction
            'HighThreatDefaultAction' = $mpPreference.HighThreatDefaultAction
            'SevereThreatDefaultAction' = $mpPreference.SevereThreatDefaultAction
        }
        
        $issues = @()
        $details = @()
        $unknownCount = 0
        
        foreach ($threatLevel in @('LowThreatDefaultAction', 'ModerateThreatDefaultAction', 'HighThreatDefaultAction', 'SevereThreatDefaultAction')) {
            $actionValue = $threatActions[$threatLevel]
            $actionName = if ($actionNames.ContainsKey([int]$actionValue)) { $actionNames[[int]$actionValue] } else { 'Unknown' }
            $levelName = $threatLevel -replace 'ThreatDefaultAction', ''
            
            $details += "${levelName}: $actionValue ($actionName)"
            
            # Track Unknown (0) values
            if ($actionValue -eq 0) {
                $unknownCount++
            }
            
            # Check if the action is recommended
            if ($actionValue -notin $recommendedActions[$threatLevel]) {
                if ($actionValue -eq 6 -or $actionValue -eq 9) {
                    # Allow or NoAction are concerning
                    $issues += "$levelName threats are set to $actionValue ($actionName)"
                }
            }
        }
        
        $message = "Threat default actions: $($details -join '; ')"
        
        # Check if all values are 0 (Unknown) - indicates Tamper Protection may be blocking
        if ($unknownCount -eq 4) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. All threat default actions show as 0 (Unknown), which typically indicates Tamper Protection is enabled and preventing these settings from being read." `
                -Recommendation "Review the threat default action settings in Group Policy or Intune. Alternatively, temporarily disable Tamper Protection using Troubleshooting Mode to confirm the current threat default actions configuration."
        } elseif ($unknownCount -gt 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. Some threat default actions show as 0 (Unknown), which may indicate Tamper Protection is partially blocking access to these settings." `
                -Recommendation "Review the threat default action settings in Group Policy or Intune. Consider using Troubleshooting Mode to temporarily disable Tamper Protection and verify the configuration."
        } elseif ($issues.Count -gt 0) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. Potential issues: $($issues -join '; ')." `
                -Recommendation "Consider setting threat actions to Quarantine (2) or Remove (3) for all severity levels via Group Policy or Set-MpPreference."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message $message
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query threat default actions: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEExclusionVisibilityLocalAdmins {
    <#
    .SYNOPSIS
        Tests if local administrators can view exclusions.
    
    .DESCRIPTION
        Checks the HideExclusionsFromLocalAdmins setting that controls whether 
        exclusions are visible to local administrators. This setting can be 
        configured via Group Policy or Intune.
    
    .EXAMPLE
        Test-MDEExclusionVisibilityLocalAdmins
        
        Tests the exclusion visibility settings for local administrators.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry locations:
        - HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions (HideExclusionsFromLocalAdmins)
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions (HideExclusionsFromLocalAdmins)
        
        Values:
        0 or not present = Exclusions are visible (not hidden)
        1 = Exclusions are hidden
        
        These settings are available via:
        - Group Policy: Computer Configuration > Administrative Templates > Windows Components > 
          Microsoft Defender Antivirus > Exclusions
        - Intune: Endpoint Security > Antivirus > Microsoft Defender Antivirus > Exclusions
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Exclusion Visibility (Local Admins)'
    
    try {
        $hideFromLocalAdmins = $null
        $source = ''
        
        # First, check Get-MpPreference for exclusion properties that indicate hidden status
        # When exclusions are hidden from local admins, the ExclusionExtension property returns
        # a string like "{N/A: Administrators are not allowed to view exclusions}"
        try {
            $mpPreference = Get-MpPreference -ErrorAction Stop
            
            # Check if ExclusionExtension contains the "not allowed to view" message
            # This is a reliable indicator that HideExclusionsFromLocalAdmins is enabled
            # The message format is: "{N/A: Administrators are not allowed to view exclusions}"
            $exclusionsHiddenMessage = 'Administrators are not allowed to view exclusions'
            if ($null -ne $mpPreference.ExclusionExtension) {
                # Handle both array and single string cases properly
                $exclusionExtensionValue = if ($mpPreference.ExclusionExtension -is [array]) {
                    $mpPreference.ExclusionExtension -join ' '
                } else {
                    [string]$mpPreference.ExclusionExtension
                }
                if ($exclusionExtensionValue -match [regex]::Escape($exclusionsHiddenMessage)) {
                    $hideFromLocalAdmins = 1
                    $source = 'Get-MpPreference (exclusions hidden)'
                }
            }
            
            # Also check HideExclusionsFromLocalAdmins property directly
            if ($null -eq $hideFromLocalAdmins -and $null -ne $mpPreference.HideExclusionsFromLocalAdmins) {
                $hideFromLocalAdmins = if ($mpPreference.HideExclusionsFromLocalAdmins) { 1 } else { 0 }
                if ([string]::IsNullOrEmpty($source)) { $source = 'MpPreference' }
            }
        }
        catch {
            # Continue even if MpPreference fails - we may have registry values
        }
        
        # Check registry settings for exclusion visibility
        $exclusionsPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
        $policiesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
        
        # Check Group Policy settings (takes precedence over default registry)
        if ($null -eq $hideFromLocalAdmins -and (Test-Path $policiesPath)) {
            $policySettings = Get-ItemProperty -Path $policiesPath -ErrorAction SilentlyContinue
            if ($null -ne $policySettings.HideExclusionsFromLocalAdmins) {
                $hideFromLocalAdmins = $policySettings.HideExclusionsFromLocalAdmins
                $source = 'Group Policy'
            }
        }
        
        # Check default registry settings if policy not set
        if ($null -eq $hideFromLocalAdmins -and (Test-Path $exclusionsPath)) {
            $defaultSettings = Get-ItemProperty -Path $exclusionsPath -ErrorAction SilentlyContinue
            if ($null -ne $defaultSettings.HideExclusionsFromLocalAdmins) {
                $hideFromLocalAdmins = $defaultSettings.HideExclusionsFromLocalAdmins
                if ([string]::IsNullOrEmpty($source)) { $source = 'Registry' }
            }
        }
        
        # Interpret results
        $localAdminsHidden = ($hideFromLocalAdmins -eq 1)
        $sourceInfo = if ([string]::IsNullOrEmpty($source)) { '' } else { " (via $source)" }
        
        if ($localAdminsHidden) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Exclusions are hidden from local administrators.$sourceInfo"
        } elseif ($null -eq $hideFromLocalAdmins) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Exclusions visibility for local administrators is not configured (defaults to visible)." `
                -Recommendation "Configure 'Hide exclusions from local admins' via Group Policy or Intune to prevent administrators from discovering exclusion paths."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Exclusions are visible to local administrators.$sourceInfo" `
                -Recommendation "Configure 'Hide exclusions from local admins' via Group Policy or Intune to prevent administrators from discovering exclusion paths."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query exclusion visibility settings for local administrators: $_" `
            -Recommendation "Ensure you have appropriate permissions to read Windows Defender registry settings."
    }
}

function Test-MDEExclusionVisibilityLocalUsers {
    <#
    .SYNOPSIS
        Tests if local users can view exclusions.
    
    .DESCRIPTION
        Checks the HideExclusionsFromLocalUsers setting that controls whether 
        exclusions are visible to local users. This setting can be configured 
        via Group Policy or Intune.
    
    .EXAMPLE
        Test-MDEExclusionVisibilityLocalUsers
        
        Tests the exclusion visibility settings for local users.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry locations:
        - HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions (HideExclusionsFromLocalUsers)
        - HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions (HideExclusionsFromLocalUsers)
        
        Values:
        0 or not present = Exclusions are visible (not hidden)
        1 = Exclusions are hidden
        
        These settings are available via:
        - Group Policy: Computer Configuration > Administrative Templates > Windows Components > 
          Microsoft Defender Antivirus > Exclusions
        - Intune: Endpoint Security > Antivirus > Microsoft Defender Antivirus > Exclusions
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Exclusion Visibility (Local Users)'
    
    try {
        # Check registry settings for exclusion visibility
        $exclusionsPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
        $policiesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
        
        $hideFromLocalUsers = $null
        $source = ''
        
        # Check Group Policy settings first (takes precedence)
        if (Test-Path $policiesPath) {
            $policySettings = Get-ItemProperty -Path $policiesPath -ErrorAction SilentlyContinue
            if ($null -ne $policySettings.HideExclusionsFromLocalUsers) {
                $hideFromLocalUsers = $policySettings.HideExclusionsFromLocalUsers
                $source = 'Group Policy'
            }
        }
        
        # Check default registry settings if policy not set
        if ($null -eq $hideFromLocalUsers -and (Test-Path $exclusionsPath)) {
            $defaultSettings = Get-ItemProperty -Path $exclusionsPath -ErrorAction SilentlyContinue
            if ($null -ne $defaultSettings.HideExclusionsFromLocalUsers) {
                $hideFromLocalUsers = $defaultSettings.HideExclusionsFromLocalUsers
                if ([string]::IsNullOrEmpty($source)) { $source = 'Registry' }
            }
        }
        
        # Also try Get-MpPreference for these settings (if available)
        if ($null -eq $hideFromLocalUsers) {
            try {
                $mpPreference = Get-MpPreference -ErrorAction Stop
                if ($null -ne $mpPreference.HideExclusionsFromLocalUsers) {
                    $hideFromLocalUsers = if ($mpPreference.HideExclusionsFromLocalUsers) { 1 } else { 0 }
                    if ([string]::IsNullOrEmpty($source)) { $source = 'MpPreference' }
                }
            }
            catch {
                # Continue even if MpPreference fails - we may have registry values
            }
        }
        
        # Interpret results
        $localUsersHidden = ($hideFromLocalUsers -eq 1)
        $sourceInfo = if ([string]::IsNullOrEmpty($source)) { '' } else { " (via $source)" }
        
        if ($localUsersHidden) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Exclusions are hidden from local users.$sourceInfo"
        } elseif ($null -eq $hideFromLocalUsers) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Exclusions visibility for local users is not configured (defaults to visible)." `
                -Recommendation "Configure 'Hide exclusions from local users' via Group Policy or Intune to prevent standard users from discovering exclusion paths that could be exploited."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Exclusions are visible to local users.$sourceInfo" `
                -Recommendation "Configure 'Hide exclusions from local users' via Group Policy or Intune to prevent standard users from discovering exclusion paths that could be exploited."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query exclusion visibility settings for local users: $_" `
            -Recommendation "Ensure you have appropriate permissions to read Windows Defender registry settings."
    }
}

function Test-MDESmartScreen {
    <#
    .SYNOPSIS
        Tests if SmartScreen is enabled in Microsoft Edge.
    
    .DESCRIPTION
        Checks the SmartScreen configuration for Microsoft Edge browser by querying
        registry settings and Edge policies.
    
    .EXAMPLE
        Test-MDESmartScreen
        
        Tests if SmartScreen is enabled in Edge.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        SmartScreen can be tested manually by visiting https://smartscreentestratings2.net/
        which should be blocked if SmartScreen is properly configured.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen'
    
    try {
        # Check Edge SmartScreen policy settings
        # Primary location: HKLM:\SOFTWARE\Policies\Microsoft\Edge
        # User location: HKCU:\SOFTWARE\Policies\Microsoft\Edge
        # Default settings: HKLM:\SOFTWARE\Microsoft\Edge
        
        $smartScreenEnabled = $null
        $smartScreenSource = ''
        
        # Check Group Policy settings first (takes precedence)
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenEnabled'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenEnabled'; Source = 'Group Policy (User)' },
            @{ Path = 'HKLM:\SOFTWARE\Microsoft\Edge'; Name = 'SmartScreenEnabled'; Source = 'Edge Default Settings' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                $propertyValue = $value.($policy.Name)
                if ($null -ne $value -and $null -ne $propertyValue) {
                    $smartScreenEnabled = $propertyValue
                    $smartScreenSource = $policy.Source
                    break
                }
            }
        }
        
        # Also check Windows Defender SmartScreen settings
        $defenderSmartScreenPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        $defenderSmartScreen = $null
        if (Test-Path $defenderSmartScreenPath) {
            $defenderValue = Get-ItemProperty -Path $defenderSmartScreenPath -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue
            if ($null -ne $defenderValue -and $null -ne $defenderValue.SmartScreenEnabled) {
                $defenderSmartScreen = $defenderValue.SmartScreenEnabled
            }
        }
        
        # Determine overall status
        if ($null -ne $smartScreenEnabled) {
            if ($smartScreenEnabled -eq 1) {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Edge SmartScreen is enabled via Group Policy or Intune. Test URL: https://smartscreentestratings2.net/"
            } else {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Edge SmartScreen is disabled via $smartScreenSource." `
                    -Recommendation "Enable SmartScreen via Group Policy, Intune, or Edge settings. Set 'SmartScreenEnabled' to 1. Test with https://smartscreentestratings2.net/"
            }
        } elseif ($null -ne $defenderSmartScreen) {
            # Fall back to Windows Defender SmartScreen check
            if ($defenderSmartScreen -eq 'RequireAdmin' -or $defenderSmartScreen -eq 'Prompt' -or $defenderSmartScreen -eq 'On') {
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "Windows Defender SmartScreen is enabled ('$defenderSmartScreen'). Edge inherits this setting. Test URL: https://smartscreentestratings2.net/"
            } elseif ($defenderSmartScreen -eq 'Off') {
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "Windows Defender SmartScreen is disabled." `
                    -Recommendation "Enable SmartScreen via Windows Security settings, Group Policy, or Intune. Test with https://smartscreentestratings2.net/"
            } else {
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "Windows Defender SmartScreen setting is '$defenderSmartScreen'. Unable to determine if fully enabled." `
                    -Recommendation "Verify SmartScreen is properly configured via Group Policy or Intune. Test manually by visiting https://smartscreentestratings2.net/"
            }
        } else {
            # No explicit settings found - SmartScreen is typically enabled by default in modern Windows/Edge
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "No explicit SmartScreen policy found. SmartScreen may be using default settings (typically enabled)." `
                -Recommendation "Configure SmartScreen explicitly via Group Policy or Intune for consistent protection. Test manually by visiting https://smartscreentestratings2.net/"
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen status: $_" `
            -Recommendation "Ensure you have permissions to read registry settings. Test SmartScreen manually by visiting https://smartscreentestratings2.net/"
    }
}

function Test-MDESmartScreenPUA {
    <#
    .SYNOPSIS
        Tests if Microsoft Defender SmartScreen is configured to block potentially unwanted apps.
    
    .DESCRIPTION
        Checks the SmartScreenPuaEnabled policy setting that controls whether
        Microsoft Defender SmartScreen blocks potentially unwanted applications (PUAs).
    
    .EXAMPLE
        Test-MDESmartScreenPUA
        
        Tests if SmartScreen PUA blocking is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge (SmartScreenPuaEnabled)
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge (SmartScreenPuaEnabled)
        
        Values:
        1 = Enabled (blocks PUAs)
        0 = Disabled
        Not present = Not configured
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen PUA Protection'
    
    try {
        $smartScreenPuaEnabled = $null
        $source = ''
        
        # Check Group Policy settings (machine then user)
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenPuaEnabled'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'SmartScreenPuaEnabled'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                $propertyValue = $value.($policy.Name)
                if ($null -ne $propertyValue) {
                    $smartScreenPuaEnabled = $propertyValue
                    $source = $policy.Source
                    break
                }
            }
        }
        
        # Determine status
        if ($null -eq $smartScreenPuaEnabled) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen PUA protection is not configured." `
                -Recommendation "Configure 'Configure Microsoft Defender SmartScreen to block potentially unwanted apps' via Group Policy or Intune. Set SmartScreenPuaEnabled to 1."
        } elseif ($smartScreenPuaEnabled -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "SmartScreen PUA protection is enabled via $source. Potentially unwanted apps will be blocked."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen PUA protection is disabled via $source." `
                -Recommendation "Enable 'Configure Microsoft Defender SmartScreen to block potentially unwanted apps' via Group Policy or Intune. Set SmartScreenPuaEnabled to 1."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen PUA protection status: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}

function Test-MDESmartScreenPromptOverride {
    <#
    .SYNOPSIS
        Tests if bypassing Microsoft Defender SmartScreen prompts for sites is prevented.
    
    .DESCRIPTION
        Checks the PreventSmartScreenPromptOverride policy setting that controls whether
        users can bypass SmartScreen warnings about potentially malicious websites.
    
    .EXAMPLE
        Test-MDESmartScreenPromptOverride
        
        Tests if SmartScreen prompt bypassing is prevented.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge (PreventSmartScreenPromptOverride)
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge (PreventSmartScreenPromptOverride)
        
        Values:
        1 = Enabled (prevents bypassing)
        0 = Disabled (allows bypassing)
        Not present = Not configured
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen Prompt Override Prevention'
    
    try {
        $preventOverride = $null
        $source = ''
        
        # Check Group Policy settings (machine then user)
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'PreventSmartScreenPromptOverride'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'PreventSmartScreenPromptOverride'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                $propertyValue = $value.($policy.Name)
                if ($null -ne $propertyValue) {
                    $preventOverride = $propertyValue
                    $source = $policy.Source
                    break
                }
            }
        }
        
        # Determine status
        if ($null -eq $preventOverride) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen prompt override prevention is not configured. Users may be able to bypass SmartScreen warnings for sites." `
                -Recommendation "Configure 'Prevent bypassing Microsoft Defender SmartScreen prompts for sites' via Group Policy or Intune. Set PreventSmartScreenPromptOverride to 1."
        } elseif ($preventOverride -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "SmartScreen prompt override prevention is enabled via $source. Users cannot bypass SmartScreen warnings for sites."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen prompt override prevention is disabled via $source. Users can bypass SmartScreen warnings for sites." `
                -Recommendation "Enable 'Prevent bypassing Microsoft Defender SmartScreen prompts for sites' via Group Policy or Intune. Set PreventSmartScreenPromptOverride to 1."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen prompt override prevention status: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}

function Test-MDESmartScreenDownloadOverride {
    <#
    .SYNOPSIS
        Tests if bypassing Microsoft Defender SmartScreen warnings about downloads is prevented.
    
    .DESCRIPTION
        Checks the PreventSmartScreenPromptOverrideForFiles policy setting that controls whether
        users can bypass SmartScreen warnings about potentially malicious file downloads.
    
    .EXAMPLE
        Test-MDESmartScreenDownloadOverride
        
        Tests if SmartScreen download warning bypassing is prevented.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge (PreventSmartScreenPromptOverrideForFiles)
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge (PreventSmartScreenPromptOverrideForFiles)
        
        Values:
        1 = Enabled (prevents bypassing download warnings)
        0 = Disabled (allows bypassing download warnings)
        Not present = Not configured
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen Download Override Prevention'
    
    try {
        $preventOverride = $null
        $source = ''
        
        # Check Group Policy settings (machine then user)
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'PreventSmartScreenPromptOverrideForFiles'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'PreventSmartScreenPromptOverrideForFiles'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $value = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                $propertyValue = $value.($policy.Name)
                if ($null -ne $propertyValue) {
                    $preventOverride = $propertyValue
                    $source = $policy.Source
                    break
                }
            }
        }
        
        # Determine status
        if ($null -eq $preventOverride) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen download override prevention is not configured. Users may be able to bypass SmartScreen warnings about downloads." `
                -Recommendation "Configure 'Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads' via Group Policy or Intune. Set PreventSmartScreenPromptOverrideForFiles to 1."
        } elseif ($preventOverride -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "SmartScreen download override prevention is enabled via $source. Users cannot bypass SmartScreen warnings about downloads."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen download override prevention is disabled via $source. Users can bypass SmartScreen warnings about downloads." `
                -Recommendation "Enable 'Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads' via Group Policy or Intune. Set PreventSmartScreenPromptOverrideForFiles to 1."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen download override prevention status: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}

function Test-MDESmartScreenDomainExclusions {
    <#
    .SYNOPSIS
        Tests if SmartScreen domain exclusions are configured.
    
    .DESCRIPTION
        Checks the SmartScreenAllowListDomains policy setting that configures domains
        for which Microsoft Defender SmartScreen won't trigger warnings. If domains
        are configured, this is a potential security risk as those domains bypass SmartScreen.
    
    .EXAMPLE
        Test-MDESmartScreenDomainExclusions
        
        Tests if SmartScreen domain exclusions are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains
        
        Domains are stored as numbered subkeys (1, 2, 3, etc.) with string values.
        If domains are configured, they should be reported as a warning since
        those domains bypass SmartScreen protection.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen Domain Exclusions'
    
    try {
        $domains = @()
        $source = ''
        
        # Check Group Policy settings for domain exclusions
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                # Get all values from the registry key (domains are stored as numbered values)
                $regValues = Get-ItemProperty -Path $policy.Path -ErrorAction SilentlyContinue
                if ($null -ne $regValues) {
                    # Get all properties except PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
                    $domainValues = $regValues.PSObject.Properties | 
                        Where-Object { $_.Name -notmatch '^PS' } | 
                        ForEach-Object { $_.Value }
                    
                    if ($domainValues -and $domainValues.Count -gt 0) {
                        $domains = @($domainValues)
                        $source = $policy.Source
                        break
                    }
                }
            }
        }
        
        # Determine status
        if ($domains.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "No SmartScreen domain exclusions are configured. SmartScreen protection applies to all domains."
        } else {
            $domainList = $domains -join ', '
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen domain exclusions are configured via $source. The following domains bypass SmartScreen protection: $domainList" `
                -Recommendation "Review the configured domain exclusions to ensure they are necessary. Each excluded domain bypasses SmartScreen protection. Domains: $domainList"
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen domain exclusions: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}

function Test-MDESmartScreenAppRepExclusions {
    <#
    .SYNOPSIS
        Tests if SmartScreen AppRep file type exclusions are configured.
    
    .DESCRIPTION
        Checks the ExemptSmartScreenDownloadWarnings policy setting that configures
        domains and file types for which Microsoft Defender SmartScreen won't trigger
        application reputation (AppRep) warnings. If exclusions are configured, this is
        a potential security risk as those file types on those domains bypass SmartScreen.
    
    .EXAMPLE
        Test-MDESmartScreenAppRepExclusions
        
        Tests if SmartScreen AppRep exclusions are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge (ExemptSmartScreenDownloadWarnings property)
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge (ExemptSmartScreenDownloadWarnings property)
        
        The ExemptSmartScreenDownloadWarnings policy is stored as a single REG_SZ value
        containing a JSON array of exclusion objects.
        Format: [{"file_extension": "msi", "domains": ["domain1.com"]}, {"file_extension": "exe", "domains": ["domain2.com", "*"]}]
        
        If exclusions are configured, they should be reported as a warning since
        those file types on those domains bypass SmartScreen AppRep protection.
        
        Output format: domainname1.com: msi, exe | domainname2.com: xlsx | *: vbe
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen AppRep Exclusions'
    
    try {
        $exclusions = @{}  # Hashtable: domain -> list of file extensions
        $source = ''
        
        # Check Group Policy settings for AppRep exclusions
        # ExemptSmartScreenDownloadWarnings is a single REG_SZ value under the Edge policy key
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ExemptSmartScreenDownloadWarnings'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ExemptSmartScreenDownloadWarnings'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $regValue = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                if ($null -ne $regValue -and $null -ne $regValue.($policy.Name)) {
                    $jsonValue = $regValue.($policy.Name)
                    
                    try {
                        # Parse the JSON array of exclusion objects
                        $parsedArray = $jsonValue | ConvertFrom-Json
                        
                        foreach ($parsed in $parsedArray) {
                            # Extract file extension
                            $fileExt = $parsed.file_extension
                            
                            # Extract domains (the policy uses 'domains' not 'url_patterns')
                            # Ensure domains is an array (ConvertFrom-Json returns a string for single values)
                            $domains = $parsed.domains
                            if ($null -eq $domains) {
                                $domains = @('*')
                            } else {
                                $domains = @($domains)
                            }
                            
                            foreach ($domain in $domains) {
                                # Normalize the domain (remove leading *. if present)
                                $normalizedDomain = $domain -replace '^\*\.', ''
                                if ([string]::IsNullOrEmpty($normalizedDomain)) {
                                    $normalizedDomain = '*'
                                }
                                
                                if (-not $exclusions.ContainsKey($normalizedDomain)) {
                                    $exclusions[$normalizedDomain] = @()
                                }
                                if ($fileExt -and $fileExt -notin $exclusions[$normalizedDomain]) {
                                    $exclusions[$normalizedDomain] += $fileExt
                                }
                            }
                        }
                        
                        if ($exclusions.Count -gt 0) {
                            $source = $policy.Source
                            break
                        }
                    }
                    catch {
                        # JSON parsing failed - log a warning and continue to next policy path
                        Write-Verbose "Failed to parse ExemptSmartScreenDownloadWarnings JSON from $($policy.Source): $_"
                        continue
                    }
                }
            }
        }
        
        # Determine status
        if ($exclusions.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "No SmartScreen AppRep exclusions are configured. SmartScreen AppRep protection applies to all file types on all domains."
        } else {
            # Format: domainname1.com: msi, exe | domainname2.com: xlsx | *: vbe
            $exclusionList = ($exclusions.GetEnumerator() | Sort-Object Name | ForEach-Object {
                "$($_.Key): $($_.Value -join ', ')"
            }) -join ' | '
            
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen AppRep exclusions are configured via $source. The following file types on these domains bypass SmartScreen AppRep protection: $exclusionList" `
                -Recommendation "Review the configured AppRep exclusions to ensure they are necessary. Each exclusion bypasses SmartScreen application reputation warnings for the specified file types."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen AppRep exclusions: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}

function Test-MDECloudBlockLevel {
    <#
    .SYNOPSIS
        Tests the Cloud Block Level configuration.
    
    .DESCRIPTION
        Checks the Cloud Block Level (CloudBlockLevel) setting that controls
        how aggressively Microsoft Defender blocks suspicious files using cloud protection.
    
    .EXAMPLE
        Test-MDECloudBlockLevel
        
        Tests the Cloud Block Level configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        CloudBlockLevel values:
        0 = Default (Not Configured)
        1 = Moderate
        2 = High
        4 = High+ (High Plus)
        6 = Zero Tolerance
        
        Recommended: High (2), High+ (4), or Zero Tolerance (6) for enhanced protection.
        For Tier-0 assets such as Domain Controllers, Zero Tolerance or at minimum High+ 
        is recommended as these devices should typically run standard or native applications.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Cloud Block Level'
    
    # Map Cloud Block Level values to human-readable names
    $cloudBlockLevelNames = @{
        0 = 'Default (Not Configured)'
        1 = 'Moderate'
        2 = 'High'
        4 = 'High+'
        6 = 'Zero Tolerance'
    }
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # Cast to int once for consistent comparison
        $cloudBlockLevelValue = [int]$mpPreference.CloudBlockLevel
        $levelName = if ($cloudBlockLevelNames.ContainsKey($cloudBlockLevelValue)) { 
            $cloudBlockLevelNames[$cloudBlockLevelValue] 
        } else { 
            'Unknown' 
        }
        
        $message = "Cloud Block Level: $cloudBlockLevelValue ($levelName)"
        
        # Determine status based on the configured level
        switch ($cloudBlockLevelValue) {
            0 {
                # Default/Not Configured - Fail
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "$message. Cloud Block Level is not configured and using default settings." `
                    -Recommendation "Configure Cloud Block Level to High (2), High+ (4), or Zero Tolerance (6) via Group Policy or Intune. For Tier-0 assets such as Domain Controllers, aim for Zero Tolerance or at minimum High+ as these devices should typically run standard or native applications."
            }
            1 {
                # Moderate - Fail (insufficient)
                Write-ValidationResult -TestName $testName -Status 'Fail' `
                    -Message "$message. Moderate protection level may not provide sufficient protection." `
                    -Recommendation "Increase Cloud Block Level to High (2), High+ (4), or Zero Tolerance (6) via Group Policy or Intune. For Tier-0 assets such as Domain Controllers, aim for Zero Tolerance or at minimum High+ as these devices should typically run standard or native applications."
            }
            2 {
                # High - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. High protection level is configured." `
                    -Recommendation "For Tier-0 assets such as Domain Controllers, consider increasing to High+ (4) or Zero Tolerance (6) as these devices should typically run standard or native applications."
            }
            4 {
                # High+ - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. High+ protection level is configured, providing enhanced cloud protection."
            }
            6 {
                # Zero Tolerance - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. Zero Tolerance protection level is configured, providing maximum cloud protection."
            }
            default {
                # Unknown value - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Unknown Cloud Block Level value detected." `
                    -Recommendation "Verify Cloud Block Level configuration via Group Policy or Intune. Recommended values are High (2), High+ (4), or Zero Tolerance (6)."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Cloud Block Level: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDETamperProtection {
    <#
    .SYNOPSIS
        Tests if Tamper Protection is enabled.
    
    .DESCRIPTION
        Checks the Tamper Protection status and source of Windows Defender.
        Tamper Protection prevents malicious apps from changing important 
        Windows Defender Antivirus settings.
    
    .EXAMPLE
        Test-MDETamperProtection
        
        Tests if Tamper Protection is enabled and reports the source.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Tamper Protection source can be:
        - ATP (Microsoft Defender for Endpoint)
        - Intune (Microsoft Endpoint Manager)
        - ConfigMgr (Configuration Manager)
        - Admin (locally configured by admin)
        - Unknown
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Tamper Protection'
    
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        
        $isTamperProtected = $mpStatus.IsTamperProtected
        $tamperProtectionSource = $mpStatus.TamperProtectionSource
        
        # Build source information string
        $sourceInfo = if ([string]::IsNullOrEmpty($tamperProtectionSource)) {
            ''
        } else {
            " Source: $tamperProtectionSource."
        }
        
        if ($isTamperProtected -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Tamper Protection is enabled.$sourceInfo"
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Tamper Protection is disabled.$sourceInfo" `
                -Recommendation "Enable Tamper Protection via Microsoft Defender for Endpoint portal, Intune, or Group Policy. Tamper Protection prevents malicious apps from changing important Windows Defender Antivirus settings."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Tamper Protection status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and the Defender PowerShell module is available."
    }
}

function Test-MDECloudExtendedTimeout {
    <#
    .SYNOPSIS
        Tests the Cloud Extended Timeout configuration.
    
    .DESCRIPTION
        Checks the Cloud Extended Timeout (CloudExtendedTimeout) setting that controls
        how long Windows Defender Antivirus can block a file while waiting for a 
        cloud-based determination. This is an extension to the default 10-second timeout.
    
    .EXAMPLE
        Test-MDECloudExtendedTimeout
        
        Tests the Cloud Extended Timeout configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        CloudExtendedTimeout values:
        0 = Not configured (uses default 10-second timeout only)
        1-50 = Additional seconds to wait for cloud verdict (on top of built-in 10 seconds)
        
        Recommended: 41-50 seconds for maximum cloud protection capability.
        This gives the cloud a total of 51-60 seconds (10 built-in + 41-50 extended) 
        to analyze suspicious files.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Cloud Extended Timeout'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $cloudExtendedTimeout = $mpPreference.CloudExtendedTimeout
        
        # Handle null or not configured
        if ($null -eq $cloudExtendedTimeout) {
            $cloudExtendedTimeout = 0
        }
        
        $recommendationNote = "This feature allows Windows Defender Antivirus to block a suspicious file for up to 60 seconds, and scan it in the cloud to make sure it's safe. The more time you provide, the better chance of blocking a suspicious file. 10 seconds is already built-in."
        
        if ($cloudExtendedTimeout -ge 41 -and $cloudExtendedTimeout -le 50) {
            # Pass: 41-50 seconds (total 51-60 seconds with built-in)
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Cloud Extended Timeout is set to $cloudExtendedTimeout seconds (total: $($cloudExtendedTimeout + 10) seconds including built-in 10 seconds)."
        } elseif ($cloudExtendedTimeout -ge 21 -and $cloudExtendedTimeout -le 40) {
            # Warning: 21-40 seconds
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Cloud Extended Timeout is set to $cloudExtendedTimeout seconds (total: $($cloudExtendedTimeout + 10) seconds including built-in 10 seconds)." `
                -Recommendation "Consider increasing CloudExtendedTimeout to 50 seconds via Group Policy or 'Set-MpPreference -CloudExtendedTimeout 50'. $recommendationNote"
        } else {
            # Fail: 0-20 seconds or not configured
            $message = if ($cloudExtendedTimeout -eq 0) {
                "Cloud Extended Timeout is not configured (using default 10 seconds only)."
            } else {
                "Cloud Extended Timeout is set to $cloudExtendedTimeout seconds (total: $($cloudExtendedTimeout + 10) seconds including built-in 10 seconds)."
            }
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message $message `
                -Recommendation "Configure CloudExtendedTimeout to 50 seconds via Group Policy or 'Set-MpPreference -CloudExtendedTimeout 50'. $recommendationNote"
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Cloud Extended Timeout: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEDisableCatchupQuickScan {
    <#
    .SYNOPSIS
        Tests if Catchup Quick Scan is enabled.
    
    .DESCRIPTION
        Checks the DisableCatchupQuickScan setting in Windows Defender.
        When DisableCatchupQuickScan is False, catchup quick scan is enabled,
        which ensures missed scheduled scans are performed at the next opportunity.
    
    .EXAMPLE
        Test-MDEDisableCatchupQuickScan
        
        Tests if Catchup Quick Scan is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        DisableCatchupQuickScan values:
        $false = Catchup Quick Scan is enabled (recommended)
        $true = Catchup Quick Scan is disabled
        
        When enabled, if the device is offline during a scheduled quick scan,
        the scan will be performed at the next opportunity when the device is online.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Catchup Quick Scan'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        # DisableCatchupQuickScan: $false = Enabled (good), $true = Disabled (bad)
        if ($mpPreference.DisableCatchupQuickScan -eq $false) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Catchup Quick Scan is enabled. Missed scheduled quick scans will be performed at the next opportunity."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Catchup Quick Scan is disabled." `
                -Recommendation "Enable Catchup Quick Scan via Group Policy or 'Set-MpPreference -DisableCatchupQuickScan `$false' to ensure missed scans are performed."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Catchup Quick Scan status: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDERealTimeScanDirection {
    <#
    .SYNOPSIS
        Tests the Real-Time Scan Direction configuration.
    
    .DESCRIPTION
        Checks the RealTimeScanDirection setting that controls which file operations
        are monitored by real-time protection.
    
    .EXAMPLE
        Test-MDERealTimeScanDirection
        
        Tests the Real-Time Scan Direction configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        RealTimeScanDirection values:
        0 = Monitor all files (bi-directional) - recommended
        1 = Monitor incoming files only
        2 = Monitor outgoing files only
        
        Bi-directional monitoring provides the most comprehensive protection.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Real Time Scan Direction'
    
    # Map RealTimeScanDirection values to human-readable names
    $scanDirectionNames = @{
        0 = 'Monitor all files (bi-directional)'
        1 = 'Monitor incoming files'
        2 = 'Monitor outgoing files'
    }
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $scanDirection = $mpPreference.RealTimeScanDirection
        
        # Handle null value as not configured
        if ($null -eq $scanDirection) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Real Time Scan Direction is not configured." `
                -Recommendation "Configure Real Time Scan Direction to 'Monitor all files (bi-directional)' via Group Policy or 'Set-MpPreference -RealTimeScanDirection 0'."
            return
        }
        
        $directionName = if ($scanDirectionNames.ContainsKey([int]$scanDirection)) { 
            $scanDirectionNames[[int]$scanDirection] 
        } else { 
            'Unknown' 
        }
        
        $message = "Real Time Scan Direction: $scanDirection ($directionName)"
        
        switch ([int]$scanDirection) {
            0 {
                # Bi-directional - Pass
                Write-ValidationResult -TestName $testName -Status 'Pass' `
                    -Message "$message. All file operations are monitored for threats."
            }
            1 {
                # Incoming only - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Only incoming files are monitored." `
                    -Recommendation "Configure Real Time Scan Direction to 'Monitor all files (bi-directional)' via Group Policy or 'Set-MpPreference -RealTimeScanDirection 0' for comprehensive protection."
            }
            2 {
                # Outgoing only - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Only outgoing files are monitored." `
                    -Recommendation "Configure Real Time Scan Direction to 'Monitor all files (bi-directional)' via Group Policy or 'Set-MpPreference -RealTimeScanDirection 0' for comprehensive protection."
            }
            default {
                # Unknown value - Warning
                Write-ValidationResult -TestName $testName -Status 'Warning' `
                    -Message "$message. Unknown Real Time Scan Direction value detected." `
                    -Recommendation "Verify Real Time Scan Direction configuration via Group Policy or Intune."
            }
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Real Time Scan Direction: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDESignatureUpdateFallbackOrder {
    <#
    .SYNOPSIS
        Tests the Signature Update Fallback Order configuration.
    
    .DESCRIPTION
        Checks the SignatureFallbackOrder setting that controls the order in which
        signature update sources are used when the primary source is unavailable.
    
    .EXAMPLE
        Test-MDESignatureUpdateFallbackOrder
        
        Tests the Signature Update Fallback Order configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        The recommended SignatureFallbackOrder is:
        MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer
        
        This ensures that Microsoft Malware Protection Center (MMPC) is tried first,
        followed by Microsoft Update Server, and then internal definition update servers.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Signature Update Fallback Order'
    $recommendedOrder = 'MMPC|MicrosoftUpdateServer|InternalDefinitionUpdateServer'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $fallbackOrder = $mpPreference.SignatureFallbackOrder
        
        # Handle null or empty value as not configured
        if ([string]::IsNullOrEmpty($fallbackOrder)) {
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "Signature Update Fallback Order is not configured." `
                -Recommendation "Configure Signature Update Fallback Order to '$recommendedOrder' via Group Policy or 'Set-MpPreference -SignatureFallbackOrder `"$recommendedOrder`"'."
            return
        }
        
        $message = "Signature Update Fallback Order: $fallbackOrder"
        
        if ($fallbackOrder -eq $recommendedOrder) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "$message. The recommended fallback order is configured."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. This differs from the recommended order." `
                -Recommendation "Consider configuring Signature Update Fallback Order to '$recommendedOrder' via Group Policy or 'Set-MpPreference -SignatureFallbackOrder `"$recommendedOrder`"'."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Signature Update Fallback Order: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDESignatureUpdateInterval {
    <#
    .SYNOPSIS
        Tests the Signature Update Interval configuration.
    
    .DESCRIPTION
        Checks the SignatureUpdateInterval setting that controls how frequently
        Windows Defender checks for signature updates. A lower value ensures
        more frequent delta updates.
    
    .EXAMPLE
        Test-MDESignatureUpdateInterval
        
        Tests the Signature Update Interval configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        SignatureUpdateInterval values:
        0 = Disabled (never checks for updates automatically) - Fail
        1-4 = Optimal interval for frequent delta updates - Pass
        5-24 = Less frequent updates - Warning
        
        Recommended: Set to 1 to ensure delta updates are applied frequently.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Signature Update Interval'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $signatureUpdateInterval = $mpPreference.SignatureUpdateInterval
        
        # Handle null as not configured (treat as 0/disabled)
        if ($null -eq $signatureUpdateInterval) {
            $signatureUpdateInterval = 0
        }
        
        $message = "Signature Update Interval: $signatureUpdateInterval hour(s)"
        
        if ($signatureUpdateInterval -eq 0) {
            # Fail: Disabled
            Write-ValidationResult -TestName $testName -Status 'Fail' `
                -Message "$message. Automatic signature update checking is disabled." `
                -Recommendation "Set Signature Update Interval to 1 hour via Group Policy or 'Set-MpPreference -SignatureUpdateInterval 1' to ensure delta updates are applied frequently."
        } elseif ($signatureUpdateInterval -ge 1 -and $signatureUpdateInterval -le 4) {
            # Pass: 1-4 hours
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "$message. Signature updates are checked frequently."
        } elseif ($signatureUpdateInterval -ge 5 -and $signatureUpdateInterval -le 24) {
            # Warning: 5-24 hours
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. Signature updates are checked less frequently than recommended." `
                -Recommendation "Set Signature Update Interval to 1 hour via Group Policy or 'Set-MpPreference -SignatureUpdateInterval 1' to ensure delta updates are applied frequently."
        } else {
            # Unknown/invalid value - Warning
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "$message. Unexpected Signature Update Interval value." `
                -Recommendation "Set Signature Update Interval to 1 hour via Group Policy or 'Set-MpPreference -SignatureUpdateInterval 1' to ensure delta updates are applied frequently."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Signature Update Interval: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEDisableLocalAdminMerge {
    <#
    .SYNOPSIS
        Tests if Disable Local Admin Merge is configured.
    
    .DESCRIPTION
        Checks the DisableLocalAdminMerge setting that controls whether local
        administrators can add exclusions. When enabled (set to $true), local
        administrator exclusions are ignored, improving security.
    
    .EXAMPLE
        Test-MDEDisableLocalAdminMerge
        
        Tests the Disable Local Admin Merge configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        DisableLocalAdminMerge values:
        $true = Local admin merge is disabled (recommended) - Pass
        $false or not configured = Local admin merge is enabled - Warning
        
        When DisableLocalAdminMerge is enabled, exclusions added by local 
        administrators are ignored, preventing potential security bypasses.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Disable Local Admin Merge'
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $disableLocalAdminMerge = $mpPreference.DisableLocalAdminMerge
        
        # Handle null as not configured
        if ($null -eq $disableLocalAdminMerge) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Disable Local Admin Merge is not configured. Local administrator exclusions may be applied." `
                -Recommendation "Configure Disable Local Admin Merge via Group Policy or 'Set-MpPreference -DisableLocalAdminMerge `$true' to prevent local administrators from adding exclusions."
        } elseif ($disableLocalAdminMerge -eq $true) {
            # Pass: Disabled (local admin merge is disabled = exclusions are ignored)
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Disable Local Admin Merge is enabled. Local administrator exclusions are ignored."
        } else {
            # Warning: Enabled (local admin merge is enabled = exclusions are applied)
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Disable Local Admin Merge is disabled. Local administrator exclusions may be applied." `
                -Recommendation "Configure Disable Local Admin Merge via Group Policy or 'Set-MpPreference -DisableLocalAdminMerge `$true' to prevent local administrators from adding exclusions."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Disable Local Admin Merge setting: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEFileHashComputation {
    <#
    .SYNOPSIS
        Tests if File Hash Computation is enabled.
    
    .DESCRIPTION
        Checks the EnableFileHashComputation setting in Windows Defender.
        When enabled, Windows Defender computes file hashes for files that are scanned,
        which can be used for threat intelligence, hunting, and IoC matching.
    
    .EXAMPLE
        Test-MDEFileHashComputation
        
        Tests if File Hash Computation is enabled.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        EnableFileHashComputation values:
        $true = File Hash Computation is enabled (recommended)
        $false or not configured = File Hash Computation is disabled
        
        When enabled, file hashes are computed for scanned files, enabling:
        - Threat intelligence matching
        - Indicator of Compromise (IoC) hunting
        - Enhanced threat detection via file hash reputation
        
        This can be configured via:
        - Group Policy: Computer Configuration > Administrative Templates > Windows Components > 
          Microsoft Defender Antivirus > Enable file hash computation feature
        - Intune/MEM: Endpoint Security > Antivirus
        - PowerShell: Set-MpPreference -EnableFileHashComputation $true
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'File Hash Computation'
    $enableRecommendation = "Enable File Hash Computation via Group Policy or 'Set-MpPreference -EnableFileHashComputation `$true' to enable file hash-based threat detection and IoC matching."
    
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        
        $enableFileHashComputation = $mpPreference.EnableFileHashComputation
        
        # Handle null as not configured (disabled by default)
        if ($null -eq $enableFileHashComputation) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "File Hash Computation is not configured (disabled by default)." `
                -Recommendation $enableRecommendation
        } elseif ($enableFileHashComputation -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "File Hash Computation is enabled. File hashes are computed for scanned files."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "File Hash Computation is disabled." `
                -Recommendation $enableRecommendation
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query File Hash Computation setting: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured."
    }
}

function Test-MDEConfiguration {
    <#
    .SYNOPSIS
        Runs all MDE configuration validation tests.
    
    .DESCRIPTION
        Executes a comprehensive validation of Microsoft Defender for Endpoint
        configuration settings and returns the results.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .PARAMETER IncludePolicyVerification
        Include policy registry verification sub-tests. These sub-tests verify that
        settings returned by Get-MpPreference match the corresponding registry/policy
        entries based on the device's management type (Intune vs Security Settings Management).
        
        Registry locations checked:
        - Intune: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager
        - SSM/GPO/SCCM: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
        
        Note: Some tests (Edge SmartScreen, Exclusion Visibility) are not applicable
        for Security Settings Management as only Antivirus, ASR, EDR, and Firewall
        policies are supported.
    
    .EXAMPLE
        Test-MDEConfiguration
        
        Runs all MDE configuration validation tests.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludeOnboarding
        
        Runs all tests including MDE onboarding status check.
    
    .EXAMPLE
        Test-MDEConfiguration -IncludePolicyVerification
        
        Runs all tests with policy registry verification sub-tests.
    
    .OUTPUTS
        Array of PSCustomObjects with validation results.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludeOnboarding,
        
        [Parameter()]
        [switch]$IncludePolicyVerification
    )
    
    $results = @()
    
    Write-Verbose "Starting MDE configuration validation..."
    
    # Check for elevation
    $isElevated = Test-IsElevated
    if (-not $isElevated) {
        Write-Warning "Some tests may require elevated privileges. Consider running as Administrator."
    }
    
    # Run all validation tests
    $results += Test-MDEServiceStatus
    $results += Test-MDEPassiveMode
    
    $results += Test-MDERealTimeProtection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Real-Time Protection' `
            -SettingKey 'RealTimeProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudProtection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud-Delivered Protection' `
            -SettingKey 'CloudProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudBlockLevel
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud Block Level' `
            -SettingKey 'CloudBlockLevel' -IsApplicableToSSM $true
    }
    
    $results += Test-MDECloudExtendedTimeout
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Cloud Extended Timeout' `
            -SettingKey 'CloudExtendedTimeout' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESampleSubmission
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Automatic Sample Submission' `
            -SettingKey 'SampleSubmission' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEBehaviorMonitoring
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Behavior Monitoring' `
            -SettingKey 'BehaviorMonitoring' -IsApplicableToSSM $true
    }
    
    $results += Test-MDENetworkProtection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Network Protection' `
            -SettingKey 'NetworkProtection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDENetworkProtectionWindowsServer
    $results += Test-MDEDatagramProcessingWindowsServer
    
    $results += Test-MDEAttackSurfaceReduction
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Attack Surface Reduction Rules' `
            -SettingKey 'AttackSurfaceReduction' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEThreatDefaultActions
    $results += Test-MDETamperProtection
    
    # Exclusion visibility tests - NOT applicable to Security Settings Management
    $results += Test-MDEExclusionVisibilityLocalAdmins
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Exclusion Visibility (Local Admins)' `
            -SettingKey 'HideExclusionsFromLocalAdmins' -IsApplicableToSSM $false
    }
    
    $results += Test-MDEExclusionVisibilityLocalUsers
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Exclusion Visibility (Local Users)' `
            -SettingKey 'HideExclusionsFromLocalUsers' -IsApplicableToSSM $false
    }
    
    # Edge SmartScreen tests - NOT applicable to Security Settings Management
    # These are Edge browser policies, not Windows Defender policies
    $results += Test-MDESmartScreen
    $results += Test-MDESmartScreenPUA
    $results += Test-MDESmartScreenPromptOverride
    $results += Test-MDESmartScreenDownloadOverride
    $results += Test-MDESmartScreenDomainExclusions
    $results += Test-MDESmartScreenAppRepExclusions
    
    $results += Test-MDEDisableCatchupQuickScan
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Catchup Quick Scan' `
            -SettingKey 'CatchupQuickScan' -IsApplicableToSSM $true
    }
    
    $results += Test-MDERealTimeScanDirection
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Real Time Scan Direction' `
            -SettingKey 'RealTimeScanDirection' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESignatureUpdateFallbackOrder
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Signature Update Fallback Order' `
            -SettingKey 'SignatureFallbackOrder' -IsApplicableToSSM $true
    }
    
    $results += Test-MDESignatureUpdateInterval
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Signature Update Interval' `
            -SettingKey 'SignatureUpdateInterval' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEDisableLocalAdminMerge
    if ($IncludePolicyVerification) {
        $results += Test-MDEPolicyRegistryVerification -ParentTestName 'Disable Local Admin Merge' `
            -SettingKey 'DisableLocalAdminMerge' -IsApplicableToSSM $true
    }
    
    $results += Test-MDEFileHashComputation
    
    if ($IncludeOnboarding) {
        $results += Test-MDEOnboardingStatus
    }
    
    Write-Verbose "MDE configuration validation completed."
    
    return $results
}

function Get-MDEValidationReport {
    <#
    .SYNOPSIS
        Generates a formatted MDE validation report.
    
    .DESCRIPTION
        Runs all MDE configuration validation tests and generates a report
        in the specified format.
    
    .PARAMETER OutputFormat
        The format of the output report. Valid values are 'Console', 'HTML', or 'Object'.
        Default is 'Console'.
    
    .PARAMETER OutputPath
        The path to save the HTML report. Only used when OutputFormat is 'HTML'.
    
    .PARAMETER IncludeOnboarding
        Include MDE onboarding status check (requires elevated privileges).
    
    .PARAMETER IncludePolicyVerification
        Include policy registry verification sub-tests. These sub-tests verify that
        settings returned by Get-MpPreference match the corresponding registry/policy
        entries based on the device's management type (Intune vs Security Settings Management).
    
    .EXAMPLE
        Get-MDEValidationReport
        
        Displays a console-formatted validation report.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat HTML -OutputPath "C:\Reports\MDEReport.html"
        
        Generates an HTML report and saves it to the specified path.
    
    .EXAMPLE
        Get-MDEValidationReport -OutputFormat Object
        
        Returns validation results as PowerShell objects.
    
    .EXAMPLE
        Get-MDEValidationReport -IncludePolicyVerification
        
        Displays a validation report with policy registry verification sub-tests.
    
    .OUTPUTS
        Console output, HTML file, or array of PSCustomObjects depending on OutputFormat.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Console', 'HTML', 'Object')]
        [string]$OutputFormat = 'Console',
        
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [switch]$IncludeOnboarding,
        
        [Parameter()]
        [switch]$IncludePolicyVerification
    )
    
    # Run all validation tests
    $results = Test-MDEConfiguration -IncludeOnboarding:$IncludeOnboarding -IncludePolicyVerification:$IncludePolicyVerification
    
    # Get OS information for the report header
    $osInfo = Get-MDEOperatingSystemInfo
    
    # Get management status for the report header
    $managedByStatus = Get-MDESecuritySettingsManagementStatus
    
    switch ($OutputFormat) {
        'Object' {
            return $results
        }
        
        'Console' {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  MDE Configuration Validation Report" -ForegroundColor Cyan
            Write-Host "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
            Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
            Write-Host "  OS: $osInfo" -ForegroundColor Cyan
            Write-Host "  Managed By: $managedByStatus" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
            
            foreach ($result in $results) {
                $statusColor = switch ($result.Status) {
                    'Pass' { 'Green' }
                    'Fail' { 'Red' }
                    'Warning' { 'Yellow' }
                    'Info' { 'Cyan' }
                    'NotApplicable' { 'Gray' }
                    default { 'White' }
                }
                
                $statusSymbol = switch ($result.Status) {
                    'Pass' { '[PASS]' }
                    'Fail' { '[FAIL]' }
                    'Warning' { '[WARN]' }
                    'Info' { '[INFO]' }
                    'NotApplicable' { '[N/A]' }
                    default { '[???]' }
                }
                
                Write-Host "$statusSymbol " -ForegroundColor $statusColor -NoNewline
                Write-Host "$($result.TestName)" -ForegroundColor White
                Write-Host "         $($result.Message)" -ForegroundColor Gray
                
                if ($result.Recommendation) {
                    Write-Host "         Recommendation: $($result.Recommendation)" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            
            # Summary
            $passCount = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
            $failCount = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
            $warnCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
            $totalCount = @($results).Count
            
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  Summary: $passCount/$totalCount Passed" -ForegroundColor $(if ($failCount -eq 0) { 'Green' } else { 'Yellow' })
            Write-Host "  Passed: $passCount | Failed: $failCount | Warnings: $warnCount" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
        }
        
        'HTML' {
            if ([string]::IsNullOrEmpty($OutputPath)) {
                $tempDir = if ($env:TEMP) { $env:TEMP } elseif ($env:TMPDIR) { $env:TMPDIR } else { '/tmp' }
                $OutputPath = Join-Path $tempDir "MDEValidationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            }
            
            $passCount = @($results | Where-Object { $_.Status -eq 'Pass' }).Count
            $failCount = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
            $warnCount = @($results | Where-Object { $_.Status -eq 'Warning' }).Count
            $totalCount = @($results).Count
            
            $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MDE Configuration Validation Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #0078d4;
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
        }
        .meta {
            color: #666;
            margin-bottom: 20px;
        }
        .summary {
            display: flex;
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            flex: 1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card.pass { background-color: #dff6dd; color: #107c10; }
        .summary-card.fail { background-color: #fde7e9; color: #d13438; }
        .summary-card.warn { background-color: #fff4ce; color: #797673; }
        .summary-card h2 { margin: 0; font-size: 2em; }
        .summary-card p { margin: 5px 0 0 0; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #0078d4;
            color: white;
        }
        tr:hover { background-color: #f5f5f5; }
        .status {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .status.pass { background-color: #dff6dd; color: #107c10; }
        .status.fail { background-color: #fde7e9; color: #d13438; }
        .status.warning { background-color: #fff4ce; color: #797673; }
        .status.info { background-color: #cce4f6; color: #0078d4; }
        .recommendation {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>MDE Configuration Validation Report</h1>
        <div class="meta">
            <p><strong>Computer:</strong> $(ConvertTo-HtmlEncodedString $env:COMPUTERNAME)</p>
            <p><strong>OS:</strong> $(ConvertTo-HtmlEncodedString $osInfo)</p>
            <p><strong>Managed By:</strong> $(ConvertTo-HtmlEncodedString $managedByStatus)</p>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <div class="summary">
            <div class="summary-card pass">
                <h2>$passCount</h2>
                <p>Passed</p>
            </div>
            <div class="summary-card fail">
                <h2>$failCount</h2>
                <p>Failed</p>
            </div>
            <div class="summary-card warn">
                <h2>$warnCount</h2>
                <p>Warnings</p>
            </div>
        </div>
        
        <table>
            <tr>
                <th>Test</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
            
            foreach ($result in $results) {
                $statusClass = $result.Status.ToLower()
                $encodedTestName = ConvertTo-HtmlEncodedString $result.TestName
                $encodedMessage = ConvertTo-HtmlEncodedString $result.Message
                $encodedRecommendation = ConvertTo-HtmlEncodedString $result.Recommendation
                $recommendation = if ($result.Recommendation) {
                    "<div class='recommendation'><strong>Recommendation:</strong> $encodedRecommendation</div>"
                } else { '' }
                
                $htmlContent += @"
            <tr>
                <td>$encodedTestName</td>
                <td><span class="status $statusClass">$($result.Status.ToUpper())</span></td>
                <td>$encodedMessage$recommendation</td>
            </tr>
"@
            }
            
            $htmlContent += @"
        </table>
    </div>
</body>
</html>
"@
            
            $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "HTML report saved to: $OutputPath" -ForegroundColor Green
            return $OutputPath
        }
    }
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Test-MDEConfiguration',
    'Get-MDEValidationReport',
    'Get-MDEOperatingSystemInfo',
    'Get-MDESecuritySettingsManagementStatus',
    'Get-MDEManagementType',
    'Get-MDEManagementTypeFallback',
    'Get-MDEPolicyRegistryPath',
    'Get-MDEPolicySettingConfig',
    'Test-MDEPolicyRegistryValue',
    'Test-MDEPolicyRegistryVerification',
    'Test-MDEServiceStatus',
    'Test-MDEPassiveMode',
    'Test-MDERealTimeProtection',
    'Test-MDECloudProtection',
    'Test-MDECloudBlockLevel',
    'Test-MDECloudExtendedTimeout',
    'Test-MDESampleSubmission',
    'Test-MDEBehaviorMonitoring',
    'Test-MDEOnboardingStatus',
    'Test-MDENetworkProtection',
    'Test-MDENetworkProtectionWindowsServer',
    'Test-MDEDatagramProcessingWindowsServer',
    'Test-MDEAttackSurfaceReduction',
    'Test-MDEThreatDefaultActions',
    'Test-MDETamperProtection',
    'Test-MDEExclusionVisibilityLocalAdmins',
    'Test-MDEExclusionVisibilityLocalUsers',
    'Test-MDESmartScreen',
    'Test-MDESmartScreenPUA',
    'Test-MDESmartScreenPromptOverride',
    'Test-MDESmartScreenDownloadOverride',
    'Test-MDESmartScreenDomainExclusions',
    'Test-MDESmartScreenAppRepExclusions',
    'Test-MDEDisableCatchupQuickScan',
    'Test-MDERealTimeScanDirection',
    'Test-MDESignatureUpdateFallbackOrder',
    'Test-MDESignatureUpdateInterval',
    'Test-MDEDisableLocalAdminMerge',
    'Test-MDEFileHashComputation'
)
