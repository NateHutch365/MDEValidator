function Test-MDEDisableLocalAdminMerge {
    <#
    .SYNOPSIS
        Tests if Disable Local Admin Merge is configured.
    
    .DESCRIPTION
        Checks the DisableLocalAdminMerge setting that controls whether local
        administrators can add exclusions. When enabled (set to 1), local
        administrator exclusions are ignored, improving security.
        
        Note: This setting cannot be checked via Get-MpPreference. On Intune-only and
        Configuration Manager-only devices, when HideExclusionsFromLocalAdmins is enabled,
        the registry location may be inaccessible. In such cases, if Tamper Protection
        for Exclusions is enabled (TPExclusions=1), DisableLocalAdminMerge is considered
        enabled because Tamper Protection for Exclusions can only be enabled when
        DisableLocalAdminMerge is enforced.
    
    .EXAMPLE
        Test-MDEDisableLocalAdminMerge
        
        Tests the Disable Local Admin Merge configuration.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry locations (based on management type):
        - Intune: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager\DisableLocalAdminMerge
        - GPO/SCCM/SSM: HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\DisableLocalAdminMerge
        
        DisableLocalAdminMerge values:
        1 = Local admin merge is disabled (recommended) - Pass
        0 or not configured = Local admin merge is enabled - Warning
        
        When DisableLocalAdminMerge is enabled, exclusions added by local 
        administrators are ignored, preventing potential security bypasses.
        
        Special logic for Intune-only and Configuration Manager-only devices:
        If Tamper Protection for Exclusions (TPExclusions=1) is enabled, DisableLocalAdminMerge
        is inferred to be enabled because Tamper Protection for Exclusions requires
        DisableLocalAdminMerge to be enforced.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Disable Local Admin Merge'
    Write-Verbose "Checking $testName..."
    
    try {
        # Determine the management type to know which registry path to check
        $managementType = Get-MDEManagementType
        $config = Get-MDEPolicySettingConfig -SettingKey 'DisableLocalAdminMerge' -ManagementType $managementType
        
        Write-Debug "ManagementType: $managementType"
        
        $disableLocalAdminMerge = $null
        $source = ''
        
        # Check the appropriate registry path based on management type
        if ($null -ne $config) {
            if (Test-Path $config.Path) {
                $regValue = Get-ItemProperty -Path $config.Path -Name $config.SettingName -ErrorAction SilentlyContinue
                if ($null -ne $regValue -and $null -ne $regValue.($config.SettingName)) {
                    # Registry values are already integers, but normalize boolean to integer for consistency
                    $disableLocalAdminMerge = if ($regValue.($config.SettingName) -is [bool]) {
                        if ($regValue.($config.SettingName)) { 1 } else { 0 }
                    } else {
                        $regValue.($config.SettingName)
                    }
                    $source = "Registry ($managementType)"
                }
            }
        }
        
        Write-Debug "DisableLocalAdminMerge (registry): $disableLocalAdminMerge"
        
        # If registry check didn't find a value, check if we can infer the setting
        # from Tamper Protection for Exclusions on Intune-only or ConfigMgr-only devices
        if ($null -eq $disableLocalAdminMerge) {
            # Check if device is managed for exclusions (Intune-only or ConfigMgr-only)
            $managedDefenderInfo = Get-MDEManagedDefenderProductType
            
            if ($managedDefenderInfo.IsManagedForExclusions) {
                # Check if Tamper Protection for Exclusions is enabled
                $featuresPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
                $tpExclusions = $null
                
                if (Test-Path $featuresPath) {
                    $features = Get-ItemProperty -Path $featuresPath -ErrorAction SilentlyContinue
                    if ($null -ne $features -and $features.PSObject.Properties['TPExclusions']) {
                        $tpExclusions = $features.TPExclusions
                    }
                }
                
                Write-Debug "TPExclusions: $tpExclusions"
                
                if ($tpExclusions -eq 1) {
                    # TPExclusions can only be enabled if DisableLocalAdminMerge is enforced
                    $disableLocalAdminMerge = 1
                    $source = "Inferred from Tamper Protection for Exclusions ($($managedDefenderInfo.ManagementType))"
                }
            }
        }
        
        Write-Debug "DisableLocalAdminMerge (final): $disableLocalAdminMerge"
        
        # Interpret the results
        $sourceInfo = if ([string]::IsNullOrEmpty($source)) { '' } else { " (via $source)" }
        
        if ($null -eq $disableLocalAdminMerge) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Disable Local Admin Merge is not configured. Local administrator exclusions may be applied." `
                -Recommendation "Configure Disable Local Admin Merge via Group Policy or Intune to prevent local administrators from adding exclusions. Set DisableLocalAdminMerge to 1."
        }
        elseif ($disableLocalAdminMerge -eq 1) {
            # Pass: Disabled (local admin merge is disabled = exclusions are ignored)
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Disable Local Admin Merge is enabled. Local administrator exclusions are ignored.$sourceInfo"
        }
        else {
            # Warning: Enabled (local admin merge is enabled = exclusions are applied)
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Disable Local Admin Merge is disabled. Local administrator exclusions may be applied.$sourceInfo" `
                -Recommendation "Configure Disable Local Admin Merge via Group Policy or Intune to prevent local administrators from adding exclusions. Set DisableLocalAdminMerge to 1."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Disable Local Admin Merge setting: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured, and that you have appropriate permissions to read registry settings."
    }
}
