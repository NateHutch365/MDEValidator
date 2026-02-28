function Test-MDEExclusionVisibilityLocalAdmins {
    <#
    .SYNOPSIS
        Tests if local administrators can view exclusions.
    
    .DESCRIPTION
        Checks the HideExclusionsFromLocalAdmins setting that controls whether 
        exclusions are visible to local administrators. This setting can be 
        configured via Group Policy or Intune.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
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
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Exclusion Visibility (Local Admins)'
    Write-Verbose "Checking $testName..."
    
    try {
        $hideFromLocalAdmins = $null
        $source = ''
        
        # First, check Get-MpPreference for exclusion properties that indicate hidden status
        # When exclusions are hidden from local admins, the ExclusionExtension property returns
        # a string like "{N/A: Administrators are not allowed to view exclusions}"
        try {
            if ($null -eq $MpPreference) {
                $MpPreference = Get-MpPreference -ErrorAction Stop
            }
            
            # Check if ExclusionExtension contains the "not allowed to view" message
            # This is a reliable indicator that HideExclusionsFromLocalAdmins is enabled
            # The message format is: "{N/A: Administrators are not allowed to view exclusions}"
            $exclusionsHiddenMessage = 'Administrators are not allowed to view exclusions'
            if ($null -ne $MpPreference.ExclusionExtension) {
                # Handle both array and single string cases properly
                $exclusionExtensionValue = if ($MpPreference.ExclusionExtension -is [array]) {
                    $MpPreference.ExclusionExtension -join ' '
                } else {
                    [string]$MpPreference.ExclusionExtension
                }
                Write-Debug "ExclusionExtension value: $exclusionExtensionValue"
                if ($exclusionExtensionValue -match [regex]::Escape($exclusionsHiddenMessage)) {
                    $hideFromLocalAdmins = 1
                    $source = 'Get-MpPreference (exclusions hidden)'
                }
            }
            
            # Also check HideExclusionsFromLocalAdmins property directly
            if ($null -eq $hideFromLocalAdmins -and $null -ne $MpPreference.HideExclusionsFromLocalAdmins) {
                $hideFromLocalAdmins = if ($MpPreference.HideExclusionsFromLocalAdmins) { 1 } else { 0 }
                if ([string]::IsNullOrEmpty($source)) { $source = 'MpPreference' }
            }
        }
        catch {
            # Continue even if MpPreference fails - we may have registry values
        }
        
        Write-Debug "HideExclusionsFromLocalAdmins after MpPreference check: $hideFromLocalAdmins (Source: $source)"
        
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
        
        Write-Debug "Final HideExclusionsFromLocalAdmins: $hideFromLocalAdmins (Source: $source)"
        
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
