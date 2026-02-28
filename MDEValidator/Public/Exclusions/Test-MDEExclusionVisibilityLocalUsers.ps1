function Test-MDEExclusionVisibilityLocalUsers {
    <#
    .SYNOPSIS
        Tests if local users can view exclusions.
    
    .DESCRIPTION
        Checks the HideExclusionsFromLocalUsers setting that controls whether 
        exclusions are visible to local users. This setting can be configured 
        via Group Policy or Intune.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
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
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Exclusion Visibility (Local Users)'
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "HideExclusionsFromLocalUsers after registry check: $hideFromLocalUsers (Source: $source)"
        
        # Also try Get-MpPreference for these settings (if available)
        if ($null -eq $hideFromLocalUsers) {
            try {
                if ($null -eq $MpPreference) {
                    $MpPreference = Get-MpPreference -ErrorAction Stop
                }
                if ($null -ne $MpPreference.HideExclusionsFromLocalUsers) {
                    $hideFromLocalUsers = if ($MpPreference.HideExclusionsFromLocalUsers) { 1 } else { 0 }
                    if ([string]::IsNullOrEmpty($source)) { $source = 'MpPreference' }
                }
            }
            catch {
                # Continue even if MpPreference fails - we may have registry values
            }
        }
        
        Write-Debug "Final HideExclusionsFromLocalUsers: $hideFromLocalUsers (Source: $source)"
        
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
