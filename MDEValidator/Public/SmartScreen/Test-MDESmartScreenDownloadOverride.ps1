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
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "PreventSmartScreenPromptOverrideForFiles: $preventOverride (Source: $source)"
        
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
