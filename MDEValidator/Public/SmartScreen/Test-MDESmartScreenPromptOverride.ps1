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
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "PreventSmartScreenPromptOverride: $preventOverride (Source: $source)"
        
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
