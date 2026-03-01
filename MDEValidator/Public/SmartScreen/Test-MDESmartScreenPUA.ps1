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
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "SmartScreenPuaEnabled: $smartScreenPuaEnabled (Source: $source)"
        
        # Determine status
        if ($null -eq $smartScreenPuaEnabled) {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen PUA protection is not configured." `
                -Recommendation "Configure 'Configure Microsoft Defender SmartScreen to block potentially unwanted apps' via Group Policy or Intune. Set SmartScreenPuaEnabled to 1."
        } elseif ($smartScreenPuaEnabled -eq 1) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "SmartScreen PUA protection is enabled via Group Policy or Intune. Potentially unwanted apps will be blocked."
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
