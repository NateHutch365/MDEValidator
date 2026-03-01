function Test-MDEDeviceTags {
    <#
    .SYNOPSIS
        Lists any locally configured MDE device tags on the device.
    
    .DESCRIPTION
        Checks the Windows registry for Microsoft Defender for Endpoint (MDE) device tags
        that have been locally configured on the device. Device tags are used for grouping
        and organizing devices in the Microsoft 365 Defender portal.
        
        Registry location: HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging
        Value name: Group (REG_SZ)
        
        Note: Only locally added tags (set via Group Policy, Intune, or registry) are visible
        here. Tags assigned directly in the Microsoft Defender XDR portal are not written
        back to the device registry and will not appear in this check.
    
    .EXAMPLE
        Test-MDEDeviceTags
        
        Lists the locally configured MDE device tags on the device.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        This is an informational check that displays any locally configured device tags.
        Device tags are typically set via Group Policy, Intune, or the MDE onboarding script.
        Tags assigned via the Defender XDR portal are not reflected in this check.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'MDE Device Tags'
    Write-Verbose "Checking $testName..."
    
    try {
        $deviceTagPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'
        
        if (Test-Path $deviceTagPath) {
            $deviceTagReg = Get-ItemProperty -Path $deviceTagPath -ErrorAction SilentlyContinue
            $tagValue = $deviceTagReg.Group
            
            Write-Debug "Device tag value: $tagValue"
            
            if (-not [string]::IsNullOrWhiteSpace($tagValue)) {
                Write-ValidationResult -TestName $testName -Status 'Info' `
                    -Message "Locally configured MDE device tag: $tagValue. Note: Tags assigned via the Defender XDR portal are not reflected here."
            } else {
                Write-ValidationResult -TestName $testName -Status 'Info' `
                    -Message "No locally configured MDE device tags found. Note: Tags assigned via the Defender XDR portal are not reflected here."
            }
        } else {
            Write-Debug "Device tag registry path not found: $deviceTagPath"
            Write-ValidationResult -TestName $testName -Status 'Info' `
                -Message "No locally configured MDE device tags found. Note: Tags assigned via the Defender XDR portal are not reflected here."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Info' `
            -Message "Unable to query MDE device tags: $_"
    }
}
