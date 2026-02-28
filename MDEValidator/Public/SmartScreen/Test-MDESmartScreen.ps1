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
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "SmartScreenEnabled: $smartScreenEnabled (Source: $smartScreenSource)"
        Write-Debug "DefenderSmartScreen: $defenderSmartScreen"
        
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
