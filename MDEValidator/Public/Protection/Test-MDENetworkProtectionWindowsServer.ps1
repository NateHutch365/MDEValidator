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
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "AllowNetworkProtectionOnWinServer: $allowOnWinServer, AllowNetworkProtectionDownLevel: $allowDownLevel"
        
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
