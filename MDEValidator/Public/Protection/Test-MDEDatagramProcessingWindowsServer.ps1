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
    Write-Verbose "Checking $testName..."
    
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
        
        Write-Debug "AllowDatagramProcessingOnWinServer: $allowDatagramProcessing"
        
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
