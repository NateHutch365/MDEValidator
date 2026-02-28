function Test-MDEAutoExclusionsWindowsServer {
    <#
    .SYNOPSIS
        Tests if Auto Exclusions for Servers is enabled.
    
    .DESCRIPTION
        Checks if the DisableAutoExclusions setting is enabled for Windows Server 
        operating systems. Windows Server roles automatically add exclusions for their 
        components (like SQL Server, Exchange, etc.). Disabling auto exclusions improves 
        security by preventing these automatic exclusions and requiring explicit configuration.
        
        For non-Server operating systems (e.g., Windows 10/11 Professional, Enterprise), 
        this check returns NotApplicable as auto exclusions are primarily a Server concern.
    
    .PARAMETER MpPreference
        Optional. A pre-fetched MpPreference object from Get-MpPreference.
        If not provided, the function will call Get-MpPreference internally.
    
    .EXAMPLE
        Test-MDEAutoExclusionsWindowsServer
        
        Tests if Auto Exclusions is properly disabled for Windows Server.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        DisableAutoExclusions values (via Get-MpPreference):
        $true = Auto exclusions are disabled (recommended for security)
        $false or not set = Auto exclusions are enabled (roles add their own exclusions)
        
        This setting can be configured via:
        - Group Policy: Computer Configuration > Administrative Templates > Windows Components > 
          Microsoft Defender Antivirus > Exclusions > Turn off Auto Exclusions
        - Intune/MEM: Endpoint Security > Antivirus
        - PowerShell: Set-MpPreference -DisableAutoExclusions $true
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSObject]$MpPreference
    )
    
    $testName = 'Auto Exclusions for Servers (DisableAutoExclusions)'
    Write-Verbose "Checking $testName..."
    
    # Check if running on Windows Server
    if (-not (Test-IsWindowsServer)) {
        Write-ValidationResult -TestName $testName -Status 'NotApplicable' `
            -Message "This check only applies to Windows Server operating systems."
        return
    }
    
    try {
        if ($null -eq $MpPreference) {
            $MpPreference = Get-MpPreference -ErrorAction Stop
        }
        
        Write-Debug "DisableAutoExclusions: $($MpPreference.DisableAutoExclusions)"
        
        # DisableAutoExclusions: $true = Disabled (good for security), $false = Enabled (allows automatic exclusions)
        if ($MpPreference.DisableAutoExclusions -eq $true) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "Auto Exclusions for Servers is disabled. Server roles will not automatically add exclusions."
        } else {
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "Auto Exclusions for Servers is enabled. Server roles (SQL, Exchange, etc.) automatically add their own exclusions." `
                -Recommendation "Consider disabling Auto Exclusions via Intune or Group Policy and explicitly configure required exclusions for better security control. Set DisableAutoExclusions to `$true."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query Auto Exclusions setting: $_" `
            -Recommendation "Ensure Windows Defender is properly installed and configured, and that you have appropriate permissions."
    }
}
