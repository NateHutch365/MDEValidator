function Test-MDESmartScreenDomainExclusions {
    <#
    .SYNOPSIS
        Tests if SmartScreen domain exclusions are configured.
    
    .DESCRIPTION
        Checks the SmartScreenAllowListDomains policy setting that configures domains
        for which Microsoft Defender SmartScreen won't trigger warnings. If domains
        are configured, this is a potential security risk as those domains bypass SmartScreen.
    
    .EXAMPLE
        Test-MDESmartScreenDomainExclusions
        
        Tests if SmartScreen domain exclusions are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains
        
        Domains are stored as numbered subkeys (1, 2, 3, etc.) with string values.
        If domains are configured, they should be reported as a warning since
        those domains bypass SmartScreen protection.
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen Domain Exclusions'
    Write-Verbose "Checking $testName..."
    
    try {
        $domains = @()
        $source = ''
        
        # Check Group Policy settings for domain exclusions
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenAllowListDomains'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                # Get all values from the registry key (domains are stored as numbered values)
                $regValues = Get-ItemProperty -Path $policy.Path -ErrorAction SilentlyContinue
                if ($null -ne $regValues) {
                    # Get all properties except PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
                    $domainValues = $regValues.PSObject.Properties | 
                        Where-Object { $_.Name -notmatch '^PS' } | 
                        ForEach-Object { $_.Value }
                    
                    if ($domainValues -and $domainValues.Count -gt 0) {
                        $domains = @($domainValues)
                        $source = $policy.Source
                        break
                    }
                }
            }
        }
        
        Write-Debug "SmartScreen domain exclusions count: $($domains.Count) (Source: $source)"
        
        # Determine status
        if ($domains.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "No SmartScreen domain exclusions are configured. SmartScreen protection applies to all domains."
        } else {
            $domainList = $domains -join ', '
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen domain exclusions are configured via Group Policy or Intune. The following domains bypass SmartScreen protection: $domainList" `
                -Recommendation "Review the configured domain exclusions to ensure they are necessary. Each excluded domain bypasses SmartScreen protection. Domains: $domainList"
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen domain exclusions: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}
