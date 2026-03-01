function Test-MDESmartScreenAppRepExclusions {
    <#
    .SYNOPSIS
        Tests if SmartScreen AppRep file type exclusions are configured.
    
    .DESCRIPTION
        Checks the ExemptSmartScreenDownloadWarnings policy setting that configures
        domains and file types for which Microsoft Defender SmartScreen won't trigger
        application reputation (AppRep) warnings. If exclusions are configured, this is
        a potential security risk as those file types on those domains bypass SmartScreen.
    
    .EXAMPLE
        Test-MDESmartScreenAppRepExclusions
        
        Tests if SmartScreen AppRep exclusions are configured.
    
    .OUTPUTS
        PSCustomObject with validation results.
    
    .NOTES
        Registry location:
        - HKLM:\SOFTWARE\Policies\Microsoft\Edge (ExemptSmartScreenDownloadWarnings property)
        - HKCU:\SOFTWARE\Policies\Microsoft\Edge (ExemptSmartScreenDownloadWarnings property)
        
        The ExemptSmartScreenDownloadWarnings policy is stored as a single REG_SZ value
        containing a JSON array of exclusion objects.
        Format: [{"file_extension": "msi", "domains": ["domain1.com"]}, {"file_extension": "exe", "domains": ["domain2.com", "*"]}]
        
        If exclusions are configured, they should be reported as a warning since
        those file types on those domains bypass SmartScreen AppRep protection.
        
        Output format: domainname1.com: msi, exe | domainname2.com: xlsx | *: vbe
    #>
    [CmdletBinding()]
    param()
    
    $testName = 'Edge SmartScreen AppRep Exclusions'
    Write-Verbose "Checking $testName..."
    
    try {
        $exclusions = @{}  # Hashtable: domain -> list of file extensions
        $source = ''
        
        # Check Group Policy settings for AppRep exclusions
        # ExemptSmartScreenDownloadWarnings is a single REG_SZ value under the Edge policy key
        $policyPaths = @(
            @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ExemptSmartScreenDownloadWarnings'; Source = 'Group Policy (Machine)' },
            @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ExemptSmartScreenDownloadWarnings'; Source = 'Group Policy (User)' }
        )
        
        foreach ($policy in $policyPaths) {
            if (Test-Path $policy.Path) {
                $regValue = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
                if ($null -ne $regValue -and $null -ne $regValue.($policy.Name)) {
                    $jsonValue = $regValue.($policy.Name)
                    
                    try {
                        # Parse the JSON array of exclusion objects
                        $parsedArray = $jsonValue | ConvertFrom-Json
                        
                        foreach ($parsed in $parsedArray) {
                            # Extract file extension
                            $fileExt = $parsed.file_extension
                            
                            # Extract domains (the policy uses 'domains' not 'url_patterns')
                            # Ensure domains is an array (ConvertFrom-Json returns a string for single values)
                            $domains = $parsed.domains
                            if ($null -eq $domains) {
                                $domains = @('*')
                            } else {
                                $domains = @($domains)
                            }
                            
                            foreach ($domain in $domains) {
                                # Normalize the domain (remove leading *. if present)
                                $normalizedDomain = $domain -replace '^\*\.', ''
                                if ([string]::IsNullOrEmpty($normalizedDomain)) {
                                    $normalizedDomain = '*'
                                }
                                
                                if (-not $exclusions.ContainsKey($normalizedDomain)) {
                                    $exclusions[$normalizedDomain] = @()
                                }
                                if ($fileExt -and $fileExt -notin $exclusions[$normalizedDomain]) {
                                    $exclusions[$normalizedDomain] += $fileExt
                                }
                            }
                        }
                        
                        if ($exclusions.Count -gt 0) {
                            $source = $policy.Source
                            break
                        }
                    }
                    catch {
                        # JSON parsing failed - log a warning and continue to next policy path
                        Write-Verbose "Failed to parse ExemptSmartScreenDownloadWarnings JSON from $($policy.Source): $_"
                        continue
                    }
                }
            }
        }
        
        Write-Debug "SmartScreen AppRep exclusions count: $($exclusions.Count) (Source: $source)"
        
        # Determine status
        if ($exclusions.Count -eq 0) {
            Write-ValidationResult -TestName $testName -Status 'Pass' `
                -Message "No SmartScreen AppRep exclusions are configured. SmartScreen AppRep protection applies to all file types on all domains."
        } else {
            # Format: domainname1.com: msi, exe | domainname2.com: xlsx | *: vbe
            $exclusionList = ($exclusions.GetEnumerator() | Sort-Object Name | ForEach-Object {
                "$($_.Key): $($_.Value -join ', ')"
            }) -join ' | '
            
            Write-ValidationResult -TestName $testName -Status 'Warning' `
                -Message "SmartScreen AppRep exclusions are configured via Group Policy or Intune. The following file types on these domains bypass SmartScreen AppRep protection: $exclusionList" `
                -Recommendation "Review the configured AppRep exclusions to ensure they are necessary. Each exclusion bypasses SmartScreen application reputation warnings for the specified file types."
        }
    }
    catch {
        Write-ValidationResult -TestName $testName -Status 'Fail' `
            -Message "Unable to query SmartScreen AppRep exclusions: $_" `
            -Recommendation "Ensure you have permissions to read Edge policy registry settings."
    }
}
