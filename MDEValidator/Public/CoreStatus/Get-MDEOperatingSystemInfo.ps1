function Get-MDEOperatingSystemInfo {
    <#
    .SYNOPSIS
        Gets the operating system version and build information.
    
    .DESCRIPTION
        Retrieves detailed information about the Windows operating system including
        the product name, version (e.g., 22H2, 25H2), and build number.
    
    .EXAMPLE
        Get-MDEOperatingSystemInfo
        
        Returns a string like "Windows 10 Professional Version 22H2 19045.6575"
    
    .OUTPUTS
        String containing the OS name, version, and build information.
    #>
    [CmdletBinding()]
    param()
    
    Write-Verbose "Retrieving operating system information..."
    
    try {
        $osRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        
        if (-not (Test-Path $osRegPath)) {
            return "Unknown OS"
        }
        
        $osInfo = Get-ItemProperty -Path $osRegPath -ErrorAction Stop
        
        $productName = $osInfo.ProductName
        $displayVersion = $osInfo.DisplayVersion
        $currentBuild = $osInfo.CurrentBuild
        $ubr = $osInfo.UBR
        
        Write-Debug "ProductName=$productName, DisplayVersion=$displayVersion, CurrentBuild=$currentBuild, UBR=$ubr"
        
        $fullBuild = if ($null -ne $currentBuild -and $null -ne $ubr) {
            "$currentBuild.$ubr"
        } elseif ($null -ne $currentBuild) {
            $currentBuild
        } else {
            ""
        }
        
        $osString = $productName
        
        if (-not [string]::IsNullOrEmpty($displayVersion)) {
            $osString += " Version $displayVersion"
        }
        
        if (-not [string]::IsNullOrEmpty($fullBuild)) {
            $osString += " $fullBuild"
        }
        
        Write-Verbose "OS: $osString"
        return $osString
    }
    catch {
        Write-Verbose "Error retrieving OS info: $_"
        return "Unknown OS"
    }
}
