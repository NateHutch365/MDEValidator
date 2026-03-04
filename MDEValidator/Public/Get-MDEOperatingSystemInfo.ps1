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
    
    try {
        # Get OS information from registry
        $osRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        
        if (-not (Test-Path $osRegPath)) {
            return "Unknown OS"
        }
        
        $osInfo = Get-ItemProperty -Path $osRegPath -ErrorAction Stop
        
        # Get product name (e.g., "Windows 10 Pro", "Windows 11 Enterprise", "Windows Server 2022")
        $productName = $osInfo.ProductName
        
        # Get display version (e.g., "22H2", "25H2")
        $displayVersion = $osInfo.DisplayVersion
        
        # Get current build number and UBR (Update Build Revision)
        $currentBuild = $osInfo.CurrentBuild
        $ubr = $osInfo.UBR
        
        # Construct the full build string
        $fullBuild = if ($null -ne $currentBuild -and $null -ne $ubr) {
            "$currentBuild.$ubr"
        } elseif ($null -ne $currentBuild) {
            $currentBuild
        } else {
            ""
        }
        
        # Build the output string
        $osString = $productName
        
        if (-not [string]::IsNullOrEmpty($displayVersion)) {
            $osString += " Version $displayVersion"
        }
        
        if (-not [string]::IsNullOrEmpty($fullBuild)) {
            $osString += " $fullBuild"
        }
        
        return $osString
    }
    catch {
        return "Unknown OS"
    }
}