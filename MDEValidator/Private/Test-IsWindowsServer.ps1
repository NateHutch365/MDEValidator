function Test-IsWindowsServer {
    <#
    .SYNOPSIS
        Checks if the current operating system is Windows Server.
    .NOTES
        Uses the InstallationType registry value which is more reliable than pattern matching.
        InstallationType values: "Client" for workstation, "Server" or "Server Core" for servers.
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get OS information from registry
        $osRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        
        if (-not (Test-Path $osRegPath)) {
            return $false
        }
        
        $osInfo = Get-ItemProperty -Path $osRegPath -ErrorAction Stop
        
        # Check InstallationType - more reliable than pattern matching ProductName
        # InstallationType is "Client" for workstation, "Server" or "Server Core" for servers
        if ($null -ne $osInfo.InstallationType) {
            if ($osInfo.InstallationType -eq 'Server' -or $osInfo.InstallationType -eq 'Server Core') {
                return $true
            }
            return $false
        }
        
        # Fallback: Check ProductName if InstallationType is not available
        # Use specific "Windows Server" pattern to avoid false positives like "Workstation"
        $productName = $osInfo.ProductName
        if ($productName -match '^Windows Server') {
            return $true
        }
        
        return $false
    }
    catch {
        return $false
    }
}
