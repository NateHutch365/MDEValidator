function Test-IsElevated {
    <#
    .SYNOPSIS
        Checks if the current PowerShell session is running with elevated privileges.
    #>
    [CmdletBinding()]
    param()
    
    # Only perform elevation check on Windows
    if ($IsWindows -or ([System.Environment]::OSVersion.Platform -eq 'Win32NT')) {
        try {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch {
            # If we can't determine elevation status, assume not elevated
            return $false
        }
    }
    
    # On non-Windows platforms, check if running as root
    if ($IsLinux -or $IsMacOS) {
        try {
            return (& id -u) -eq 0
        }
        catch {
            return $false
        }
    }
    
    return $false
}
