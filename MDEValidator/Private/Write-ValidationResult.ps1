function Write-ValidationResult {
    <#
    .SYNOPSIS
        Formats and outputs a validation result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TestName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'NotApplicable')]
        [string]$Status,
        
        [Parameter()]
        [string]$Message = '',
        
        [Parameter()]
        [string]$Recommendation = ''
    )
    
    [PSCustomObject]@{
        TestName = $TestName
        Status = $Status
        Message = $Message
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
}
