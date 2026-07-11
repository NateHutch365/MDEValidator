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
        [string]$Recommendation = '',
        
        [Parameter()]
        [string]$Category = '',
        
        [Parameter()]
        [string]$Expected = '',
        
        [Parameter()]
        [string]$Actual = ''
    )
    
    [PSCustomObject]@{
        TestName = $TestName
        Category = $Category
        Status = $Status
        Message = $Message
        Expected = $Expected
        Actual = $Actual
        Recommendation = $Recommendation
        Timestamp = Get-Date
    }
}