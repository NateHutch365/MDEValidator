function ConvertTo-HtmlEncodedString {
    <#
    .SYNOPSIS
        HTML-encodes a string to prevent XSS vulnerabilities.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InputString
    )
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return $InputString
    }
    
    return [System.Net.WebUtility]::HtmlEncode($InputString)
}
