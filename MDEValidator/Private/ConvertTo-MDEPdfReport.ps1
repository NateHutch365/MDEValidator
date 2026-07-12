function ConvertTo-MDEPdfReport {
    <#
    .SYNOPSIS
        Converts an HTML report file to PDF using Microsoft Edge headless printing.

    .DESCRIPTION
        Takes the path to a generated HTML report and produces a PDF file using
        Microsoft Edge's headless --print-to-pdf capability. Edge is pre-installed
        on Windows 10/11 systems. If Edge is not found, an informative error is thrown.

    .PARAMETER HtmlPath
        The full path to the HTML file to convert to PDF.

    .PARAMETER OutputPath
        The full path for the output PDF file.

    .OUTPUTS
        [string] The path to the generated PDF file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$HtmlPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # Locate Microsoft Edge executable
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:LOCALAPPDATA}\Microsoft\Edge\Application\msedge.exe"
    )

    $edgeExe = $null
    foreach ($path in $edgePaths) {
        if (Test-Path -Path $path) {
            $edgeExe = $path
            break
        }
    }

    if (-not $edgeExe) {
        throw "Microsoft Edge was not found on this system. PDF export requires Microsoft Edge. " +
              "Please install Edge or use -OutputFormat HTML and print to PDF manually from a browser."
    }

    # Ensure the HTML file exists
    if (-not (Test-Path -Path $HtmlPath)) {
        throw "HTML source file not found: $HtmlPath"
    }

    # Ensure output directory exists
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrEmpty($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
        try {
            New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
        }
        catch {
            throw "Failed to create output directory: $outputDirectory. Error: $_"
        }
    }

    # Convert file path to file:// URI for Edge
    $htmlUri = "file:///$($HtmlPath -replace '\\', '/')"

    # Invoke Edge headless print-to-pdf
    $arguments = @(
        '--headless',
        '--disable-gpu',
        "--print-to-pdf=`"$OutputPath`"",
        '--no-pdf-header-footer',
        $htmlUri
    )

    try {
        $process = Start-Process -FilePath $edgeExe -ArgumentList $arguments -Wait -PassThru -NoNewWindow -ErrorAction Stop

        if ($process.ExitCode -ne 0) {
            throw "Edge headless printing failed with exit code $($process.ExitCode)."
        }

        if (-not (Test-Path -Path $OutputPath)) {
            throw "PDF file was not created. Edge may have encountered an error rendering the HTML."
        }

        return $OutputPath
    }
    catch {
        if ($_.Exception.Message -like '*Edge headless*' -or $_.Exception.Message -like '*PDF file was not created*') {
            throw $_
        }
        throw "Failed to invoke Microsoft Edge for PDF conversion. Error: $_"
    }
}
