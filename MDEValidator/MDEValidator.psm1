#Requires -Version 5.1

# Dot-source all private functions first (helpers used by public functions)
$privateFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $privateFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import private function '$($file.FullName)': $_"
    }
}

# Dot-source all public functions
$publicFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $publicFunctions) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import public function '$($file.FullName)': $_"
    }
}

# Export only public functions (belt-and-suspenders with .psd1 FunctionsToExport)
Export-ModuleMember -Function $publicFunctions.BaseName