@{
    Severity    = @('Error', 'Warning')
    ExcludeRules = @(
        # Intentional: Get-MDEValidationReport uses Write-Host for color-coded console output
        # (Pass=Green, Fail=Red, Warning=Yellow). Converting to Write-Information breaks colored output.
        'PSAvoidUsingWriteHost',

        # Intentional: Function names are established public API locked in Phase 1
        # (Test-MDEDeviceTags, Test-MDEExclusionVisibilityLocalAdmins, etc.) — renaming breaks callers.
        'PSUseSingularNouns'
    )
}
