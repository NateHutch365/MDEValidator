#Requires -Modules Pester
<#
.SYNOPSIS
    Pester tests for post-publish verification script (VER-01).

.DESCRIPTION
    Structural and behavioral tests for scripts/Test-PSGalleryPackage.ps1.
    Verifies script contract, parameters, and retry logic via AST analysis
    and content pattern matching. No live PSGallery calls are made.
#>

BeforeAll {
    $repoRoot            = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:scriptPath   = Join-Path $repoRoot 'scripts\Test-PSGalleryPackage.ps1'
}

Describe 'Post-Publish Verification Script — VER-01: File Contract' {
    It 'Script exists at scripts/Test-PSGalleryPackage.ps1' {
        Test-Path $script:scriptPath | Should -BeTrue
    }
    It 'Script parses as valid PowerShell without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $script:scriptPath, [ref]$null, [ref]$errors
        )
        $errors | Should -BeNullOrEmpty
    }
}

Describe 'Post-Publish Verification Script — VER-01: Parameters' {
    BeforeAll {
        $ast             = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:scriptPath, [ref]$null, [ref]$null
        )
        $script:params   = $ast.ParamBlock.Parameters
    }

    It 'Has a -Version parameter' {
        $p = $script:params | Where-Object { $_.Name.VariablePath.UserPath -eq 'Version' }
        $p | Should -Not -BeNullOrEmpty
    }
    It 'Has a -MaxWaitSeconds parameter defaulting to 600' {
        $p = $script:params | Where-Object { $_.Name.VariablePath.UserPath -eq 'MaxWaitSeconds' }
        $p | Should -Not -BeNullOrEmpty
        $p.DefaultValue.Value | Should -Be 600
    }
    It 'Has a -PollingIntervalSeconds parameter defaulting to 30' {
        $p = $script:params | Where-Object { $_.Name.VariablePath.UserPath -eq 'PollingIntervalSeconds' }
        $p | Should -Not -BeNullOrEmpty
        $p.DefaultValue.Value | Should -Be 30
    }
}

Describe 'Post-Publish Verification Script — VER-01: Retry and Verification Logic' {
    BeforeAll {
        $script:content = Get-Content $script:scriptPath -Raw
    }

    It 'Contains a while loop for retry' {
        $script:content | Should -Match 'while\s*\('
    }
    It 'Uses Start-Sleep for polling delay' {
        $script:content | Should -Match 'Start-Sleep'
    }
    It 'Uses Find-Module with -RequiredVersion for discovery' {
        $script:content | Should -Match 'Find-Module.*-RequiredVersion'
    }
    It 'Uses Save-Module to download the package' {
        $script:content | Should -Match 'Save-Module.*-Name'
    }
    It 'Uses Import-Module to load the saved package' {
        $script:content | Should -Match 'Import-Module'
    }
    It 'Uses Get-Command -Module to verify exported commands' {
        $script:content | Should -Match 'Get-Command.*-Module'
    }
    It 'Cleans up temp directory with Remove-Item -Recurse' {
        $script:content | Should -Match 'Remove-Item.*-Recurse'
    }
}
