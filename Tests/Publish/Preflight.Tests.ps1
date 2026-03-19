#Requires -Modules Pester
<#
.SYNOPSIS
    Pester tests for publish preflight logic (REL-02, REL-03, REL-04, REL-05).

.DESCRIPTION
    Unit and integration tests verifying the PowerShell logic used in the
    publish.yml preflight steps. No live PSGallery calls. REL-05 tests
    copy the module to a temp directory to simulate the packaged layout.
#>

BeforeAll {
    $script:repoRoot     = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    $script:manifestPath = Join-Path $script:repoRoot 'MDEValidator\MDEValidator.psd1'
}

Describe 'Publish Preflight — REL-02: API Key Check' {
    It 'Should detect empty string as missing API key' {
        [string]::IsNullOrWhiteSpace('') | Should -BeTrue
    }
    It 'Should detect whitespace-only string as missing API key' {
        [string]::IsNullOrWhiteSpace('   ') | Should -BeTrue
    }
    It 'Should accept a non-blank value as a present API key' {
        [string]::IsNullOrWhiteSpace('myapikey') | Should -BeFalse
    }
}

Describe 'Publish Preflight — REL-03: Tag-Version Alignment' {
    It 'Strips v prefix from release tag before comparison' {
        'v1.0.0' -replace '^v', '' | Should -Be '1.0.0'
    }
    It 'Is idempotent when tag has no v prefix' {
        '1.0.0' -replace '^v', '' | Should -Be '1.0.0'
    }
    It 'Detects a version mismatch between tag and manifest' {
        $tagVersion      = 'v1.1.0' -replace '^v', ''
        $manifestVersion = '1.0.0'
        ($tagVersion -ne $manifestVersion) | Should -BeTrue
    }
    It 'Confirms version alignment when tag and manifest agree' {
        $tagVersion      = 'v1.0.0' -replace '^v', ''
        $manifestVersion = '1.0.0'
        ($tagVersion -eq $manifestVersion) | Should -BeTrue
    }
    It 'Can read ModuleVersion from the real manifest file' {
        $manifest = Test-ModuleManifest -Path $script:manifestPath -ErrorAction Stop
        $manifest.Version.ToString() | Should -Not -BeNullOrEmpty
    }
}

Describe 'Publish Preflight — REL-04: Manifest Validation' {
    It 'Test-ModuleManifest does not throw on the project manifest' {
        { Test-ModuleManifest -Path $script:manifestPath -ErrorAction Stop } | Should -Not -Throw
    }
    It 'Manifest returns a System.Version object' {
        $manifest = Test-ModuleManifest -Path $script:manifestPath -ErrorAction Stop
        $manifest.Version | Should -BeOfType [System.Version]
    }
    It 'Manifest RootModule is MDEValidator.psm1' {
        $manifest = Test-ModuleManifest -Path $script:manifestPath -ErrorAction Stop
        $manifest.RootModule | Should -Be 'MDEValidator.psm1'
    }
}

Describe 'Publish Preflight — REL-05: Packaged Import Smoke Test' {
    BeforeAll {
        $script:tempDir    = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidator-preflight-test-$(Get-Random)"
        $script:sourcePath = Join-Path $script:repoRoot 'MDEValidator'
        Copy-Item -Path $script:sourcePath -Destination $script:tempDir -Recurse -Force
    }
    AfterAll {
        Remove-Module MDEValidator -Force -ErrorAction SilentlyContinue
        if (Test-Path $script:tempDir) {
            Remove-Item $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Import-Module from a temp directory copy does not throw' {
        { Import-Module "$script:tempDir\MDEValidator" -Force -ErrorAction Stop } | Should -Not -Throw
    }
    It 'All FunctionsToExport entries are available as commands after import' {
        Import-Module "$script:tempDir\MDEValidator" -Force -ErrorAction Stop
        $expected = (Import-PowerShellDataFile $script:manifestPath).FunctionsToExport
        $missing  = $expected | Where-Object {
            -not (Get-Command $_ -Module MDEValidator -ErrorAction SilentlyContinue)
        }
        $missing | Should -BeNullOrEmpty
    }
}
