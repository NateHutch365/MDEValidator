---
created: 2026-03-11T21:46:00Z
title: Publish module to PSGallery
area: general
files:
  - MDEValidator/MDEValidator.psd1
---

## Problem

The module is not published to PowerShell Gallery, so users cannot install it via `Install-Module MDEValidator`. This was previously scoped as Phase 5 but has been deferred — it requires the CI/CD pipeline (Phase 4) to be in place first, and involves external account setup (PSGallery API key) that falls outside the automated GSD workflow.

## Solution

After Phase 4 (CI/CD Pipeline) is complete:
1. Verify manifest is gallery-ready (`Test-ModuleManifest` passes, LicenseUri/ProjectUri are real URLs, not placeholders)
2. Register a PSGallery API key and store securely (GitHub Actions secret)
3. Publish via `Publish-Module -Name MDEValidator -NuGetApiKey $key`
4. Verify `Install-Module MDEValidator -Force` succeeds and `Import-Module MDEValidator` loads all 45 functions
5. Tag the release in git with SemVer version matching the manifest ModuleVersion

Note: LicenseUri and ProjectUri currently use placeholder GitHub URLs — update to real URLs before publishing.
