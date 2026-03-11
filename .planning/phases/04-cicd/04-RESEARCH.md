# Phase 4: CI/CD Pipeline - Research

**Researched:** 2026-03-11
**Domain:** GitHub Actions workflows for PowerShell module testing, linting, coverage reporting, and PSGallery publishing
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| CICD-01 | GitHub Actions workflow runs Pester tests on push and PR to main | Verified pattern: `on: push/pull_request with branches: [main]`, `runs-on: windows-latest`, invoke `run-tests.ps1` via `pwsh`. Pester 5.7.1 must be explicitly installed. |
| CICD-02 | GitHub Actions workflow runs PSScriptAnalyzer lint on push and PR to main | Verified pattern: Install PSScriptAnalyzer, run `Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1 -Severity @('Error','Warning')`, throw on violations. |
| CICD-03 | CI runs on windows-latest runner | `runs-on: windows-latest` is the correct GitHub-hosted runner label. Both public and private repos support it. Default shell on windows-latest is `pwsh`. |
| CICD-04 | Automated PSGallery publish triggered on GitHub release/tag | `on: release: types: [published]` trigger + `Publish-Module -NuGetApiKey $env:NUGET_API_KEY`. Secret `NUGET_API_KEY` must be configured in repo settings. |
| CICD-05 | CI reports code coverage results | Two options researched: (A) `actions/upload-artifact@v4` to upload `coverage.xml` as downloadable artifact (always works), (B) `madrapps/jacoco-report@v1.7.2` to post PR comment with metrics. Using both is recommended. |
</phase_requirements>

---

## Summary

Phase 4 requires two GitHub Actions workflow files in `.github/workflows/`. The first (`ci.yml`) runs on push and PR to main, executing the full Pester test suite via the existing `run-tests.ps1` and running PSScriptAnalyzer in fail-fast mode. The second (`publish.yml`) triggers on GitHub Release published events and calls `Publish-Module` to submit to PSGallery.

The project already has all prerequisites in place: `run-tests.ps1` produces JaCoCo XML at `Tests/Artifacts/coverage.xml`, PSScriptAnalyzer settings live at `.PSScriptAnalyzerSettings.psd1`, and the manifest metadata is publish-ready from Phase 3. The CI workflow needs to install Pester and PSScriptAnalyzer explicitly since they are not pre-installed on the `windows-latest` runner.

Coverage reporting uses two complementary mechanisms: artifact upload (visible in every workflow run's artifact tab) and a PR comment via `madrapps/jacoco-report` (visible inline on pull requests with coverage percentage and per-file breakdown). PSGallery publishing requires exactly one repository secret — `NUGET_API_KEY` — sourced from the publisher's PSGallery account page.

**Primary recommendation:** Two workflow files — `ci.yml` for test/lint/coverage (push + PR to main) and `publish.yml` for PSGallery publish (release trigger). Keep lint and test in one job (faster feedback, no artifact sharing needed), upload coverage as artifact unconditionally, run JaCoCo PR comment conditionally on `pull_request` events.

---

## Standard Stack

### Core
| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| `actions/checkout` | v4 | Check out repository code | Official GitHub action, required first step |
| `actions/upload-artifact` | v4 | Upload coverage.xml and test-results.xml as CI artifacts | Official GitHub action, v4 is current stable |
| `madrapps/jacoco-report` | v1.7.2 | Post JaCoCo coverage as PR comment | Current stable (March 2026), widely used for JaCoCo on GitHub |
| `Pester` | 5.7.1+ | PowerShell test framework | Already used in project; must be installed on runner |
| `PSScriptAnalyzer` | 1.24.0+ | Static analysis | Already used in project; must be installed on runner |
| `Publish-Module` | Built into PowerShellGet | Push module to PSGallery | Official Microsoft cmdlet, no alternatives |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `madrapps/jacoco-report` | `codecov/codecov-action` | Codecov requires account, doesn't natively parse JaCoCo from PowerShell projects well |
| Release trigger for publish | Tag push trigger (`on: push: tags: ['v*']`) | Tag trigger fires immediately on `git push --tags`; release trigger requires explicit GitHub Release creation (safer, allows release notes) |
| Inline PSScriptAnalyzer in workflow | Separate job for lint | Single job is simpler; separate jobs only needed if you want parallel execution (not worth the complexity here) |

---

## Architecture Patterns

### Recommended Workflow Structure
```
.github/
└── workflows/
    ├── ci.yml          # push + PR to main → test + lint + coverage
    └── publish.yml     # GitHub Release published → PSGallery publish
```

### Pattern 1: Test + Lint + Coverage Workflow
**What:** Single job on `windows-latest` that installs dependencies, runs tests, uploads artifacts, and lints.
**When to use:** Every push and PR to `main` (CICD-01, CICD-02, CICD-03, CICD-05).

```yaml
# Source: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test-and-lint:
    name: Test and Lint
    runs-on: windows-latest
    permissions:
      contents: read
      pull-requests: write   # Required for JaCoCo PR comment

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Pester
        shell: pwsh
        run: Install-Module -Name Pester -MinimumVersion 5.7.1 -Force -Scope CurrentUser

      - name: Install PSScriptAnalyzer
        shell: pwsh
        run: Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser

      - name: Run Pester Tests
        shell: pwsh
        run: .\run-tests.ps1

      - name: Upload Test Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: Tests/Artifacts/test-results.xml

      - name: Upload Coverage Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: Tests/Artifacts/coverage.xml

      - name: JaCoCo Coverage Report on PR
        if: github.event_name == 'pull_request'
        uses: madrapps/jacoco-report@v1.7.2
        with:
          paths: ${{ github.workspace }}/Tests/Artifacts/coverage.xml
          token: ${{ secrets.GITHUB_TOKEN }}
          min-coverage-overall: 60
          title: Code Coverage Report
          update-comment: true

      - name: Run PSScriptAnalyzer
        shell: pwsh
        run: |
          $violations = Invoke-ScriptAnalyzer `
            -Path .\MDEValidator `
            -Recurse `
            -Settings .\.PSScriptAnalyzerSettings.psd1 `
            -Severity @('Error', 'Warning')

          if ($violations) {
            $violations | Format-Table ScriptName, Line, RuleName, Message -AutoSize
            throw "PSScriptAnalyzer found $($violations.Count) violation(s). Build failed."
          }

          Write-Host "PSScriptAnalyzer: PASS (0 violations)" -ForegroundColor Green
```

### Pattern 2: PSGallery Publish Workflow
**What:** Triggered by GitHub Release published event; publishes module to PSGallery via `Publish-Module`.
**When to use:** When a GitHub Release is published (CICD-04).

```yaml
# Source: https://learn.microsoft.com/en-us/powershell/scripting/gallery/how-to/publishing-packages/publishing-a-package
name: Publish to PSGallery

on:
  release:
    types: [published]

jobs:
  publish:
    name: Publish Module
    runs-on: windows-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Publish to PSGallery
        shell: pwsh
        env:
          NUGET_API_KEY: ${{ secrets.NUGET_API_KEY }}
        run: |
          Publish-Module -Path ".\MDEValidator" -NuGetApiKey $env:NUGET_API_KEY -Verbose
```

### Pattern 3: Fail on PSScriptAnalyzer Violations
**What:** Use `throw` inside a `pwsh` run step to produce a non-zero exit code when violations are found.
**Why it works:** GitHub Actions prepends `$ErrorActionPreference = 'stop'` to all `pwsh` scripts automatically, so an unhandled `throw` terminates the script with a failure exit code, which fails the step and the job.

```powershell
# Source: GitHub Actions docs - exit codes and error action preference
# pwsh scripts auto-get $ErrorActionPreference = 'stop'
if ($violations) {
    throw "PSScriptAnalyzer found $($violations.Count) violation(s)"
}
# Alternatively, use: exit 1
```

**Do NOT use** `Write-Error` alone — it outputs an error stream entry but does not terminate the script unless `$ErrorActionPreference = 'Stop'` is set.

### Anti-Patterns to Avoid
- **Installing Pester with `-SkipPublisherCheck`**: Not needed; the Windows runner's execution policy allows installation.
- **Using `powershell` shell** (Windows PowerShell 5.1) **instead of `pwsh`** (PowerShell Core 7.x): The runner has both but `pwsh` is the default and matches modern module dev. Be explicit.
- **Storing `NUGET_API_KEY` in workflow YAML**: Never. Always use `${{ secrets.NUGET_API_KEY }}` via environment variable injection.
- **Running PSScriptAnalyzer on the whole repo root**: Run only against `.\MDEValidator` to avoid flagging test helper patterns and workflow files.
- **Skipping `if: always()` on artifact upload steps**: Without this, artifacts won't be uploaded when tests fail, making failure diagnosis impossible.

---

## Workflow Structure

### CI Workflow (`ci.yml`)

| Step Order | Step Name | Purpose |
|-----------|-----------|---------|
| 1 | Checkout | Get repository code |
| 2 | Install Pester | Ensure 5.7.1+ is available (not pre-installed on runner) |
| 3 | Install PSScriptAnalyzer | Ensure current version available |
| 4 | Run Pester Tests | Execute `run-tests.ps1` — produces coverage.xml and test-results.xml |
| 5 | Upload Test Results | Upload `Tests/Artifacts/test-results.xml` (always, even on failure) |
| 6 | Upload Coverage Report | Upload `Tests/Artifacts/coverage.xml` (always, even on failure) |
| 7 | JaCoCo PR Comment | Post coverage metrics as PR comment (PR events only) |
| 8 | Run PSScriptAnalyzer | Lint module, fail if any violations found |

**Note on step ordering:** PSScriptAnalyzer runs AFTER test/coverage steps. This means coverage artifacts are always uploaded even if lint fails. If tests fail, the lint step still runs (failing fast on tests is done via `run-tests.ps1` exit code propagation).

### Publish Workflow (`publish.yml`)

| Step Order | Step Name | Purpose |
|-----------|-----------|---------|
| 1 | Checkout | Get tagged release code |
| 2 | Publish to PSGallery | Call `Publish-Module` with NuGet API key |

**Why no test step in publish workflow?** The release is only created after CI has passed on main. Running tests again in publish is redundant and adds latency. If you want belt-and-suspenders, add a test step before publish.

---

## Secrets Required

| Secret Name | Where to Set | Value Source | Purpose |
|-------------|-------------|-------------|---------|
| `NUGET_API_KEY` | GitHub repo Settings → Secrets and variables → Actions | https://www.powershellgallery.com — Account → API Keys | Authenticates `Publish-Module` to PSGallery |
| `GITHUB_TOKEN` | Automatically available | Built-in GitHub token | Used by JaCoCo action to post PR comments (no manual setup) |

**To create `NUGET_API_KEY`:**
1. Sign in at https://www.powershellgallery.com
2. Click username → "API Keys"
3. Create a key scoped to "Push new packages and package versions" for `MDEValidator`
4. Copy the key value (shown only once)
5. In GitHub: Settings → Secrets and variables → Actions → New repository secret → Name: `NUGET_API_KEY`

**Security note:** Treat the PSGallery API key as a password. Rotate it regularly. Scope it to the specific module name if the PSGallery UI allows it.

---

## Coverage Reporting

### Mechanism 1: Artifact Upload (CICD-05 primary)
`actions/upload-artifact@v4` uploads `Tests/Artifacts/coverage.xml` to the workflow run. Anyone with repo access can download it from the Actions tab. Works for both push and PR triggers.

### Mechanism 2: JaCoCo PR Comment (CICD-05 enhanced)
`madrapps/jacoco-report@v1.7.2` reads the JaCoCo XML and posts a table comment on the PR showing:
- Overall coverage percentage
- Per-file coverage for changed files
- Pass/fail based on configurable minimum threshold

**Required permissions for JaCoCo action:**
```yaml
permissions:
  contents: read
  pull-requests: write  # REQUIRED for PR comment posting
```
Without `pull-requests: write`, the action will succeed silently but no comment will appear.

**Known limitation:** The JaCoCo action only runs on `pull_request` events (not plain `push` to main). For push-to-main coverage visibility, the artifact is the mechanism.

---

## Publish Trigger

### Release Trigger (Recommended)
```yaml
on:
  release:
    types: [published]
```
- Fires when a GitHub Release is **published** (not just created as draft)
- Requires human to go to GitHub UI → Releases → Draft release → Publish
- Safe: accidental tag pushes don't trigger publishing
- The checked-out commit will be the tag's commit SHA

### Tag Push Trigger (Alternative, not recommended)
```yaml
on:
  push:
    tags:
      - 'v*'
```
- Fires immediately when a tag matching `v*` is pushed
- Easier to accidentally trigger with `git push --tags`
- Cannot be easily blocked/reviewed before execution

**Decision: Use release trigger** (`on: release: types: [published]`). It requires explicit human action per publish and allows attaching release notes before firing.

---

## Risks & Mitigations

### Risk 1: Pester version mismatch on runner
**Issue:** `windows-latest` has Pester pre-installed but it may be an older version (3.x or 4.x) that conflicts with 5.x configuration object syntax.
**Mitigation:** Always run `Install-Module -Name Pester -MinimumVersion 5.7.1 -Force -Scope CurrentUser` before invoking tests. `-Force` overwrites any existing version. Verified: this pattern is used in Pester's own official GitHub Actions documentation.

### Risk 2: PSScriptAnalyzer not pre-installed
**Issue:** `windows-latest` does not pre-install PSScriptAnalyzer. Installing at runtime adds ~30 seconds.
**Mitigation:** Accept the install time; it's unavoidable. Add `Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser` as a dedicated step before the lint step.

### Risk 3: JaCoCo action requires `pull-requests: write` permission
**Issue:** If the workflow's default token lacks write permission on PRs (org-level restriction), the JaCoCo PR comment silently fails.
**Mitigation:** Explicitly declare `permissions: pull-requests: write` in the job. If the org restricts this for forks, accept graceful degradation (artifact upload still works).

### Risk 4: Empty `coverage.xml` on test failure
**Issue:** If tests fail before completion, Pester may not write `coverage.xml`, causing the artifact upload step to warn/fail.
**Mitigation:** `run-tests.ps1` uses `exit $result.FailedCount` — coverage processing happens before that exit. Even with failed tests, `coverage.xml` is written. Use `if: always()` on upload steps to guarantee they run.

### Risk 5: PSGallery publish on stale manifest URLs
**Issue:** The manifest uses placeholder GitHub URLs (`https://github.com/YOUR_ORG/MDEValidator`). PSGallery validates that `LicenseUri` and `ProjectUri` are reachable before accepting publish.
**Mitigation:** Must update manifest URLs to real GitHub repo URLs before the first PSGallery publish attempt. This is a pre-condition for Phase 5, but note it here as a Phase 4 risk.

### Risk 6: NuGet API key not set → publish silently fails
**Issue:** If `NUGET_API_KEY` secret is not configured in GitHub, `$env:NUGET_API_KEY` is empty and `Publish-Module` will fail with an authentication error.
**Mitigation:** Validate secret existence at workflow start or document clearly in Phase 4 plan that the secret must be configured. Test with `Publish-Module -WhatIf` locally before triggering the workflow.

### Risk 7: Windows Defender on runner scans test artifacts
**Issue:** On `windows-latest`, Windows Defender is active and can intermittently flag or delay operations on newly created files in temp directories. This could cause flaky test artifact writes.
**Mitigation:** Since all tests are mock-based (no live Defender interaction), this is a low risk. If observed, use `$env:RUNNER_TEMP` paths or add Defender exclusion steps.

---

## Validation Architecture

> `workflow.nyquist_validation` is `true` — section required.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Pester 5.7.1 (local) |
| Config file | `run-tests.ps1` — calls `New-PesterConfiguration` |
| Quick run command | `.\run-tests.ps1` |
| Full suite command | `.\run-tests.ps1` |

### Phase Requirements → Validation Map

CI/CD workflows are configuration artifacts, not code — their primary validation is:
1. **Syntax validation** (YAML parseable, PowerShell scripts executable locally)
2. **Dry-run validation** (PowerShell steps can be run locally before push)
3. **Integration validation** (actual GitHub Actions run confirming each job passes)

| Req ID | Behavior | Validation Type | Command / Method | Pre-existing? |
|--------|----------|-----------------|------------------|--------------|
| CICD-01 | Pester tests run on GHA push/PR | Integration (GHA run) | Push to main branch / open PR | ❌ Workflow file must be created |
| CICD-01 | `run-tests.ps1` exits 0 on clean suite | Local smoke | `.\run-tests.ps1` | ✅ Existing runner |
| CICD-02 | PSScriptAnalyzer passes | Local smoke | `Invoke-ScriptAnalyzer -Path .\MDEValidator -Recurse -Settings .\.PSScriptAnalyzerSettings.psd1 -Severity @('Error','Warning')` | ✅ QUAL phase confirmed 0 violations |
| CICD-03 | Workflow runs on windows-latest | Integration (GHA run) | Inspect GHA run summary | ❌ Workflow file must be created |
| CICD-04 | PSGallery publish on release | Integration (GHA run) | Create GitHub Release → inspect GHA run | ❌ Workflow file + secret must exist |
| CICD-05 | Coverage XML uploaded as artifact | Integration (GHA run) | Inspect workflow run artifacts tab | ❌ Workflow file must be created |
| CICD-05 | JaCoCo PR comment appears | Integration (GHA PR) | Open PR → inspect PR comments | ❌ Workflow file + PR write permission |

### Pre-execution Local Dry-Runs (Wave 0 substitute)

Before pushing workflows to GitHub, validate PowerShell steps locally:

```powershell
# Validate test runner works (CICD-01)
.\run-tests.ps1

# Validate lint script works (CICD-02)
$violations = Invoke-ScriptAnalyzer `
    -Path .\MDEValidator `
    -Recurse `
    -Settings .\.PSScriptAnalyzerSettings.psd1 `
    -Severity @('Error', 'Warning')
if ($violations) { $violations | Format-Table; throw "Violations found" }
Write-Host "PASS"

# Validate YAML syntax (manual check or use VSCode YAML extension)
# No automated YAML validation command available without ci-act tool

# Validate publish (dry run - do not actually publish)
# Publish-Module -Path ".\MDEValidator" -NuGetApiKey "test" -WhatIf -Verbose
```

### Sampling Rate
- **Per workflow commit:** Push to non-main branch first, verify GHA run passes before merging to main
- **CI gate:** Full Pester suite must pass + zero PSScriptAnalyzer violations
- **Publish gate:** GitHub Release creation (manual human review step)

### Wave 0 Gaps
- [ ] `.github/workflows/ci.yml` — covers CICD-01, CICD-02, CICD-03, CICD-05
- [ ] `.github/workflows/publish.yml` — covers CICD-04
- [ ] Repository secret `NUGET_API_KEY` configured in GitHub repo settings
- [ ] (Pre-condition for Phase 5, noted here) Manifest `LicenseUri` and `ProjectUri` must use real GitHub URLs before publish workflow is activated

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Coverage PR comments | Custom script parsing coverage.xml | `madrapps/jacoco-report@v1.7.2` | JaCoCo XML is complex; the action handles multi-module, PR diffing, threshold enforcement |
| Module publishing | Custom `Invoke-RestMethod` to NuGet API | `Publish-Module` (built-in) | PowerShellGet handles metadata validation, file packaging, and API auth correctly |
| Artifact upload | Manual `Copy-Item` to a server | `actions/upload-artifact@v4` | Official GitHub action with retention, compression, and UI integration |
| Fail-on-lint | Custom exit code logic | `throw` in pwsh step | GHA's auto-prepended `$ErrorActionPreference = 'stop'` + `throw` is the idiomatic pattern |

---

## Common Pitfalls

### Pitfall 1: Old Pester version on runner
**What goes wrong:** Tests fail with `Cannot validate argument on parameter 'Configuration'` or similar, because Pester 3.x/4.x is picked up instead of 5.x.
**Why it happens:** `windows-latest` pre-installs an older Pester in the system path. Without `-Force`, `Install-Module` may not override it.
**How to avoid:** Always use `Install-Module -Name Pester -MinimumVersion 5.7.1 -Force -Scope CurrentUser`. The `-Force` flag is essential.

### Pitfall 2: PSScriptAnalyzer violations not failing the job
**What goes wrong:** PSSA runs and finds violations, but the job passes because the exit code was not set non-zero.
**Why it happens:** `Write-Error` doesn't terminate a script by default; only `throw` or `exit 1` does.
**How to avoid:** Use `throw "PSScriptAnalyzer found $n violations"` inside the `if ($violations)` block.

### Pitfall 3: JaCoCo PR comment never appears
**What goes wrong:** The `madrapps/jacoco-report` step completes successfully but no comment appears on the PR.
**Why it happens:** Missing `pull-requests: write` permission at the job level.
**How to avoid:** Explicitly add `permissions: pull-requests: write` to the job block.

### Pitfall 4: `coverage.xml` not found after test failure
**What goes wrong:** Upload artifact step fails because `coverage.xml` doesn't exist.
**Why it happens:** Pester was configured with code coverage but didn't generate the file because tests errored before completing.
**How to avoid:** Add `if: always()` to all upload artifact steps. This ensures they run even when previous steps fail.

### Pitfall 5: Publish workflow triggered on draft release
**What goes wrong:** Module is published to PSGallery before the release is ready.
**Why it happens:** Using `types: [created]` instead of `types: [published]` in the release trigger.
**How to avoid:** Always use `on: release: types: [published]`. Draft releases do not trigger this event.

### Pitfall 6: Publish fails due to existing version
**What goes wrong:** `Publish-Module` errors with "version already exists" on PSGallery.
**Why it happens:** The module version in `.psd1` was not bumped before triggering the release.
**How to avoid:** Bump `ModuleVersion` in `MDEValidator.psd1` before creating the GitHub Release. Consider adding a manifest validation step in the publish workflow.

---

## Code Examples

### Install Pester on CI (idiomatic)
```powershell
# Source: https://pester.dev/docs/usage/code-coverage#integrating-with-github-actions
Install-Module -Name Pester -MinimumVersion 5.7.1 -Force -Scope CurrentUser
```

### Run existing test runner
```powershell
# Existing run-tests.ps1 already configured with JaCoCo output
# Output: Tests/Artifacts/coverage.xml (JaCoCo format)
# Output: Tests/Artifacts/test-results.xml (NUnitXml format)
.\run-tests.ps1
```

### PSScriptAnalyzer fail-fast CI check
```powershell
# Source: verified against existing .PSScriptAnalyzerSettings.psd1 and run in Phase 3
$violations = Invoke-ScriptAnalyzer `
    -Path .\MDEValidator `
    -Recurse `
    -Settings .\.PSScriptAnalyzerSettings.psd1 `
    -Severity @('Error', 'Warning')

if ($violations) {
    $violations | Format-Table ScriptName, Line, RuleName, Message -AutoSize
    throw "PSScriptAnalyzer found $($violations.Count) violation(s). Build failed."
}
Write-Host "PSScriptAnalyzer: PASS (0 violations)" -ForegroundColor Green
```

### PSGallery publish (in CI context)
```powershell
# Source: https://learn.microsoft.com/en-us/powershell/scripting/gallery/how-to/publishing-packages/publishing-a-package
# NuGetApiKey comes from environment variable (injected from GitHub secret)
Publish-Module -Path ".\MDEValidator" -NuGetApiKey $env:NUGET_API_KEY -Verbose
```

### JaCoCo action with PR write permission
```yaml
# Source: https://github.com/marketplace/actions/jacoco-report (v1.7.2)
permissions:
  pull-requests: write

steps:
  - name: JaCoCo Coverage Report on PR
    if: github.event_name == 'pull_request'
    uses: madrapps/jacoco-report@v1.7.2
    with:
      paths: ${{ github.workspace }}/Tests/Artifacts/coverage.xml
      token: ${{ secrets.GITHUB_TOKEN }}
      min-coverage-overall: 60
      title: Code Coverage Report
      update-comment: true
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `Invoke-Pester -CodeCoverage` (legacy params) | `New-PesterConfiguration` object | Pester 5.0 | Already using new approach in `run-tests.ps1` |
| `actions/upload-artifact@v2/v3` | `actions/upload-artifact@v4` | 2023 | v3 deprecated; v4 required for new workflows |
| `actions/checkout@v2/v3` | `actions/checkout@v4` | 2023 | v4 uses Node 20, security improvements |
| Manual Publish-Module in CI | `on: release` trigger | N/A — always best practice | Makes PSGallery publish an explicit human decision |

---

## Sources

### Primary (HIGH confidence)
- GitHub official docs (https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) — workflow YAML syntax, trigger events, `permissions`, `runs-on` labels
- Pester official docs (https://pester.dev/docs/usage/code-coverage) — GitHub Actions integration pattern with JaCoCo, `Install-Module -Force`, `New-PesterConfiguration` usage
- Microsoft PSGallery docs (https://learn.microsoft.com/en-us/powershell/scripting/gallery/how-to/publishing-packages/publishing-a-package) — `Publish-Module`, NuGet API key requirements, metadata requirements

### Secondary (MEDIUM confidence)
- `madrapps/jacoco-report@v1.7.2` marketplace page (https://github.com/marketplace/actions/jacoco-report) — action inputs, `pull-requests: write` requirement, PR comment behavior
- Phase 3 RESEARCH.md (project-local) — confirmed 0 PSScriptAnalyzer violations, `.PSScriptAnalyzerSettings.psd1` location at repo root
- `run-tests.ps1` (project-local direct inspection) — confirmed JaCoCo output path `Tests/Artifacts/coverage.xml`, NUnitXml at `Tests/Artifacts/test-results.xml`, exit code pattern

### Tertiary (LOW confidence — needs runtime verification)
- PSScriptAnalyzer on `windows-latest` not pre-installed: Based on training knowledge + community reports; verify on first CI run
- Pester 3.x pre-installed on runner conflicting with 5.x: Known historical issue; `-Force` flag is the established mitigation

---

## Metadata

**Confidence breakdown:**
- Workflow syntax/triggers: HIGH — verified against official GitHub docs
- Pester/PSScriptAnalyzer CI steps: HIGH — verified against official Pester docs and project artifacts
- JaCoCo action: HIGH — verified against action marketplace page (v1.7.2 current)
- PSGallery publish: HIGH — verified against official Microsoft docs
- Runner-specific quirks: MEDIUM — Pester pre-install version, PSScriptAnalyzer availability; established mitigations exist

**Research date:** 2026-03-11
**Valid until:** 2026-09-11 (6 months — GitHub Actions runner images update regularly; verify `windows-latest` spec if issues arise)
