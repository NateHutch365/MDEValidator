# Phase 2: Testing Infrastructure - Research

**Researched:** 2026-03-07
**Domain:** PowerShell module testing with Pester 5.x, mock isolation, and JaCoCo coverage output
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Organize tests by module visibility with two roots: `Tests/Public` and `Tests/Private`.
- Use a flat file-per-function layout inside each root.
- Name test files exactly as `<FunctionName>.Tests.ps1` for direct function-to-test traceability.
- Keep each test file independent with no execution order assumptions.
- Use minimal shared bootstrap plus explicit per-file setup.
- Migrate incrementally from the current monolithic suite, with parity checks during transition.
- Maintain an explicit mapping checklist proving each function has a corresponding test.

### Claude's Discretion
- Final choice for private helper test grouping within `Tests/Private` (one-helper-per-file vs combined helper file), while preserving TEST-06 coverage expectations.

### Deferred Ideas (OUT OF SCOPE)
None - discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TEST-01 | Each public validation function has a corresponding Pester 5.x test file | File-per-function structure under `Tests/Public` with generated mapping checklist and CI assertion that all public `*.ps1` files have matching `*.Tests.ps1`. |
| TEST-02 | Tests mock all external dependencies (`Get-MpPreference`, `Get-MpComputerStatus`, `Get-Service`, `Get-ItemProperty`) | Define module-level mock boundaries and centralized mock builders; enforce `Should -Invoke` assertions per dependency path. |
| TEST-03 | Tests validate both pass and fail scenarios for each check | Standard two-context pattern per function: `Pass path` and `Fail path`, optionally `Error/NotApplicable` where code supports it. |
| TEST-04 | Tests can run without admin privileges and without Defender installed | No live Defender/service/registry calls in tests; all external calls mocked with fallback-path tests to simulate missing Defender/admin. |
| TEST-05 | Pester generates JaCoCo code coverage output | Use `New-PesterConfiguration` and enable `CodeCoverage.Enabled = $true` with `OutputFormat = 'JaCoCo'` and explicit output path in runner script. |
| TEST-06 | Private helper functions have test coverage via module-scoped mocking | Use constrained `InModuleScope` for private helper invocation plus module-scoped mocks where helpers call external commands. |
</phase_requirements>

## Summary

Phase 2 should establish a deterministic, mock-first Pester 5.x test architecture that mirrors the module's already completed file-per-function layout. The module currently has 45 public function files and 4 private helper files, but only one monolithic test file (`Tests/MDEValidator.Tests.ps1`, 964 lines) and a basic runner (`run-tests.ps1`) that invokes one file directly without modern Pester configuration or coverage output configuration. This is the main planning gap.

The current codebase is highly dependent on external/environment commands: `Get-MpPreference` appears in 21 function files, `Get-MpComputerStatus` in 4, `Get-Service` in 3, and `Get-ItemProperty` in 23. Because Phase 2 requires no-admin/no-Defender execution, test plans must treat these as strict mock boundaries. Pester supports this directly through `Mock -ModuleName` for public-function testing and `InModuleScope` for private helpers.

JaCoCo coverage generation is natively supported in Pester 5.x and should be configured through `New-PesterConfiguration` rather than legacy parameter style. Planner should explicitly include wave-0 tasks to establish the new test folder structure, a bootstrap helper, migration checklist generation, and runner updates before large-scale test splitting begins.

**Primary recommendation:** Plan Phase 2 as a three-wave migration: `infrastructure baseline -> public function split -> private helper coverage + parity gate`, with coverage and mapping checklist validated at each wave.

## Requirement-to-Plan Implications

| Requirement | Planning Implication | Definition of Done Signal |
|------------|----------------------|---------------------------|
| TEST-01 | Create `Tests/Public/<FunctionName>.Tests.ps1` for all 45 public functions; build automated inventory check against `MDEValidator/Public/*.ps1`. | Mapping script reports 45/45 matched and no orphan test files. |
| TEST-02 | Introduce reusable mock setup pattern per dependency family (Defender cmdlets, services, registry). Ban unmocked external calls in test review checklist. | All new tests include explicit `Mock` statements and `Should -Invoke` verification for expected external call paths. |
| TEST-03 | Template each test file with pass/fail contexts; use data-driven test cases to reduce duplication. | Every public function test file has at least one pass and one fail assertion path. |
| TEST-04 | Add baseline test mode that assumes no Defender/admin and validates behavior under unavailable dependencies. | Full suite green on non-elevated session with mocked external commands only. |
| TEST-05 | Replace ad hoc runner options with Pester config object and explicit coverage artifact path under `Tests/Artifacts/coverage.xml`. | `coverage.xml` exists, non-empty, and parseable as JaCoCo XML after test run. |
| TEST-06 | Choose private helper strategy: one-helper-per-file (recommended) for auditability and alignment with file-per-function intent. | 4/4 private helper tests present in `Tests/Private`, each executes helper code paths. |

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Pester | 5.7.1 (observed available locally) | Unit test framework, mocking, coverage | Official current 5.x model; supports configuration object, module mocking, InModuleScope, JaCoCo coverage output. |
| PowerShell | 5.1+ (`#Requires -Version 5.1` in module) | Runtime for module and tests | Matches module baseline and Windows endpoint target. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| PesterConfiguration (`New-PesterConfiguration`) | Pester 5.x built-in | Centralize run/test-result/coverage options | Always for suite execution and CI-consistent behavior. |
| NUnit/JUnit test result output (optional in this phase) | Pester 5.x built-in | Future CI integration traceability | Useful if planner wants early artifact compatibility for Phase 4. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `Mock -ModuleName` for public function dependency seams | Extensive `InModuleScope` usage everywhere | Easier short-term access, but worse discovery performance and weaker exported-surface validation. |
| Flat file-per-function private tests | Combined private-helper test file | Slightly fewer files, but weaker function-to-test traceability and more merge conflicts. |

**Installation:**
```bash
pwsh -NoProfile -Command "Install-Module Pester -MinimumVersion 5.7.1 -Scope CurrentUser -Force"
```

## Architecture Patterns

### Recommended Project Structure
```
Tests/
├── Public/                              # One test file per exported function
├── Private/                             # One test file per private helper (recommended)
├── Helpers/
│   ├── TestBootstrap.ps1                # Common module import + shared helpers
│   └── MockBuilders.ps1                 # Standard mock builders by dependency type
├── Artifacts/
│   ├── coverage.xml                     # JaCoCo coverage
│   └── test-results.xml                 # Optional NUnit/JUnit output
└── Mapping/
    └── function-test-map.json           # Generated checklist for TEST-01/TEST-06
```

### Pattern 1: Public Function Isolation with Module-Scoped Mocks
**What:** Test exported functions directly while injecting mocks into `MDEValidator` module scope using `Mock -ModuleName`.
**When to use:** All public function tests that call Defender cmdlets, service APIs, registry APIs, or time/system APIs.
**Example:**
```powershell
# Source: https://pester.dev/docs/usage/modules and https://pester.dev/docs/commands/Mock
BeforeAll {
    Import-Module "$PSScriptRoot/../../MDEValidator/MDEValidator.psd1" -Force
}

Describe 'Test-MDEServiceStatus' {
    It 'returns Pass when WinDefend is running and automatic' {
        Mock Get-Service -ModuleName MDEValidator {
            [pscustomobject]@{ Name = 'WinDefend'; Status = 'Running'; StartType = 'Automatic' }
        }

        $result = Test-MDEServiceStatus

        $result.Status | Should -Be 'Pass'
        Should -Invoke Get-Service -ModuleName MDEValidator -Times 1
    }
}
```

### Pattern 2: Private Helper Testing with Constrained InModuleScope
**What:** Use `InModuleScope` only inside `It` blocks to invoke non-exported helper functions.
**When to use:** TEST-06 coverage for `ConvertTo-HtmlEncodedString`, `Write-ValidationResult`, `Test-IsElevated`, `Test-IsWindowsServer`.
**Example:**
```powershell
# Source: https://pester.dev/docs/commands/InModuleScope and https://pester.dev/docs/usage/modules
BeforeAll {
    Import-Module "$PSScriptRoot/../../MDEValidator/MDEValidator.psd1" -Force
}

Describe 'Test-IsWindowsServer (private)' {
    It 'returns true for InstallationType Server' {
        InModuleScope MDEValidator {
            Mock Get-ItemProperty { [pscustomobject]@{ InstallationType = 'Server' } }
            Mock Test-Path { $true }

            Test-IsWindowsServer | Should -BeTrue
            Should -Invoke Get-ItemProperty -Times 1
        }
    }
}
```

### Pattern 3: Pass/Fail Dual-Path Test Template
**What:** Each function test includes a minimum of two behavior contexts.
**When to use:** All validation functions under TEST-03.
**Example:**
```powershell
Describe 'Test-MDECloudProtection' {
    Context 'Pass path' {
        It 'returns Pass when cloud protection enabled' { }
    }
    Context 'Fail path' {
        It 'returns Fail when cloud protection disabled' { }
    }
}
```

### Anti-Patterns to Avoid
- **Top-level executable code in test files:** Causes discovery-time side effects; keep executable code inside `BeforeAll`/`It` blocks.
- **One giant shared context script:** Increases coupling and hides per-test setup intent.
- **Using live Defender/registry/service calls in tests:** Violates TEST-04 and causes environment-dependent failures.
- **Wrapping entire Describe blocks in `InModuleScope`:** Pester docs caution this can slow discovery and reduce export-surface confidence.

## Recommended Mock Boundaries and Test Isolation Strategy

### Required Mock Boundaries
| Boundary | Commands | Rationale | Standard Mock Scope |
|----------|----------|-----------|---------------------|
| Defender preference/status API | `Get-MpPreference`, `Get-MpComputerStatus` | Defender may be absent; output varies by host | `Mock ... -ModuleName MDEValidator` in public tests |
| Service state API | `Get-Service` | Service presence/start type is host-dependent | `Mock ... -ModuleName MDEValidator` |
| Registry reads | `Get-ItemProperty`, `Test-Path` | Host policy/edition differences and access issues | `Mock ... -ModuleName MDEValidator` or inside `InModuleScope` |
| Time/random/system identity | `Get-Date`, identity APIs if asserted | Deterministic assertions | Mock only when test asserts exact timestamps/identity behavior |

### Isolation Rules
- Each test file must import module in `BeforeAll` and not assume prior module state.
- Reset behavior by re-importing module with `-Force` in file-level setup.
- Keep test data local to each file; no implicit globals.
- Prefer `BeforeEach` for mutable mocked return values.
- Use `Should -Invoke` to verify expected dependency interactions.
- Private helper tests use `InModuleScope` minimally and never around top-level `Describe`.

## Incremental Migration Strategy

### Wave A: Infrastructure Bootstrap (no behavioral rewrite)
- Create `Tests/Public`, `Tests/Private`, `Tests/Helpers`, `Tests/Artifacts`, and mapping script.
- Add bootstrap helper for common module import and reusable mock builders.
- Update `run-tests.ps1` to use `New-PesterConfiguration` and suite path `./Tests`.
- Keep existing monolithic test file runnable for parity checks.

### Wave B: Public Function Split (high-volume)
- For each `MDEValidator/Public/*.ps1`, create `Tests/Public/<FunctionName>.Tests.ps1`.
- Move assertions from monolith into per-function files where possible.
- Add missing pass/fail coverage while splitting.
- Mark migrated coverage in mapping checklist.

### Wave C: Private Helpers + Cutover
- Create one test file per private helper (recommended final discretion choice).
- Implement `InModuleScope` tests for helper behavior and module-scoped dependency mocking.
- Run parity comparison against monolithic suite outcomes.
- Retire monolithic file once mapping checklist and parity gate are both green.

### Cutover Gates
- Gate 1: mapping checklist complete for all 45 public functions.
- Gate 2: private helper checklist complete for all 4 private helpers.
- Gate 3: no-admin/no-Defender run green.
- Gate 4: JaCoCo artifact generated and non-empty.

## JaCoCo Coverage Generation Approach (Pester 5.x)

### Recommended Configuration
```powershell
# Source: https://pester.dev/docs/usage/code-coverage
$config = New-PesterConfiguration
$config.Run.Path = './Tests'
$config.Run.PassThru = $true
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = './Tests/Artifacts/coverage.xml'
$config.CodeCoverage.Path = @('./MDEValidator/Public/*.ps1', './MDEValidator/Private/*.ps1')

# Optional but useful for downstream CI
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'NUnitXml'
$config.TestResult.OutputPath = './Tests/Artifacts/test-results.xml'

Invoke-Pester -Configuration $config
```

### Constraints and Risks
- If `CodeCoverage.Path` is not scoped correctly, output can be empty or misleading.
- Coverage percent may drop initially during migration because new tests begin strict path scoping.
- JaCoCo output confirms line/command execution, not semantic correctness.
- Running old and new suites together can double-count or skew coverage unless run paths are controlled.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Module command interception | Custom function wrappers around each dependency | Pester `Mock` with `-ModuleName` | Native semantics, call assertions, less maintenance. |
| Private member access harness | Custom dot-sourcing tricks into private function files | `InModuleScope` | Officially supported and explicit intent. |
| Coverage XML serialization | Custom coverage converters | Pester `CodeCoverage.OutputFormat = 'JaCoCo'` | Built-in output compatible with CI tooling. |
| Inventory mapping | Manual spreadsheet tracking | Generated map from `Public/*.ps1` and `Private/*.ps1` | Prevents drift and audit gaps. |

**Key insight:** Hand-rolled testing utilities will increase Phase 2 complexity and create migration debt before Phase 4 CI/CD.

## Common Pitfalls

### Pitfall 1: Discovery-Time Side Effects
**What goes wrong:** Commands execute outside test blocks and fail before run phase.
**Why it happens:** Pester 5 discovery/run separation; top-level code executes too early.
**How to avoid:** Put executable setup in `BeforeAll`/`BeforeEach` only.
**Warning signs:** Tests fail during discovery or with null setup variables.

### Pitfall 2: Overusing InModuleScope
**What goes wrong:** Slower discovery and weaker confidence in exported interface tests.
**Why it happens:** Wrapping large blocks rather than targeted helper assertions.
**How to avoid:** Use `Mock -ModuleName` for public tests; reserve `InModuleScope` for private helper invocations.
**Warning signs:** Most tests no longer call exported functions directly.

### Pitfall 3: Partial Mocking of External Dependencies
**What goes wrong:** Tests pass on developer machine but fail in clean/CI environment.
**Why it happens:** Hidden live calls remain (registry, service, Defender cmdlets).
**How to avoid:** Per-test `Should -Invoke` and dependency checklist in code review.
**Warning signs:** Intermittent failures on non-admin sessions or hosts without Defender.

### Pitfall 4: Coverage Artifact Misconfiguration
**What goes wrong:** `coverage.xml` empty or includes wrong files.
**Why it happens:** Incorrect run path or coverage path scoping.
**How to avoid:** Set both `Run.Path` and `CodeCoverage.Path` explicitly.
**Warning signs:** `coverage.xml` exists but has 0 analyzed commands.

## Code Examples

Verified patterns from official sources:

### Mocking commands called inside a module
```powershell
# Source: https://pester.dev/docs/usage/modules
Mock Get-Version -ModuleName MyModule { 1.1 }
Mock Get-NextVersion -ModuleName MyModule { 1.2 }
```

### Testing private functions
```powershell
# Source: https://pester.dev/docs/commands/InModuleScope
InModuleScope MyModule {
    PrivateFunction | Should -Be $true
}
```

### Pester 5 coverage configuration
```powershell
# Source: https://pester.dev/docs/usage/code-coverage
$config = New-PesterConfiguration
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = 'coverage.xml'
Invoke-Pester -Configuration $config
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `Invoke-Pester -Path ...` monolithic run only | `Invoke-Pester -Configuration $config` | Pester 5 model | Centralized, deterministic run/coverage settings. |
| Legacy `-CodeCoverage` usage | `CodeCoverage` settings in config object | Pester 5 guidance | Better control over scope/output format/path. |
| Single large test file | File-per-function tests with explicit mapping | Modern maintainability practice | Easier ownership, traceability, and parallelizable growth. |

**Deprecated/outdated:**
- Monolithic one-file suite for all functions: conflicts with current phase traceability goals and requirement-level accountability.

## Open Questions

1. **Should private helper tests be one-file-per-helper or partially combined?**
   - What we know: Context grants discretion; 4 helpers exist.
   - What's unclear: Team preference for file count vs grouping.
   - Recommendation: Choose one-file-per-helper for strict traceability and lower merge conflict risk.

2. **Should optional test result XML (`NUnitXml`) be included in Phase 2 or deferred to Phase 4?**
   - What we know: Coverage artifact is required now; test result XML is optional but useful.
   - What's unclear: Whether planner wants early CI artifact alignment.
   - Recommendation: Include optional test result output in runner now; low cost and forward-compatible.

3. **What parity threshold should gate monolith retirement?**
   - What we know: Context requires parity checks during transition.
   - What's unclear: Exact acceptance metric (all historical asserts preserved vs behaviorally equivalent checks).
   - Recommendation: Define parity as equal pass/fail outcome by function plus no net loss in scenario coverage.

## Risks, Unknowns, and Decision Points for Planner

### Risks
- High-volume split (45 public + 4 private) can drift without automated mapping enforcement.
- Existing monolithic tests may contain implicit environment assumptions that fail under strict mocks.
- Coverage can be gamed by shallow invocation unless pass/fail behavior assertions are mandated.

### Unknowns
- Exact list of monolith assertions that are still meaningful versus brittle after split.
- Whether all functions currently return deterministic structures under mock-only execution.
- Baseline acceptable coverage target for phase exit.

### Decision Points
- Private helper file strategy (recommended: one-helper-per-file).
- Minimum coverage threshold for phase completion (for example, non-zero for all function files vs fixed percentage).
- Whether to keep temporary dual-run mode (monolith + split) for one or multiple waves.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Pester 5.7.1 |
| Config file | none - configure via `run-tests.ps1` in Wave A |
| Quick run command | `pwsh -NoProfile -File ./run-tests.ps1` |
| Full suite command | `pwsh -NoProfile -Command "$config = New-PesterConfiguration; $config.Run.Path='./Tests'; $config.CodeCoverage.Enabled=$true; $config.CodeCoverage.OutputFormat='JaCoCo'; $config.CodeCoverage.OutputPath='./Tests/Artifacts/coverage.xml'; Invoke-Pester -Configuration $config"` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEST-01 | One test file per public function | unit/structure | `pwsh -NoProfile -Command "(Get-ChildItem ./MDEValidator/Public/*.ps1).BaseName | ForEach-Object { Test-Path \"./Tests/Public/$_.Tests.ps1\" } | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count"` | ❌ Wave 0 |
| TEST-02 | External dependencies mocked | unit | `pwsh -NoProfile -Command "Invoke-Pester -Path ./Tests/Public -Output None"` | ❌ Wave 0 |
| TEST-03 | Pass and fail scenarios per check | unit | `pwsh -NoProfile -Command "Invoke-Pester -Path ./Tests/Public -Output None"` | ❌ Wave 0 |
| TEST-04 | Runs without admin/Defender | integration/smoke | `pwsh -NoProfile -Command "$env:MDE_TEST_NO_DEFENDER='1'; Invoke-Pester -Path ./Tests -Output Detailed"` | ❌ Wave 0 |
| TEST-05 | JaCoCo coverage output produced | integration | `pwsh -NoProfile -Command "$config = New-PesterConfiguration; $config.Run.Path='./Tests'; $config.CodeCoverage.Enabled=$true; $config.CodeCoverage.OutputFormat='JaCoCo'; $config.CodeCoverage.OutputPath='./Tests/Artifacts/coverage.xml'; Invoke-Pester -Configuration $config"` | ❌ Wave 0 |
| TEST-06 | Private helper coverage via module scope | unit | `pwsh -NoProfile -Command "Invoke-Pester -Path ./Tests/Private -Output None"` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pwsh -NoProfile -File ./run-tests.ps1`
- **Per wave merge:** full suite command with coverage enabled
- **Phase gate:** Full suite green + mapping checklist complete + `Tests/Artifacts/coverage.xml` present

### Wave 0 Gaps
- [ ] `Tests/Public/*.Tests.ps1` - create 45 function-aligned files covering TEST-01/02/03/04
- [ ] `Tests/Private/*.Tests.ps1` - create 4 private helper tests for TEST-06
- [ ] `Tests/Helpers/TestBootstrap.ps1` - shared import/setup helpers
- [ ] `Tests/Helpers/MockBuilders.ps1` - dependency-specific standardized mocks
- [ ] `Tests/Mapping/function-test-map.json` (generated) - audit checklist for coverage of function inventory
- [ ] `Tests/Artifacts/` directory and coverage output wiring in `run-tests.ps1`
- [ ] Update `run-tests.ps1` to use `New-PesterConfiguration` and JaCoCo output

## Sources

### Primary (HIGH confidence)
- https://pester.dev/docs/usage/code-coverage - Pester 5 coverage model, JaCoCo output defaults/config
- https://pester.dev/docs/commands/New-PesterConfiguration - configuration object schema and usage
- https://pester.dev/docs/commands/Mock - module-scoped mocking, parameter filtering, verifiable mocks
- https://pester.dev/docs/commands/InModuleScope - private function testing semantics
- https://pester.dev/docs/usage/modules - public vs private module testing patterns and cautions
- `MDEValidator/Public/*.ps1` - external dependency usage and function inventory
- `MDEValidator/Private/*.ps1` - private helper inventory and behavior
- `Tests/MDEValidator.Tests.ps1` - current monolithic test baseline
- `run-tests.ps1` - current test execution approach

### Secondary (MEDIUM confidence)
- https://pester.dev/docs/usage/test-file-structure - recommended file structure, discovery/run hygiene
- https://pester.dev/docs/usage/test-results - optional result artifact configuration for CI alignment

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - official Pester docs + local environment check shows Pester 5.7.1 availability
- Architecture: HIGH - tightly constrained by phase context and current module layout
- Pitfalls: HIGH - aligned with official Pester discovery/mocking guidance and current code dependency profile

**Research date:** 2026-03-07
**Valid until:** 2026-04-06
