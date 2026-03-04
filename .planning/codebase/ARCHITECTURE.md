# Architecture

**Analysis Date:** 2026-03-04

## Pattern Overview

**Overall:** Monolithic PowerShell module with function-based layered architecture, plus a documentation-driven GSD workflow subsystem.

**Key Characteristics:**
- Core runtime logic is centralized in a single module file: `MDEValidator/MDEValidator.psm1`.
- Public behavior is exposed through explicit function exports in both `MDEValidator/MDEValidator.psd1` and `MDEValidator/MDEValidator.psm1`.
- Planning/workflow automation is defined declaratively in markdown command/workflow files under `.claude/` and mirrored prompt files under `.github/prompts/`.

## Layers

**Module Manifest and Export Contract:**
- Purpose: Define module metadata and the public API surface for import consumers.
- Location: `MDEValidator/MDEValidator.psd1`
- Contains: Module metadata, compatibility requirements, and `FunctionsToExport` list.
- Depends on: `MDEValidator/MDEValidator.psm1` via `RootModule`.
- Used by: `Import-Module` consumers and test import flow in `Tests/MDEValidator.Tests.ps1`.

**Helper and Infrastructure Functions:**
- Purpose: Provide reusable primitives for encoding, result shaping, privilege/OS checks, and policy path lookup.
- Location: `MDEValidator/MDEValidator.psm1`
- Contains: `ConvertTo-HtmlEncodedString`, `Write-ValidationResult`, `Test-IsElevated`, `Test-IsWindowsServer`, `Get-MDEManagementType`, `Get-MDEPolicySettingConfig`.
- Depends on: PowerShell runtime, registry APIs (`Get-ItemProperty`, `Test-Path`), system identity APIs.
- Used by: All validation and reporting functions in `MDEValidator/MDEValidator.psm1`.

**Validation Rule Layer:**
- Purpose: Execute individual MDE/Defender checks and normalize outcomes.
- Location: `MDEValidator/MDEValidator.psm1`
- Contains: `Test-MDEServiceStatus`, `Test-MDECloudProtection`, `Test-MDEAttackSurfaceReduction`, `Test-MDESmartScreen*`, `Test-MDEFileHashComputation`, and related checks.
- Depends on: Helper functions and Defender/Windows providers (`Get-MpPreference`, `Get-Service`, registry reads).
- Used by: Aggregator function `Test-MDEConfiguration` in `MDEValidator/MDEValidator.psm1`.

**Orchestration and Presentation Layer:**
- Purpose: Compose rule outputs and emit object, console, or HTML report outputs.
- Location: `MDEValidator/MDEValidator.psm1`
- Contains: `Test-MDEConfiguration`, `Get-MDEValidationReport`.
- Depends on: Validation rule layer and helper layer.
- Used by: End users invoking exported commands; test harness in `Tests/MDEValidator.Tests.ps1`.

**Test Layer:**
- Purpose: Verify module import, export surface, and result-shape expectations.
- Location: `Tests/MDEValidator.Tests.ps1`
- Contains: Pester `Describe`/`Context` suites and assertions for command existence and return contracts.
- Depends on: `MDEValidator/MDEValidator.psm1` import and exported functions.
- Used by: Manual/CI test execution via `Invoke-Pester`.

**GSD Command and Workflow Layer:**
- Purpose: Define planning/execution workflows for repository management tasks.
- Location: `.claude/commands/gsd/*.md`, `.claude/get-shit-done/workflows/*.md`, `.claude/get-shit-done/bin/*.cjs`, `.github/prompts/*.prompt.md`
- Contains: Command descriptors, workflow definitions, orchestration CLI (`.claude/get-shit-done/bin/gsd-tools.cjs`), and ported prompt artifacts.
- Depends on: Node.js runtime for `.cjs` and `.js` scripts and markdown-driven command execution.
- Used by: GSD command invocations such as `gsd:map-codebase` in `.claude/commands/gsd/map-codebase.md`.

## Data Flow

**Validation Execution Flow:**

1. User imports module using manifest `MDEValidator/MDEValidator.psd1` or directly loads `MDEValidator/MDEValidator.psm1`.
2. User calls `Get-MDEValidationReport` or `Test-MDEConfiguration` in `MDEValidator/MDEValidator.psm1`.
3. `Test-MDEConfiguration` executes each `Test-MDE*` function in sequence and optionally appends policy-verification sub-tests via `Test-MDEPolicyRegistryVerification`.
4. Each test function reads Defender/service/registry state and emits a normalized PSCustomObject through `Write-ValidationResult`.
5. `Get-MDEValidationReport` either returns raw objects, writes console output, or renders/saves HTML.

**Policy Verification Sub-Flow:**

1. `Test-MDEPolicyRegistryVerification` resolves management type using `Get-MDEManagementType` in `MDEValidator/MDEValidator.psm1`.
2. Registry location and key names are selected via `Get-MDEPolicySettingConfig`.
3. `Test-MDEPolicyRegistryValue` probes registry state and returns a structured result object.
4. Verification result is transformed to pass/warning/not-applicable object via `Write-ValidationResult`.

**State Management:**
- Module execution is mostly stateless and computes results on demand.
- Aggregated state is held in in-memory arrays (`$results`) inside `Test-MDEConfiguration` and `Get-MDEValidationReport`.
- Persistent state for workflow tooling is file-backed in markdown/json under `.planning/` and `.claude/get-shit-done/templates/` via `.claude/get-shit-done/bin/gsd-tools.cjs`.

## Key Abstractions

**Validation Result Object:**
- Purpose: Standardize outcomes across heterogeneous checks.
- Examples: `MDEValidator/MDEValidator.psm1`
- Pattern: `Write-ValidationResult` returns PSCustomObject with `TestName`, `Status`, `Message`, `Recommendation`, `Timestamp`.

**Management Type Resolver:**
- Purpose: Select management context (Intune/SSM/SCCM/GPO/None) and route policy reads.
- Examples: `MDEValidator/MDEValidator.psm1`
- Pattern: Registry-driven strategy with fallback logic (`Get-MDEManagedDefenderProductType`, `Get-MDEManagementType`, `Get-MDEManagementTypeFallback`).

**Policy Setting Map:**
- Purpose: Decouple logical setting keys from provider-specific registry paths and names.
- Examples: `MDEValidator/MDEValidator.psm1`
- Pattern: Hashtable-backed lookup in `Get-MDEPolicySettingConfig` returning path/name/display metadata.

**Workflow Command Contract:**
- Purpose: Keep command behavior declarative and tool-constrained.
- Examples: `.claude/commands/gsd/map-codebase.md`, `.claude/get-shit-done/workflows/map-codebase.md`, `.github/prompts/gsd.map-codebase.prompt.md`
- Pattern: Markdown frontmatter + objective/process blocks, with execution delegated to workflow files.

## Entry Points

**PowerShell Module Import:**
- Location: `MDEValidator/MDEValidator.psd1`
- Triggers: `Import-Module MDEValidator` or direct import of manifest path.
- Responsibilities: Load root module and define exported functions.

**Validation API:**
- Location: `MDEValidator/MDEValidator.psm1`
- Triggers: `Test-MDEConfiguration` invocation.
- Responsibilities: Execute all checks and aggregate result objects.

**Reporting API:**
- Location: `MDEValidator/MDEValidator.psm1`
- Triggers: `Get-MDEValidationReport` invocation.
- Responsibilities: Execute validation run and present output in `Object`, `Console`, or `HTML` format.

**Test Runner Entry Point:**
- Location: `Tests/MDEValidator.Tests.ps1`
- Triggers: `Invoke-Pester -Path ./Tests/MDEValidator.Tests.ps1`.
- Responsibilities: Validate module import, exports, and output contracts.

**GSD CLI Entry Point:**
- Location: `.claude/get-shit-done/bin/gsd-tools.cjs`
- Triggers: Node CLI invocation (`node .claude/get-shit-done/bin/gsd-tools.cjs <command>`).
- Responsibilities: Route subcommands to state/phase/roadmap/template/verification operations.

**GSD Command Entry Point:**
- Location: `.claude/commands/gsd/map-codebase.md`
- Triggers: Command execution `gsd:map-codebase`.
- Responsibilities: Orchestrate parallel mapper agents that write codebase docs in `.planning/codebase/`.

## Error Handling

**Strategy:** Fail-safe result reporting over exception propagation for validation operations.

**Patterns:**
- Individual tests wrap provider access in `try/catch` and emit `Fail`/`Warning`/`Info` result objects instead of terminating execution (`MDEValidator/MDEValidator.psm1`).
- Applicability gates return `NotApplicable` for unsupported environments (for example Windows Server-specific checks and SSM incompatibility paths in `MDEValidator/MDEValidator.psm1`).
- Workflow scripts and hooks use defensive parsing and silent fallback for non-critical telemetry/hook paths (`.claude/hooks/gsd-context-monitor.js`, `.claude/hooks/gsd-statusline.js`).

## Cross-Cutting Concerns

**Logging:** Write-Verbose/Write-Warning/Write-Host in `MDEValidator/MDEValidator.psm1`; hook/CLI diagnostics in `.claude/hooks/*.js` and `.claude/get-shit-done/bin/*.cjs`.
**Validation:** Parameter attributes (`[ValidateSet]`, mandatory params), and centralized result schema in `MDEValidator/MDEValidator.psm1`.
**Authentication:** Not detected for the PowerShell validator module runtime path; workflow tooling includes optional external service integration surfaces in `.claude/get-shit-done/bin/gsd-tools.cjs` but no mandatory auth path in core validation flow.

---

*Architecture analysis: 2026-03-04*
