# Codebase Concerns

**Analysis Date:** 2026-03-04

## Tech Debt

**Monolithic validation module and high change coupling:**
- Issue: Most product logic is concentrated in one large script module, with dozens of checks and report rendering in a single file.
- Files: `MDEValidator/MDEValidator.psm1`
- Impact: Small changes can create broad regressions; review and testing effort grows as the file grows.
- Fix approach: Split into focused files/modules (helpers, management-detection, individual check groups, reporting) and keep `Test-MDEConfiguration` as an orchestrator only.

**Duplicated public API declarations:**
- Issue: Exported function lists are maintained in both the manifest and script module.
- Files: `MDEValidator/MDEValidator.psd1`, `MDEValidator/MDEValidator.psm1`
- Impact: Risk of export drift during future additions/removals; maintenance overhead.
- Fix approach: Keep one source of truth for exports (prefer manifest list), then validate parity in tests.

**Broad exception swallowing across core detection paths:**
- Issue: Many `catch {}` / fallback patterns suppress error context and return generic statuses.
- Files: `MDEValidator/MDEValidator.psm1`, `.claude/get-shit-done/bin/lib/commands.cjs`
- Impact: Real runtime problems can be misclassified as benign states, reducing trust in results and making diagnostics harder.
- Fix approach: Capture structured error details (source, operation, exception type) in `Info`/`Fail` results and avoid empty catches.

## Known Bugs

**Todo completion directory mismatch in GSD tooling:**
- Symptoms: Workflow docs instruct moving todos to `.planning/todos/done/`, while CLI command writes to `.planning/todos/completed/`.
- Files: `.claude/get-shit-done/workflows/check-todos.md`, `.claude/get-shit-done/workflows/add-todo.md`, `.claude/get-shit-done/bin/lib/commands.cjs`, `.claude/get-shit-done/bin/lib/init.cjs`
- Trigger: Running todo completion flow via documented workflow + CLI commands.
- Workaround: Standardize manually on one directory name in local usage until code and docs are aligned.

**Report summary inconsistency with documented example:**
- Symptoms: README example summary includes Info count, while console output implementation omits Info.
- Files: `README.md`, `MDEValidator/MDEValidator.psm1`
- Trigger: Running `Get-MDEValidationReport -OutputFormat Console` and comparing to README output section.
- Workaround: Use object output and compute status counts externally for accurate reporting breakdown.

## Security Considerations

**Sensitive endpoint posture details are written to unprotected report locations by default:**
- Risk: HTML output includes host identity and detailed security posture, and default output can land in a shared temp directory.
- Files: `MDEValidator/MDEValidator.psm1`
- Current mitigation: HTML-encoding is applied to rendered fields to reduce XSS risk.
- Recommendations: Require explicit output path for HTML mode in hardened environments, add optional redaction mode, and document handling requirements for generated reports.

**Ambiguous handling of access-denied scenarios can mask enforcement failures:**
- Risk: Security-relevant checks can downgrade to warning/info-like behavior when registry/cmdlet access fails, without enough provenance.
- Files: `MDEValidator/MDEValidator.psm1`
- Current mitigation: Many checks return `Fail`/`Warning` with recommendations.
- Recommendations: Add explicit error classification (`AccessDenied`, `CmdletMissing`, `RegistryMissing`) and include machine-readable reason codes in output objects.

## Performance Bottlenecks

**Repeated expensive cmdlet calls across checks:**
- Problem: Multiple checks independently call `Get-MpPreference`/`Get-MpComputerStatus`, increasing runtime and overhead.
- Files: `MDEValidator/MDEValidator.psm1`
- Cause: Per-check direct dependency calls without shared cache/context.
- Improvement path: Build a single snapshot context in `Test-MDEConfiguration` and pass it to each check function.

**String-heavy HTML assembly in a large loop:**
- Problem: Report generation concatenates large HTML strings repeatedly.
- Files: `MDEValidator/MDEValidator.psm1`
- Cause: Incremental string appends in loop.
- Improvement path: Use array buffering + `-join` pattern for large report bodies and isolate templating helpers.

## Fragile Areas

**Management-type inference logic is distributed and heuristic-heavy:**
- Files: `MDEValidator/MDEValidator.psm1`
- Why fragile: Multiple functions infer management state using different registry combinations and fallback behavior.
- Safe modification: Consolidate management detection into one authoritative function returning typed status + evidence.
- Test coverage: Current tests verify shape/allowed values more than branch-level decision correctness.

**Cross-platform command assumptions in workflow docs:**
- Files: `.claude/get-shit-done/workflows/add-todo.md`, `.claude/get-shit-done/workflows/check-todos.md`, `.claude/get-shit-done/workflows/cleanup.md`
- Why fragile: Workflows rely on Unix shell commands (`mkdir -p`, `mv`, `grep`) in a Windows-heavy repository context.
- Safe modification: Provide PowerShell-native command variants and environment-aware command blocks.
- Test coverage: No automated validation of workflow command portability detected.

## Scaling Limits

**Adding new checks currently requires edits in multiple places:**
- Current capacity: A new validation check typically touches function implementation, orchestrator invocation, export lists, docs, and tests.
- Limit: Manual synchronization overhead grows with each new check, increasing omission risk.
- Scaling path: Introduce a declarative check registry (metadata + executor) to reduce fan-out edits.

## Dependencies at Risk

**Test dependency is not declared in module manifest:**
- Risk: Test execution depends on local/global Pester installation state.
- Impact: Inconsistent developer and CI behavior if Pester version differs or missing.
- Migration plan: Add explicit test-tooling bootstrap (version pin + install script) and CI test job.

## Missing Critical Features

**No deterministic CI enforcement for validation quality:**
- Problem: Repository shows local test instructions but no detected CI gate for tests/linting on pull requests.
- Blocks: Regressions can merge without automated validation.

**Limited machine-readable failure taxonomy for automation consumers:**
- Problem: Result objects carry human-readable messages but no normalized error/category codes.
- Blocks: Reliable downstream automation and trend analysis.

## Test Coverage Gaps

**Behavioral branch coverage is weak compared to API-shape assertions:**
- What's not tested: Deep branch behavior for access-denied, missing cmdlets, management-type edge cases, and policy-verification decision paths.
- Files: `Tests/MDEValidator.Tests.ps1`, `MDEValidator/MDEValidator.psm1`
- Risk: False positives/false negatives can ship unnoticed, especially in enterprise edge environments.
- Priority: High

**No mocking strategy for external dependencies:**
- What's not tested: Deterministic outcomes when Defender cmdlets/services/registry calls return controlled values.
- Files: `Tests/MDEValidator.Tests.ps1`
- Risk: Tests depend on host state and can miss regressions or become flaky across environments.
- Priority: High

---

*Concerns audit: 2026-03-04*
