# Phase 2: Testing Infrastructure - Context

**Gathered:** 2026-03-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Build mock-based Pester 5.x testing infrastructure so every public validation function and private helper has coverage that runs without Defender installed and without admin privileges, including JaCoCo coverage output.

This phase defines how tests are structured and executed; it does not add new product capabilities.

</domain>

<decisions>
## Implementation Decisions

### Test suite structure and granularity
- Organize tests by module visibility with two roots: `Tests/Public` and `Tests/Private`.
- Use a flat file-per-function layout inside each root.
- Name test files exactly as `<FunctionName>.Tests.ps1` for direct function-to-test traceability.
- Keep each test file independent with no execution order assumptions.
- Use minimal shared bootstrap plus explicit per-file setup.
- Migrate incrementally from the current monolithic suite, with parity checks during transition.
- Maintain an explicit mapping checklist proving each function has a corresponding test.

### Claude's Discretion
- Final choice for private helper test grouping within `Tests/Private` (one-helper-per-file vs combined helper file), while preserving TEST-06 coverage expectations.

</decisions>

<specifics>
## Specific Ideas

- Prioritize maintainability and auditability by making function-to-test mapping obvious from filenames and checklist.
- Prefer safe transition over one-shot rewrite by using incremental split with parity checks.

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `Tests/MDEValidator.Tests.ps1`: existing assertion style and module import bootstrap can seed per-file test patterns.
- `run-tests.ps1`: existing test runner script can be adapted to execute the new folder-based suite.

### Established Patterns
- Module source is already function-per-file under `MDEValidator/Public` and `MDEValidator/Private`, which supports matching file-per-function tests.
- Current tests use Pester `Describe`/`Context`/`It` structure and `Should` assertions.
- Current suite has no mocking; Phase 2 introduces mock boundaries for external dependencies.

### Integration Points
- Test execution entry points: `run-tests.ps1` and direct `Invoke-Pester` calls.
- Coverage requirement integration: Pester execution must emit JaCoCo output for downstream CI use.
- Validation of coverage scope should tie back to exported and private function inventory from module file layout.

</code_context>

<deferred>
## Deferred Ideas

None - discussion stayed within phase scope.

</deferred>

---

*Phase: 02-testing-infrastructure*
*Context gathered: 2026-03-07*
