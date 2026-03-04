# Research Summary: MDEValidator Restructuring + UI

**Domain:** PowerShell module restructuring, testing, desktop UI, publishing
**Researched:** 2026-03-04
**Overall Confidence:** HIGH

## Executive Summary

MDEValidator is a working monolithic PowerShell module (~2000+ lines, ~45 exported functions) that validates Microsoft Defender for Endpoint configurations. The restructuring, testing, UI, and publishing stack is well-established in the PowerShell ecosystem with no ambiguity in technology choices.

The module restructuring follows the universal function-per-file pattern (Public/Private folders with dot-source loader). Testing uses Pester 5.x with its built-in `Mock` command — the only real option for PowerShell, and well-suited to mocking Defender cmdlets, registry reads, and service queries. The desktop UI uses WPF with runtime-loaded XAML — native to Windows, zero dependencies, and proven for PowerShell IT tools. CI/CD uses GitHub Actions with `windows-latest` runners.

There are no risky technology choices in this stack. Every component is mature, well-documented, and standard practice. The main execution risk is in the restructuring itself (preserving 45-function API surface during split) and the mock coverage (ensuring all external dependency paths are adequately mocked).

## Key Findings

**Stack:** Pester 5.6+ for testing, WPF for UI, InvokeBuild for build automation, PSScriptAnalyzer for linting, GitHub Actions for CI/CD. All standard, all mature.
**Architecture:** Function-per-file with Public/Private folder convention. Dot-source loader in .psm1. XAML-based WPF UI in a UI/ subfolder.
**Critical pitfall:** Pester mock scoping — mocks must be in the correct `BeforeAll`/`It` scope or they silently don't apply. Most common source of "tests pass but shouldn't" bugs.

## Implications for Roadmap

Based on research, suggested phase structure:

1. **Module Restructuring** — Split monolithic .psm1 into function-per-file layout
   - Addresses: Navigability, maintainability, testability
   - Avoids: Losing exports or breaking public API during split
   - Rationale: Must happen first — testing individual functions requires individual files

2. **Testing Infrastructure** — Add Pester mock-based tests for all validation functions
   - Addresses: CI-compatible testing without live Defender instance
   - Avoids: Mock scoping bugs, incomplete mock coverage
   - Rationale: Depends on restructured files to test against. Must be solid before UI work begins.

3. **Build & Lint Pipeline** — InvokeBuild tasks + PSScriptAnalyzer + GitHub Actions CI
   - Addresses: Automated quality gates, repeatable builds
   - Avoids: Manual publishing errors, lint regressions
   - Rationale: Can run in parallel with testing phase or immediately after

4. **Desktop UI** — WPF application shell with DataGrid display
   - Addresses: Visual validation results for non-terminal users
   - Avoids: Over-engineering (Electron, MAUI, web stack)
   - Rationale: Depends on stable, tested module as foundation

5. **PSGallery Publishing** — Manifest completion + publish pipeline
   - Addresses: Easy installation for target audience
   - Avoids: Missing manifest fields, broken publish
   - Rationale: Final step — needs complete, tested, linted module

**Phase ordering rationale:**
- Restructuring enables testability (can't mock individual functions in a monolith easily)
- Testing enables confident UI development (validation logic is verified)
- CI/CD can start once tests exist
- UI is independent of publishing and comes before it
- Publishing is last because it needs everything else done

**Research flags for phases:**
- Phase 1 (Restructuring): Standard patterns, unlikely to need research
- Phase 2 (Testing): May need phase-specific research for complex mock scenarios (ASR rules, policy registry verification)
- Phase 3 (CI/CD): Standard patterns, unlikely to need research
- Phase 4 (UI): May need research for specific WPF DataGrid patterns and color-coded status rendering
- Phase 5 (Publishing): Standard process, unlikely to need research

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All tools are mature, standard, well-documented |
| Features | HIGH | Feature landscape is defined by existing module capabilities |
| Architecture | HIGH | Function-per-file is universal convention |
| Pitfalls | HIGH | Well-known pitfalls from community experience |

## Gaps to Address

- platyPS v2 GA status — verify if v2 is stable or fall back to v0.14.2 for help generation
- PSResourceGet adoption — verify enterprise readiness or stick with PowerShellGet 2.x
- WPF DataGrid specific patterns for validation result display — may need phase-specific research when UI work begins
