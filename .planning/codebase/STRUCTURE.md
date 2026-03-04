# Codebase Structure

**Analysis Date:** 2026-03-04

## Directory Layout

```text
MDEValidator/
|-- .claude/               # GSD command system: agents, commands, workflows, hooks, templates, and Node tooling
|-- .github/               # Ported prompt artifacts and repository instructions
|-- .planning/             # Planning state and generated codebase mapping documents
|-- images/                # Static documentation assets
|-- MDEValidator/          # PowerShell module source and module manifest
|-- Tests/                 # Pester tests for module behavior and export contracts
|-- README.md              # User-facing usage and operational documentation
|-- LICENSE                # License metadata
`-- .gitignore             # Ignore rules
```

## Directory Purposes

**`.claude/`:**
- Purpose: Houses the GSD workflow framework integrated into the repository.
- Contains: Agent profiles (`.claude/agents/*.md`), command definitions (`.claude/commands/gsd/*.md`), workflow docs (`.claude/get-shit-done/workflows/*.md`), templates (`.claude/get-shit-done/templates/**/*.md`), Node CLI (`.claude/get-shit-done/bin/gsd-tools.cjs`), and hook scripts (`.claude/hooks/*.js`).
- Key files: `.claude/get-shit-done/bin/gsd-tools.cjs`, `.claude/commands/gsd/map-codebase.md`, `.claude/get-shit-done/workflows/map-codebase.md`.

**`.github/`:**
- Purpose: Stores instruction and prompt artifacts used by Copilot/agent workflows.
- Contains: Instruction files and mapped prompt files.
- Key files: `.github/instructions/gsd-port.instructions.md`, `.github/prompts/gsd.map-codebase.prompt.md`.

**`.planning/`:**
- Purpose: Workspace planning outputs and generated analysis assets.
- Contains: Codebase mapping docs in `.planning/codebase/` and other planning state when initialized.
- Key files: `.planning/codebase/ARCHITECTURE.md`, `.planning/codebase/STRUCTURE.md`.

**`MDEValidator/`:**
- Purpose: Production PowerShell module implementation.
- Contains: Module manifest and module script.
- Key files: `MDEValidator/MDEValidator.psd1`, `MDEValidator/MDEValidator.psm1`.

**`Tests/`:**
- Purpose: Validation of module import/export behavior and function output contracts.
- Contains: Pester test suite.
- Key files: `Tests/MDEValidator.Tests.ps1`.

**`images/`:**
- Purpose: Documentation screenshots.
- Contains: Image assets for README/report examples.
- Key files: `images/html_report_screenshot.png`.

## Key File Locations

**Entry Points:**
- `MDEValidator/MDEValidator.psd1`: PowerShell module manifest entry and export surface declaration.
- `MDEValidator/MDEValidator.psm1`: Runtime implementation and exported public functions.
- `Tests/MDEValidator.Tests.ps1`: Test execution entry for Pester.
- `.claude/get-shit-done/bin/gsd-tools.cjs`: CLI router for GSD operations.
- `.claude/commands/gsd/map-codebase.md`: Command entry that orchestrates codebase mapping.

**Configuration:**
- `.claude/get-shit-done/templates/config.json`: GSD runtime/config defaults.
- `.claude/package.json`: Node module format declaration for `.claude` scripts.
- `.github/instructions/gsd-port.instructions.md`: Prompt-porting guardrails.

**Core Logic:**
- `MDEValidator/MDEValidator.psm1`: Validation logic, policy resolution, and report generation.
- `.claude/get-shit-done/bin/lib/*.cjs`: State/phase/roadmap/template/verification implementation for GSD CLI.
- `.claude/hooks/gsd-context-monitor.js`: Context threshold monitoring hook.
- `.claude/hooks/gsd-statusline.js`: Statusline formatting and context bridge output.

**Testing:**
- `Tests/MDEValidator.Tests.ps1`: Pester test suite for module contracts.

## Naming Conventions

**Files:**
- `PascalCase` for PowerShell module artifacts: `MDEValidator/MDEValidator.psm1`, `MDEValidator/MDEValidator.psd1`, `Tests/MDEValidator.Tests.ps1`.
- `kebab-case` for GSD markdown command/prompt files: `.claude/commands/gsd/plan-phase.md`, `.github/prompts/gsd.plan-phase.prompt.md`.
- `kebab-case`/descriptive lowercase for Node hooks and CJS helpers: `.claude/hooks/gsd-check-update.js`, `.claude/get-shit-done/bin/lib/roadmap.cjs`.

**Directories:**
- Dot-prefixed directories for tooling/config domains: `.claude/`, `.github/`, `.planning/`.
- Feature-oriented plain names for runtime module and tests: `MDEValidator/`, `Tests/`, `images/`.

## Where to Add New Code

**New Feature:**
- Primary code: Add new `Test-MDE*` or helper/orchestrator function in `MDEValidator/MDEValidator.psm1`.
- Export contract: Add function name to `FunctionsToExport` in `MDEValidator/MDEValidator.psd1` and export list in `MDEValidator/MDEValidator.psm1`.
- Tests: Add or extend assertions in `Tests/MDEValidator.Tests.ps1`.

**New Component/Module:**
- Implementation: Keep module runtime behavior in `MDEValidator/MDEValidator.psm1`; if splitting is introduced, keep manifest `RootModule` and export contract in `MDEValidator/MDEValidator.psd1` aligned.

**Utilities:**
- Shared PowerShell helpers: Place in helper region of `MDEValidator/MDEValidator.psm1` near existing reusable functions.
- GSD CLI helper logic: Add `.cjs` helper modules under `.claude/get-shit-done/bin/lib/` and wire command routing in `.claude/get-shit-done/bin/gsd-tools.cjs`.
- GSD command surface: Add command definitions under `.claude/commands/gsd/` and corresponding workflows under `.claude/get-shit-done/workflows/`.

## Special Directories

**`.planning/codebase/`:**
- Purpose: Generated codebase maps consumed by planning/execution commands.
- Generated: Yes.
- Committed: Yes.

**`.github/prompts/`:**
- Purpose: Prompt artifacts for GSD commands.
- Generated: Yes (treated as generated output per `.github/instructions/gsd-port.instructions.md`).
- Committed: Yes.

**`.claude/get-shit-done/templates/`:**
- Purpose: Canonical templates for generated planning docs and codebase map docs.
- Generated: No.
- Committed: Yes.

---

*Structure analysis: 2026-03-04*
