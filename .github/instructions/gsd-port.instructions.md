---
applyTo: ".github/prompts/**/*.prompt.md,.github/agents/**/*.agent.md,scripts/generate-prompts.mjs,scripts/verify-prompts.mjs"
excludeAgent: "code-review"
---

# Copilot Port Guardrails

- Treat .github/prompts as GENERATED output. Prefer editing the generator.
- Keep prompt file names stable and deterministic.
- Keep agent profiles small; do not embed huge workflow docs inside them.
