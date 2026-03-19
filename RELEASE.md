# Release Checklist

Before creating a GitHub Release for MDEValidator, confirm each item below.

## Pre-Release Checks

- [ ] `ModuleVersion` in `MDEValidator/MDEValidator.psd1` matches the intended release version (e.g., `1.0.0`)
- [ ] The GitHub release tag format is `v{ModuleVersion}` (e.g., `v1.0.0`) — tag must match the manifest version exactly
- [ ] `ReleaseNotes` in `MDEValidator/MDEValidator.psd1` (under `PrivateData.PSData`) describes what changed in this version
- [ ] `ProjectUri` and `LicenseUri` in the manifest point to the canonical public repo (`https://github.com/NateHutch365/MDEValidator`)
- [ ] `Author` and `CompanyName` in the manifest are set to `Nathan Hutchinson`
- [ ] `NUGET_API_KEY` secret is configured in the GitHub repo Settings → Secrets → Actions before creating the release
- [ ] Release branch created from `main` and named `release/v{version}` (e.g., `release/v1.1.0`)
- [ ] GitHub Release created as **Draft** targeting the `release/v{version}` branch (not `main`, not a floating tag)
- [ ] Manual UAT completed: module imported locally from the release branch, expected commands run successfully
- [ ] All Pre-Release Checks above confirmed before clicking "Publish release"

## Release Branch and UAT Approval

Public releases must originate from a dedicated `release/` branch. This is the free-tier-safe UAT gate — no GitHub paid plan required.

### Branch Naming Convention

```
release/v{version}    e.g. release/v1.1.0, release/v1.1-psgallery
```

All release branches must start with `release/`. The publish workflow rejects releases that target any other branch.

### Draft Release Gate Flow (Recommended)

Use a two-stage GitHub Release process to record UAT approval before the publish workflow triggers:

1. **Create release as Draft** — Go to GitHub → Releases → Draft a new release. Set the target to the `release/v{N}` branch (not `main`, not a tag). Fill in the tag and release notes but **do not publish yet**.
2. **Complete Pre-Release Checks** — Work through the checklist above. The publish workflow has not triggered yet.
3. **Verify manually** — Install or import the module from the release branch locally. Confirm expected outputs.
4. **Record approval** — Check off all items in this checklist and add a comment to the draft release (or PR) confirming UAT is complete.
5. **Click "Publish release"** — This triggers `publish.yml`. The branch check passes because the release targets `release/v{N}`.

### Branch Protection Recommendation (Optional)

For an additional audit trail, configure branch protection on `main`:

> GitHub → Repo Settings → Branches → Add rule → Branch name pattern: `main`
> Enable: "Require a pull request before merging"
> Enable: "Require approvals: 1" (requires a second reviewer or co-maintainer)

This creates a PR review record for every merge from `release/v{N}` → `main`.
For solo maintainers, the draft release gate (above) is sufficient — GitHub does not allow self-approval of PRs by default.

### ⚠️ Critical: Tag From the Release Branch, Not From Main

The GitHub Release **must be created by targeting the `release/v{N}` branch**, not `main` and not a pre-existing floating tag.

| Action | `target_commitish` value | Publish job |
|--------|--------------------------|-------------|
| Release targeting `release/v1.1.0` branch | `release/v1.1.0` | ✅ Runs |
| Release targeting `main` | `main` | ⊘ Skipped |
| Release created from existing tag (not branch) | commit SHA | ⊘ Skipped |

**How to create the release correctly:**
- In GitHub UI: Releases → Draft a new release → "Target" dropdown → select `release/v{N}` branch → type the new tag name → GitHub creates the tag from branch HEAD.
- Do NOT push a tag via `git push origin v1.1.0` and then create a release from that existing tag — this sets `target_commitish` to the commit SHA, not the branch name, and the publish job will be skipped.

## Notes

- Version consistency in Phase 5 is convention-only. Preflight automation (tag vs manifest alignment, `Test-ModuleManifest`, packaged import checks) is added in Phase 7.
- The sync workflow (`sync-public.yml`) automatically pushes this checklist to the public repo on every push to `main`.
