# Release Guide

This document describes how to create a new release of M-Security after merging changes to the `main` branch.

## Versioning

M-Security follows [Semantic Versioning](https://semver.org/) (SemVer):

- **MAJOR** (`X.0.0`) — Breaking API changes (e.g., removing a function, changing a return type).
- **MINOR** (`0.X.0`) — New features, backward-compatible (e.g., adding a new cipher or hash algorithm).
- **PATCH** (`0.0.X`) — Bug fixes and patches, backward-compatible (e.g., fixing edge case in encryption).

For pre-release versions, append a suffix: `0.2.0-dev.1`, `1.0.0-beta.1`.

## Release Workflow

### 1. Prepare the Release Branch

All development happens on the `dev` branch. When ready to release:

```bash
# Ensure dev is up to date
git checkout dev
git pull origin dev

# Create a release branch
git checkout -b release/vX.Y.Z
```

### 2. Update Version Numbers

Update the version in these files:

**`pubspec.yaml`** (root):
```yaml
version: X.Y.Z
```

**`rust/Cargo.toml`**:
```toml
[package]
version = "X.Y.Z"
```

### 3. Update CHANGELOG.md

Move the `## Unreleased` section content under a new version header with the current date:

```markdown
## X.Y.Z - YYYY-MM-DD

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description
```

Follow [Keep a Changelog](https://keepachangelog.com/) format with these categories:
- **Added** — New features
- **Changed** — Changes to existing functionality
- **Deprecated** — Features that will be removed in future versions
- **Removed** — Removed features
- **Fixed** — Bug fixes
- **Security** — Vulnerability fixes

### 4. Run All Checks

```bash
# Rust checks
cd rust
cargo clippy --all-targets -- -D warnings
cargo test
cd ..

# Dart checks
flutter pub get
flutter_rust_bridge_codegen generate
dart run build_runner build --delete-conflicting-outputs
dart analyze lib/ integration_test/

# Run integration tests (requires a device/simulator)
cd example
flutter test integration_test/
cd ..
```

### 5. Open a Pull Request to `main`

```bash
git add -A
git commit -m "chore(release): prepare vX.Y.Z"
git push origin release/vX.Y.Z
```

Open a PR from `release/vX.Y.Z` to `main`. Ensure CI passes and get a maintainer review.

### 6. Merge and Tag

After the PR is approved and merged:

```bash
git checkout main
git pull origin main

# Create an annotated tag
git tag -a vX.Y.Z -m "Release vX.Y.Z"

# Push the tag
git push origin vX.Y.Z
```

### 7. Create a GitHub Release

Using the GitHub CLI:

```bash
gh release create vX.Y.Z \
  --title "vX.Y.Z" \
  --notes-file CHANGELOG_EXCERPT.md
```

Or via the GitHub web UI:

1. Go to [Releases](https://github.com/MicroClub-USTHB/M-Security/releases).
2. Click **"Draft a new release"**.
3. Select the `vX.Y.Z` tag.
4. Set the title to `vX.Y.Z`.
5. Copy the relevant CHANGELOG.md section into the description.
6. Click **"Publish release"**.

### 8. Publish to pub.dev

> **First-time setup**: Ensure you are authenticated with `dart pub login` and that the package publisher is configured on pub.dev. See [Verified Publishers](https://dart.dev/tools/pub/verified-publishers).

```bash
# Dry run first — review what will be published
dart pub publish --dry-run

# If everything looks good, publish
dart pub publish
```

**Important notes:**
- Publishing is **permanent** — you cannot unpublish a version (only retract within 7 days).
- Ensure `lib/src/rust/` generated files are included (they are needed by consumers).
- The `.pubignore` or `.gitignore` controls which files are excluded from the published package.
- Verify the package size is under 100 MB (gzip) / 256 MB (uncompressed).

### 9. Post-Release

After publishing:

```bash
# Merge main back into dev to sync version numbers
git checkout dev
git pull origin dev
git merge main
git push origin dev
```

Add a new `## Unreleased` section at the top of `CHANGELOG.md` on `dev`:

```markdown
## Unreleased

### Added

### Changed

### Fixed
```

## Quick Reference

| Step | Command |
|------|---------|
| Create release branch | `git checkout -b release/vX.Y.Z` |
| Run Rust tests | `cd rust && cargo test` |
| Run Dart analysis | `dart analyze lib/ integration_test/` |
| Dry-run publish | `dart pub publish --dry-run` |
| Tag the release | `git tag -a vX.Y.Z -m "Release vX.Y.Z"` |
| Push the tag | `git push origin vX.Y.Z` |
| Create GitHub release | `gh release create vX.Y.Z --title "vX.Y.Z"` |
| Publish to pub.dev | `dart pub publish` |

## Hotfix Releases

For urgent fixes to the current stable release:

```bash
# Branch from the release tag
git checkout -b hotfix/vX.Y.Z main

# Make the fix, then follow steps 2-9 above with an incremented PATCH version
```

## Checklist

Use this checklist when preparing a release:

- [ ] Version updated in `pubspec.yaml`
- [ ] Version updated in `rust/Cargo.toml`
- [ ] CHANGELOG.md updated with release date
- [ ] All Rust tests pass (`cargo test`)
- [ ] Clippy clean (`cargo clippy -- -D warnings`)
- [ ] Dart analysis clean (`dart analyze`)
- [ ] Integration tests pass
- [ ] CI pipeline passes on the PR
- [ ] PR merged to `main`
- [ ] Git tag created and pushed
- [ ] GitHub Release created
- [ ] Published to pub.dev (`dart pub publish`)
- [ ] `main` merged back into `dev`
- [ ] `Unreleased` section added to CHANGELOG.md on `dev`
