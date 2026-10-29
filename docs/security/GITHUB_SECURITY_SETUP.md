# GitHub Security & Collaboration Setup

This document outlines all the security measures, workflows, and protections implemented for the FlowStream repository.

## Overview

FlowStream is a security-critical zkRollup project. All configurations below have been added to ensure safe collaboration, supply chain security, and code quality.

## Implemented Components

### 1. GitHub Actions Workflows

| Workflow | File | Purpose | Trigger |
|----------|------|---------|---------|
| **CI** | `.github/workflows/ci.yml` | Linting, testing, building, security audit, coverage | Push/PR to `main`, `develop` |
| **CodeQL** | `.github/workflows/codeql.yml` | Static analysis for security vulnerabilities | Push/PR to `main`, `develop`, Weekly |
| **Scorecard** | `.github/workflows/scorecard.yml` | OpenSSF supply-chain security assessment | Branch protection changes, Weekly, Push to `main` |
| **Dependency Review** | `.github/workflows/dependency-review.yml` | Scans dependencies for vulnerabilities in PRs | Pull requests |
| **Release** | `.github/workflows/release.yml` | Automated multi-platform releases with checksums | Tags `v*.*.*` |

### 2. Branch Protection (Rulesets)

Three rulesets have been configured in `.github/rulesets/`:

#### `main-protection.json`
- **Target**: `main` branch
- **Approvals required**: 2
- **Code owner reviews required**: Yes
- **Stale reviews dismissed**: Yes
- **Conversation resolution required**: Yes
- **Linear history required**: Yes
- **Signed commits required**: Yes
- **Force pushes/deletions blocked**: Yes
- **Merge methods**: Squash only
- **Required checks**: Check, Test, Clippy, Build, Security Audit

#### `develop-protection.json`
- **Target**: `develop` branch
- **Approvals required**: 1
- **Code owner reviews required**: Yes
- **Stale reviews dismissed**: Yes
- **Conversation resolution required**: Yes
- **Force pushes/deletions blocked**: Yes
- **Merge methods**: Squash, Rebase
- **Required checks**: Check, Test, Clippy, Security Audit

#### `tags-protection.json`
- **Target**: Tags matching `v*`
- **Deletions blocked**: Yes
- **Force pushes blocked**: Yes

### 3. Issue & PR Templates

- **PR Template**: `.github/PULL_REQUEST_TEMPLATE.md` - Includes security checklist for crypto/consensus changes
- **Bug Report**: `.github/ISSUE_TEMPLATE/bug_report.md`
- **Feature Request**: `.github/ISSUE_TEMPLATE/feature_request.md`
- **Config**: `.github/ISSUE_TEMPLATE/config.yml` - Links to research docs

### 4. Dependency Management

- **Dependabot**: `.github/dependabot.yml` - Weekly updates for Cargo and GitHub Actions

### 5. Code Ownership

- **CODEOWNERS**: Requires reviews from designated owners for critical paths
  - Global: `@wisemrmusa`
  - Crypto/State: `@wisemrmusa` (security-critical)
  - STF/Tx: `@wisemrmusa` (consensus-critical)
  - Binaries/Workflows: `@wisemrmusa`

### 6. Documentation

- **CONTRIBUTING.md**: Development workflow, commit conventions, security guidelines
- **SECURITY.md**: Vulnerability reporting process
- **This document**: Setup instructions

## Manual Configuration Required

Some settings must be configured in GitHub UI as they can't be fully automated via files:

### Repository Settings > Security & Analysis
- [ ] Enable Dependency graph
- [ ] Enable Dependabot alerts
- [ ] Enable Dependabot security updates
- [ ] Enable Secret scanning
- [ ] Enable Push protection
- [ ] Enable Code scanning (CodeQL) - workflow is added
- [ ] Enable Private vulnerability reporting

### Repository Settings > Branches > Rulesets
Import the rulesets from `.github/rulesets/` or create them manually using the JSON files as reference.

### Repository Settings > Environments
Create a `release` environment with:
- Required reviewers
- Wait timer (e.g., 5 minutes)
- Deployment branch protection (only tags `v*`)

### Repository Settings > Actions > General
- [ ] Set workflow permissions to "Read repository contents and packages permissions"
- [ ] Allow GitHub Actions to create and approve pull requests (if needed for some actions)
- [ ] Pin actions to full length commit SHAs (already done in workflows)

### Secrets (if needed)
Add the following secrets if using external services:
- `CODECOV_TOKEN` - For code coverage uploads
- Any deployment keys for environments

## Security Best Practices Enforced

1. **Least Privilege**: All workflows use minimal permissions
2. **Pinned Actions**: Critical actions pinned to commit SHAs
3. **Supply Chain Security**: Scorecard, dependency review, Dependabot
4. **Code Quality**: fmt, clippy with `-D warnings`, tests required
5. **Security Scanning**: CodeQL, cargo audit
6. **Review Requirements**: CODEOWNERS + required approvals
7. **History Protection**: No force pushes, linear history on main
8. **Secret Protection**: Push protection enabled
9. **Determinism Focus**: PR template includes STF determinism checklist

## Verification

After pushing, verify:
```bash
# Check workflows are valid
gh workflow list

# View branch protection
gh api repos/:owner/:repo/rulesets

# Check security status
gh api repos/:owner/:repo --jq '.security_and_analysis'
```

## Notes

- All workflows are configured for the current skeleton state
- As the project matures, additional security measures may be needed (e.g., fuzzing, formal verification)
- For zkRollup-specific security, consider adding circuits audits and proof verification tests
