# Contributing to WorkStream

Thank you for your interest in contributing to WorkStream! This document provides guidelines for contributing to this sovereign zkRollup project.

## Code of Conduct

Be respectful, collaborative, and constructive. We welcome contributions from everyone.

## Getting Started

1. **Read the research**: Familiarize yourself with the design in `/research/` directory
2. **Understand the architecture**: Read `docs/ARCHITECTURE.md`
3. **Check limitations**: Review `.idea/limitations.md` to understand current state
4. **Fork and clone**: Fork the repo and clone your fork locally
5. **Build and test**: Ensure everything compiles and tests pass

```bash
cargo build --workspace
cargo test --workspace
```

## Development Workflow

### Branching Strategy
- `main`: Stable, production-ready code
- `develop`: Integration branch for features
- Feature branches: `feature/description` or `fix/description`

### Making Changes

1. Create a feature branch from `develop`
2. Make your changes with clear, focused commits
3. Follow Rust style guidelines (use `rustfmt`)
4. Add tests for new functionality
5. Update documentation as needed
6. Run checks before pushing

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `security`

Examples:
- `feat(stf): implement task claim with commit-reveal`
- `fix(crypto): correct SMT proof verification`
- `docs: update architecture diagram`

## Code Standards

### Rust Guidelines
- Use `rustfmt` with default settings
- Follow Clippy recommendations (treat warnings as errors in CI)
- Prefer explicit error types over `unwrap()`/`expect()` in library code
- Use `Result<T, Error>` from `workstream-core`
- Add `#[derive(...)]` as appropriate

### Security-Critical Code
For changes to cryptography, STF, consensus, or state management:

- **Determinism**: No wall clocks (`SystemTime`), network I/O, file I/O, or randomness in STF execution
- **Validation**: Validate all inputs, especially from transactions
- **Testing**: Add unit tests and property-based tests where appropriate
- **Review**: These changes require extra scrutiny
- **Comments**: Document security assumptions and invariants

### Testing Requirements
- Unit tests for all new public functions
- Integration tests for protocol flows
- Property-based tests for cryptographic operations
- All tests must pass in CI

## Pull Request Process

1. Update `README.md` or docs if needed
2. Add tests covering your changes
3. Ensure CI passes (fmt, clippy, tests, build)
4. Fill out the PR template completely
5. Request review from maintainers
6. Address review feedback
7. Squash commits if requested

## Areas Needing Help

Check the [limitations](.idea/limitations.md) document for priority areas:
- **Cryptography**: SMT/MMR implementations, canonical serialization
- **STF**: Implementing remaining action handlers
- **zkVM**: Proof generation and verification
- **Networking**: P2P and sync
- **Privacy**: Shielded notes implementation

## Questions?

Feel free to open an issue for discussion before starting major work.

Thank you for contributing to WorkStream!
