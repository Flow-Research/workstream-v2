# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in FlowStream, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: wisemrmusa@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Considerations

FlowStream is a zkRollup implementing complex cryptography and consensus. Key security areas:

### Critical Components
- **State Transition Function (STF)**: Must be fully deterministic
- **Cryptography**: Merkle trees, signatures, commitments must be correct
- **zkVM Proofs**: Validity proof verification is critical
- **Account Abstraction**: Authorization checks must be airtight
- **Consensus**: Sequencer, fork choice, and finality

### Known Limitations (Current State)
This is a starter template with many components stubbed. See [.idea/limitations.md](.idea/limitations.md) for details.

**Do not use in production** - this is research/development code.

### Security Best Practices for Contributors

- Never use `unwrap()`, `expect()`, or `panic!()` in security-critical paths
- All cryptographic operations must be constant-time where appropriate
- Validate all external inputs
- Maintain determinism in STF - no non-deterministic operations
- Add tests for edge cases and attack scenarios
- Follow principle of least privilege
- Review all changes to consensus-critical code

## Audit Status

No security audits have been performed yet. This project is in early development.

## Bug Bounty

No bug bounty program is currently active.
