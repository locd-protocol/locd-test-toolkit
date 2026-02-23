# Contributing to Loc'd Protocol Test Toolkit

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Git
- A GitHub account

### Setup

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/locd-test-toolkit.git
   cd locd-test-toolkit
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/locd-protocol/locd-test-toolkit.git
   ```
4. Install development dependencies:
   ```bash
   # For fuzzing (optional)
   rustup install nightly
   cargo install cargo-fuzz

   # For coverage (optional)
   cargo install cargo-tarpaulin

   # For auditing (optional)
   cargo install cargo-audit
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-new-feature
```

Use descriptive branch names:
- `feature/` for new features
- `fix/` for bug fixes
- `docs/` for documentation
- `test/` for test additions

### 2. Make Changes

Follow the code style guidelines below.

### 3. Test Your Changes

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p locd-core

# Run benchmarks (if applicable)
cargo bench -p locd-bench

# Run security checks
cargo run -p locd-audit -- scan

# Format code
cargo fmt

# Run linter
cargo clippy --workspace -- -D warnings
```

### 4. Commit Changes

Write clear commit messages:
```
Add feature X to handle Y

- Implement core logic
- Add tests
- Update documentation

Fixes #123
```

### 5. Push and Create PR

```bash
git push origin feature/my-new-feature
```

Then create a pull request on GitHub.

## Code Style

### Rust Style

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting (enforced in CI)
- Use `cargo clippy` to catch common mistakes
- Maximum line length: 100 characters
- Prefer explicit types in public APIs

### Documentation

- Document all public APIs with `///` doc comments
- Include examples in doc comments
- Add module-level documentation with `//!`
- Update README if adding new components

### Testing

- Write unit tests for all new logic
- Add integration tests for cross-crate features
- Include edge cases and negative tests
- Aim for >80% code coverage

**Test Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = setup_test_data();

        // Act
        let result = my_function(input);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_invalid_input() {
        my_function(invalid_input());
    }
}
```

## Project Structure

```
locd-test-toolkit/
├── crates/           # Core protocol libraries
├── tools/            # CLI applications
├── locd-bench/       # Performance benchmarks
├── locd-audit/       # Security tools
├── locd-mock-dns/    # Testing infrastructure
├── examples/         # Usage examples
├── docs/             # Additional documentation
└── .github/          # CI/CD workflows
```

## Adding New Features

### New Crate

1. Create directory: `crates/locd-mynewcrate/`
2. Add to workspace in root `Cargo.toml`
3. Follow existing crate structure
4. Add comprehensive tests
5. Write README.md
6. Update main README

### New CLI Tool

1. Create directory: `tools/locd-mytool/`
2. Use clap for argument parsing
3. Follow existing tool patterns
4. Add help text and examples
5. Update tools README

### New Test Suite

1. Add to appropriate crate's `tests/` directory
2. Follow naming convention: `test_feature.rs`
3. Include positive and negative cases
4. Document test purpose

## Pull Request Process

1. **Update Documentation**
   - Update README if adding features
   - Add doc comments to new APIs
   - Include examples if helpful

2. **Pass All Checks**
   - All tests must pass
   - `cargo fmt --check` must pass
   - `cargo clippy` must have no warnings
   - No new security vulnerabilities

3. **Get Review**
   - At least one maintainer must approve
   - Address all review comments
   - Rebase on main if needed

4. **Merge**
   - Maintainer will merge when ready
   - Delete your branch after merge

## Reporting Bugs

Use GitHub Issues with this information:

- **Description:** Clear description of the bug
- **Steps to Reproduce:** Minimal example
- **Expected Behavior:** What should happen
- **Actual Behavior:** What actually happens
- **Environment:** Rust version, OS, etc.
- **Logs:** Relevant error messages

## Security Issues

**Do not open public issues for security vulnerabilities.**

Email security@locd-protocol.org with:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the community

### Unacceptable Behavior

- Harassment or discriminatory language
- Personal attacks
- Publishing others' private information
- Other unprofessional conduct

## Questions?

- Open a GitHub Discussion
- Join our Discord: [link]
- Email: dev@locd-protocol.org

## License

By contributing, you agree that your contributions will be licensed under MIT OR Apache-2.0.

---

Thank you for contributing to the Loc'd Protocol Test Toolkit!
