# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build and Development
```bash
# Build the project (release mode)
cargo build --release

# Build for development
cargo build

# Run the binary (requires sudo)
sudo ./target/release/nix-mount-namespace /path/to/your/nix/store

# Format code
cargo fmt

# Run clippy lints
cargo clippy

# Run tests
cargo test

# Run a specific test
cargo test test_name

# Check for compilation errors without building
cargo check
```

## Architecture

### Core Design
This is a security-focused Linux utility that creates private mount namespaces to bind mount user-specific Nix directories to `/nix`. The architecture emphasizes:

1. **Library/Binary Separation**: Core functionality in `lib.rs` with a thin CLI wrapper in `main.rs`
2. **Security-First**: Extensive validation against symlink attacks, path traversal, and environment tampering
3. **Error Handling**: Dual approach using custom `NixNamespaceError` for public API and `anyhow` for internal implementation

### Key Components

**`src/lib.rs`**: Core library providing:
- `create_nix_namespace()`: Main function that creates namespace and performs bind mount
- `NixNamespaceError`: Public error type for library consumers
- Security validations: Path validation, symlink checks, environment safety
- NFS-aware operations with special handling for root squashing

**`src/main.rs`**: CLI application using clap for argument parsing, calls library function

**`tests/integration_tests.rs`**: Integration tests that verify namespace creation and error conditions

### Security Considerations
- Must run as root (sudo) for mount operations
- Validates all paths to prevent directory traversal
- Checks for suspicious symlinks
- Sanitizes environment variables before executing subprocesses
- Special handling for NFS environments where root access might be squashed

### Linux Namespace Usage
Uses `unshare(CLONE_NEWNS)` to create a new mount namespace, allowing private `/nix` mounts without affecting the host system.
