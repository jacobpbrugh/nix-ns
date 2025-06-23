# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build and Development
```bash
# Build the project (release mode)
cargo build --release

# Build for development
cargo build

# Installation (setuid root - most secure with privilege dropping)
sudo chown root:root ./target/release/nix-mount-namespace
sudo chmod u+s ./target/release/nix-mount-namespace

# Run the binary (after installation)
./target/release/nix-mount-namespace

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
- `create_nix_namespace_secure()`: Secure entry point for setuid installations
- `NixNamespaceError`: Public error type for library consumers
- Security validations: Path validation, symlink checks, environment safety
- NFS-aware operations with special handling for root squashing

**`src/security.rs`**: New security module providing:
- `SecurityContext`: Manages user context and privilege operations
- Configuration loading from `~/.config/nix-ns/config.toml`
- TOCTTOU-resistant file operations
- Secure privilege dropping and restoration

**`src/main.rs`**: CLI application with secure setuid operation

**`examples/config.toml`**: Example configuration file

**`tests/integration_tests.rs`**: Integration tests that verify namespace creation and error conditions

### Security Considerations
- **Setuid Installation**: Uses setuid root for privilege management
- **Immediate Privilege Dropping**: Drops root privileges immediately after mount operations
- **Privilege Management**: Drops root privileges permanently immediately after mount operations
- **Configuration Security**: Validates config file ownership and permissions
- **Path Validation**: Comprehensive validation against directory traversal and symlink attacks
- **TOCTTOU Prevention**: Uses file descriptors and atomic operations where possible
- **Environment Sanitization**: Cleans dangerous environment variables
- **NFS Compatibility**: Special handling for NFS environments with root squashing


### Security Model
This implementation uses setuid root exclusively:
1. Requires setuid root installation for privilege elevation
2. Drops ALL privileges immediately after mount operations
3. No lingering elevated privileges during shell execution
4. Follows the principle of least privilege
### Linux Namespace Usage
Uses `unshare(CLONE_NEWNS)` to create a new mount namespace, allowing private `/nix` mounts without affecting the host system.

### Configuration
The Nix store source path can be configured in multiple ways (in priority order):
1. Command-line argument: `--source /path/to/nix/store`
2. Environment variable: `NIX_NS_SOURCE=/path/to/nix/store`
3. Configuration file: `~/.config/nix-ns/config.toml`
4. Default: `~/.local/share/nix-ns/store`

Configuration file format:
```toml
# Source path for your Nix store (relative to home directory)
source_path = ".local/share/nix-ns/store"
# Whether to allow symlinks in the source path (default: false)
allow_symlinks = false
```

Configuration files must be owned by the user or root and not writable by group/others.
