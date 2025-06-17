# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build and Development
```bash
# Build the project (release mode)
cargo build --release

# Build for development
cargo build

# Installation methods (in order of security preference):
# 1. Setuid root (RECOMMENDED - most secure with privilege dropping)
sudo chown root:root ./target/release/nix-mount-namespace
sudo chmod u+s ./target/release/nix-mount-namespace

# 2. Traditional sudo (good alternative)
sudo ./target/release/nix-mount-namespace

# 3. Capabilities-based (NOT RECOMMENDED - CAP_SYS_ADMIN too broad)
# sudo setcap cap_sys_admin+ep ./target/release/nix-mount-namespace

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
- `create_nix_namespace_secure()`: New secure entry point for setuid/setcap installations
- Legacy functions for sudo-based operation
- `NixNamespaceError`: Public error type for library consumers
- Security validations: Path validation, symlink checks, environment safety
- NFS-aware operations with special handling for root squashing

**`src/security.rs`**: New security module providing:
- `SecurityContext`: Manages user context and privilege operations
- Configuration loading from `~/.config/nix-ns/config.toml`
- TOCTTOU-resistant file operations
- Secure privilege dropping and restoration

**`src/main.rs`**: CLI application with dual-mode operation (secure vs legacy)

**`examples/config.toml`**: Example configuration file

**`tests/integration_tests.rs`**: Integration tests that verify namespace creation and error conditions

### Security Considerations
- **Multiple Installation Methods**: Supports setuid root (recommended), traditional sudo, or capabilities (CAP_SYS_ADMIN)
- **Why Setuid is Recommended**: Research shows CAP_SYS_ADMIN is "overloaded" with extensive privileges, making it less secure than setuid with immediate privilege dropping
- **Privilege Management**: Drops root privileges permanently immediately after mount operations
- **Configuration Security**: Validates config file ownership and permissions
- **Path Validation**: Comprehensive validation against directory traversal and symlink attacks
- **TOCTTOU Prevention**: Uses file descriptors and atomic operations where possible
- **Environment Sanitization**: Cleans dangerous environment variables
- **NFS Compatibility**: Special handling for NFS environments with root squashing


### Security Analysis
Based on security research, this implementation prioritizes setuid over capabilities because:
1. CAP_SYS_ADMIN grants "almost complete access to administrative privileges"
2. With setuid, we can drop ALL privileges immediately after mount operations
3. Capabilities persist throughout program execution and cannot be easily restricted
4. Industry standard tools like `mount` use setuid rather than capabilities for these reasons
### Linux Namespace Usage
Uses `unshare(CLONE_NEWNS)` to create a new mount namespace, allowing private `/nix` mounts without affecting the host system.

### Configuration
The Nix store source path can be configured in multiple ways (in priority order):
1. Command-line argument: `--source /path/to/nix/store`
2. Environment variable: `NIX_NS_SOURCE=/path/to/nix/store`
3. Configuration file: `~/.config/nix-ns/config.toml`
4. Default: `~/.local/share/nix`

Configuration file format:
```toml
# Source path for your Nix store (relative to home directory)
source_path = ".local/share/nix"
# Whether to allow symlinks in the source path (default: false)
allow_symlinks = false
```

Configuration files must be owned by the user or root and not writable by group/others.
