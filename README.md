# Nix Mount Namespace Tool

A security-focused Rust implementation that creates private mount namespaces to bind mount user-specific Nix directories to `/nix` in shared environments.

## Key Features

- **Security-First Design**: Comprehensive validation against symlink attacks, path traversal, and environment variable tampering
- **Modular Architecture**: Clean separation between CLI (`main.rs`) and core logic (`lib.rs`) for better testability
- **Rich Error Context**: Using `anyhow` for detailed error messages with full context chains
- **Type-Safe System Calls**: Leveraging the `nix` crate for safe wrappers around Linux system calls
- **NFS-Aware**: Special handling for root-squashed NFS environments with helpful diagnostics

## Building

```bash
cargo build --release
```

## Usage

```bash
sudo -E ./target/release/nix-mount-namespace
```

With debug output:
```bash
sudo -E ./target/release/nix-mount-namespace --debug
```

## Security Features

1. **Sudo Environment Validation**: Cross-checks SUDO_* variables against `/etc/passwd`
2. **Symlink Attack Prevention**: Refuses to use symlinks for `/nix` or user directories
3. **Path Containment**: Ensures user Nix directory is within their home directory
4. **Mount Namespace Isolation**: Changes don't affect the host system
5. **Automatic Cleanup**: Bind mounts are removed when the shell exits

## Implementation Notes

### Error Handling Philosophy

The library uses a dual error handling strategy:
- **Public API**: Exposes `NixNamespaceError` implementing `std::error::Error`
- **Internal Implementation**: Uses `anyhow` for convenient error context
- **Main Binary**: Uses `anyhow::Result` with automatic conversion from library errors

This design avoids forcing `anyhow` as a dependency on library consumers while maintaining rich error context internally.

### System Call Safety

All system calls go through the `nix` crate which:
- Provides type-safe wrappers
- Handles errno automatically
- Reduces unsafe code blocks

### Key Differences from C++ Original

1. **Fixed Bug**: Correctly parses SUDO_GID (original had a copy-paste error)
2. **Enhanced Security**: Added symlink and path traversal protections
3. **Better Diagnostics**: Specific error messages for NFS root-squash scenarios
4. **Explicit Shell Setting**: Uses `--shell` flag with runuser for consistency

## Testing

The modular design enables unit testing of individual components:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_user_validation() {
        // Test cases for verify_sudo_user
    }

    #[test]
    fn test_path_validation() {
        // Test cases for validate_user_nix_directory
    }
}
```

## License

MIT OR Apache-2.0
