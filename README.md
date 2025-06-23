# nix-ns

A simple tool that creates a private mount namespace and bind mounts a user-specified directory to `/nix`.

## Features

-   Creates a new mount namespace (isolated from host)
-   Bind mounts any directory to `/nix`
-   Configurable via CLI arguments or config file
-   Automatic cleanup when shell exits

## How it works

1. Checks for root privileges (sudo or setuid)
2. Loads configuration from file and CLI args
3. Creates new mount namespace with `unshare(CLONE_NEWNS)`
4. Makes mount tree private to prevent host propagation
5. Bind mounts source directory to `/nix`
6. Executes specified shell

When the shell exits, the mount namespace is automatically cleaned up.

## Installation & Usage

### Option 1: Run with sudo (temporary)

```bash
# Build the binary
cargo build --release

# Run with sudo each time
sudo ./target/release/nix-ns --source /path/to/my/nix/store
sudo ./target/release/nix-ns --shell /bin/zsh --debug
```

### Option 2: Install as setuid (permanent)

**⚠️ SECURITY WARNING**: Setuid binaries run with root privileges and can be security risks if not properly audited. Only install as setuid if you understand the implications and trust this code.

```bash
# Install as setuid root (no sudo needed for subsequent runs)
sudo chown root:root ./target/release/nix-ns
sudo chmod u+s ./target/release/nix-ns

# Now run directly
./target/release/nix-ns --source /path/to/my/nix/store
./target/release/nix-ns --shell /bin/zsh --debug
```

## Usage Examples

### Basic usage with default location (~/.local/share/nix-ns/store):

```bash
# With sudo
sudo ./target/release/nix-ns

# Or with setuid installation
./target/release/nix-ns
```

### Specify source directory:

```bash
sudo ./target/release/nix-ns --source /path/to/my/nix/store
# or: ./target/release/nix-ns --source /path/to/my/nix/store  (if setuid)
```

### Specify shell:

```bash
sudo ./target/release/nix-ns --shell /bin/zsh
# or: ./target/release/nix-ns --shell /bin/zsh  (if setuid)
```

### Debug mode:

```bash
sudo ./target/release/nix-ns --debug
# or: ./target/release/nix-ns --debug  (if setuid)
```

## Configuration

Create `~/.config/nix-ns/config.toml`:

```toml
# Source directory to mount to /nix
source = "/home/user/my-nix-store"

# Shell to execute (optional)
shell = "/bin/zsh"
```

CLI arguments override config file settings.

## Requirements

-   Linux with mount namespace support
-   Root privileges (via sudo or setuid installation)
-   Rust 1.70+ for building

## Building

```bash
cargo build --release
```

## License

MIT OR Apache-2.0
