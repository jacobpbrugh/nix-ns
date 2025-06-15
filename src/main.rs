use anyhow::{Context, Result};
use clap::Parser;
use nix::unistd::Uid;
use std::env;
use std::path::Path;

mod lib;
use lib::*;

// Implement conversion from our library error to anyhow::Error
impl From<lib::NixNamespaceError> for anyhow::Error {
    fn from(err: lib::NixNamespaceError) -> Self {
        anyhow::anyhow!("{}", err)
    }
}

#[derive(Parser)]
#[command(
    name = "nix-mount-namespace",
    about = "Creates a private mount namespace and bind mounts user's Nix directory",
    long_about = "This tool creates a private mount namespace and bind mounts \
                  ~/.local/share/nix to /nix for Nix usage on shared environments.\n\n\
                  Requirements:\n\
                  - Must be run with sudo, ensuring SUDO_UID, SUDO_GID, and SUDO_USER are set.\n\
                  - ~/.local/share/nix directory must exist on NFS with correct permissions."
)]
struct Args {
    /// Show debug information during execution
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.debug {
        env::set_var("RUST_BACKTRACE", "1");
    }

    // 1. Ensure running as root via sudo
    let current_euid = Uid::effective();
    if !current_euid.is_root() {
        anyhow::bail!("This program must be run as root (via sudo)");
    }

    // Fetch and validate sudo environment variables
    let sudo_uid = env::var("SUDO_UID")
        .context("Missing SUDO_UID environment variable - not running via sudo?")?;
    let sudo_gid = env::var("SUDO_GID")
        .context("Missing SUDO_GID environment variable - not running via sudo?")?;
    let sudo_user = env::var("SUDO_USER")
        .context("Missing SUDO_USER environment variable - not running via sudo?")?;

    // 2. Parse UID/GID with proper error handling
    let uid: u32 = sudo_uid
        .parse()
        .with_context(|| format!("Invalid SUDO_UID value '{}' - expected numeric UID", sudo_uid))?;
    let gid: u32 = sudo_gid
        .parse()
        .with_context(|| format!("Invalid SUDO_GID value '{}' - expected numeric GID", sudo_gid))?;

    // 3. Verify the sudo user against system database
    let user_info = verify_sudo_user(&sudo_user, uid, gid)
        .with_context(|| format!("Failed to verify sudo user '{}'", sudo_user))?;

    if args.debug {
        eprintln!("DEBUG: Verified user '{}' (UID: {}, GID: {}, Home: {}, Shell: {})",
                  user_info.name, user_info.uid, user_info.gid,
                  user_info.home.display(), user_info.shell.display());
    }

    // 4. Ensure /nix mount point is properly prepared
    prepare_nix_mount_point()
        .context("Failed to prepare /nix mount point")?;

    // 5. Validate the user's Nix directory
    let user_nix_path = get_user_nix_path(&user_info)
        .context("Failed to determine user's Nix directory path")?;

    validate_user_nix_directory(&user_nix_path, &user_info)
        .with_context(|| format!(
            "User Nix directory '{}' validation failed",
            user_nix_path.display()
        ))?;

    if args.debug {
        eprintln!("DEBUG: Validated user Nix directory at '{}'", user_nix_path.display());
    }

    // 6. Create private mount namespace
    enter_private_mount_namespace()
        .context("Failed to create private mount namespace")?;

    // 7. Bind mount user's Nix directory to /nix
    bind_mount_nix(&user_nix_path, Path::new(NIX_MOUNT_DIR))
        .with_context(|| format!(
            "Failed to bind mount '{}' to '{}'",
            user_nix_path.display(),
            NIX_MOUNT_DIR
        ))?;

    if args.debug {
        eprintln!("DEBUG: Successfully mounted '{}' at '{}'",
                  user_nix_path.display(), NIX_MOUNT_DIR);
    }

    // 8. Clean up sudo-specific environment variables
    clean_sudo_environment()
        .context("Failed to clean sudo environment variables")?;

    // 9. Execute user's shell with preserved environment
    execute_user_shell(&user_info)
        .with_context(|| format!(
            "Failed to execute shell '{}' for user '{}'",
            user_info.shell.display(),
            user_info.name
        ))
}
