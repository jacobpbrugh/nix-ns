use anyhow::{Context, Result};
use clap::Parser;
use nix::unistd::Uid;
use std::env;
use std::path::{Path, PathBuf};
use tracing::{info, debug, error};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use nix_ns::*;


#[derive(Parser)]
#[command(
    name = "nix-mount-namespace",
    about = "Creates a private mount namespace and bind mounts user's Nix directory",
    long_about = "This tool creates a private mount namespace and bind mounts \
                  a user's Nix store to /nix for Nix usage on shared environments.\n\n\
                  Installation methods (in order of security preference):\n\
                  1. Setuid root: chmod u+s /path/to/nix-mount-namespace (RECOMMENDED)\n\
                  2. Traditional sudo: sudo /path/to/nix-mount-namespace\n\
                  3. Capabilities: setcap cap_sys_admin+ep /path/to/nix-mount-namespace (NOT RECOMMENDED)\n\n\
                  Note: CAP_SYS_ADMIN grants extensive privileges and is less secure than setuid with privilege dropping.\n\n\
                  The Nix store location can be configured via ~/.config/nix-ns/config.toml"
)]
struct Args {
    /// Show debug information during execution
    #[arg(short, long)]
    debug: bool,
    

    /// Path to user's Nix store directory (overrides config)
    #[arg(short, long)]
    source: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing/logging
    let log_level = if args.debug { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("nix_ns={}", log_level)));
    
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to initialize logging")?;

    if args.debug {
        unsafe {
            env::set_var("RUST_BACKTRACE", "1");
        }
    }
    
    info!("nix-ns starting");

    // Check if we have root privileges
    let current_euid = Uid::effective();
    if !current_euid.is_root() {
        error!("Insufficient privileges: effective UID is {}", current_euid);
        anyhow::bail!("This program requires root privileges. Install with setuid/setcap or run with sudo.");
    }

    debug!("Root privileges confirmed: effective UID is {}", current_euid);

    // Detect mode of operation
    let is_sudo = env::var("SUDO_UID").is_ok() && 
                  env::var("SUDO_GID").is_ok() && 
                  env::var("SUDO_USER").is_ok();

    info!("Operating mode: {}", if is_sudo { "legacy sudo" } else { "secure setuid/setcap" });

    if is_sudo {
        // Legacy sudo mode
        run_legacy_sudo_mode(&args)
    } else {
        // Modern secure mode
        run_secure_mode(&args)
    }
}

fn run_legacy_sudo_mode(args: &Args) -> Result<()> {

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
    let user_nix_path = if let Some(ref source) = args.source {
        // Use command-line override
        PathBuf::from(source)
    } else {
        // Use default path
        get_user_nix_path(&user_info)
            .context("Failed to determine user's Nix directory path")?
    };

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

fn run_secure_mode(args: &Args) -> Result<()> {
    if args.debug {
        eprintln!("DEBUG: Running in secure mode (setuid/setcap)");
    }

    // Use the new secure entry point
    create_nix_namespace_secure(args.source.clone())
        .context("Failed to create Nix namespace in secure mode")
}
