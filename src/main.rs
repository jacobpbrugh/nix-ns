use anyhow::{Context, Result, bail};
use clap::Parser;
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{Uid, execvp};
use serde::Deserialize;
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "nix-ns",
    about = "Creates a mount namespace and bind mounts a directory to /nix",
    long_about = "Creates a private mount namespace and bind mounts a user-specified directory to /nix.\n\
                  Requires root privileges (run with sudo or install setuid)."
)]
struct Args {
    /// Source directory to mount to /nix
    #[arg(short, long)]
    source: Option<PathBuf>,

    /// Shell to execute (overrides config file)
    #[arg(long)]
    shell: Option<String>,

    /// Show debug information
    #[arg(short, long)]
    debug: bool,
}

#[derive(Deserialize, Default)]
struct Config {
    source: Option<PathBuf>,
    shell: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Check root privileges
    if !Uid::effective().is_root() {
        bail!(
            "This program requires root privileges. Run with sudo or install with setuid:\n\
             sudo chown root:root nix-ns && sudo chmod u+s nix-ns"
        );
    }

    // Load config from ~/.config/nix-ns/config.toml if it exists
    let config = load_config().unwrap_or_default();

    // Determine source directory (CLI arg > config > default)
    let source = args.source
        .or(config.source)
        .unwrap_or_else(|| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".local/share/nix-ns/store")
        });

    // Determine shell (CLI arg > config > $SHELL > /bin/sh)
    let shell = args.shell
        .or(config.shell)
        .or_else(|| env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());

    if args.debug {
        eprintln!("Source directory: {}", source.display());
        eprintln!("Shell: {}", shell);
    }

    // Validate source directory exists
    if !source.exists() {
        bail!("Source directory does not exist: {}", source.display());
    }

    if !source.is_dir() {
        bail!("Source path is not a directory: {}", source.display());
    }

    // Create /nix if it doesn't exist
    if !Path::new("/nix").exists() {
        fs::create_dir("/nix")
            .context("Failed to create /nix directory")?;
        if args.debug {
            eprintln!("Created /nix directory");
        }
    }

    // Enter new mount namespace
    unshare(CloneFlags::CLONE_NEWNS)
        .context("Failed to create new mount namespace")?;

    if args.debug {
        eprintln!("Created new mount namespace");
    }

    // Make mount tree private to prevent propagation to host
    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_SLAVE | MsFlags::MS_REC, None)
        .context("Failed to make mount tree private")?;

    // Bind mount source to /nix
    mount(
        Some(&*source),
        "/nix",
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("Failed to bind mount {} to /nix", source.display()))?;

    if args.debug {
        eprintln!("Successfully mounted {} to /nix", source.display());
        eprintln!("Executing shell: {}", shell);
    }

    // Execute the shell
    let shell_cstr = CString::new(shell.as_str())
        .context("Shell path contains null bytes")?;
    let args = [&shell_cstr];

    execvp(&shell_cstr, &args)
        .context("Failed to execute shell")?;

    Ok(())
}

fn load_config() -> Result<Config> {
    let home = env::var("HOME").context("HOME environment variable not set")?;
    let config_path = PathBuf::from(home)
        .join(".config")
        .join("nix-ns")
        .join("config.toml");

    if !config_path.exists() {
        return Ok(Config::default());
    }

    let contents = fs::read_to_string(&config_path)
        .context("Failed to read config file")?;

    toml::from_str(&contents)
        .context("Failed to parse config file")
}
