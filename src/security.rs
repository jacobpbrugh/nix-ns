use anyhow::{anyhow, bail, Context, Result};
use nix::unistd::{Gid, Uid, User, geteuid, getegid, getuid, getgid, setresgid, setresuid, setgroups};
use std::env;
use std::fs;
use std::os::unix::fs::{PermissionsExt, MetadataExt};
use std::path::{Path, PathBuf};

/// Configuration for the Nix store source path
#[derive(Debug, Clone)]
pub struct NixStoreConfig {
    /// The source path for the Nix store (e.g., ~/.local/share/nix)
    pub source_path: PathBuf,
    /// Whether to allow symlinks in the source path
    pub allow_symlinks: bool,
}

impl Default for NixStoreConfig {
    fn default() -> Self {
        Self {
            source_path: PathBuf::from(".local/share/nix"),
            allow_symlinks: false,
        }
    }
}

/// Security context for the application
#[derive(Debug)]
pub struct SecurityContext {
    /// Real user ID (from getuid())
    pub real_uid: Uid,
    /// Real group ID (from getgid())
    pub real_gid: Gid,
    /// Effective user ID (should be 0 if setuid/setcap)
    pub effective_uid: Uid,
    /// Effective group ID
    pub effective_gid: Gid,
    /// User information from passwd database
    pub user: Option<User>,
    /// Whether we detected we're running under sudo
    pub is_sudo: bool,
    /// Configuration loaded securely
    pub config: NixStoreConfig,
}

impl SecurityContext {
    /// Initialize security context, detecting how we were invoked
    pub fn init(source_override: Option<String>) -> Result<Self> {
        let real_uid = getuid();
        let real_gid = getgid();
        let effective_uid = geteuid();
        let effective_gid = getegid();

        // Check if we have elevated privileges
        if !effective_uid.is_root() {
            bail!("This program requires root privileges. Please install with setuid root or setcap CAP_SYS_ADMIN");
        }

        // Detect if running under sudo
        let is_sudo = env::var("SUDO_UID").is_ok() && 
                     env::var("SUDO_GID").is_ok() && 
                     env::var("SUDO_USER").is_ok();

        // Get user information
        let (user, config) = if is_sudo {
            // Running under sudo - validate environment
            let sudo_uid = env::var("SUDO_UID")
                .context("SUDO_UID not set")?
                .parse::<u32>()
                .context("Invalid SUDO_UID")?;
            
            let user = User::from_uid(Uid::from_raw(sudo_uid))
                .context("Failed to lookup user")?
                .ok_or_else(|| anyhow!("User not found for UID {}", sudo_uid))?;
            
            // Load config for sudo user
            let config = load_config_for_user(&user)?;
            
            (Some(user), config)
        } else {
            // Running setuid/setcap - use real UID
            let user = if real_uid.is_root() {
                // Running as actual root (not recommended)
                None
            } else {
                Some(User::from_uid(real_uid)
                    .context("Failed to lookup user")?
                    .ok_or_else(|| anyhow!("User not found for UID {}", real_uid))?)
            };
            
            // Load config for real user
            let config = if let Some(ref u) = user {
                load_config_for_user(u)?
            } else {
                NixStoreConfig::default()
            };
            
            (user, config)
        };

        // Apply command-line override if provided
        let mut config = config;
        if let Some(source) = source_override {
            config.source_path = PathBuf::from(source);
        }

        Ok(Self {
            real_uid,
            real_gid,
            effective_uid,
            effective_gid,
            user,
            is_sudo,
            config,
        })
    }

    /// Drop privileges permanently to the target user (recommended for setuid)
    pub fn drop_privileges(&self) -> Result<()> {
        if let Some(ref user) = self.user {
            // Set supplementary groups
            setgroups(&[])
                .context("Failed to clear supplementary groups")?;

            // Drop group privileges first
            setresgid(user.gid, user.gid, user.gid)
                .context("Failed to drop group privileges")?;

            // Then drop user privileges permanently
            setresuid(user.uid, user.uid, user.uid)
                .context("Failed to drop user privileges")?;

            // Verify we can't get privileges back
            if geteuid().is_root() || getegid() == Gid::from_raw(0) {
                bail!("Failed to fully drop privileges - still have root access");
            }
            
            // Additional verification: try to regain root (should fail)
            if setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)).is_ok() {
                bail!("Security failure: was able to regain root privileges after dropping them");
            }
        }
        Ok(())
    }

    /// Temporarily drop privileges for a specific operation
    pub fn with_dropped_privileges<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        if let Some(ref user) = self.user {
            // Save current IDs
            let saved_uid = geteuid();
            let saved_gid = getegid();

            // Temporarily drop privileges
            setresgid(user.gid, user.gid, saved_gid)
                .context("Failed to temporarily drop group privileges")?;
            setresuid(user.uid, user.uid, saved_uid)
                .context("Failed to temporarily drop user privileges")?;

            // Execute the function
            let result = f();

            // Restore privileges
            setresuid(saved_uid, saved_uid, saved_uid)
                .context("Failed to restore user privileges")?;
            setresgid(saved_gid, saved_gid, saved_gid)
                .context("Failed to restore group privileges")?;

            result
        } else {
            // No user context, just run the function
            f()
        }
    }
}

/// Load configuration for a specific user
fn load_config_for_user(user: &User) -> Result<NixStoreConfig> {
    let mut config = NixStoreConfig::default();

    // Try to load from user-specific config file
    let user_config_path = PathBuf::from(&user.dir)
        .join(".config")
        .join("nix-ns")
        .join("config.toml");

    if user_config_path.exists() {
        // Validate config file ownership and permissions
        validate_config_file(&user_config_path, user)?;
        
        // Parse config file
        let contents = fs::read_to_string(&user_config_path)
            .context("Failed to read user config file")?;
        
        // Simple parsing for now - in real implementation use toml crate
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("source_path") {
                if let Some(value) = line.split('=').nth(1) {
                    let path = value.trim().trim_matches('"');
                    config.source_path = PathBuf::from(path);
                }
            } else if line.starts_with("allow_symlinks") {
                if let Some(value) = line.split('=').nth(1) {
                    config.allow_symlinks = value.trim() == "true";
                }
            }
        }
    }

    // If source_path is relative, make it relative to user's home
    if config.source_path.is_relative() {
        config.source_path = PathBuf::from(&user.dir).join(&config.source_path);
    }

    Ok(config)
}

/// Validate that a config file has secure ownership and permissions
fn validate_config_file(path: &Path, expected_owner: &User) -> Result<()> {
    let metadata = fs::metadata(path)
        .context("Failed to stat config file")?;

    // Check ownership
    let file_uid = metadata.uid();
    if file_uid != expected_owner.uid.as_raw() && file_uid != 0 {
        bail!(
            "Config file {} is not owned by user {} or root",
            path.display(),
            expected_owner.name
        );
    }

    // Check permissions - should not be writable by others
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        bail!(
            "Config file {} has insecure permissions {:o} (writable by group/others)",
            path.display(),
            mode & 0o777
        );
    }

    Ok(())
}

/// Securely validate a path provided by the user
pub fn validate_user_path(path: &Path, allow_symlinks: bool) -> Result<PathBuf> {
    // Check for null bytes or other invalid characters
    if path.as_os_str().is_empty() {
        bail!("Empty path provided");
    }

    // Check for path traversal attempts
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                bail!("Path contains '..' which is not allowed");
            }
            std::path::Component::RootDir => {
                // Allow absolute paths but validate them carefully
            }
            std::path::Component::CurDir => {
                // '.' is okay
            }
            std::path::Component::Prefix(_) => {
                bail!("Windows-style paths are not supported");
            }
            std::path::Component::Normal(s) => {
                // Check for suspicious patterns
                let s_str = s.to_string_lossy();
                if s_str.contains('\0') {
                    bail!("Path contains null bytes");
                }
                if s_str.starts_with('.') && s_str != "." && s_str != ".." {
                    // Hidden files/directories are okay
                }
            }
        }
    }

    // Get metadata without following symlinks
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Cannot access path: {}", path.display()))?;

    if metadata.file_type().is_symlink() && !allow_symlinks {
        bail!("Path {} is a symlink, which is not allowed", path.display());
    }

    // Canonicalize to get the real path
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

    Ok(canonical)
}

/// Perform TOCTTOU-resistant verification of the /nix directory
pub fn verify_nix_mount_point_secure() -> Result<()> {
    let nix_path = Path::new("/nix");
    
    // Check if /nix exists using lstat to avoid following symlinks
    match fs::symlink_metadata(nix_path) {
        Ok(metadata) => {
            // Verify it's a directory, not a symlink
            if metadata.file_type().is_symlink() {
                bail!("/nix exists but is a symlink - potential security issue");
            }
            
            if !metadata.file_type().is_dir() {
                bail!("/nix exists but is not a directory");
            }
            
            // Check permissions
            let perms = metadata.permissions().mode() & 0o777;
            if perms & 0o022 != 0 {
                eprintln!("Warning: /nix has permissive write permissions ({:o})", perms);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Directory doesn't exist, try to create it
            fs::create_dir(nix_path)
                .context("Failed to create /nix directory")?;
            
            // Set secure permissions
            fs::set_permissions(nix_path, fs::Permissions::from_mode(0o755))
                .context("Failed to set permissions on /nix")?;
        }
        Err(e) => {
            return Err(e).context("Failed to check /nix directory");
        }
    }

    Ok(())
}

/// Get the Nix store path for the current user from the security context
pub fn get_nix_store_path(ctx: &SecurityContext) -> Result<PathBuf> {
    if let Some(ref user) = ctx.user {
        let source_path = &ctx.config.source_path;
        
        // Validate the path
        let validated_path = validate_user_path(source_path, ctx.config.allow_symlinks)?;
        
        // Ensure it's within the user's home directory (unless explicitly allowed)
        let user_home = PathBuf::from(&user.dir);
        let canonical_home = fs::canonicalize(&user_home)
            .context("Failed to canonicalize user home")?;
        
        if !validated_path.starts_with(&canonical_home) {
            bail!(
                "Nix store path {} is outside user's home directory {}",
                validated_path.display(),
                canonical_home.display()
            );
        }
        
        Ok(validated_path)
    } else {
        bail!("No user context available for Nix store path");
    }
}