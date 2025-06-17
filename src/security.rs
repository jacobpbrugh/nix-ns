use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use nix::unistd::{Gid, Uid, User, geteuid, getegid, getuid, getgid, setresgid, setresuid, setgroups};
use std::env;
use std::fs;
use std::os::unix::fs::{PermissionsExt, MetadataExt};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn, error, instrument};
use caps::{CapSet, Capability};

/// Configuration for the Nix store source path
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NixStoreConfig {
    /// The source path for the Nix store (e.g., ~/.local/share/nix)
    #[serde(default = "default_source_path")]
    pub source_path: PathBuf,
    /// Whether to allow symlinks in the source path
    #[serde(default)]
    pub allow_symlinks: bool,
}

fn default_source_path() -> PathBuf {
    PathBuf::from(".local/share/nix")
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
    #[instrument(skip(source_override), fields(has_override = source_override.is_some()))]
    pub fn init(source_override: Option<String>) -> Result<Self> {
        let real_uid = getuid();
        let real_gid = getgid();
        let effective_uid = geteuid();
        let effective_gid = getegid();

        // Check if we have elevated privileges
        if !effective_uid.is_root() {
            error!("Insufficient privileges: effective_uid={}, real_uid={}", effective_uid, real_uid);
            
            // Check if we have CAP_SYS_ADMIN capability instead
            match check_required_capabilities() {
                Ok(_) => {
                    info!("Running with CAP_SYS_ADMIN capability instead of root");
                }
                Err(cap_err) => {
                    error!("Neither root privileges nor CAP_SYS_ADMIN capability available: {}", cap_err);
                    bail!("This program requires root privileges or CAP_SYS_ADMIN capability. Please install with setuid root or setcap CAP_SYS_ADMIN");
                }
            }
        } else {
            debug!("Privilege check passed: effective_uid={}, real_uid={}", effective_uid, real_uid);
            
            // Even with root, log capability information for audit purposes
            if let Err(e) = log_capability_info() {
                debug!("Could not read capability information: {}", e);
            }
        }

        // Detect if running under sudo
        let is_sudo = env::var("SUDO_UID").is_ok() && 
                     env::var("SUDO_GID").is_ok() && 
                     env::var("SUDO_USER").is_ok();
        
        info!("Detected invocation method: {}", if is_sudo { "sudo" } else { "setuid/setcap" });

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
            
            info!("Sudo user validated: name={}, uid={}, home={}", user.name, user.uid, user.dir.display());
            
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
    #[instrument(skip(self), fields(target_uid = ?self.user.as_ref().map(|u| u.uid)))]
    pub fn drop_privileges(&self) -> Result<()> {
        use anyhow::ensure;
        
        if let Some(ref user) = self.user {
            info!("Dropping privileges to user: name={}, uid={}, gid={}", user.name, user.uid, user.gid);
            
            // Clear supplementary groups first
            setgroups(&[])
                .context("Failed to clear supplementary groups")?;
            debug!("Cleared supplementary groups");
            
            // Drop to target user permanently
            setresgid(user.gid, user.gid, user.gid)
                .context("Failed to drop group privileges")?;
            debug!("Dropped group privileges to gid={}", user.gid);
            
            setresuid(user.uid, user.uid, user.uid)
                .context("Failed to drop user privileges")?;
            debug!("Dropped user privileges to uid={}", user.uid);
            
            // Verify final state
            let final_uid = geteuid();
            let final_gid = getegid();
            ensure!(
                !final_uid.is_root() && final_gid != Gid::from_raw(0),
                "Failed to drop privileges completely"
            );
            
            info!("Successfully dropped privileges: final_uid={}, final_gid={}", final_uid, final_gid);
        } else {
            debug!("No user context - skipping privilege drop");
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
    let config_path = PathBuf::from(&user.dir)
        .join(".config")
        .join("nix-ns")
        .join("config.toml");
    
    if !config_path.exists() {
        return Ok(NixStoreConfig::default());
    }
    
    validate_config_file(&config_path, user)?;
    
    let contents = fs::read_to_string(&config_path)
        .context("Failed to read user config file")?;
    let mut config: NixStoreConfig = toml::from_str(&contents)
        .context("Failed to parse TOML config file")?;
    
    // Make relative paths absolute
    if config.source_path.is_relative() {
        config.source_path = PathBuf::from(&user.dir).join(config.source_path);
    }
    
    Ok(config)
}
/// Validate that a config file has secure ownership and permissions
fn validate_config_file(path: &Path, expected_owner: &User) -> Result<()> {
    let metadata = fs::metadata(path)
        .context("Failed to stat config file")?;

    use anyhow::ensure;
    
    // Check ownership
    let file_uid = metadata.uid();
    ensure!(
        file_uid == expected_owner.uid.as_raw() || file_uid == 0,
        "Config file {} is not owned by user {} or root",
        path.display(),
        expected_owner.name
    );

    // Check permissions - should not be writable by others
    let mode = metadata.permissions().mode();
    ensure!(
        mode & 0o022 == 0,
        "Config file {} has insecure permissions {:o} (writable by group/others)",
        path.display(),
        mode & 0o777
    );

    Ok(())
}

/// Securely validate a path provided by the user
pub fn validate_user_path(path: &Path, allow_symlinks: bool) -> Result<PathBuf> {
    use anyhow::ensure;
    
    // Check for null bytes or other invalid characters
    ensure!(!path.as_os_str().is_empty(), "Empty path provided");

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
                ensure!(!s_str.contains('\0'), "Path contains null bytes");
                if s_str.starts_with('.') && s_str != "." && s_str != ".." {
                    // Hidden files/directories are okay
                }
            }
        }
    }

    // Get metadata without following symlinks
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Cannot access path: {}", path.display()))?;

    ensure!(
        !metadata.file_type().is_symlink() || allow_symlinks,
        "Path {} is a symlink, which is not allowed", 
        path.display()
    );

    // Canonicalize to get the real path
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("Failed to canonicalize path: {}", path.display()))?;

    Ok(canonical)
}

/// Perform TOCTTOU-resistant verification of the /nix directory
#[instrument]
pub fn verify_nix_mount_point_secure() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    
    let nix_path = Path::new("/nix");
    
    // Try to create with specific permissions atomically
    match fs::DirBuilder::new()
        .mode(0o755)
        .create(nix_path) 
    {
        Ok(_) => {
            // Successfully created directory
            info!("Created /nix directory with permissions 755");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            debug!("/nix directory already exists - verifying security");
            
            // Directory exists - verify it is safe
            let metadata = fs::symlink_metadata(nix_path)
                .context("Failed to check existing /nix directory")?;
            
            if metadata.file_type().is_symlink() {
                error!("Security violation: /nix is a symlink");
                bail!("Security violation: /nix exists but is a symlink - potential attack");
            }
            
            if !metadata.file_type().is_dir() {
                error!("Security violation: /nix exists but is not a directory");
                bail!("/nix exists but is not a directory (type: {:?})", metadata.file_type());
            }
            
            // Check permissions
            let perms = metadata.permissions().mode() & 0o777;
            if perms & 0o022 != 0 {
                warn!("/nix has permissive write permissions ({:o}) - should be 0755", perms);
            } else {
                debug!("/nix directory verified with permissions {:o}", perms);
            }
            
            Ok(())
        }
        Err(e) => {
            error!("Failed to create /nix directory: {}", e);
            Err(e).context("Failed to create or verify /nix directory")
        }
    }
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
        
        use anyhow::ensure;
        
        ensure!(
            validated_path.starts_with(&canonical_home),
            "Nix store path {} is outside user's home directory {}",
            validated_path.display(),
            canonical_home.display()
        );
        
        Ok(validated_path)
    } else {
        bail!("No user context available for Nix store path");
    }
}

/// Check if the process has the required capabilities for mount operations
#[instrument]
fn check_required_capabilities() -> Result<()> {
    // Read effective capabilities
    let effective_caps = caps::read(None, CapSet::Effective)
        .context("Failed to read effective capabilities")?;
    
    use anyhow::ensure;
    
    // Check for CAP_SYS_ADMIN
    ensure!(
        effective_caps.contains(&Capability::CAP_SYS_ADMIN),
        "Missing CAP_SYS_ADMIN capability required for mount operations"
    );
    
    info!("Verified CAP_SYS_ADMIN capability is present");
    
    // Warn about the extensive privileges granted by CAP_SYS_ADMIN
    warn!("Running with CAP_SYS_ADMIN grants extensive system privileges. Consider using setuid root with privilege dropping instead for better security.");
    
    Ok(())
}

/// Log capability information for audit purposes
#[instrument]
fn log_capability_info() -> Result<()> {
    let effective_caps = caps::read(None, CapSet::Effective)
        .context("Failed to read effective capabilities")?;
    
    let permitted_caps = caps::read(None, CapSet::Permitted)
        .context("Failed to read permitted capabilities")?;
    
    debug!("Process capabilities - Effective: {:?}, Permitted: {:?}", 
           effective_caps, permitted_caps);
    
    // Log specific security-relevant capabilities
    let security_caps = [
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_SETUID,
        Capability::CAP_SETGID,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_SYS_CHROOT,
    ];
    
    for cap in &security_caps {
        if effective_caps.contains(cap) {
            debug!("Process has effective capability: {:?}", cap);
        }
    }
    
    Ok(())
}