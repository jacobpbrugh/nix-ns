use anyhow::{anyhow, bail, Context};
use std::error::Error;
use std::fmt;
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{self, AccessFlags, Gid, Uid, User};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub mod security;
use security::{SecurityContext, get_nix_store_path, verify_nix_mount_point_secure};

pub const NIX_MOUNT_DIR: &str = "/nix";
pub const NIX_USER_DIR: &str = ".local/share/nix";

// Custom error type for the library's public API
#[derive(Debug)]
pub enum NixNamespaceError {
    /// User validation failed
    UserValidation(String),
    /// Filesystem operation failed
    Filesystem { path: PathBuf, message: String },
    /// Security violation detected
    SecurityViolation(String),
    /// Mount operation failed
    MountOperation(String),
    /// System call failed
    SystemCall { call: String, source: nix::Error },
    /// I/O error
    Io { context: String, source: io::Error },
    /// Environment variable error
    Environment(String),
    /// Permission denied with helpful context
    PermissionDenied { path: PathBuf, suggestion: String },
}

impl fmt::Display for NixNamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserValidation(msg) => write!(f, "User validation failed: {}", msg),
            Self::Filesystem { path, message } => {
                write!(f, "Filesystem error at '{}': {}", path.display(), message)
            }
            Self::SecurityViolation(msg) => write!(f, "Security violation: {}", msg),
            Self::MountOperation(msg) => write!(f, "Mount operation failed: {}", msg),
            Self::SystemCall { call, source } => {
                write!(f, "System call '{}' failed: {}", call, source)
            }
            Self::Io { context, source } => write!(f, "{}: {}", context, source),
            Self::Environment(msg) => write!(f, "Environment error: {}", msg),
            Self::PermissionDenied { path, suggestion } => {
                write!(f, "Permission denied accessing '{}'. {}", path.display(), suggestion)
            }
        }
    }
}

impl Error for NixNamespaceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SystemCall { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

// Convenience type alias for internal use
type AnyhowResult<T> = anyhow::Result<T>;

// Public result type using our custom error
pub type Result<T> = std::result::Result<T, NixNamespaceError>;

/// Structure holding verified information about the sudo-invoking user
#[derive(Debug, Clone)]
pub struct SudoUser {
    pub uid: Uid,
    pub gid: Gid,
    pub name: String,
    pub home: PathBuf,
    pub shell: PathBuf,
}

/// Verify that the provided username and UID/GID correspond to a valid user
/// and match the environment variables set by sudo.
///
/// This provides defense against tampered environment variables by cross-checking
/// against the system user database (/etc/passwd).
pub fn verify_sudo_user(user_name: &str, uid: u32, gid: u32) -> Result<SudoUser> {
    verify_sudo_user_internal(user_name, uid, gid)
        .map_err(|e| NixNamespaceError::UserValidation(format!("{:#}", e)))
}

// Internal implementation using anyhow for rich error context
fn verify_sudo_user_internal(user_name: &str, uid: u32, gid: u32) -> AnyhowResult<SudoUser> {
    // First, lookup by UID to get the canonical user information
    let uid = Uid::from_raw(uid);
    let gid = Gid::from_raw(gid);

    let user_by_uid = User::from_uid(uid)
        .map_err(|e| anyhow!("Failed to lookup user by UID: {}", e))?
        .ok_or_else(|| anyhow!("No user found with UID {} in system records", uid))?;

    // Verify username matches what sudo provided
    if user_by_uid.name != user_name {
        bail!(
            "Security check failed: SUDO_USER '{}' does not match the username '{}' \
             for UID {} in /etc/passwd. This may indicate tampered environment variables.",
            user_name,
            user_by_uid.name,
            uid
        );
    }

    // Also lookup by name as additional verification
    let user_by_name = User::from_name(user_name)
        .map_err(|e| anyhow!("Failed to lookup user by name: {}", e))?
        .ok_or_else(|| anyhow!("User '{}' not found in system records", user_name))?;

    // Ensure both lookups agree
    if user_by_uid.uid != user_by_name.uid {
        bail!(
            "Security check failed: User '{}' has inconsistent UIDs \
             (by UID lookup: {}, by name lookup: {})",
            user_name,
            user_by_uid.uid,
            user_by_name.uid
        );
    }

    // Verify primary GID matches (fixing the C++ bug where sudoGidStr was parsed incorrectly)
    if user_by_uid.gid != gid {
        bail!(
            "Security check failed: SUDO_GID {} does not match primary GID {} \
             for user '{}' in /etc/passwd",
            gid.as_raw(),
            user_by_uid.gid.as_raw(),
            user_name
        );
    }

    Ok(SudoUser {
        uid,
        gid,
        name: user_by_uid.name,
        home: PathBuf::from(user_by_uid.dir),
        shell: PathBuf::from(user_by_uid.shell),
    })
}

/// Ensure that /nix exists as a real directory (not a symlink).
/// Creates it with appropriate permissions if it doesn't exist.
///
/// This prevents symlink attacks where /nix could point to unexpected locations.
pub fn prepare_nix_mount_point() -> Result<()> {
    verify_nix_mount_point_secure()
        .map_err(|e| {
            // Check if it's a security violation
            let error_string = format!("{:#}", e);
            if error_string.contains("Security violation") {
                NixNamespaceError::SecurityViolation(error_string)
            } else {
                NixNamespaceError::Filesystem {
                    path: PathBuf::from(NIX_MOUNT_DIR),
                    message: error_string,
                }
            }
        })
}


/// Compute the path to the user's Nix directory
pub fn get_user_nix_path(user: &SudoUser) -> Result<PathBuf> {
    Ok(user.home.join(NIX_USER_DIR))
}

/// Comprehensively validate the user's Nix directory for security and accessibility.
///
/// Checks include:
/// - Directory exists and is actually a directory
/// - Path is within the user's home (no symlink escapes)
/// - Root can traverse the directory (important for NFS with root squashing)
pub fn validate_user_nix_directory(path: &Path, user: &SudoUser) -> Result<()> {
    validate_user_nix_directory_internal(path, user)
        .map_err(|e| {
            let error_string = format!("{:#}", e);

            // Categorize the error appropriately
            if error_string.contains("Security violation") {
                NixNamespaceError::SecurityViolation(error_string)
            } else if error_string.contains("Permission denied") || error_string.contains("Insufficient permissions") {
                NixNamespaceError::PermissionDenied {
                    path: path.to_path_buf(),
                    suggestion: if error_string.contains("NFS") {
                        "This is likely due to NFS root squashing. To fix:\n\
                         1. Run: chmod o+x ~/.local ~/.local/share ~/.local/share/nix\n\
                         2. Or configure NFS export with no_root_squash".to_string()
                    } else {
                        "Check directory permissions and ownership".to_string()
                    },
                }
            } else {
                NixNamespaceError::Filesystem {
                    path: path.to_path_buf(),
                    message: error_string,
                }
            }
        })
}

fn validate_user_nix_directory_internal(path: &Path, user: &SudoUser) -> AnyhowResult<()> {
    // Check existence and type using symlink_metadata to detect symlinks
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!(
            "Cannot access '{}'. Please ensure this directory exists and has \
             appropriate permissions for root access.",
            path.display()
        ))?;

    if metadata.file_type().is_symlink() {
        bail!(
            "Security violation: '{}' is a symlink. The user Nix directory must be \
             a real directory, not a symlink.",
            path.display()
        );
    }

    if !metadata.file_type().is_dir() {
        bail!("'{}' exists but is not a directory", path.display());
    }

    // Canonicalize paths to prevent directory traversal attacks
    let canonical_path = fs::canonicalize(path)
        .with_context(|| format!("Failed to resolve canonical path for '{}'", path.display()))?;

    let canonical_home = fs::canonicalize(&user.home)
        .with_context(|| format!(
            "Failed to resolve canonical path for user home '{}'",
            user.home.display()
        ))?;

    // Ensure the Nix directory is actually within the user's home
    if !canonical_path.starts_with(&canonical_home) {
        bail!(
            "Security violation: Directory '{}' (canonical: '{}') is not within \
             the user's home directory '{}' (canonical: '{}'). \
             This could indicate a symlink escape attempt.",
            path.display(),
            canonical_path.display(),
            user.home.display(),
            canonical_home.display()
        );
    }

    // Check that root can traverse the directory (X_OK)
    // This is crucial for NFS environments with root squashing
    if let Err(e) = unistd::access(path, AccessFlags::X_OK) {
        bail!(
            "Insufficient permissions to access '{}': {} \
             (root may be restricted by NFS root-squash)",
            path.display(),
            e
        );
    }

    Ok(())
}

/// Enter a new mount namespace and make all mounts private.
///
/// This ensures our bind mount won't affect the host system and will
/// be automatically cleaned up when the process exits.
pub fn enter_private_mount_namespace() -> Result<()> {
    // Create new mount namespace
    unshare(CloneFlags::CLONE_NEWNS)
        .map_err(|e| NixNamespaceError::SystemCall {
            call: "unshare(CLONE_NEWNS)".to_string(),
            source: e,
        })?;

    // Make entire mount tree private to prevent propagation
    // Using explicit type parameters to help Rust's type inference
    let flags = MsFlags::MS_PRIVATE | MsFlags::MS_REC;
    mount::<str, str, str, str>(None, "/", None, flags, None)
        .map_err(|e| NixNamespaceError::MountOperation(format!(
            "Failed to make mount tree private with MS_PRIVATE|MS_REC: {}. \
             This is required to prevent mount propagation to the host.",
            e
        )))?;

    Ok(())
}

/// Bind mount the source directory to the target mount point.
///
/// Uses MS_BIND without MS_REC as we're mounting a single directory.
pub fn bind_mount_nix(source: &Path, target: &Path) -> Result<()> {
    // Final verification that source exists
    if !source.exists() {
        return Err(NixNamespaceError::Filesystem {
            path: source.to_path_buf(),
            message: "Source directory does not exist".to_string(),
        });
    }

    // Perform the bind mount
    let flags = MsFlags::MS_BIND;
    mount(
        Some(source),
        target,
        None::<&str>,  // No filesystem type needed for bind mount
        flags,
        None::<&str>,  // No mount options needed
    )
    .map_err(|e| NixNamespaceError::MountOperation(format!(
        "Bind mount failed: {} -> {}. Error: {}. \
         This could be due to insufficient permissions, \
         missing source/target, or mount namespace restrictions.",
        source.display(),
        target.display(),
        e
    )))?;

    Ok(())
}

/// Clean up sudo-related environment variables to prevent confusion
/// in the new shell environment.
pub fn clean_sudo_environment() -> Result<()> {
    // List of sudo-related variables to remove
    let sudo_vars = [
        "SUDO_UID",
        "SUDO_GID",
        "SUDO_USER",
        "SUDO_COMMAND",  // Additional cleanup from PDF version
    ];

    for var in &sudo_vars {
        unsafe {
            env::remove_var(var);
        }
    }

    Ok(())
}

/// Execute the user's shell, replacing the current process.
///
/// Uses runuser for proper privilege dropping and PAM session handling.
pub fn execute_user_shell(user: &SudoUser) -> Result<()> {
    execute_user_shell_internal(user)
        .map_err(|e| NixNamespaceError::Environment(format!("{:#}", e)))
}

/// Main entry point for creating a Nix namespace with security context
/// This is the preferred method for setuid/setcap installations
pub fn create_nix_namespace_secure() -> Result<()> {
    create_nix_namespace_secure_internal()
        .map_err(|e| {
            let error_string = format!("{:#}", e);
            if error_string.contains("Security violation") {
                NixNamespaceError::SecurityViolation(error_string)
            } else if error_string.contains("Permission") {
                NixNamespaceError::PermissionDenied {
                    path: PathBuf::from("/nix"),
                    suggestion: "Check setuid/setcap installation".to_string(),
                }
            } else {
                NixNamespaceError::MountOperation(error_string)
            }
        })
}

fn execute_user_shell_internal(user: &SudoUser) -> AnyhowResult<()> {
    // First verify runuser is available
    let runuser_path = Path::new("/sbin/runuser");
    if !runuser_path.exists() {
        // Try alternative location
        let alt_path = Path::new("/usr/sbin/runuser");
        if !alt_path.exists() {
            bail!(
                "runuser binary not found in /sbin/runuser or /usr/sbin/runuser. \
                 Please install util-linux package."
            );
        }
    }

    // Ensure we can execute it
    if let Err(e) = unistd::access(runuser_path, AccessFlags::X_OK) {
        bail!("runuser binary exists but is not executable: {}", e);
    }

    // Build runuser arguments
    // Explicitly specify shell with --shell to ensure correct shell is used
    let shell_str = user.shell
        .to_str()
        .ok_or_else(|| anyhow!("User shell path contains invalid UTF-8"))?;

    let args = vec![
        CString::new("runuser")?,
        CString::new("--preserve-environment")?,
        CString::new("-u")?,
        CString::new(user.name.as_str())?,
        CString::new("--shell")?,
        CString::new(shell_str)?,
    ];

    // Execute runuser, which will drop privileges and exec the shell
    // This replaces our process, so it should never return on success
    let prog = &args[0];
    match unistd::execvp(prog, &args) {
        Ok(_) => unreachable!("execvp should not return on success"),
        Err(e) => Err(anyhow!(e)).context(
            "execvp failed to execute runuser. \
             This should not happen if runuser exists and is executable."
        ),
    }
}

fn create_nix_namespace_secure_internal() -> AnyhowResult<()> {
    // Initialize security context
    let ctx = SecurityContext::init()
        .context("Failed to initialize security context")?;

    // Prepare /nix mount point (requires root)
    prepare_nix_mount_point()
        .context("Failed to prepare /nix mount point")?;

    // Get and validate the user's Nix store path
    let nix_store_path = get_nix_store_path(&ctx)
        .context("Failed to determine Nix store path")?;

    // Validate the directory with dropped privileges
    ctx.with_dropped_privileges(|| {
        // Check directory exists and is accessible
        if !nix_store_path.exists() {
            bail!("Nix store directory {} does not exist", nix_store_path.display());
        }
        
        // Verify we can access it
        if let Err(e) = unistd::access(&nix_store_path, AccessFlags::R_OK | AccessFlags::X_OK) {
            bail!("Cannot access Nix store directory {}: {}", nix_store_path.display(), e);
        }
        
        Ok(())
    })?;

    // Create private mount namespace (requires root)
    enter_private_mount_namespace()
        .context("Failed to create private mount namespace")?;

    // Perform the bind mount (requires root)
    bind_mount_nix(&nix_store_path, Path::new(NIX_MOUNT_DIR))
        .context("Failed to bind mount Nix store")?;


    // CRITICAL: Drop root privileges immediately after mount operations
    // This is the key security benefit of setuid over capabilities
    ctx.drop_privileges()
        .context("Failed to drop root privileges after mount operations")?;
    // Clean environment if running under sudo
    if ctx.is_sudo {
        clean_sudo_environment()
            .context("Failed to clean sudo environment")?;
    }

    // Execute the user's shell
    if let Some(ref user) = ctx.user {
        // For non-root users, use their shell
        execute_user_shell(&SudoUser {
            uid: user.uid,
            gid: user.gid,
            name: user.name.clone(),
            home: PathBuf::from(&user.dir),
            shell: PathBuf::from(&user.shell),
        })?;
    } else {
        // Running as actual root - just exec a shell
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let shell_cstr = CString::new(shell.as_str())?;
        let args = vec![shell_cstr.clone()];
        unistd::execvp(&shell_cstr, &args)?;
    }

    Ok(())
}
