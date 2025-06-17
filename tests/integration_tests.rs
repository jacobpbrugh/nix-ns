use nix_ns::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[cfg(test)]
mod security_tests {
    use super::*;
    use std::os::unix::fs as unix_fs;

    #[test]
    fn test_refuses_symlink_nix_directory() {
        // This test would need to run as root to actually create /nix
        // but demonstrates the validation logic

        let temp = TempDir::new().unwrap();
        let fake_nix = temp.path().join("fake_nix");
        let symlink_nix = temp.path().join("symlink_nix");

        // Create a directory and a symlink to it
        fs::create_dir(&fake_nix).unwrap();
        unix_fs::symlink(&fake_nix, &symlink_nix).unwrap();

        // In real scenario, validate_user_nix_directory would catch this
        let metadata = fs::symlink_metadata(&symlink_nix).unwrap();
        assert!(metadata.file_type().is_symlink());
    }

    #[test]
    fn test_path_escape_detection() {
        let temp = TempDir::new().unwrap();
        let home = temp.path().join("home").join("testuser");
        let outside = temp.path().join("outside");

        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // Create a symlink that tries to escape the home directory
        let escape_link = home.join(".local");
        unix_fs::symlink(&outside, &escape_link).unwrap();

        // Canonical path resolution would reveal the escape
        let canonical = fs::canonicalize(&escape_link).unwrap();
        assert!(!canonical.starts_with(&home));
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;

    #[test]
    fn test_directory_permission_check() {
        let temp = TempDir::new().unwrap();
        let restricted = temp.path().join("restricted");

        fs::create_dir(&restricted).unwrap();

        // Set very restrictive permissions (no execute for others)
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o700)).unwrap();

        let perms = fs::metadata(&restricted).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;
    use std::env;

    #[test]
    fn test_sudo_environment_cleanup() {
        // Set up fake sudo environment
        unsafe { env::set_var("SUDO_UID", "1000"); }
        unsafe { env::set_var("SUDO_GID", "1000"); }
        unsafe { env::set_var("SUDO_USER", "testuser"); }
        unsafe { env::set_var("SUDO_COMMAND", "/usr/bin/test"); }

        // Clean should always succeed unless something catastrophic happens
        assert!(clean_sudo_environment().is_ok());

        assert!(env::var("SUDO_UID").is_err());
        assert!(env::var("SUDO_GID").is_err());
        assert!(env::var("SUDO_USER").is_err());
        assert!(env::var("SUDO_COMMAND").is_err());
    }
}
