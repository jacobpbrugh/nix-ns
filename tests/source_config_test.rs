use nix_ns::security::NixStoreConfig;
use std::path::PathBuf;

#[test]
fn test_source_override() {
    // Test that command-line override works
    let source_override = Some("/custom/nix/path".to_string());
    
    // Note: This test would require running as root to fully test SecurityContext::init
    // For unit testing, we can at least verify the configuration structure
    let config = NixStoreConfig {
        source_path: PathBuf::from("/custom/nix/path"),
        allow_symlinks: false,
    };
    
    assert_eq!(config.source_path.to_str().unwrap(), "/custom/nix/path");
    assert_eq!(config.allow_symlinks, false);
}

#[test]
fn test_default_config() {
    let config = NixStoreConfig::default();
    assert_eq!(config.source_path.to_str().unwrap(), ".local/share/nix");
    assert_eq!(config.allow_symlinks, false);
}