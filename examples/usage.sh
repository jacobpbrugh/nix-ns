#!/bin/bash
# Example usage of nix-mount-namespace with different source configurations

# Method 1: Using default location (~/.local/share/nix)
./nix-mount-namespace

# Method 2: Using command-line argument
./nix-mount-namespace --source /home/myuser/my-nix-store

# Method 3: Using environment variable
export NIX_NS_SOURCE=/home/myuser/alt-nix-store
./nix-mount-namespace

# Method 4: Using configuration file
# Create ~/.config/nix-ns/config.toml with:
# source_path = "custom/nix/location"
# allow_symlinks = false

# Debug mode to see what path is being used
./nix-mount-namespace --debug

# Combine with sudo (if not installed setuid)
sudo ./nix-mount-namespace --source /custom/path