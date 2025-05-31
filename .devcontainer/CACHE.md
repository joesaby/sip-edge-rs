# Dev Container Cache Setup

This dev container is configured to use host folder mounts for persistent caching, which means your build caches will survive container rebuilds.

## Cache Directories

The following host directories are mounted into the container:

1. **`.devcontainer/cache/cargo-registry/`** → `/usr/local/cargo/registry/`
   - Cargo package registry cache
   - Stores downloaded crate metadata and source code

2. **`.devcontainer/cache/cargo-git/`** → `/usr/local/cargo/git/`
   - Git dependencies cache  
   - Stores cloned git repositories for dependencies

3. **`.devcontainer/cache/target/`** → `/workspaces/sip-edge-rs/target/`
   - Build output cache
   - Stores compiled artifacts and incremental compilation data

## Benefits

- **Faster rebuilds**: Cargo doesn't need to re-download dependencies
- **Faster compilation**: Incremental compilation data is preserved
- **Bandwidth savings**: No re-downloading of crates on each rebuild
- **Development efficiency**: Immediate productivity after container rebuild

## Host vs Docker Volume

We use **host folder mounts** instead of Docker volumes because:

- ✅ Cache persists even if you remove all Docker volumes
- ✅ Easy to inspect cache contents from host OS
- ✅ Easy to backup/restore cache
- ✅ Works across different Docker environments
- ❌ Slightly slower on Docker Desktop (especially macOS/Windows)

## Cache Management

### Clear All Caches
```bash
# From host (outside container)
rm -rf .devcontainer/cache/*

# From inside container
cargo clean
rm -rf /usr/local/cargo/registry/*
rm -rf /usr/local/cargo/git/*
```

### View Cache Size
```bash
# From host
du -sh .devcontainer/cache/*

# From inside container  
du -sh /usr/local/cargo/registry /usr/local/cargo/git target/
```

### Troubleshooting

If you encounter permission issues:

1. **Container rebuild**: The setup script should fix permissions automatically
2. **Manual fix**: Run `make setup` or the setup script manually
3. **Reset cache**: Delete `.devcontainer/cache/` and rebuild container

## Alternative: Docker Volumes

If you prefer Docker volumes (slightly faster on non-Linux hosts), modify `.devcontainer/devcontainer.json`:

```json
"mounts": [
    "source=sip-edge-cargo-registry,target=/usr/local/cargo/registry,type=volume",
    "source=sip-edge-cargo-git,target=/usr/local/cargo/git,type=volume", 
    "source=sip-edge-target,target=/workspaces/sip-edge-rs/target,type=volume"
]
```

Docker volumes persist until explicitly deleted with `docker volume rm`. 