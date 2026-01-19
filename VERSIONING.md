# Versioning

### 1. Unified Workspace

All crates in this workspace (e.g., `starknet-core`, `starknet-providers`, `starknet-crypto`) are strictly locked to the
**same version number**.

- When a new version is released, **every** crate is updated to that version.
- This ensures that dependencies between internal crates never drift out of sync.

### 2. RPC Support & Backports

We allow the community to stay on older versions of the library while maintaining access to critical fixes.

- **Support Window:** We match ours support window with starknet network. Current size of window is three latest versions.
- **Backports:** Only critical fixes and essential updates are backported to the relevant release branches for supported versions.

### 3. Recommendation for Users

Because backports are released as patch updates (e.g., `0.11.1` -> `0.11.2`) and may contain changes required for RPC
compliance, **we strictly recommend pinning your dependencies** to specific versions to ensure build stability.
