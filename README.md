# Project Aegis — Zero-Trust USB Security Suite

Project Aegis is an enterprise-grade USB security daemon and desktop interface designed to prevent malicious USB devices (Rubber Duckies, BadUSB, ransomware mass-storage) from compromising Linux workstations. It enforces a strict zero-trust policy by intercepting devices at the kernel level via `udev` and `sysfs`.

## Key Features
* **Pre-mount Interception**: Enforces a hardware read-only state before the filesystem mounts using sysfs (`/sys/block/.../ro`).
* **Deep Analysis Pipeline**: Analyzes block device data (first 512KB) using Shannon entropy to detect packed ransomware payloads, and scans for YARA signatures.
* **ML Keystroke Anomaly Detection (In Development)**: Analyzes the cadence and timing of typing to differentiate a human from a BadUSB executing a pre-programmed payload. (Currently implemented as a heuristic stub).
* **Dynamic Threat Intelligence (Planned)**: Syncs YARA rules and IOCs from central servers. (Currently stubbed).
* **HID Spoof Detection**: Identifies mass storage devices that hide malicious keyboard interfaces.
* **NIST SP 800-53 Audit Logging**: Maintains a tamper-proof event log secured by a cryptographic HMAC-SHA256 chain.
* **Real-time UI**: A Tauri-based dashboard providing real-time device mapping (D3.js) and status notifications.

## Architecture

The suite consists of four Rust crates:
1. `aegis-daemon`: The root-level background daemon orchestrating `udev` events, sysfs write-blocking, and analysis.
2. `aegis-analysis`: The pipeline engine for Entropy, YARA, and ML detection.
3. `aegis-common`: Shared types, device definitions, IPC protocol, and cryptographic logging.
4. `aegis-ui`: The Tauri (React/TypeScript) frontend that visualizes the state.

## Installation (Production)

The project includes an installer that builds the Rust release binaries, configures systemd, sets up `udev` rules, and locks down permissions.

```bash
sudo bash install/install.sh
```

**What the installer does:**
1. Builds `aegis-daemon` in release mode.
2. Installs the binary to `/usr/local/bin/aegis-daemon`.
3. Creates a configuration file at `/etc/aegis/aegis.toml` with a newly generated cryptographic HMAC key.
4. Secures the audit log directory at `/var/log/aegis`.
5. Loads `udev` rules to `/etc/udev/rules.d/99-aegis.rules`.
6. Enables and starts the `aegis-daemon` systemd service.

### Uninstallation

```bash
sudo bash install/install.sh --uninstall
```

## Packaging (.deb)

To build a Debian package for the daemon (requires `cargo-deb`):
```bash
make package-deb
```
This produces a `.deb` artifact in `target/debian/` that can be distributed to endpoints.

## Development

A complete Makefile is provided.

```bash
make help          # Show all available commands
make run           # Run the full stack (daemon + UI) in dev mode
make test          # Run all workspace unit tests
```

## Security Considerations
- **HMAC Key**: The daemon requires a strong, randomly generated HMAC key to ensure audit log integrity. The installer handles this automatically.
- **Root Privileges**: The daemon must run as root to manipulate sysfs read-only flags and raw block devices.
- **Polkit**: In a full enterprise environment, you may want to configure PolicyKit to allow non-root users to manage specific daemon interactions if they aren't using the Tauri UI.
