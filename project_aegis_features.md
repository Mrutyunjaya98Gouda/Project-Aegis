# Project Aegis - Complete Features & Functionalities

This document enumerates the comprehensive suite of capabilities embedded within the Project Aegis Zero-Trust USB defense platform.

## 🛡️ 1. Core Interception & Isolation (The Guard)
*   **Kernel Intercept**: Uses `udev` and `sysfs` on Linux to intercept the device mount process. It structurally holds the block mount in a "frozen" state until the daemon authorizes it.
*   **Hardware Write-Blocker (Software Emulated)**: Enforces a strict "Read-Only" mode by default by blocking outbound SCSI commands. Prevents host malware from exfiltrating data to an inserted drive.
*   **Motherboard Protection (Kill-Switch)**: Constantly monitors USB Hub telemetry for rapid voltage spikes characteristic of a "USB Killer," instantly cutting port power to prevent motherboard burnout.

## 🧠 2. Static & Behavioral Analysis (The Brain)
*   **Shannon Entropy Scanner**: Reads raw file buffers to measure statistical entropy (randomness), swiftly identifying and blocking highly encrypted or packed files associated with ransomware.
*   **YARA-X Signature Engine**: Facilitates high-speed, structural pattern matching against RAW memory buffers utilizing standard malware Indicators of Compromise (IOCs).

### 5. Keystroke Anomaly Detection (ML) - *In Development*
**Concept**: BadUSB attacks simulate a keyboard typing at superhuman speeds. Aegis will use an ONNX-based ML model to analyze input event timings (inter-keystroke latency) to differentiate human typists from automated payloads.
*Status*: Currently a heuristic stub. Full ML integration is planned.

### 6. Honey-Token Implantation - *Proof of Concept*
**Concept**: When an authorized USB is inserted, Aegis silently writes hidden "honey-token" files (e.g., `.git/index.lock` or `thumbs.db` containing tracking beacons) to the drive. If the drive is later used in an adversary's compromised environment that bulk-exfiltrates files, the beacons phone home, revealing the leak path.
*Status*: Module is written as a proof-of-concept but is not yet integrated into the daemon pipeline.

### 7. Threat Intelligence Sync - *Planned*
**Concept**: The daemon periodically polls a central threat intel server to pull the latest YARA signatures, malicious device passports, and IOCs.
*Status*: Currently a stub. Local configuration files are used.

## 🪪 3. Hardware Fingerprinting & Spoof Defense
*   **Device Digital Passport**: Generates a resilient hash signature tracking the `VID`, `PID`, `Serial Number`, and `Revision ID` to securely identify distinct hardware devices globally.
*   **HID Spoof Validation**: Verifies USB configuration descriptors to ensure a drive mounting as "Mass Storage" isn't covertly attempting to inject standard "Human Interface Device" endpoints (Keyboards).

## 🛂 4. Forensics & Compliance Documentation
*   **Slack Space Scanning**: Unlocks low-level logic specifically designed to skip partition tables entirely, targeting unallocated raw sectors for deliberately hidden boot code or fragments.
*   **Secure Audit Logging**: Creates immutable, append-only JSON logs calibrated rigorously toward NIST SP 800-53 standards to ensure optimal SIEM integration.
*   **Role-Based Access Control (RBAC)**: Integrates directly with Active Directory. Denied flash drives strictly require Administrator credentials to mount.
*   **Physical Topology Geo-fencing**: Defines mounting authorizations directly bound to the geographical topology of the motherboard (e.g., Back I/O vs. Front Chassis) to prevent drive-by hardware attacks.

## 🖥️ 5. Zero-Trust Dashboard (The Face)
*   **Modern Tauri UI**: A performant, low-footprint desktop app utilizing React and Vanilla CSS glassmorphism.
*   **Live Hardware Map**: Displays real-time visualizations mimicking logical power flows, connection paths (`Host PC ➔ Hub ➔ Root Partition`), and consolidating them into a visually understandable "Trust Score."
*   **Sanitize & Trust (CDR Toolkit)**: Extracts benign, definitely safe files (e.g., standard text/PDF files) out of an infected drive individually, reconstructing documents and isolating macros so users can seamlessly retrieve what they need without mounting the entire payload.
*   **Valet / Kiosk Mode**: An aggressive lockdown toggle. When the endpoint screen locks, all new peripheral driver connections are instantly and universally ignored until the exact user logs back in.
