# Project Aegis - Complete Features & Functionalities

This document enumerates the comprehensive suite of capabilities embedded within the Project Aegis Zero-Trust USB defense platform.

## 🛡️ 1. Core Interception & Isolation (The Guard)
*   **Multi-OS Kernel Intercept**: Uses `eBPF` & `udev` on Linux and `WDK/C++` filter drivers on Windows to intercept the device mount process. It structurally holds the block mount in a "frozen" state until the daemon authorizes it.
*   **Hardware Write-Blocker (Software Emulated)**: Enforces a strict "Read-Only" mode by default by blocking outbound SCSI commands. Prevents host malware from exfiltrating data to an inserted drive.
*   **Motherboard Protection (Kill-Switch)**: Constantly monitors USB Hub telemetry for rapid voltage spikes characteristic of a "USB Killer," instantly cutting port power to prevent motherboard burnout.
*   **Wireless Out-of-Band Detection**: Correlates USB insertion timestamps with host Wi-Fi/Bluetooth adapters to identify O.MG Cables broadcasting unknown SSIDs upon insertion.

## 🧠 2. Static & Behavioral Analysis (The Brain)
*   **Shannon Entropy Scanner**: Reads raw file buffers to measure statistical entropy (randomness), swiftly identifying and blocking highly encrypted or packed files associated with ransomware.
*   **YARA-X Signature Engine**: Facilitates high-speed, structural pattern matching against RAW memory buffers utilizing standard malware Indicators of Compromise (IOCs).
*   **Continuous Threat-Intel Sync**: Periodically updates local YARA-X dictionaries by pulling the latest global threat intelligence feeds (e.g., MISP, VirusTotal) to ensure 0-day protection.
*   **Ephemeral MicroVM Detonation (Dynamic Sandbox)**: Momentarily mounts suspect payloads inside a fast-booting MicroVM (like Firecracker/QEMU) managed by Rust to safely detonate files and observe their behavior in an isolated environment.
*   **Local ML Anomaly Detection**: Parses keystroke and input interval timings via an offline ONNX Machine Learning model to catch advanced BadUSBs simulating high-speed human typing.

## 🪪 3. Hardware Fingerprinting & Spoof Defense
*   **Device Digital Passport**: Generates a resilient hash signature tracking the `VID`, `PID`, `Serial Number`, and `Revision ID` to securely identify distinct hardware devices globally.
*   **HID Spoof Validation**: Verifies USB configuration descriptors to ensure a drive mounting as "Mass Storage" isn't covertly attempting to inject standard "Human Interface Device" endpoints (Keyboards).
*   **Deception Technology (Honey-Tokens)**: Implants generic USBs post-authorization with a hidden "Honey-File." If that specific USB is subsequently jacked into a remote infected computer that copies it, the file pings an external Aegis alarm server.

## 🛂 4. Forensics & Compliance Documentation
*   **Slack Space Scanning**: Unlocks low-level logic specifically designed to skip partition tables entirely, targeting unallocated raw sectors for deliberately hidden boot code or fragments.
*   **Secure Audit Logging**: Creates immutable, append-only JSON logs calibrated rigorously toward NIST SP 800-53 standards to ensure optimal SIEM integration.
*   **Role-Based Access Control (RBAC)**: Integrates directly with Active Directory. Denied flash drives strictly require Administrator credentials to mount.
*   **Physical Topology Geo-fencing**: Defines mounting authorizations directly bound to the geographical topology of the motherboard (e.g., Back I/O vs. Front Chassis) to prevent drive-by hardware attacks.

## 🖥️ 5. Zero-Trust Dashboard (The Face)
*   **Modern Tauri UI**: A performant, low-footprint desktop app utilizing React and Vanilla CSS glassmorphism.
*   **Live Hardware Map**: Displays real-time visualizations mimicking logical power flows, connection paths (`Host PC ➔ Hub ➔ Root Partition`), and consolidating them into a visually understandable "Trust Score."
*   **Sanitize & Trust (CDR Toolkit)**: Extracts benign, definitely safe files (e.g., standard text/PDF files) out of an infected drive individually, reconstructing documents and isolating macros so users can seamlessly retrieve what they need without mounting the entire payload.
*   **Mobile Push Approvals**: Pushes Webhooks to Administrator mobile devices, displaying the drive's snapshot details globally so they can approve or block remotely.
*   **Valet / Kiosk Mode**: An aggressive lockdown toggle. When the endpoint screen locks, all new peripheral driver connections are instantly and universally ignored until the exact user logs back in.
