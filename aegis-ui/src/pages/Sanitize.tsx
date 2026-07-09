import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SafeFile {
    name: string;
    size: string;
    type: string;
    safe: boolean;
    reason?: string;
}

const MOCK_FILES: SafeFile[] = [
    { name: "report_q4_2025.pdf", size: "2.4 MB", type: "PDF", safe: true },
    { name: "meeting_notes.txt", size: "12 KB", type: "Text", safe: true },
    { name: "photo_001.jpg", size: "3.1 MB", type: "Image", safe: true },
    { name: "budget.xlsx", size: "890 KB", type: "Excel", safe: false, reason: "Contains VBA macros — stripped for safety" },
    { name: "installer.exe", size: "15.2 MB", type: "Executable", safe: false, reason: "PE executable blocked — potential threat" },
    { name: "backup.zip.enc", size: "45.0 MB", type: "Encrypted", safe: false, reason: "Shannon entropy: 7.9 — likely encrypted payload" },
    { name: "readme.md", size: "4 KB", type: "Text", safe: true },
    { name: "autorun.inf", size: "1 KB", type: "Config", safe: false, reason: "Autorun.inf — USB auto-execution vector blocked" },
];

export function Sanitize() {
    const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
    const [quarantinedDevice, setQuarantinedDevice] = useState<any>(null);

    useEffect(() => {
        const fetchDevices = async () => {
            try {
                const devs: any[] = await invoke("list_devices");
                const qDev = devs.find((d: any) => d.status === "Quarantined");
                setQuarantinedDevice(qDev || null);
            } catch (err) {
                console.error(err);
            }
        };

        fetchDevices();
        const interval = setInterval(fetchDevices, 2000);
        return () => clearInterval(interval);
    }, []);

    const safeFiles = MOCK_FILES.filter((f) => f.safe);
    const blockedFiles = MOCK_FILES.filter((f) => !f.safe);

    const toggleFile = (name: string) => {
        const next = new Set(selectedFiles);
        if (next.has(name)) next.delete(name);
        else next.add(name);
        setSelectedFiles(next);
    };

    const selectAllSafe = () => {
        setSelectedFiles(new Set(safeFiles.map((f) => f.name)));
    };

    const fileIcon = (type: string) => {
        switch (type) {
            case "PDF": return "📄";
            case "Text": return "📝";
            case "Image": return "🖼️";
            case "Excel": return "📊";
            case "Executable": return "⚙️";
            case "Encrypted": return "🔒";
            case "Config": return "⚙️";
            default: return "📁";
        }
    };

    return (
        <>
            <div className="page-header">
                <h2>Sanitize & Trust</h2>
                <p>Content Disarm & Reconstruction — safely extract files from quarantined drives</p>
            </div>
            <div className="page-content animate-in">
                {!quarantinedDevice ? (
                    <div className="glass-panel" style={{ padding: 40, textAlign: "center", color: "var(--text-muted)" }}>
                        <div style={{ fontSize: 48, marginBottom: 16 }}>🛡️</div>
                        <h3 style={{ marginBottom: 8, color: "var(--text-primary)" }}>No Action Required</h3>
                        <p>No quarantined USB drives detected requiring content sanitization.</p>
                    </div>
                ) : (
                    <>
                        {/* Source device info */}
                        <div className="glass-panel" style={{ marginBottom: 20, display: "flex", alignItems: "center", gap: 16, padding: "16px 24px" }}>
                            <div className="device-icon quarantined" style={{ width: 40, height: 40, fontSize: 20 }}>⚠️</div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 15 }}>{quarantinedDevice.product_name || "Unknown Device"} — Quarantined</div>
                                <div style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                                    {quarantinedDevice.vendor_id.toString(16).padStart(4, '0')}:{quarantinedDevice.product_id.toString(16).padStart(4, '0')} • Port {quarantinedDevice.port_path} • Trust Score: {quarantinedDevice.trust_score}%
                                </div>
                            </div>
                            <div style={{ marginLeft: "auto" }}>
                                <span className="status-badge quarantined">⚠️ Quarantined</span>
                            </div>
                        </div>

                        <div className="grid-2">
                            {/* Safe Files */}
                            <div className="glass-panel">
                                <div className="panel-title" style={{ justifyContent: "space-between" }}>
                                    <span>✅ Safe Files ({safeFiles.length})</span>
                                    <button className="btn btn-ghost btn-sm" onClick={selectAllSafe}>Select All</button>
                                </div>
                                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                                    {safeFiles.map((file) => (
                                        <div
                                            key={file.name}
                                            onClick={() => toggleFile(file.name)}
                                            style={{
                                                display: "flex",
                                                alignItems: "center",
                                                gap: 12,
                                                padding: "10px 14px",
                                                borderRadius: "var(--border-radius-sm)",
                                                background: selectedFiles.has(file.name) ? "rgba(34, 197, 94, 0.08)" : "transparent",
                                                border: selectedFiles.has(file.name) ? "1px solid rgba(34, 197, 94, 0.25)" : "1px solid transparent",
                                                cursor: "pointer",
                                                transition: "all 0.15s ease",
                                            }}
                                        >
                                            <span style={{ fontSize: 20 }}>{fileIcon(file.type)}</span>
                                            <div style={{ flex: 1 }}>
                                                <div style={{ fontSize: 14, fontWeight: 500 }}>{file.name}</div>
                                                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                                                    {file.type} • {file.size}
                                                </div>
                                            </div>
                                            <div style={{
                                                width: 22, height: 22, borderRadius: 6,
                                                border: selectedFiles.has(file.name) ? "2px solid var(--success)" : "2px solid var(--glass-border)",
                                                background: selectedFiles.has(file.name) ? "var(--success)" : "transparent",
                                                display: "flex", alignItems: "center", justifyContent: "center",
                                                fontSize: 12, color: "white", transition: "all 0.15s",
                                            }}>
                                                {selectedFiles.has(file.name) && "✓"}
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                {selectedFiles.size > 0 && (
                                    <button
                                        className="btn btn-primary"
                                        style={{ width: "100%", marginTop: 16, justifyContent: "center", padding: "12px" }}
                                    >
                                        🧹 Extract {selectedFiles.size} Safe File{selectedFiles.size > 1 ? "s" : ""}
                                    </button>
                                )}
                            </div>

                            {/* Blocked Files */}
                            <div className="glass-panel">
                                <div className="panel-title">🚫 Blocked Files ({blockedFiles.length})</div>
                                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                                    {blockedFiles.map((file) => (
                                        <div
                                            key={file.name}
                                            style={{
                                                display: "flex",
                                                alignItems: "flex-start",
                                                gap: 12,
                                                padding: "10px 14px",
                                                borderRadius: "var(--border-radius-sm)",
                                                borderLeft: "3px solid var(--danger)",
                                                background: "rgba(239, 68, 68, 0.03)",
                                            }}
                                        >
                                            <span style={{ fontSize: 20 }}>{fileIcon(file.type)}</span>
                                            <div style={{ flex: 1 }}>
                                                <div style={{ fontSize: 14, fontWeight: 500, color: "var(--danger)" }}>{file.name}</div>
                                                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                                                    {file.type} • {file.size}
                                                </div>
                                                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4 }}>
                                                    {file.reason}
                                                </div>
                                            </div>
                                            <span className="status-badge blocked" style={{ fontSize: 10 }}>Stripped</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </>
                )}
            </div>
        </>
    );
}
