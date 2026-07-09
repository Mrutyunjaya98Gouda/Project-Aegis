import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

interface UsbDevice {
    session_id: string;
    vendor_id: number;
    product_id: number;
    manufacturer?: string;
    product_name?: string;
    port_path: string;
    block_device?: string;
    status: "Pending" | "Authorized" | "Blocked" | "Analyzing" | "Quarantined" | "Ejected";
    trust_score: number;
    has_hid_interface: boolean;
    first_seen: string;
}

interface EventEntry {
    timestamp: string;
    icon: string;
    message: string;
    type: "info" | "warning" | "danger" | "success";
}

export function Dashboard() {
    const [uptime, setUptime] = useState(0);
    const [devices, setDevices] = useState<UsbDevice[]>([]);
    const [events, setEvents] = useState<EventEntry[]>([]);
    const [actionLoading, setActionLoading] = useState<string | null>(null);

    const pushEvent = useCallback((icon: string, message: string, type: EventEntry["type"]) => {
        const entry: EventEntry = { timestamp: new Date().toISOString(), icon, message, type };
        setEvents((prev) => [entry, ...prev].slice(0, 40));
    }, []);

    useEffect(() => {
        // Initial fetch
        const fetchData = async () => {
            try {
                const ping: any = await invoke("ping_daemon");
                setUptime(ping.uptime);
                const devs: UsbDevice[] = await invoke("list_devices");
                setDevices(Array.isArray(devs) ? devs : []);
            } catch (err) {
                console.error("Failed to fetch daemon state:", err);
            }
        };
        fetchData();

        // Listen for real-time device updates from event bridge
        const unlistenDevices = listen<UsbDevice[]>("aegis://device-update", (event) => {
            const newDevices = Array.isArray(event.payload) ? event.payload : [];
            setDevices((prev) => {
                // Detect new devices and push events
                newDevices.forEach((d) => {
                    const existing = prev.find((p) => p.session_id === d.session_id);
                    if (!existing) {
                        pushEvent("🔌", `New device detected: ${d.product_name || "Unknown USB"} at port ${d.port_path}`, "info");
                    } else if (existing.status !== d.status) {
                        if (d.status === "Quarantined") pushEvent("⚠️", `Device quarantined: ${d.product_name || d.port_path} (trust: ${d.trust_score}%)`, "danger");
                        if (d.status === "Authorized") pushEvent("✅", `Device authorized: ${d.product_name || d.port_path}`, "success");
                        if (d.status === "Blocked") pushEvent("🚫", `Device blocked: ${d.product_name || d.port_path}`, "danger");
                    }
                });
                // Detect disconnections
                prev.forEach((p) => {
                    if (!newDevices.find((d) => d.session_id === p.session_id)) {
                        pushEvent("⏏️", `Device removed: ${p.product_name || p.port_path}`, "warning");
                    }
                });
                return newDevices;
            });
        });

        // Listen for daemon status updates
        const unlistenStatus = listen<{ online: boolean; uptime?: number }>(
            "aegis://daemon-status",
            (event) => {
                if (event.payload.uptime !== undefined) {
                    setUptime(event.payload.uptime);
                }
            }
        );

        return () => {
            unlistenDevices.then((f) => f());
            unlistenStatus.then((f) => f());
        };
    }, [pushEvent]);

    const handleAction = async (action: () => Promise<void>, deviceId: string) => {
        setActionLoading(deviceId);
        try {
            await action();
        } catch (err) {
            console.error("Action failed:", err);
        } finally {
            setActionLoading(null);
        }
    };

    const formatUptime = (secs: number) => {
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = secs % 60;
        return `${h.toString().padStart(2, "0")}:${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
    };

    const statusIcon = (status: string) => {
        switch (status) {
            case "Authorized": return "✅";
            case "Blocked": return "🚫";
            case "Quarantined": return "⚠️";
            case "Analyzing": return "🔍";
            case "Ejected": return "⏏️";
            default: return "⏳";
        }
    };

    const trustBadgeClass = (score: number) => {
        if (score >= 70) return "high";
        if (score >= 40) return "medium";
        return "low";
    };

    const activeDevices = devices.filter((d) => d.status !== "Ejected");
    const blockedCount = devices.filter((d) => d.status === "Blocked").length;
    const quarantinedCount = devices.filter((d) => d.status === "Quarantined").length;
    const avgTrust = activeDevices.length > 0
        ? Math.round(activeDevices.reduce((s, d) => s + d.trust_score, 0) / activeDevices.length)
        : 100;

    return (
        <>
            <div className="page-header">
                <h2>Zero-Trust Dashboard</h2>
                <p>Real-time USB device security monitoring and threat analysis</p>
            </div>

            <div className="page-content animate-in">
                {/* Stats Row */}
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-icon">🔌</div>
                        <div className="stat-value">{activeDevices.length}</div>
                        <div className="stat-label">Connected Devices</div>
                    </div>

                    <div className="stat-card">
                        <div className="stat-icon">🚫</div>
                        <div className="stat-value">{blockedCount + quarantinedCount}</div>
                        <div className="stat-label">Threats Detected</div>
                    </div>

                    <div className="stat-card">
                        <div className="stat-icon">🛡️</div>
                        <div className="stat-value">{avgTrust}</div>
                        <div className="stat-label">Avg Trust Score</div>
                    </div>

                    <div className="stat-card">
                        <div className="stat-icon">⏱️</div>
                        <div className="stat-value" style={{ fontSize: "24px", fontFamily: "var(--font-mono)" }}>
                            {formatUptime(uptime)}
                        </div>
                        <div className="stat-label">Daemon Uptime</div>
                    </div>
                </div>

                {/* Two-column layout */}
                <div className="grid-2">
                    {/* Device List */}
                    <div className="glass-panel">
                        <div className="panel-title">🔌 Connected Devices</div>
                        <div className="device-list">
                            {activeDevices.length === 0 && (
                                <div style={{ color: "var(--text-muted)", fontSize: 13, padding: "20px 0", textAlign: "center" }}>
                                    <div style={{ fontSize: 32, marginBottom: 8 }}>🔒</div>
                                    No USB devices connected. System is secure.
                                </div>
                            )}
                            {activeDevices.map((device) => (
                                <div className="device-card" key={device.session_id}>
                                    <div className={`device-icon ${device.status.toLowerCase()}`}>
                                        {statusIcon(device.status)}
                                    </div>
                                    <div className="device-info">
                                        <div className="device-name">
                                            {device.product_name || "Unknown USB Device"}
                                            {device.has_hid_interface && (
                                                <span title="HID interface detected — possible BadUSB" style={{
                                                    marginLeft: 6,
                                                    fontSize: 11,
                                                    background: "var(--warning-bg)",
                                                    color: "var(--warning)",
                                                    padding: "2px 6px",
                                                    borderRadius: 4,
                                                    fontWeight: 600,
                                                }}>⚠ HID</span>
                                            )}
                                        </div>
                                        <div className="device-meta">
                                            {device.vendor_id.toString(16).padStart(4, "0")}:{device.product_id.toString(16).padStart(4, "0")}
                                            {" • "}Port {device.port_path}
                                            {device.block_device && ` • ${device.block_device}`}
                                        </div>
                                        {device.manufacturer && (
                                            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                                                {device.manufacturer}
                                            </div>
                                        )}
                                    </div>
                                    <div className={`trust-badge ${trustBadgeClass(device.trust_score)}`}>
                                        {device.trust_score}%
                                    </div>
                                    <div className="device-actions">
                                        {(device.status === "Pending" || device.status === "Analyzing" || device.status === "Quarantined") && (
                                            <>
                                                <button
                                                    className="btn btn-success btn-sm"
                                                    disabled={actionLoading === device.session_id}
                                                    onClick={() => handleAction(
                                                        () => invoke("authorize_device", { sessionId: device.session_id }),
                                                        device.session_id
                                                    )}
                                                >
                                                    {actionLoading === device.session_id ? "..." : "Approve"}
                                                </button>
                                                <button
                                                    className="btn btn-danger btn-sm"
                                                    disabled={actionLoading === device.session_id}
                                                    onClick={() => handleAction(
                                                        () => invoke("block_device", { sessionId: device.session_id, reason: "Manual block" }),
                                                        device.session_id
                                                    )}
                                                >
                                                    Block
                                                </button>
                                            </>
                                        )}
                                        {device.status === "Authorized" && (
                                            <>
                                                <button
                                                    className="btn btn-danger btn-sm"
                                                    disabled={actionLoading === device.session_id}
                                                    onClick={() => handleAction(
                                                        () => invoke("block_device", { sessionId: device.session_id, reason: "Manual block" }),
                                                        device.session_id
                                                    )}
                                                >
                                                    Block
                                                </button>
                                                <button
                                                    className="btn btn-ghost btn-sm"
                                                    disabled={actionLoading === device.session_id}
                                                    onClick={() => handleAction(
                                                        () => invoke("eject_device", { sessionId: device.session_id }),
                                                        device.session_id
                                                    )}
                                                >
                                                    Eject
                                                </button>
                                            </>
                                        )}
                                        {device.status === "Blocked" && (
                                            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                                                <span className="status-badge blocked">Blocked</span>
                                                <button
                                                    className="btn btn-success btn-sm"
                                                    disabled={actionLoading === device.session_id}
                                                    onClick={() => handleAction(
                                                        () => invoke("authorize_device", { sessionId: device.session_id }),
                                                        device.session_id
                                                    )}
                                                >
                                                    Override
                                                </button>
                                                <button
                                                    className="btn btn-ghost btn-sm"
                                                    disabled={actionLoading === device.session_id}
                                                    onClick={() => handleAction(
                                                        () => invoke("eject_device", { sessionId: device.session_id }),
                                                        device.session_id
                                                    )}
                                                >
                                                    Eject
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Event Feed */}
                    <div className="glass-panel">
                        <div className="panel-title">📡 Live Event Feed</div>
                        <div className="event-feed">
                            {events.length === 0 && (
                                <div style={{ color: "var(--text-muted)", fontSize: 13, padding: "20px 0", textAlign: "center" }}>
                                    <div style={{ fontSize: 28, marginBottom: 8 }}>📡</div>
                                    Monitoring for USB events...
                                </div>
                            )}
                            {events.map((ev, i) => (
                                <div
                                    key={i}
                                    style={{
                                        display: "flex",
                                        alignItems: "flex-start",
                                        gap: 10,
                                        padding: "8px 0",
                                        borderBottom: "1px solid var(--glass-border)",
                                        fontSize: 13,
                                    }}
                                >
                                    <span style={{ fontSize: 16, flexShrink: 0 }}>{ev.icon}</span>
                                    <div>
                                        <div style={{ color: "var(--text-primary)", lineHeight: 1.4 }}>{ev.message}</div>
                                        <div style={{ color: "var(--text-muted)", fontSize: 11, fontFamily: "var(--font-mono)", marginTop: 2 }}>
                                            {new Date(ev.timestamp).toLocaleTimeString()}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}
