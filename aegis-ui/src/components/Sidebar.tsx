import { useState, useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import type { Page } from "../App";

interface SidebarProps {
    currentPage: Page;
    onNavigate: (page: Page) => void;
}

export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
    const [daemonOnline, setDaemonOnline] = useState(false);
    const [daemonVersion, setDaemonVersion] = useState("—");
    const [threatCount, setThreatCount] = useState(0);
    const [logCount, setLogCount] = useState(0);

    useEffect(() => {
        // Listen for real-time daemon status events from the Tauri event bridge
        const unlistenStatus = listen<{ online: boolean; version?: string }>(
            "aegis://daemon-status",
            (event) => {
                setDaemonOnline(event.payload.online);
                if (event.payload.version) {
                    setDaemonVersion(event.payload.version);
                }
            }
        );

        // Listen for device updates to count threats
        const unlistenDevices = listen<any[]>("aegis://device-update", (event) => {
            const devices = Array.isArray(event.payload) ? event.payload : [];
            const threats = devices.filter(
                (d) => d.status === "Blocked" || d.status === "Quarantined"
            ).length;
            setThreatCount(threats);
        });

        return () => {
            unlistenStatus.then((f) => f());
            unlistenDevices.then((f) => f());
        };
    }, []);

    return (
        <nav className="sidebar">
            {/* Logo */}
            <div className="sidebar-logo">
                <div className="logo-icon">🛡️</div>
                <div>
                    <h1>AEGIS</h1>
                    <span className="version-badge">v{daemonVersion}</span>
                </div>
            </div>

            {/* Navigation */}
            <div className="sidebar-nav">
                <div className="nav-section-label">Overview</div>

                <div
                    className={`nav-item ${currentPage === "dashboard" ? "active" : ""}`}
                    onClick={() => onNavigate("dashboard")}
                >
                    <span className="nav-icon">📊</span>
                    <span>Dashboard</span>
                </div>

                <div
                    className={`nav-item ${currentPage === "devices" ? "active" : ""}`}
                    onClick={() => onNavigate("devices")}
                >
                    <span className="nav-icon">🔌</span>
                    <span>Hardware Map</span>
                    {threatCount > 0 && (
                        <span className="nav-badge danger">{threatCount}</span>
                    )}
                </div>

                <div className="nav-section-label">Security</div>

                <div
                    className={`nav-item ${currentPage === "sanitize" ? "active" : ""}`}
                    onClick={() => onNavigate("sanitize")}
                >
                    <span className="nav-icon">🧹</span>
                    <span>Sanitize &amp; Trust</span>
                </div>

                <div
                    className={`nav-item ${currentPage === "audit" ? "active" : ""}`}
                    onClick={() => onNavigate("audit")}
                >
                    <span className="nav-icon">📋</span>
                    <span>Audit Log</span>
                    {logCount > 0 && (
                        <span className="nav-badge warning">{logCount}</span>
                    )}
                </div>

                <div className="nav-section-label">System</div>

                <div
                    className={`nav-item ${currentPage === "settings" ? "active" : ""}`}
                    onClick={() => onNavigate("settings")}
                >
                    <span className="nav-icon">⚙️</span>
                    <span>Settings</span>
                </div>
            </div>

            {/* Footer: Daemon Status */}
            <div className="sidebar-footer">
                <div className="daemon-status">
                    <div className={`status-dot ${daemonOnline ? "online" : "offline"}`} />
                    <span>{daemonOnline ? "Daemon Online" : "Daemon Offline"}</span>
                    {daemonOnline && (
                        <span style={{ marginLeft: "auto", color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 11 }}>
                            v{daemonVersion}
                        </span>
                    )}
                </div>
            </div>
        </nav>
    );
}
