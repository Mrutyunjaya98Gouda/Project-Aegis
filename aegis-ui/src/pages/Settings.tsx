import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SettingToggle {
    id: string;
    label: string;
    description: string;
    enabled: boolean;
}

export function Settings() {
    const [analysisSettings, setAnalysisSettings] = useState<SettingToggle[]>([
        { id: "yara_enabled", label: "YARA Signature Scanning", description: "Scan files against known malware signatures", enabled: false },
        { id: "entropy_enabled", label: "Shannon Entropy Analysis", description: "Detect encrypted/packed payloads via statistical randomness", enabled: false },
        { id: "hid_spoof_detection", label: "HID Spoof Detection", description: "Detect BadUSB devices claiming keyboard interfaces", enabled: false },
        { id: "ml_anomaly", label: "ML Keystroke Anomaly Detection", description: "Detect synthetic keyboard input from BadUSBs (ONNX model)", enabled: false },
        { id: "sandbox", label: "MicroVM Dynamic Sandbox", description: "Detonate suspicious files in ephemeral VMs", enabled: false },
    ]);

    const [policySettings, setPolicySettings] = useState<SettingToggle[]>([
        { id: "default_action", label: "Default Action (Block = Enabled)", description: "Default action for new unknown USBs", enabled: false },
        { id: "geofence", label: "Physical Geofencing", description: "Deny devices plugged into unauthorized physical ports", enabled: false },
    ]);

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                const conf: any = await invoke("get_config");
                if (conf) {
                    const cfg = typeof conf === 'string' ? JSON.parse(conf) : conf;

                    setAnalysisSettings(prev => prev.map(s => {
                        if (s.id === "yara_enabled") return { ...s, enabled: cfg.analysis?.yara_enabled ?? s.enabled };
                        if (s.id === "hid_spoof_detection") return { ...s, enabled: cfg.analysis?.hid_spoof_detection ?? s.enabled };
                        return s;
                    }));

                    setPolicySettings(prev => prev.map(s => {
                        if (s.id === "default_action") return { ...s, enabled: cfg.policy?.default_action !== "authorize" };
                        return s;
                    }));
                }
            } catch (err) {
                console.error("Config fetch error:", err);
            }
        };
        fetchConfig();
    }, []);

    const [saving, setSaving] = useState(false);
    const [saveStatus, setSaveStatus] = useState<"idle" | "saved" | "error">("idle");

    const toggleSetting = async (
        settings: SettingToggle[],
        setter: React.Dispatch<React.SetStateAction<SettingToggle[]>>,
        id: string
    ) => {
        const newSettings = settings.map((s) => s.id === id ? { ...s, enabled: !s.enabled } : s);
        setter(newSettings);

        // Build updated config patch and persist to daemon
        setSaving(true);
        setSaveStatus("idle");
        try {
            const currentConf: any = await invoke("get_config");
            const cfg = typeof currentConf === "string" ? JSON.parse(currentConf) : currentConf;

            // Apply changes from all current toggles
            const allSettings = [...(id.startsWith("default_action") || id.startsWith("geofence")
                ? analysisSettings
                : newSettings), ...newSettings];

            // Analysis settings
            const getEnabled = (arr: SettingToggle[], settingId: string) =>
                arr.find((s) => s.id === settingId)?.enabled ?? false;

            const finalAnalysis = [...analysisSettings.map((s) => s.id === id ? { ...s, enabled: !s.enabled } : s)];
            const finalPolicy = [...policySettings.map((s) => s.id === id ? { ...s, enabled: !s.enabled } : s)];

            cfg.analysis.yara_enabled = getEnabled(finalAnalysis, "yara_enabled");
            cfg.analysis.hid_spoof_detection = getEnabled(finalAnalysis, "hid_spoof_detection");
            cfg.analysis.ml_anomaly_detection = getEnabled(finalAnalysis, "ml_anomaly");
            cfg.analysis.sandbox_enabled = getEnabled(finalAnalysis, "sandbox");
            cfg.policy.default_action = getEnabled(finalPolicy, "default_action") ? "block" : "quarantine";

            await invoke("update_config", { configJson: JSON.stringify(cfg) });
            setSaveStatus("saved");
            setTimeout(() => setSaveStatus("idle"), 2000);
        } catch (err) {
            console.error("Failed to save config:", err);
            setSaveStatus("error");
            setTimeout(() => setSaveStatus("idle"), 3000);
        } finally {
            setSaving(false);
        }
    };


    return (
        <>
            <div className="page-header">
                <h2>Settings</h2>
                <p>Configure analysis engine, policies, RBAC, and geo-fencing rules</p>
            </div>
            <div className="page-content animate-in">
                <div className="grid-2">
                    {/* Analysis Engine */}
                    <div className="glass-panel">
                        <div className="settings-section">
                            <h3>🧠 Analysis Engine</h3>
                            {analysisSettings.map((setting) => (
                                <div className="setting-row" key={setting.id}>
                                    <div>
                                        <div className="setting-label">{setting.label}</div>
                                        <div className="setting-desc">{setting.description}</div>
                                    </div>
                                    <div
                                        className={`toggle-switch ${setting.enabled ? "active" : ""}`}
                                        onClick={() => toggleSetting(analysisSettings, setAnalysisSettings, setting.id)}
                                    />
                                </div>
                            ))}
                        </div>

                        <div className="settings-section" style={{ marginTop: 24 }}>
                            <h3>📊 Thresholds</h3>
                            <div className="setting-row">
                                <div>
                                    <div className="setting-label">Entropy Threshold</div>
                                    <div className="setting-desc">Files above this value are flagged (0-8 bits/byte)</div>
                                </div>
                                <div style={{
                                    background: "var(--bg-tertiary)",
                                    border: "1px solid var(--glass-border)",
                                    borderRadius: "var(--border-radius-sm)",
                                    padding: "6px 12px",
                                    color: "var(--accent-primary)",
                                    fontFamily: "var(--font-mono)",
                                    fontSize: 14,
                                    fontWeight: 600,
                                    width: 80,
                                    textAlign: "center",
                                }}>
                                    7.5
                                </div>
                            </div>
                            <div className="setting-row">
                                <div>
                                    <div className="setting-label">Auth Timeout</div>
                                    <div className="setting-desc">Auto-block if not approved within this period</div>
                                </div>
                                <div style={{
                                    background: "var(--bg-tertiary)",
                                    border: "1px solid var(--glass-border)",
                                    borderRadius: "var(--border-radius-sm)",
                                    padding: "6px 12px",
                                    color: "var(--accent-primary)",
                                    fontFamily: "var(--font-mono)",
                                    fontSize: 14,
                                    fontWeight: 600,
                                    width: 80,
                                    textAlign: "center",
                                }}>
                                    300s
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Policy & RBAC */}
                    <div className="glass-panel">
                        <div className="settings-section">
                            <h3>🛂 Policy & Access Control</h3>
                            {policySettings.map((setting) => (
                                <div className="setting-row" key={setting.id}>
                                    <div>
                                        <div className="setting-label">{setting.label}</div>
                                        <div className="setting-desc">{setting.description}</div>
                                    </div>
                                    <div
                                        className={`toggle-switch ${setting.enabled ? "active" : ""}`}
                                        onClick={() => toggleSetting(policySettings, setPolicySettings, setting.id)}
                                    />
                                </div>
                            ))}
                        </div>

                        <div className="settings-section" style={{ marginTop: 24 }}>
                            <h3>👥 RBAC Roles</h3>
                            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                                {[
                                    { role: "Admin", perms: "Full Access", color: "var(--danger)" },
                                    { role: "User", perms: "View Logs, Eject Only", color: "var(--warning)" },
                                    { role: "Kiosk", perms: "No Access", color: "var(--text-muted)" },
                                ].map((r) => (
                                    <div key={r.role} style={{
                                        display: "flex",
                                        justifyContent: "space-between",
                                        alignItems: "center",
                                        padding: "10px 14px",
                                        background: "var(--bg-tertiary)",
                                        borderRadius: "var(--border-radius-sm)",
                                        borderLeft: `3px solid ${r.color}`,
                                    }}>
                                        <span style={{ fontWeight: 600, fontSize: 14 }}>{r.role}</span>
                                        <span style={{ fontSize: 12, color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>{r.perms}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="settings-section" style={{ marginTop: 24 }}>
                            <h3>🪪 Trusted Devices</h3>
                            <div className="empty-state" style={{ padding: "30px 20px" }}>
                                <div className="empty-icon">📱</div>
                                <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                                    No trusted device passports configured. Approve a device to add it.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
}
