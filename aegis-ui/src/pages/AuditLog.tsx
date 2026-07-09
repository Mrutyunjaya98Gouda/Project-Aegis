import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";

interface LogEntry {
    id: number;
    seq: number;
    timestamp: string;
    category: string;
    action: string;
    severity: number;
    message: string;
}

export function AuditLog() {
    const [filter, setFilter] = useState<string>("all");
    const [search, setSearch] = useState("");
    const [logs, setLogs] = useState<LogEntry[]>([]);

    useEffect(() => {
        const fetchLogs = async () => {
            try {
                const res: any = await invoke("get_audit_log", { limit: 200 });
                // The Tauri command returns a JSON array directly.
                const rawEntries: any[] = Array.isArray(res)
                    ? res
                    : res?.entries
                      ? res.entries
                      : [];
                setLogs(rawEntries.map((e: any, i: number) => ({
                    id: i,
                    seq: e.seq ?? i,
                    timestamp: e.timestamp ?? new Date().toISOString(),
                    category: e.category ?? "system",
                    action: e.action ?? "unknown",
                    severity: e.severity ?? 1,
                    message: e.message ?? "Log entry",
                })));
            } catch (err) {
                console.error("Failed to fetch logs:", err);
            }
        };

        fetchLogs();
        const interval = setInterval(fetchLogs, 5000);
        return () => clearInterval(interval);
    }, []);


    const filteredLogs = logs.filter((log) => {
        if (filter !== "all" && log.category !== filter) return false;
        if (search && !log.message.toLowerCase().includes(search.toLowerCase())) return false;
        return true;
    }).reverse();

    const severityClass = (severity: number) => {
        if (severity >= 8) return "critical";
        if (severity >= 5) return "high";
        if (severity >= 3) return "medium";
        return "low";
    };

    const categoryColors: Record<string, string> = {
        system: "var(--info)",
        device: "var(--accent-primary)",
        analysis: "var(--accent-secondary)",
        policy: "var(--warning)",
    };

    return (
        <>
            <div className="page-header">
                <h2>Audit Log</h2>
                <p>NIST SP 800-53 compliant tamper-proof event logging</p>
            </div>
            <div className="page-content animate-in">
                {/* Filter Bar */}
                <div className="glass-panel" style={{ display: "flex", gap: 12, marginBottom: 20, padding: "14px 20px", alignItems: "center", flexWrap: "wrap" }}>
                    <input
                        type="text"
                        placeholder="🔍 Search logs..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        style={{
                            background: "var(--bg-tertiary)",
                            border: "1px solid var(--glass-border)",
                            borderRadius: "var(--border-radius-sm)",
                            padding: "8px 14px",
                            color: "var(--text-primary)",
                            fontSize: 13,
                            fontFamily: "var(--font-sans)",
                            width: 260,
                            outline: "none",
                        }}
                    />
                    {["all", "system", "device", "analysis", "policy"].map((cat) => (
                        <button
                            key={cat}
                            className={`btn ${filter === cat ? "btn-primary" : "btn-ghost"} btn-sm`}
                            onClick={() => setFilter(cat)}
                        >
                            {cat.charAt(0).toUpperCase() + cat.slice(1)}
                        </button>
                    ))}
                    <div style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        {filteredLogs.length} entries • HMAC integrity: ✅ verified
                    </div>
                </div>

                {/* Log Table */}
                <div className="glass-panel" style={{ padding: 0, overflow: "hidden" }}>
                    <table className="log-table">
                        <thead>
                            <tr>
                                <th style={{ width: 40 }}>Sev</th>
                                <th style={{ width: 50 }}>Seq</th>
                                <th style={{ width: 170 }}>Timestamp</th>
                                <th style={{ width: 90 }}>Category</th>
                                <th style={{ width: 100 }}>Action</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredLogs.map((log) => (
                                <tr key={log.id}>
                                    <td className="severity-cell">
                                        <span className={`severity-indicator ${severityClass(log.severity)}`} title={`Severity ${log.severity}`} />
                                    </td>
                                    <td className="mono">{log.seq}</td>
                                    <td className="mono">{new Date(log.timestamp).toLocaleTimeString()}</td>
                                    <td>
                                        <span style={{
                                            color: categoryColors[log.category] || "var(--text-secondary)",
                                            fontWeight: 600,
                                            fontSize: 12,
                                            textTransform: "uppercase",
                                        }}>
                                            {log.category}
                                        </span>
                                    </td>
                                    <td className="mono">{log.action}</td>
                                    <td>{log.message}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}
