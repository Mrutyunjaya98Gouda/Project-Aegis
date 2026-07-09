import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { invoke } from "@tauri-apps/api/core";

interface TreeNode {
    name: string;
    type: "host" | "hub" | "device" | "partition";
    status?: "authorized" | "blocked" | "quarantined" | "analyzing" | "pending";
    trust?: number;
    vidPid?: string;
    children?: TreeNode[];
}

export function DeviceMap() {
    const svgRef = useRef<SVGSVGElement>(null);
    const [treeData, setTreeData] = useState<TreeNode>({ name: "Host PC", type: "host", children: [] });

    useEffect(() => {
        const fetchDevices = async () => {
            try {
                const devs: any[] = await invoke("list_devices");
                // Construct a base tree
                let root: TreeNode = {
                    name: "Host PC",
                    type: "host",
                    children: [
                        {
                            name: "USB Root Hub",
                            type: "hub",
                            children: devs.map(d => ({
                                name: d.product_name || "Unknown Device",
                                type: "device",
                                status: d.status.toLowerCase(),
                                trust: d.trust_score,
                                vidPid: `${d.vendor_id.toString(16)}:${d.product_id.toString(16)}`,
                                children: []
                            }))
                        }
                    ]
                };
                setTreeData(root);
            } catch (err) {
                console.error(err);
            }
        };

        fetchDevices();
        const int = setInterval(fetchDevices, 3000);
        return () => clearInterval(int);
    }, []);

    useEffect(() => {
        if (!svgRef.current) return;

        const svg = d3.select(svgRef.current);

        const width = svgRef.current.clientWidth || 800;
        const height = svgRef.current.clientHeight || 500;
        const margin = { top: 40, right: 120, bottom: 40, left: 120 };

        svg.attr("width", width).attr("height", height);

        let g = svg.select<SVGGElement>("g.map-container");
        if (g.empty()) {
            g = svg.append("g")
                .attr("class", "map-container")
                .attr("transform", `translate(${margin.left},${margin.top})`);
        }

        const treeLayout = d3.tree<TreeNode>()
            .size([height - margin.top - margin.bottom, width - margin.left - margin.right]);

        const root = d3.hierarchy(treeData);
        const hierarchyData = treeLayout(root);

        // Node colors mapping helper
        const getNodeColor = (d: d3.HierarchyPointNode<TreeNode>) => {
            const data = d.data;
            if (data.type === "host") return "#4b82ff";
            if (data.type === "hub") return "#7c5cff";
            if (data.status === "authorized") return "#22c55e";
            if (data.status === "blocked") return "#ef4444";
            if (data.status === "quarantined") return "#f59e0b";
            if (data.status === "analyzing" || data.status === "pending") return "#3b82f6";
            return "#5a6478";
        };

        const getNodeSize = (d: d3.HierarchyPointNode<TreeNode>) => {
            if (d.data.type === "host") return 18;
            if (d.data.type === "hub") return 14;
            if (d.data.type === "device") return 12;
            return 8;
        };

        // Draw links
        const linkData = hierarchyData.links();
        const link = g.selectAll<SVGPathElement, any>(".map-link")
            .data(linkData, (d: any) => d.target.data.vidPid || d.target.data.name);

        link.join(
            enter => enter.append("path")
                .attr("class", "map-link")
                .attr("d", d3.linkHorizontal<any, any>().x(d => d.y).y(d => d.x))
                .style("opacity", 0)
                .call(enter => enter.transition().duration(800).style("opacity", 1)),
            update => update.call(update => update.transition().duration(600)
                .attr("d", d3.linkHorizontal<any, any>().x(d => d.y).y(d => d.x))),
            exit => exit.call(exit => exit.transition().duration(400).style("opacity", 0).remove())
        );

        // Draw nodes
        const nodeData = hierarchyData.descendants();
        const node = g.selectAll<SVGGElement, any>(".map-node")
            .data(nodeData, (d: any) => d.data.vidPid || d.data.name);

        node.join(
            enter => {
                const n = enter.append("g")
                    .attr("class", "map-node")
                    .attr("transform", d => `translate(${d.y},${d.x})`)
                    .style("opacity", 0);

                n.append("title")
                    .text(d => `${d.data.name}\n${d.data.vidPid ? 'ID: ' + d.data.vidPid : ''}\nStatus: ${d.data.status || 'Active'}\nClick to view details`);

                n.append("circle")
                    .attr("r", d => getNodeSize(d))
                    .attr("fill", d => getNodeColor(d))
                    .attr("stroke", d => getNodeColor(d))
                    .attr("stroke-width", 2)
                    .attr("fill-opacity", 0.2)
                    .attr("cursor", "pointer")
                    .on("click", (_, d) => alert(`Selected Device: ${d.data.name}\nType: ${d.data.type}\nStatus: ${d.data.status || 'N/A'}\nTrust Score: ${d.data.trust !== undefined ? d.data.trust + '%' : 'N/A'}`))
                    .style("filter", d => d.data.status === "blocked" ? "drop-shadow(0 0 8px rgba(239,68,68,0.6))" : "drop-shadow(0 0 6px rgba(75,130,255,0.3))");

                n.append("text")
                    .attr("class", "map-label")
                    .attr("dy", d => d.children && d.children.length > 0 ? -20 : 4)
                    .attr("dx", d => d.children && d.children.length > 0 ? 0 : 20)
                    .attr("text-anchor", d => d.children && d.children.length > 0 ? "middle" : "start")
                    .attr("fill", "#e8edf5")
                    .style("font-size", d => d.data.type === "host" ? "13px" : "11px")
                    .style("font-weight", d => d.data.type === "host" || d.data.type === "hub" ? "600" : "400")
                    .style("pointer-events", "none")
                    .text(d => d.data.name);

                n.filter(d => d.data.trust !== undefined)
                    .append("text")
                    .attr("class", "trust-label")
                    .attr("dy", 18)
                    .attr("dx", 20)
                    .attr("fill", d => {
                        const t = d.data.trust || 0;
                        if (t >= 70) return "#22c55e";
                        if (t >= 40) return "#f59e0b";
                        return "#ef4444";
                    })
                    .style("font-size", "10px")
                    .style("font-family", "var(--font-mono)")
                    .style("font-weight", "600")
                    .style("pointer-events", "none")
                    .text(d => `Trust: ${d.data.trust}%`);

                n.call(enter => enter.transition().duration(600).style("opacity", 1));
                return n;
            },
            update => {
                update.call(update => update.transition().duration(600).attr("transform", d => `translate(${d.y},${d.x})`));

                update.select("circle")
                    .attr("fill", d => getNodeColor(d))
                    .attr("stroke", d => getNodeColor(d))
                    .style("filter", d => d.data.status === "blocked" ? "drop-shadow(0 0 8px rgba(239,68,68,0.6))" : "drop-shadow(0 0 6px rgba(75,130,255,0.3))");

                update.select("title")
                    .text(d => `${d.data.name}\n${d.data.vidPid ? 'ID: ' + d.data.vidPid : ''}\nStatus: ${d.data.status || 'Active'}\nClick to view details`);

                update.select("text.trust-label")
                    .text(d => `Trust: ${d.data.trust}%`);

                return update;
            },
            exit => exit.call(exit => exit.transition().duration(400).style("opacity", 0).remove())
        );

    }, [treeData]);

    return (
        <>
            <div className="page-header">
                <h2>Hardware Map</h2>
                <p>Interactive USB device tree topology with real-time trust indicators</p>
            </div>
            <div className="page-content animate-in">
                <div className="glass-panel" style={{ padding: 0, overflow: "hidden" }}>
                    <div className="hardware-map-container">
                        <svg ref={svgRef} style={{ width: "100%", height: "500px" }} />
                    </div>
                </div>

                {/* Legend */}
                <div className="glass-panel" style={{ marginTop: 16, display: "flex", gap: 24, flexWrap: "wrap", padding: "16px 24px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#4b82ff" }}></div>
                        Host PC
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#7c5cff" }}></div>
                        USB Hub
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#22c55e" }}></div>
                        Authorized
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#f59e0b" }}></div>
                        Quarantined
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
                        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ef4444" }}></div>
                        Blocked
                    </div>
                </div>
            </div>
        </>
    );
}
