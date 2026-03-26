"use client"

import { use, useState, useEffect, useRef } from "react"
import { useRouter } from "next/navigation"
import { motion } from "framer-motion"
import { ShieldAlert, Download, Share2, Globe, FileCode, Cpu, Hash, TerminalSquare, Camera, ExternalLink, Home, Info, Check, Network } from "lucide-react"

// ── Node type config for the dynamic graph ──────────────────────────────────
const NODE_STYLES: Record<string, { icon: string; color: string; border: string; shape: string }> = {
    artifact:   { icon: "◼", color: "#FF3B00", border: "#FF3B00", shape: "square" },
    ip:         { icon: "⊕", color: "#ef4444", border: "#ef4444", shape: "circle" },
    domain:     { icon: "◎", color: "#3b82f6", border: "#3b82f6", shape: "circle" },
    asn:        { icon: "#", color: "#a855f7", border: "#a855f7", shape: "diamond" },
    country:    { icon: "⚑", color: "#22c55e", border: "#22c55e", shape: "diamond" },
    registrar:  { icon: "R", color: "#f59e0b", border: "#f59e0b", shape: "circle" },
}

// ── Dynamic Infrastructure Graph ────────────────────────────────────────────
const GraphWidget = ({ nodes, edges, threatScore }: { nodes: any[]; edges: any[]; threatScore: number }) => {
    // Layout nodes in a radial pattern around center
    const positions = useRef<Record<string, { x: number; y: number }>>({})

    if (nodes.length > 0 && Object.keys(positions.current).length !== nodes.length) {
        const center = { x: 50, y: 50 }
        const pos: Record<string, { x: number; y: number }> = {}

        // Center node = artifact
        const artifactNode = nodes.find(n => n.type === "artifact")
        if (artifactNode) pos[artifactNode.id] = center

        // Arrange others in a ring
        const others = nodes.filter(n => n.type !== "artifact")
        others.forEach((node, i) => {
            const angle = (2 * Math.PI * i) / Math.max(others.length, 1) - Math.PI / 2
            const radius = 30 + (i % 2) * 8 // alternating radius for visual spacing
            pos[node.id] = {
                x: Math.max(12, Math.min(88, center.x + radius * Math.cos(angle))),
                y: Math.max(12, Math.min(88, center.y + radius * Math.sin(angle))),
            }
        })
        positions.current = pos
    }

    const getNodeStyle = (type: string) => NODE_STYLES[type] || NODE_STYLES.domain

    return (
        <div className="w-full h-[500px] bg-[#050505] border-y border-[#333] relative overflow-hidden select-none">
            {/* Grid */}
            <div className="absolute inset-0 opacity-15 pointer-events-none"
                style={{ backgroundImage: 'linear-gradient(#222 1px, transparent 1px), linear-gradient(90deg, #222 1px, transparent 1px)', backgroundSize: '40px 40px' }}
            />
            {/* Radar */}
            {threatScore > 0 && (
                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] bg-[conic-gradient(from_0deg,transparent_0_340deg,rgba(255,59,0,0.08)_360deg)] animate-[spin_4s_linear_infinite] rounded-full pointer-events-none" />
            )}

            {/* SVG Edges */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
                {edges.map((edge: any, i: number) => {
                    const from = positions.current[edge.source]
                    const to = positions.current[edge.target]
                    if (!from || !to) return null
                    return (
                        <motion.line
                            key={i}
                            x1={`${from.x}%`} y1={`${from.y}%`}
                            x2={`${to.x}%`} y2={`${to.y}%`}
                            stroke="#333" strokeWidth="1"
                            initial={{ pathLength: 0, opacity: 0 }}
                            animate={{ pathLength: 1, opacity: 0.6 }}
                            transition={{ duration: 0.8, delay: 0.3 + i * 0.1 }}
                        />
                    )
                })}
            </svg>

            {/* Nodes */}
            {nodes.map((node: any, i: number) => {
                const pos = positions.current[node.id]
                if (!pos) return null
                const style = getNodeStyle(node.type)
                const isArtifact = node.type === "artifact"
                const riskColor = node.risk === "high" ? "#FF3B00" : node.risk === "medium" ? "#f59e0b" : style.color

                return (
                    <motion.div
                        key={node.id}
                        className="absolute -translate-x-1/2 -translate-y-1/2 z-20 group/node"
                        style={{ left: `${pos.x}%`, top: `${pos.y}%` }}
                        initial={{ scale: 0, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ delay: 0.5 + i * 0.12, type: "spring", stiffness: 200 }}
                    >
                        <div className="flex flex-col items-center cursor-pointer">
                            {/* Node circle/square */}
                            <div
                                className={`flex items-center justify-center transition-all ${isArtifact ? 'w-16 h-16' : 'w-10 h-10'} ${style.shape === 'diamond' ? 'rotate-45' : style.shape === 'circle' ? 'rounded-full' : ''}`}
                                style={{ border: `1.5px solid ${riskColor}`, backgroundColor: '#0A0A0A' }}
                            >
                                <span className={`font-mono text-xs font-bold ${style.shape === 'diamond' ? '-rotate-45' : ''}`} style={{ color: riskColor }}>
                                    {isArtifact ? <TerminalSquare className="w-6 h-6" style={{ color: riskColor }} /> : style.icon}
                                </span>
                            </div>
                            {/* Label */}
                            {isArtifact && (
                                <div className="absolute -bottom-7 w-max">
                                    <div className="text-[8px] font-mono tracking-[0.2em] px-2 py-0.5 border" style={{ color: riskColor, borderColor: `${riskColor}40`, backgroundColor: '#121212' }}>
                                        HOST: ARTIFACT
                                    </div>
                                </div>
                            )}
                            {/* Tooltip on hover */}
                            <div className="absolute top-full mt-2 bg-[#121212]/95 border border-gray-700 p-2 backdrop-blur-md opacity-0 group-hover/node:opacity-100 transition-opacity w-40 z-50 pointer-events-none">
                                <div className="text-[9px] font-mono font-bold mb-1 border-b border-gray-700 pb-1" style={{ color: riskColor }}>
                                    {node.type.toUpperCase()}
                                </div>
                                <div className="text-[9px] font-mono text-gray-400 break-all">{node.label}</div>
                                {node.risk === "high" && <div className="text-[8px] text-red-500 font-mono mt-1 uppercase">⚠ High Risk</div>}
                            </div>
                            {/* Risk pulse */}
                            {node.risk === "high" && !isArtifact && (
                                <div className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-red-500 rounded-full border border-[#0A0A0A] animate-ping opacity-60" />
                            )}
                        </div>
                    </motion.div>
                )
            })}

            {/* HUD */}
            <div className="absolute top-4 left-4 font-mono text-[9px] text-gray-600">
                NODES: {nodes.length} | EDGES: {edges.length}
            </div>
            {threatScore > 0 && (
                <div className="absolute bottom-4 left-4 font-mono text-[9px] text-[#FF3B00] animate-pulse">
                    LIVE_FEED :: MAPPING_INFRASTRUCTURE
                </div>
            )}
            {nodes.length === 0 && (
                <div className="absolute inset-0 flex items-center justify-center font-mono text-xs text-gray-600 tracking-wider">
                    NO INFRASTRUCTURE DATA AVAILABLE
                </div>
            )}
        </div>
    )
}

// --- MAIN PAGE COMPONENT ---
export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
    const resolvedParams = use(params)
    const router = useRouter()

    const [reportData, setReportData] = useState<any>(null)
    const [loading, setLoading] = useState(true)
    const [shareToast, setShareToast] = useState(false)

    useEffect(() => {
        const fetchReport = async () => {
            try {
                const res = await fetch(`/api/status/${resolvedParams.id}`)
                if (res.ok) {
                    const data = await res.json()
                    if (data.status === 'Failed') {
                        setReportData({ score: 0, verdict: "Failed", reasons: ["Analysis encountered a fatal error. Please check server logs."] })
                    } else {
                        setReportData(data.results || { score: 0, verdict: "Clear", reasons: ["No data available"] })
                    }
                }
            } catch (e) {
                console.error(e)
                setReportData({ score: 0, verdict: "Error", reasons: ["Backend Offline"] })
            } finally {
                setLoading(false)
            }
        }
        fetchReport()
    }, [resolvedParams.id])

    // --- PDF Export (native print → Save as PDF) ---
    const handleExportPDF = () => {
        document.title = `MalScan_Report_${resolvedParams.id.slice(0, 8)}`
        window.print()
        setTimeout(() => { document.title = 'MalScan Report' }, 1000)
    }

    // --- Share Intel ---
    const handleShare = async () => {
        const url = window.location.href
        try {
            await navigator.clipboard.writeText(url)
            setShareToast(true)
            setTimeout(() => setShareToast(false), 2500)
        } catch {
            // Fallback
            const ta = document.createElement('textarea')
            ta.value = url
            document.body.appendChild(ta)
            ta.select()
            document.execCommand('copy')
            document.body.removeChild(ta)
            setShareToast(true)
            setTimeout(() => setShareToast(false), 2500)
        }
    }

    if (loading) return <div className="min-h-screen bg-[#F5F5F3] flex items-center justify-center font-mono">LOADING_REPORT...</div>

    const threatScore = reportData?.score || 0
    const verdict = reportData?.verdict || "Clear"
    const reasons = reportData?.reasons || []
    const family = reportData?.family || "Unknown"
    const attribution = reportData?.attribution || "Unattributed"
    const fileHash = reportData?.file_hash || "N/A"
    const imphash = reportData?.imphash || "N/A"
    const vtStats = reportData?.osint_summary?.virustotal || null
    const urlscanData = reportData?.osint_summary?.urlscan || null
    const graphNodes = reportData?.graph_nodes || []
    const graphEdges = reportData?.graph_edges || []

    // Build IOC rows from real backend data
    const indicators = reportData?.indicators || {}
    const iocs = [
        ...(indicators.ips || []).map((v: string) => ({ type: "IPv4", val: v, tag: "EXTRACTED" })),
        ...(indicators.urls || []).map((v: string) => ({ type: "URL", val: v, tag: "EXTRACTED" })),
        ...(indicators.domains || []).map((v: string) => ({ type: "DOMAIN", val: v, tag: "EXTRACTED" })),
    ]

    // VT bar total (including undetected)
    const vtTotal = vtStats ? (vtStats.malicious + vtStats.suspicious + vtStats.harmless + (vtStats.undetected || 0)) || 1 : 1

    return (
        <div className="min-h-screen bg-[#F5F5F3] text-[#121212] font-sans pb-20">
            {/* Print-optimized: hide toolbar when printing */}
            <style>{`@media print { header { display: none !important; } body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }`}</style>
            {/* TOOLBAR */}
            <header className="sticky top-0 bg-[#F5F5F3]/90 backdrop-blur-md border-b border-gray-200 px-8 py-4 z-40 flex justify-between items-center">
                <div className="flex items-center gap-4 font-mono text-xs">
                    <button
                        onClick={() => router.push('/')}
                        className="flex items-center gap-1.5 text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors border border-gray-300 hover:border-[#FF3B00] px-3 py-1.5 bg-white"
                        title="Back to Home"
                    >
                        <Home size={13} /> HOME
                    </button>
                    <span className="text-gray-400 uppercase tracking-wider">JOB ID: {resolvedParams.id}</span>
                    <span className={`px-3 py-1 font-bold rounded-sm uppercase tracking-widest ${verdict === 'Clear'
                            ? 'bg-green-900 text-green-400'
                            : verdict === 'Suspicious'
                                ? 'bg-amber-900 text-amber-400'
                                : 'bg-red-900 text-[#FF3B00]'
                        }`}>{verdict}</span>
                </div>
                <div className="flex gap-4 relative">
                    <button
                        onClick={handleExportPDF}
                        className="flex items-center gap-2 text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors"
                    >
                        <Download size={14} /> EXPORT PDF
                    </button>
                    <button
                        onClick={handleShare}
                        className="flex items-center gap-2 text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors"
                    >
                        <Share2 size={14} /> SHARE INTEL
                    </button>
                    {/* Toast notification */}
                    {shareToast && (
                        <motion.div
                            initial={{ opacity: 0, y: -8 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0 }}
                            className="absolute -bottom-10 right-0 bg-[#121212] text-white text-[10px] font-mono px-3 py-1.5 tracking-widest flex items-center gap-2 shadow-lg"
                        >
                            <Check size={10} className="text-green-400" /> LINK COPIED
                        </motion.div>
                    )}
                </div>
            </header>

            <main className="max-w-[1400px] mx-auto p-8 grid grid-cols-1 lg:grid-cols-12 gap-8 mt-4">

                {/* COL 1: VERDICT & SCORE */}
                <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className="lg:col-span-4 bg-white p-8 border border-gray-200 shadow-xl shadow-gray-200/30 flex flex-col justify-between h-[600px]">
                    <div>
                        <ShieldAlert className="w-16 h-16 text-[#121212] mb-8" />
                        <h2 className="text-xs font-bold tracking-[0.3em] text-gray-400 uppercase mb-4">Analysis Verdict</h2>
                        <h1 className="text-5xl font-medium tracking-tight mb-10 leading-tight">
                            {verdict === 'Clear' ? 'No Threat Detected.' : verdict === 'Suspicious' ? 'Suspicious Activity Detected.' : 'High Confidence Threat Detected.'}
                        </h1>
                        <div className="space-y-8">
                            <div>
                                <div className="flex justify-between text-xs font-mono mb-3 uppercase tracking-wider"><span>Threat Score</span><span className="text-[#FF3B00]">{threatScore}/100</span></div>
                                <div className="w-full h-2 bg-gray-100"><motion.div initial={{ width: 0 }} animate={{ width: `${threatScore}%` }} transition={{ delay: 0.5, duration: 1 }} className="h-full bg-[#FF3B00]" /></div>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div><h3 className="text-[10px] font-bold text-gray-400 mb-1 uppercase">Identified Family</h3><p className="font-mono text-sm">{family}</p></div>
                                <div><h3 className="text-[10px] font-bold text-gray-400 mb-1 uppercase">Attribution</h3><p className="font-mono text-sm">{attribution}</p></div>
                            </div>
                        </div>
                    </div>
                    <div className="pt-6 border-t border-gray-100"><div className="text-xs text-gray-500 font-mono leading-relaxed">EXECUTIVE SUMMARY: {reasons.map((r: string) => <p key={r}>- {r}</p>)}</div></div>

                    {/* VirusTotal Vendor Consensus — FIXED BAR */}
                    {vtStats && (
                        <div className="mt-6 border-t border-gray-100 pt-6">
                            <h3 className="text-[10px] font-bold text-gray-400 mb-4 uppercase flex items-center gap-2">
                                <ShieldAlert size={12}/> VirusTotal Vendor Consensus
                            </h3>
                            <div className="flex h-3 w-full bg-gray-100 mb-3 overflow-hidden">
                                {vtStats.malicious > 0 && <div className="h-full bg-[#FF3B00] transition-all" style={{ width: `${(vtStats.malicious / vtTotal) * 100}%` }} />}
                                {vtStats.suspicious > 0 && <div className="h-full bg-amber-500 transition-all" style={{ width: `${(vtStats.suspicious / vtTotal) * 100}%` }} />}
                                {vtStats.harmless > 0 && <div className="h-full bg-green-500 transition-all" style={{ width: `${(vtStats.harmless / vtTotal) * 100}%` }} />}
                                {(vtStats.undetected || 0) > 0 && <div className="h-full bg-gray-300 transition-all" style={{ width: `${((vtStats.undetected || 0) / vtTotal) * 100}%` }} />}
                            </div>
                            <div className="flex flex-wrap gap-3 text-[10px] font-mono uppercase">
                                <div className="flex items-center gap-1 text-[#FF3B00]"><div className="w-2 h-2 bg-[#FF3B00]" /> {vtStats.malicious} Malicious</div>
                                <div className="flex items-center gap-1 text-amber-500"><div className="w-2 h-2 bg-amber-500" /> {vtStats.suspicious} Suspicious</div>
                                <div className="flex items-center gap-1 text-green-500"><div className="w-2 h-2 bg-green-500" /> {vtStats.harmless} Harmless</div>
                                {(vtStats.undetected || 0) > 0 && (
                                    <div className="flex items-center gap-1 text-gray-400"><div className="w-2 h-2 bg-gray-300" /> {vtStats.undetected} Undetected</div>
                                )}
                            </div>
                        </div>
                    )}
                </motion.div>

                {/* COL 2: VISUAL GRAPH & IOCs */}
                <div className="lg:col-span-8 flex flex-col gap-8">
                    {/* URLScan.io Sandbox Result */}
                    {urlscanData && !urlscanData.error && (
                        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15 }} className="bg-white border border-gray-200 shadow-sm">
                            <div className="p-4 border-b border-gray-200 flex justify-between items-center">
                                <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Camera size={14}/> URLScan.io Sandbox</h3>
                                {urlscanData.is_malicious && <span className="text-[9px] bg-red-900 text-[#FF3B00] px-2 py-1 font-mono uppercase tracking-widest">MALICIOUS</span>}
                            </div>
                            <div className="p-4">
                                {urlscanData.screenshot_url && (
                                    <div className="mb-4 border border-gray-200 bg-gray-50 overflow-hidden">
                                        <img src={urlscanData.screenshot_url} alt="URLScan screenshot" className="w-full h-auto" />
                                    </div>
                                )}
                                <div className="grid grid-cols-2 gap-3 font-mono text-[10px]">
                                    {urlscanData.page_title && <div><span className="text-gray-400 uppercase">Title:</span> <span className="text-gray-700">{urlscanData.page_title}</span></div>}
                                    {urlscanData.page_ip && <div><span className="text-gray-400 uppercase">IP:</span> <span className="text-gray-700">{urlscanData.page_ip}</span></div>}
                                    {urlscanData.page_country && <div><span className="text-gray-400 uppercase">Country:</span> <span className="text-gray-700">{urlscanData.page_country}</span></div>}
                                    {urlscanData.page_server && <div><span className="text-gray-400 uppercase">Server:</span> <span className="text-gray-700">{urlscanData.page_server}</span></div>}
                                </div>
                                {urlscanData.outgoing_domains && urlscanData.outgoing_domains.length > 0 && (
                                    <div className="mt-4 border-t border-gray-100 pt-3">
                                        <span className="text-[10px] font-mono text-gray-400 uppercase">Outgoing Domains ({urlscanData.outgoing_domains.length}):</span>
                                        <div className="flex flex-wrap gap-1 mt-2">
                                            {urlscanData.outgoing_domains.map((d: string) => (
                                                <span key={d} className="text-[9px] bg-gray-100 px-2 py-0.5 font-mono text-gray-600">{d}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </motion.div>
                    )}

                    {/* URLScan info banner when sandbox is unavailable */}
                    {urlscanData && urlscanData.error && (
                        <motion.div initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15 }} className="flex items-start gap-3 px-4 py-3 bg-gray-50 border border-gray-200 text-gray-500">
                            <Info size={14} className="mt-0.5 shrink-0 text-gray-400" />
                            <div>
                                <p className="text-[10px] font-bold uppercase tracking-widest mb-0.5">Sandbox Skipped</p>
                                <p className="text-[10px] font-mono leading-relaxed">{urlscanData.error}</p>
                            </div>
                        </motion.div>
                    )}

                    {/* DYNAMIC INFRASTRUCTURE MAP */}
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }} className="bg-white border border-gray-200 shadow-sm">
                        <div className="p-4 border-b border-gray-200 flex justify-between items-center">
                            <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Network size={14} /> Infrastructure Map</h3>
                            <div className="flex gap-4">
                                {graphNodes.filter((n: any) => n.risk === 'high').length > 0 && (
                                    <div className="flex gap-2 items-center"><span className="w-2 h-2 bg-[#FF3B00] rounded-full animate-pulse"></span><span className="text-[10px] font-mono text-gray-400">HIGH RISK</span></div>
                                )}
                                <span className="text-[10px] font-mono text-gray-400">{graphNodes.length} NODES</span>
                            </div>
                        </div>
                        <GraphWidget nodes={graphNodes} edges={graphEdges} threatScore={threatScore} />
                    </motion.div>

                    {/* IOC TERMINAL */}
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }} className="bg-[#121212] text-white border border-black p-6 font-mono shadow-xl">
                        <div className="flex items-center gap-3 mb-6 pb-4 border-b border-white/20">
                            <TerminalSquare className="text-[#FF3B00]" size={20} />
                            <h3 className="text-xs font-bold tracking-[0.3em] uppercase text-gray-400">Extracted Indicators (IOCs)</h3>
                        </div>
                        <div className="h-64 overflow-y-auto pr-4 space-y-4 scrollbar-thin scrollbar-thumb-[#FF3B00] scrollbar-track-[#333]">
                            {iocs.length === 0 ? (
                                <div className="text-gray-500 text-xs tracking-wider py-8 text-center">NO NETWORK INDICATORS EXTRACTED FROM THIS ARTIFACT.</div>
                            ) : iocs.map((ioc, i) => (
                                <div key={i} className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-2 border-b border-white/10 last:border-0">
                                    <div className="flex items-center gap-4">
                                        <span className="text-[9px] text-[#FF3B00] tracking-widest uppercase w-16">{ioc.type}</span>
                                        <span className="text-sm break-all">{ioc.val}</span>
                                    </div>
                                    <span className="text-[9px] bg-white/10 px-2 py-1 rounded-sm tracking-wider uppercase text-gray-400">{ioc.tag}</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>
                </div>

                {/* FOOTER ROW */}
                <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.3 }} className="lg:col-span-12 grid grid-cols-2 md:grid-cols-4 gap-0 border border-gray-200 bg-white mt-8">
                    <TechDetail icon={Hash} label="SHA-256" value={fileHash} />
                    <TechDetail icon={Cpu} label="Imphash" value={imphash !== 'N/A' ? imphash : 'Not a PE file'} />
                    <TechDetail icon={FileCode} label="Verdict" value={verdict.toUpperCase()} />
                    <TechDetail icon={Globe} label="Score" value={`${threatScore} / 100`} />
                </motion.div>
            </main>
        </div>
    )
}

const TechDetail = ({ icon: Icon, label, value }: any) => (
    <div className="p-6 border-r border-b lg:border-b-0 border-gray-200 last:border-0 hover:bg-gray-50 transition-colors group">
        <div className="flex items-center gap-3 mb-3 text-gray-400 group-hover:text-[#FF3B00] transition-colors"><Icon size={18} /><span className="text-[10px] font-bold tracking-widest uppercase">{label}</span></div>
        <p className="font-mono text-xs text-[#121212] break-all">{value}</p>
    </div>
)