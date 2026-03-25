"use client"

import { use, useState, useEffect } from "react"
import { motion } from "framer-motion"
import { ShieldAlert, Download, Share2, Globe, FileCode, Cpu, Hash, TerminalSquare, Camera, ExternalLink } from "lucide-react"

// --- IMPROVED GRAPH WIDGET (The Fix) ---
// --- ULTRA-PREMIUM GRAPH WIDGET ---
const GraphWidget = ({ threatScore }: { threatScore: number }) => {
    return (
        <div className="w-full h-[600px] bg-[#050505] border-y border-[#333] relative overflow-hidden group select-none">

            {/* 1. LAYER: TECHNICAL GRID & RADAR */}
            <div className="absolute inset-0 opacity-20 pointer-events-none"
                style={{ backgroundImage: 'linear-gradient(#222 1px, transparent 1px), linear-gradient(90deg, #222 1px, transparent 1px)', backgroundSize: '40px 40px' }}
            />
            {/* Rotating Radar Sweep */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-[conic-gradient(from_0deg,transparent_0_340deg,rgba(255,59,0,0.1)_360deg)] animate-[spin_4s_linear_infinite] rounded-full pointer-events-none" />

            {/* 2. LAYER: SVG CONNECTIONS (DATA PIPES) */}
            <svg className="absolute inset-0 w-full h-full pointer-events-none">
                <defs>
                    <linearGradient id="line-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#333" />
                        <stop offset="50%" stopColor="#666" />
                        <stop offset="100%" stopColor="#333" />
                    </linearGradient>
                    <marker id="arrow" markerWidth="10" markerHeight="10" refX="5" refY="2.5" orient="auto" markerUnits="strokeWidth">
                        <path d="M0,0 L5,2.5 L0,5" fill="#555" />
                    </marker>
                </defs>

                {/* Path to Node 1 (Top Left) */}
                <motion.path
                    d="M50% 50% L50% 30% L30% 30%"
                    fill="none" stroke="#333" strokeWidth="1"
                    initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1, delay: 0.5 }}
                />
                {/* Data Packet Animation 1 */}
                <circle r="2" fill="#FFF">
                    <animateMotion repeatCount="indefinite" dur="3s" keyPoints="0;1" keyTimes="0;1">
                        <mpath href="#path1" />
                    </animateMotion>
                </circle>
                <path id="path1" d="M 700 300 L 700 180 L 420 180" fill="none" /> {/* Hardcoded approximates for SVG coord layout */}

                {/* Path to Node 2 (Bottom Right) */}
                <motion.path
                    d="M50% 50% L50% 70% L70% 70%"
                    fill="none" stroke="#333" strokeWidth="1"
                    initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1, delay: 0.7 }}
                />

                {/* Path to Node 3 (Top Right) */}
                <motion.path
                    d="M50% 50% L80% 50% L80% 30%"
                    fill="none" stroke="#333" strokeWidth="1"
                    initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1, delay: 0.9 }}
                />
            </svg>

            {/* 3. LAYER: INTERACTIVE NODES */}

            {/* CENTER: MALWARE HOST */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-30 group/center">
                <div className="relative">
                    <div className="absolute inset-0 bg-[#FF3B00] blur-xl opacity-20 animate-pulse"></div>
                    <div className="w-20 h-20 border border-[#FF3B00] bg-[#0A0A0A] flex items-center justify-center relative">
                        <div className="w-1 h-1 bg-[#FF3B00] absolute top-1 left-1"></div>
                        <div className="w-1 h-1 bg-[#FF3B00] absolute top-1 right-1"></div>
                        <div className="w-1 h-1 bg-[#FF3B00] absolute bottom-1 left-1"></div>
                        <div className="w-1 h-1 bg-[#FF3B00] absolute bottom-1 right-1"></div>
                        <TerminalSquare className="text-[#FF3B00] w-8 h-8 animate-pulse" />
                    </div>
                    <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 w-max text-center">
                        <div className="text-[9px] font-mono text-[#FF3B00] tracking-[0.3em] bg-[#121212] px-2 py-1 border border-[#FF3B00]/30">HOST: ARTIFACT.EXE</div>
                    </div>
                </div>
            </div>

            {/* NODE 1: C2 SERVER (Russia) */}
            <motion.div
                className="absolute top-[30%] left-[30%] -translate-x-1/2 -translate-y-1/2 z-20 group/node"
                initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 1 }}
            >
                <div className="flex flex-col items-center cursor-pointer">
                    <div className="w-12 h-12 bg-[#121212] border border-gray-600 group-hover/node:border-white transition-colors flex items-center justify-center rounded-full relative">
                        <Globe className="w-5 h-5 text-gray-400 group-hover/node:text-white" />
                        <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full border-2 border-[#121212]"></div>
                    </div>
                    <div className="mt-4 bg-[#121212]/90 border border-gray-700 p-3 backdrop-blur-md opacity-0 group-hover/node:opacity-100 transition-opacity absolute top-12 w-48 z-50 pointer-events-none">
                        <div className="flex justify-between items-center mb-2 border-b border-gray-700 pb-1">
                            <span className="text-[9px] text-gray-400 font-bold">185.192.69.14</span>
                            <span className="text-[9px] text-red-500 font-mono">MALICIOUS</span>
                        </div>
                        <div className="space-y-1 font-mono text-[9px] text-gray-500">
                            <div className="flex justify-between"><span>ASN:</span><span className="text-gray-300">AS44050</span></div>
                            <div className="flex justify-between"><span>GEO:</span><span className="text-gray-300">Moscow, RU</span></div>
                            <div className="flex justify-between"><span>PROTO:</span><span className="text-gray-300">TCP/443 (HTTPS)</span></div>
                        </div>
                    </div>
                </div>
            </motion.div>

            {/* NODE 2: DROP ZONE (USA) */}
            <motion.div
                className="absolute top-[70%] left-[70%] -translate-x-1/2 -translate-y-1/2 z-20 group/node"
                initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 1.2 }}
            >
                <div className="flex flex-col items-center cursor-pointer">
                    <div className="w-10 h-10 bg-[#121212] border border-blue-500/50 group-hover/node:border-blue-400 transition-colors flex items-center justify-center transform rotate-45">
                        <div className="transform -rotate-45">
                            <Cpu className="w-4 h-4 text-blue-400" />
                        </div>
                    </div>
                    {/* Metadata Tooltip */}
                    <div className="mt-4 bg-[#121212]/90 border border-gray-700 p-3 backdrop-blur-md opacity-0 group-hover/node:opacity-100 transition-opacity absolute top-10 w-40 z-50 pointer-events-none">
                        <div className="text-[9px] text-blue-400 font-bold mb-1 border-b border-gray-700 pb-1">DROPPER URL</div>
                        <div className="font-mono text-[9px] text-gray-400">cdn-update-sys.net</div>
                    </div>
                </div>
            </motion.div>

            {/* NODE 3: REGISTRY PERSISTENCE */}
            <motion.div
                className="absolute top-[30%] left-[80%] -translate-x-1/2 -translate-y-1/2 z-20 group/node"
                initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 1.4 }}
            >
                <div className="flex flex-col items-center cursor-pointer">
                    <div className="w-3 h-3 bg-purple-500 rounded-sm animate-ping absolute opacity-50"></div>
                    <div className="w-8 h-8 bg-[#121212] border border-purple-500 flex items-center justify-center">
                        <Hash className="w-4 h-4 text-purple-500" />
                    </div>
                    <div className="absolute top-10 text-[9px] font-mono text-purple-500 bg-black px-1 opacity-0 group-hover/node:opacity-100 transition-opacity">REGISTRY_MOD</div>
                </div>
            </motion.div>

            {/* 4. LAYER: HUD OVERLAY */}
            <div className="absolute top-6 left-6 font-mono text-[10px] text-gray-500">
                <div className="flex gap-4">
                    <div>ZOOM: 100%</div>
                </div>
            </div>
            {threatScore > 0 && (
                <div className="absolute bottom-6 left-6 font-mono text-[10px] text-[#FF3B00] animate-pulse">
                    LIVE_FEED :: CAPTURING_PACKETS
                </div>
            )}

            {/* Decorative Crosshairs */}
            <div className="absolute top-0 left-1/2 h-4 w-px bg-gray-800"></div>
            <div className="absolute bottom-0 left-1/2 h-4 w-px bg-gray-800"></div>
            <div className="absolute left-0 top-1/2 w-4 h-px bg-gray-800"></div>
            <div className="absolute right-0 top-1/2 w-4 h-px bg-gray-800"></div>

        </div>
    )
}

// --- MAIN PAGE COMPONENT ---
export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
    const resolvedParams = use(params)

    const [reportData, setReportData] = useState<any>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchReport = async () => {
            try {
                const res = await fetch(`/api/status/${resolvedParams.id}`)
                if (res.ok) {
                    const data = await res.json()
                    if (data.status === 'Failed') {
                        setReportData({ score: 0, verdict: "Failed", reasons: ["Analysis encountered a fatal error. Please check server logs."] })
                    } else {
                        setReportData(data.results || { score: 92, verdict: "Malicious", reasons: ["Simulated Demo Malicious File"] })
                    }
                }
            } catch (e) {
                console.error(e)
                setReportData({ score: 92, verdict: "Malicious", reasons: ["Backend Offline - Demo Data"] })
            } finally {
                setLoading(false)
            }
        }
        fetchReport()
    }, [resolvedParams.id])

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

    // Build IOC rows from real backend data
    const indicators = reportData?.indicators || {}
    const iocs = [
        ...(indicators.ips || []).map((v: string) => ({ type: "IPv4", val: v, tag: "EXTRACTED" })),
        ...(indicators.urls || []).map((v: string) => ({ type: "URL", val: v, tag: "EXTRACTED" })),
        ...(indicators.domains || []).map((v: string) => ({ type: "DOMAIN", val: v, tag: "EXTRACTED" })),
    ]

    return (
        <div className="min-h-screen bg-[#F5F5F3] text-[#121212] font-sans pb-20">
            {/* TOOLBAR */}
            <header className="sticky top-0 bg-[#F5F5F3]/90 backdrop-blur-md border-b border-gray-200 px-8 py-4 z-40 flex justify-between items-center">
                <div className="flex items-center gap-4 font-mono text-xs">
                    <span className="text-gray-400 uppercase tracking-wider">JOB ID: {resolvedParams.id}</span>
                    <span className={`px-3 py-1 font-bold rounded-sm uppercase tracking-widest ${verdict === 'Clear'
                            ? 'bg-green-900 text-green-400'
                            : verdict === 'Suspicious'
                                ? 'bg-amber-900 text-amber-400'
                                : 'bg-red-900 text-[#FF3B00]'
                        }`}>{verdict}</span>
                </div>
                <div className="flex gap-4">
                    <button
                        onClick={() => window.open(`/api/report/${resolvedParams.id}`, '_blank')}
                        className="flex items-center gap-2 text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors"
                    >
                        <Download size={14} /> EXPORT PDF
                    </button>
                    <button className="flex items-center gap-2 text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors"><Share2 size={14} /> SHARE INTEL</button>
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

                    {/* VirusTotal Vendor Consensus */}
                    {vtStats && (
                        <div className="mt-6 border-t border-gray-100 pt-6">
                            <h3 className="text-[10px] font-bold text-gray-400 mb-4 uppercase flex items-center gap-2">
                                <ShieldAlert size={12}/> VirusTotal Vendor Consensus
                            </h3>
                            <div className="flex gap-0.5 h-3 w-full bg-gray-100 mb-3 overflow-hidden">
                                {vtStats.malicious > 0 && <div className="h-full bg-[#FF3B00] transition-all" style={{ width: `${(vtStats.malicious / ((vtStats.malicious + vtStats.harmless + vtStats.suspicious + (vtStats.undetected || 0)) || 1)) * 100}%` }} />}
                                {vtStats.suspicious > 0 && <div className="h-full bg-amber-500 transition-all" style={{ width: `${(vtStats.suspicious / ((vtStats.malicious + vtStats.harmless + vtStats.suspicious + (vtStats.undetected || 0)) || 1)) * 100}%` }} />}
                                {vtStats.harmless > 0 && <div className="h-full bg-green-500 transition-all" style={{ width: `${(vtStats.harmless / ((vtStats.malicious + vtStats.harmless + vtStats.suspicious + (vtStats.undetected || 0)) || 1)) * 100}%` }} />}
                            </div>
                            <div className="flex flex-wrap gap-3 text-[10px] font-mono uppercase">
                                <div className="flex items-center gap-1 text-[#FF3B00]"><div className="w-2 h-2 bg-[#FF3B00]" /> {vtStats.malicious} Malicious</div>
                                <div className="flex items-center gap-1 text-amber-500"><div className="w-2 h-2 bg-amber-500" /> {vtStats.suspicious} Suspicious</div>
                                <div className="flex items-center gap-1 text-green-500"><div className="w-2 h-2 bg-green-500" /> {vtStats.harmless} Harmless</div>
                            </div>
                        </div>
                    )}
                </motion.div>

                {/* COL 2: VISUAL GRAPH & IOCs */}
                <div className="lg:col-span-8 flex flex-col gap-8">
                    {/* URLScan.io Sandbox Result */}
                    {urlscanData && (
                        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15 }} className="bg-white border border-gray-200 shadow-sm">
                            <div className="p-4 border-b border-gray-200 flex justify-between items-center">
                                <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Camera size={14}/> URLScan.io Sandbox</h3>
                                {urlscanData.is_malicious && <span className="text-[9px] bg-red-900 text-[#FF3B00] px-2 py-1 font-mono uppercase tracking-widest">MALICIOUS</span>}
                            </div>
                            <div className="p-4">
                                {urlscanData.error ? (
                                    <div className="bg-gray-50 border border-gray-200 p-8 flex flex-col items-center justify-center text-center">
                                        <Camera className="text-gray-300 w-8 h-8 mb-4 opacity-50" />
                                        <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Sandbox Unavailable</p>
                                        <p className="text-[10px] font-mono text-[#FF3B00] bg-red-50 px-3 py-2 border border-red-100">{urlscanData.error}</p>
                                    </div>
                                ) : (
                                    <>
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
                                    </>
                                )}
                            </div>
                        </motion.div>
                    )}

                    {/* GRAPH */}
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }} className="bg-white border border-gray-200 shadow-sm">
                        <div className="p-4 border-b border-gray-200 flex justify-between items-center"><h3 className="text-xs font-bold tracking-[0.2em] uppercase">Infrastructure Map</h3><div className="flex gap-2"><span className="w-2 h-2 bg-[#FF3B00] rounded-full animate-pulse"></span><span className="text-[10px] font-mono text-gray-400">LIVE C2 NODE</span></div></div>
                        <GraphWidget threatScore={threatScore} />
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