"use client"

import { useState, useEffect, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { motion } from "framer-motion"
import { ShieldAlert, Download, Share2, TerminalSquare, Camera, ExternalLink, Home, Info, Check, Package, Archive, MapPin, Network, Activity, PieChart, Radar, HelpCircle, AlertTriangle } from "lucide-react"
import dynamic from "next/dynamic"
import { apiUrl } from "../../lib/config"
import { looksLikeUrl } from "../../lib/scan"
import GraphWidget from "./GraphWidget"
import RiskRadar from "./RiskRadar"
import EntropyChart from "./EntropyChart"
import VTDonut from "./VTDonut"
import ScoreComposition from "./ScoreComposition"
import ApkAnalysis from "./ApkAnalysis"

const GeoMap = dynamic(() => import("./GeoMap"), { ssr: false, loading: () => <div className="w-full h-[420px] bg-[#0d1117] flex items-center justify-center font-mono text-xs text-gray-600">LOADING MAP...</div> })

// --- MAIN PAGE COMPONENT ---
function ReportContent() {
    const searchParams = useSearchParams()
    const id = searchParams.get("id") || ""
    // Present only when this scan came from the default-browser link interceptor
    // (see hooks/useLinkIntent.ts) — the original URL we're deciding whether to open.
    const interceptedUrl = searchParams.get("target")
    // Present only when this scan came from a native file intent (share sheet
    // or "Open with") — see hooks/useShareIntent.ts / useLinkIntent.ts.
    const fileUri = searchParams.get("fileUri")
    const fileMimeType = searchParams.get("mimeType") || "*/*"
    const router = useRouter()

    const [reportData, setReportData] = useState<any>(null)
    const [loading, setLoading] = useState(true)
    const [shareToast, setShareToast] = useState(false)
    const [isExporting, setIsExporting] = useState(false)

    // Every branch here must end in a verdict this page can render honestly.
    // Previously an unknown job id (404) set no state at all, and the `verdict`
    // default below filled in "Clear" — so /report?id=anything showed "No Threat
    // Detected" for a scan that never existed. `fetch` only rejects on network
    // failure, so an HTTP error never reached the catch either.
    useEffect(() => {
        const fetchReport = async () => {
            try {
                const res = await fetch(apiUrl(`/api/status/${id}`))
                if (!res.ok) {
                    setReportData({
                        score: 0, verdict: "Unavailable",
                        reasons: res.status === 404
                            ? ["No scan exists with this ID. It may have expired, or the link may be wrong."]
                            : [`The scanner returned an error (HTTP ${res.status}).`],
                    })
                    return
                }
                const data = await res.json()
                if (data.status === 'Failed') {
                    setReportData({ score: 0, verdict: "Failed", reasons: ["Analysis encountered a fatal error. Please check server logs."] })
                } else if (!data.results) {
                    // Submitted/Processing: there is no verdict yet. Saying
                    // "Clear" here announced a result before the scan had run.
                    setReportData({
                        score: 0, verdict: "Unavailable",
                        reasons: ["This scan has not finished yet — no verdict has been reached."],
                    })
                } else {
                    setReportData(data.results)
                }
            } catch (e) {
                console.error(e)
                setReportData({ score: 0, verdict: "Error", reasons: ["Backend Offline"] })
            } finally {
                setLoading(false)
            }
        }
        fetchReport()
    }, [id])

    // --- Open a link MalScan intercepted as the default browser, now that it's
    // verified Clear. Uses Chrome Custom Tabs on Android, falls back to a normal
    // tab on the web. ---
    const handleOpenInterceptedUrl = async (url: string) => {
        try {
            const { Browser } = await import("@capacitor/browser")
            await Browser.open({ url })
        } catch {
            window.open(url, "_blank")
        }
    }

    // --- Open the originally shared/intercepted file, now that it's verified
    // Clear. Lets Android pick whatever app handles this file type. ---
    const handleOpenFile = async () => {
        if (!fileUri) return
        try {
            const OpenFile = (await import("../../lib/native/openFile")).default
            await OpenFile.open({ path: fileUri, mimeType: fileMimeType })
        } catch (e) {
            alert(e instanceof Error ? e.message : "Could not open this file.")
        }
    }

    // --- Share Intel ---
    // --- Share the actual PDF (not just a link) through the OS share sheet —
    // WhatsApp, email, Drive, whatever the user picks. Falls back to copying
    // the report link if file-sharing isn't available on this platform. ---
    const handleShare = async () => {
        try {
            const blob = await fetchReportPdf()
            const filename = `MalScan_Report_${id.slice(0, 8)}.pdf`

            const { Capacitor } = await import("@capacitor/core")
            if (Capacitor.isNativePlatform()) {
                const { saveAndShareBlob } = await import("../../lib/saveBlob")
                await saveAndShareBlob(blob, filename)
                return
            }

            const file = new File([blob], filename, { type: "application/pdf" })
            if (navigator.share && navigator.canShare?.({ files: [file] })) {
                await navigator.share({ files: [file], title: filename })
                return
            }

            // Desktop browsers can't hand a file to other apps — fall back to
            // a direct download, which is the closest equivalent there.
            const { saveAndShareBlob } = await import("../../lib/saveBlob")
            await saveAndShareBlob(blob, filename)
        } catch (e) {
            console.error("[MalScan] PDF share failed, falling back to link copy:", e)
            const url = window.location.href
            try {
                await navigator.clipboard.writeText(url)
            } catch {
                const ta = document.createElement('textarea')
                ta.value = url
                document.body.appendChild(ta)
                ta.select()
                document.execCommand('copy')
                document.body.removeChild(ta)
            }
            setShareToast(true)
            setTimeout(() => setShareToast(false), 2500)
        }
    }

    if (loading) return <div className="min-h-screen bg-[#F5F5F3] flex items-center justify-center font-mono">LOADING_REPORT...</div>

    const threatScore = reportData?.score || 0
    // Defaulting this to "Clear" meant any path that failed to set reportData —
    // a 404, a 500, a race — rendered a green all-clear. Absence of a verdict is
    // not a verdict; fail closed.
    const verdict = reportData?.verdict || "Unavailable"
    const reasons = reportData?.reasons || []
    const family = reportData?.family || "Unknown"
    const attribution = reportData?.attribution || "Unattributed"
    const fileHash = reportData?.file_hash || "N/A"
    const originalFilename = reportData?.original_filename || "unknown"
    const submittedUrl = reportData?.submitted_url || null
    const vtStats = reportData?.osint_summary?.virustotal || null
    const urlscanData = reportData?.osint_summary?.urlscan || null
    const resourceChain = reportData?.osint_summary?.resource_chain || null
    const apkInfo = reportData?.apk_info || null
    const archiveContents = reportData?.archive_contents || []
    // Caveats about what could NOT be examined. The backend has emitted these
    // for a while but this page never read them, so a partly-scanned archive
    // looked identical to a fully-scanned one.
    const archiveEncrypted = reportData?.archive_encrypted || []
    const archiveTruncated = reportData?.archive_truncated || null
    const archiveUnreadable = reportData?.archive_unreadable || []
    const archiveUnsupported = reportData?.archive_unsupported || null
    const geoLat = reportData?.osint_summary?.lat ?? null
    const geoLon = reportData?.osint_summary?.lon ?? null
    const geoCity = reportData?.osint_summary?.city || ""
    const geoRegion = reportData?.osint_summary?.region || ""
    const geoCountry = reportData?.osint_summary?.country || ""
    const geoCountryCode = reportData?.osint_summary?.country_code || ""
    const geoIsp = reportData?.osint_summary?.hosting || ""
    const geoAsn = reportData?.osint_summary?.asn || ""
    const graphNodes = reportData?.graph_nodes || []
    const graphEdges = reportData?.graph_edges || []
    const riskProfile = reportData?.risk_profile || []
    const scoreBreakdown = reportData?.score_breakdown || []
    const isPe = reportData?.is_pe || false
    const peSections = reportData?.pe_sections || []

    // Build IOC rows from real backend data
    const indicators = reportData?.indicators || {}
    const iocs = [
        ...(indicators.ips || []).map((v: string) => ({ type: "IPv4", val: v, tag: "EXTRACTED" })),
        ...(indicators.urls || []).map((v: string) => ({ type: "URL", val: v, tag: "EXTRACTED" })),
        ...(indicators.domains || []).map((v: string) => ({ type: "DOMAIN", val: v, tag: "EXTRACTED" })),
    ]

    // VT bar total (including undetected)
    const vtTotal = vtStats ? (vtStats.malicious + vtStats.suspicious + vtStats.harmless + (vtStats.undetected || 0)) : 0

    const isClear = verdict === 'Clear'
    const isSuspicious = verdict === 'Suspicious'
    // "Inconclusive" = the scan could not complete (VirusTotal unavailable), so
    // nothing-found must NOT be painted green. Styled slate — neither safe nor
    // confirmed-bad. Note the ternaries below fall through to the red/Malicious
    // styling, so any new verdict MUST get an explicit branch here or it renders
    // as "High Confidence Threat".
    const isInconclusive = verdict === 'Inconclusive'
    // No usable verdict at all: the scan is missing, unfinished, or errored.
    // These share the Inconclusive palette because they are the same class of
    // answer — "we cannot tell you" — and because the ternaries below fall
    // through to the red branch, which would otherwise announce a high
    // confidence threat we never actually found.
    const isNoVerdict = verdict === 'Unavailable' || verdict === 'Failed' || verdict === 'Error'
    const isNeutral = isInconclusive || isNoVerdict
    // Surfaced independently of the verdict: a Malicious/Suspicious result can
    // also be partial (intel incomplete) without being downgraded.
    const isPartial = reportData?.partial === true

    // The OPEN buttons act on the user's device, so what they act on must come
    // from what the backend actually scanned — never from the query string.
    // `?target=` was previously handed straight to the browser, so a genuine
    // Clear verdict for one URL could be replayed as
    // /report?id=<that job>&target=<anything> and still render a working
    // OPEN LINK. Same for ?fileUri=. Three conditions, all required:
    //   1. the scan actually came back Clear
    //   2. the parameter matches what was scanned
    //   3. the scheme is http(s) — `javascript:` was previously opened verbatim
    const sameUrl = (a: string, b: string) =>
        a.trim().replace(/\/+$/, "") === b.trim().replace(/\/+$/, "")
    const openUrlAllowed = Boolean(
        isClear && interceptedUrl && submittedUrl &&
        looksLikeUrl(interceptedUrl) && sameUrl(interceptedUrl, submittedUrl)
    )
    // A device file URI has no backend twin, but the report does record the name
    // that was scanned — so at minimum the file being opened must be the file
    // the verdict is about.
    const fileUriName = fileUri ? decodeURIComponent(fileUri).split(/[\\/]/).pop() : null
    const openFileAllowed = Boolean(
        isClear && fileUri && originalFilename && fileUriName === originalFilename
    )

    // Glassmorphism Theme
    const themeColors = {
        bg: isClear ? 'bg-green-50' : isNeutral ? 'bg-slate-50' : isSuspicious ? 'bg-amber-50' : 'bg-red-50',
        textMain: 'text-[#121212]',
        textSub: 'text-gray-500',
        icon: isClear ? 'text-green-500' : isNeutral ? 'text-slate-500' : isSuspicious ? 'text-amber-500' : 'text-[#FF3B00]',
        iconGlow: isClear ? 'bg-green-500/20' : isNeutral ? 'bg-slate-500/20' : isSuspicious ? 'bg-amber-500/20' : 'bg-red-500/20',
        bar: isClear ? 'bg-green-500' : isNeutral ? 'bg-slate-400' : isSuspicious ? 'bg-amber-500' : 'bg-[#FF3B00]',
        // Same palette as `bar`, as a hex the SVG radar can use directly.
        accent: isClear ? '#22c55e' : isNeutral ? '#94a3b8' : isSuspicious ? '#f59e0b' : '#FF3B00',
        IconComponent: isClear ? Check : isNeutral ? HelpCircle : ShieldAlert
    }
    
    // Determine the label for the Target box. The scanned URL is named FIRST:
    // `interceptedUrl` used to win this chain, so an edited ?target= displayed
    // itself as the thing analysed while the real subject of the verdict —
    // submitted_url, which the backend does store — was hidden behind it.
    let targetLabel = 'Unknown Target'
    if (submittedUrl) {
        targetLabel = submittedUrl
    } else if (interceptedUrl) {
        targetLabel = interceptedUrl
    } else if (originalFilename !== 'unknown') {
        targetLabel = originalFilename
    } else if (urlscanData?.page?.url) {
        targetLabel = urlscanData.page.url
    } else if (urlscanData?.task?.domain) {
        targetLabel = urlscanData.task.domain
    } else if (indicators?.urls && indicators.urls.length > 0) {
        targetLabel = indicators.urls[0]
    } else if (indicators?.domains && indicators.domains.length > 0) {
        targetLabel = indicators.domains[0]
    } else if (fileHash !== 'N/A') {
        targetLabel = `File: ${fileHash.substring(0, 32)}...`
    }

    // --- PDF Export. window.print() does nothing inside the packaged app's
    // Android WebView, and screenshot-and-reassemble approaches kept hitting
    // cross-origin canvas limits. The backend now renders the report to a real
    // PDF server-side with headless Chromium (GET /report/{id}/pdf) — same
    // browser engine, just driven from the server instead of fighting the
    // WebView. This just fetches that file and saves/shares it. ---
    const fetchReportPdf = async (): Promise<Blob> => {
        const res = await fetch(apiUrl(`/api/report/${id}/pdf`))
        if (!res.ok) throw new Error(`PDF generation failed (HTTP ${res.status})`)
        return res.blob()
    }

    const handleExportPDF = async () => {
        setIsExporting(true)
        try {
            const blob = await fetchReportPdf()
            const { saveAndShareBlob } = await import("../../lib/saveBlob")
            await saveAndShareBlob(blob, `MalScan_Report_${id.slice(0, 8)}.pdf`)
        } catch (e) {
            console.error("[MalScan] PDF export failed:", e)
            alert("Could not generate the PDF. Please try again.")
        } finally {
            setIsExporting(false)
        }
    }

    return (
        <div className="min-h-screen print:!min-h-0 bg-[#F5F5F3] text-[#121212] font-sans pb-20 print:pb-0">
            {/* Print-optimized: hide toolbar when printing */}
            <style>{`@media print { header { display: none !important; } body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }`}</style>
            
            {/* TOOLBAR */}
            <header className="sticky top-0 bg-[#F5F5F3]/90 backdrop-blur-md border-b border-gray-200 px-4 md:px-8 py-4 z-40 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 print:static print:bg-[#F5F5F3] print:border-b-2 print:border-gray-300">
                <div className="flex flex-wrap items-center gap-2 md:gap-4 font-mono text-[10px] md:text-xs w-full md:w-auto">
                    <button
                        onClick={() => router.push('/')}
                        className="flex items-center gap-1.5 font-bold tracking-widest hover:text-[#FF3B00] transition-colors border border-gray-300 hover:border-[#FF3B00] px-2 py-1 md:px-3 md:py-1.5 bg-white shrink-0 print:hidden"
                        title="Back to Home"
                    >
                        <Home size={13} /> HOME
                    </button>
                    <div className="hidden print:flex items-center gap-2 mr-2">
                        <div className="w-2.5 h-2.5 bg-[#FF3B00] animate-pulse" />
                        <span className="font-bold tracking-widest text-[#121212]">MalScan</span>
                    </div>
                    <span className="text-gray-500 uppercase tracking-wider truncate max-w-[120px] md:max-w-none">JOB: {id.split('-')[0]}</span>
                    <span className={`px-2 py-1 font-bold rounded-sm uppercase tracking-widest shrink-0 ${isClear
                            ? 'bg-green-900 text-green-400'
                            : isNeutral
                                ? 'bg-slate-800 text-slate-300'
                                : isSuspicious
                                    ? 'bg-amber-900 text-amber-400'
                                    : 'bg-red-900 text-[#FF3B00]'
                        }`}>{verdict}</span>
                </div>
                <div className="flex flex-wrap gap-4 relative w-full md:w-auto justify-end print:hidden">
                    {interceptedUrl && (
                        openUrlAllowed ? (
                            <button
                                onClick={() => handleOpenInterceptedUrl(interceptedUrl)}
                                className="flex items-center gap-2 text-[10px] md:text-xs font-bold tracking-widest text-green-600 hover:text-green-700 transition-colors"
                            >
                                <ExternalLink size={14} /> OPEN LINK
                            </button>
                        ) : (
                            <span className="flex items-center gap-2 text-[10px] md:text-xs font-bold tracking-widest text-[#FF3B00]">
                                <ShieldAlert size={14} /> LINK BLOCKED
                            </span>
                        )
                    )}
                    {fileUri && (
                        openFileAllowed ? (
                            <button
                                onClick={handleOpenFile}
                                className="flex items-center gap-2 text-[10px] md:text-xs font-bold tracking-widest text-green-600 hover:text-green-700 transition-colors"
                            >
                                <ExternalLink size={14} /> OPEN FILE
                            </button>
                        ) : (
                            <span className="flex items-center gap-2 text-[10px] md:text-xs font-bold tracking-widest text-[#FF3B00]">
                                <ShieldAlert size={14} /> FILE BLOCKED
                            </span>
                        )
                    )}
                    <button
                        onClick={handleExportPDF}
                        disabled={isExporting}
                        className="flex items-center gap-1 md:gap-2 text-[10px] md:text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors disabled:opacity-50"
                    >
                        <Download size={14} /> {isExporting ? "EXPORTING..." : "EXPORT"}
                    </button>
                    <button
                        onClick={handleShare}
                        className="flex items-center gap-1 md:gap-2 text-[10px] md:text-xs font-bold tracking-widest hover:text-[#FF3B00] transition-colors"
                    >
                        <Share2 size={14} /> SHARE
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

            {/* print:flex + flex-col bypasses the grid entirely for print — grid
                track widths render unreliably in Chrome's print/PDF engine
                (the cause of the column-overlap bug), whereas a simple
                full-width vertical flex stack always renders correctly. */}
            {/* INCOMPLETE-INTEL BANNER — a scan whose verdict-critical source
                (VirusTotal) did not complete is provisional. Shown for ANY
                verdict: a Malicious/Suspicious result can be partial too without
                being downgraded, and a reader must not read either as final. */}
            {isPartial && (
                <div className="max-w-[1400px] mx-auto px-4 md:px-8 mt-4">
                    <div className="flex items-start gap-3 rounded-md border border-amber-300 bg-amber-50 px-4 py-3">
                        <AlertTriangle className="w-5 h-5 shrink-0 text-amber-600 mt-0.5" />
                        <div>
                            <p className="text-xs font-bold tracking-widest uppercase text-amber-800">
                                Incomplete Intelligence — Verdict Provisional
                            </p>
                            <p className="text-xs text-amber-900/80 mt-1">
                                VirusTotal did not return in time on this scan (usually a temporary
                                rate limit), so this artifact could not be fully checked. This is not
                                a clean bill of health — re-scan to resolve it.
                            </p>
                        </div>
                    </div>
                </div>
            )}

            <main className="max-w-[1400px] mx-auto p-4 md:p-8 grid grid-cols-1 lg:grid-cols-12 gap-8 mt-4 print:p-0 print:m-0 print:gap-6 print:!block">

                {/* COL 1: VERDICT & SCORE */}
                <div className="lg:col-span-4 flex flex-col gap-6 print:!block">
                <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} className={`p-5 md:p-6 border border-gray-200 shadow-xl shadow-gray-200/30 flex flex-col h-fit rounded-lg transition-colors duration-500 ${themeColors.bg} print:mb-6`}>
                    <div>
                        {/* Glassmorphism glowing icon */}
                        <div className="relative mb-5 inline-block">
                            <div className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-16 h-16 rounded-full blur-xl animate-pulse ${themeColors.iconGlow}`}></div>
                            <themeColors.IconComponent className={`relative z-10 w-12 h-12 ${themeColors.icon}`} />
                        </div>
                        
                        <h2 className={`text-[10px] font-bold tracking-[0.2em] uppercase mb-2 ${themeColors.textSub}`}>Analysis Verdict</h2>
                        <h1 className={`text-3xl md:text-4xl font-medium tracking-tight mb-6 leading-tight ${themeColors.textMain}`}>
                            {isClear ? 'No Threat Detected.'
                                : isInconclusive ? 'Scan Could Not Complete.'
                                : isNoVerdict ? 'No Result For This Scan.'
                                : isSuspicious ? 'Suspicious Activity Detected.'
                                : 'High Confidence Threat.'}
                        </h1>

                        {/* TARGET SCANNED */}
                        <div className="mb-6">
                            <h3 className={`text-[9px] font-bold uppercase tracking-wider mb-2 ${themeColors.textSub}`}>Target Analyzed</h3>
                            <div className={`p-3 rounded-md bg-white/80 backdrop-blur-md border border-gray-200/50 shadow-sm border-l-4 ${isClear ? 'border-l-green-500' : isNeutral ? 'border-l-slate-400' : isSuspicious ? 'border-l-amber-500' : 'border-l-[#FF3B00]'}`}>
                                <p className={`font-mono text-sm md:text-base break-all font-bold ${themeColors.textMain}`}>
                                    {targetLabel}
                                </p>
                            </div>
                        </div>

                        <div className="space-y-5">
                            <div>
                                <div className={`flex justify-between text-[10px] font-mono mb-2 uppercase tracking-wider ${themeColors.textSub}`}>
                                    <span>Threat Score</span>
                                    <span className={`font-bold ${themeColors.icon}`}>{threatScore}/100</span>
                                </div>
                                <div className="w-full h-1.5 bg-black/5 rounded-full overflow-hidden">
                                    <motion.div initial={{ width: 0 }} animate={{ width: `${threatScore}%` }} transition={{ delay: 0.5, duration: 1 }} className={`h-full ${themeColors.bar}`} />
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div><h3 className={`text-[9px] font-bold uppercase mb-1 ${themeColors.textSub}`}>Identified Family</h3><p className={`font-mono text-[11px] md:text-xs font-semibold ${themeColors.textMain}`}>{family}</p></div>
                                <div><h3 className={`text-[9px] font-bold uppercase mb-1 ${themeColors.textSub}`}>Attribution</h3><p className={`font-mono text-[11px] md:text-xs font-semibold ${themeColors.textMain}`}>{attribution}</p></div>
                            </div>
                        </div>
                    </div>
                    
                    <div className="pt-5 mt-5 border-t border-black/10">
                        <div className={`text-[10px] font-mono leading-relaxed space-y-1 ${themeColors.textSub}`}>
                            <span className="font-bold uppercase block mb-1.5 text-black/40">Executive Summary:</span>
                            {reasons.length > 0
                                ? reasons.map((r: string) => <p key={r}>- {r}</p>)
                                : <p>- No anomalies or threat indicators were identified during analysis.</p>}
                        </div>
                    </div>

                    {/* Score Composition — point-weighted breakdown of the Executive Summary above */}
                    <div className="mt-5 border-t border-black/10 pt-5">
                        <h3 className={`text-[9px] font-bold mb-3 uppercase flex items-center gap-1.5 ${themeColors.textSub}`}>
                            <PieChart size={10}/> Score Composition
                        </h3>
                        <ScoreComposition breakdown={scoreBreakdown} totalScore={threatScore} clear={isClear} />
                    </div>

                    {/* VirusTotal Vendor Consensus */}
                    {vtStats && (
                        <div className="mt-5 border-t border-black/10 pt-5">
                            <h3 className={`text-[9px] font-bold mb-3 uppercase flex items-center gap-1.5 ${themeColors.textSub}`}>
                                <ShieldAlert size={10}/> VirusTotal Consensus
                            </h3>
                            <div className="flex h-2 w-full bg-black/5 mb-2.5 overflow-hidden rounded-full">
                                {vtStats.malicious > 0 && <div className="h-full bg-red-500 transition-all" style={{ width: `${(vtStats.malicious / vtTotal) * 100}%` }} />}
                                {vtStats.suspicious > 0 && <div className="h-full bg-amber-500 transition-all" style={{ width: `${(vtStats.suspicious / vtTotal) * 100}%` }} />}
                                {vtStats.harmless > 0 && <div className="h-full bg-green-500 transition-all" style={{ width: `${(vtStats.harmless / vtTotal) * 100}%` }} />}
                                {(vtStats.undetected || 0) > 0 && <div className="h-full bg-gray-300 transition-all" style={{ width: `${((vtStats.undetected || 0) / vtTotal) * 100}%` }} />}
                            </div>
                            <div className="flex flex-wrap gap-2 text-[9px] font-mono uppercase">
                                <div className="flex items-center gap-1 text-red-600"><div className="w-1.5 h-1.5 bg-red-500 rounded-full" /> {vtStats.malicious} Malicious</div>
                                <div className="flex items-center gap-1 text-amber-600"><div className="w-1.5 h-1.5 bg-amber-500 rounded-full" /> {vtStats.suspicious} Suspicious</div>
                                <div className="flex items-center gap-1 text-green-600"><div className="w-1.5 h-1.5 bg-green-500 rounded-full" /> {vtStats.harmless} Harmless</div>
                                {(vtStats.undetected || 0) > 0 && (
                                    <div className="flex items-center gap-1 text-gray-500"><div className="w-1.5 h-1.5 bg-gray-400 rounded-full" /> {vtStats.undetected} Undetected</div>
                                )}
                            </div>
                            <VTDonut stats={vtStats} />
                        </div>
                    )}
                </motion.div>

                {/* IOC TERMINAL — moved under the verdict card and shrunk so it
                    reads as a quick-reference list rather than a full section. */}
                <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }} className="bg-[#121212] text-white border border-black p-4 font-mono shadow-xl rounded-lg print:break-inside-avoid">
                    <div className="flex items-center gap-2 mb-3 pb-3 border-b border-white/20">
                        <TerminalSquare className="text-[#FF3B00]" size={14} />
                        <h3 className="text-[10px] font-bold tracking-[0.25em] uppercase text-gray-400">Extracted Indicators</h3>
                    </div>
                    <div className="max-h-48 print:max-h-none overflow-y-auto print:overflow-visible pr-2 print:pr-0 space-y-2.5 scrollbar-thin scrollbar-thumb-[#FF3B00] scrollbar-track-[#333]">
                        {iocs.length === 0 ? (
                            <div className="text-gray-500 text-[10px] tracking-wider py-4 text-center">NO NETWORK INDICATORS EXTRACTED.</div>
                        ) : iocs.map((ioc, i) => (
                            <div key={i} className="flex flex-col gap-0.5 pb-2 border-b border-white/10 last:border-0">
                                <span className="text-[8px] text-[#FF3B00] tracking-widest uppercase">{ioc.type}</span>
                                <span className="text-[10px] truncate print:whitespace-normal print:break-all print:overflow-visible" title={ioc.val}>{ioc.val}</span>
                            </div>
                        ))}
                    </div>
                </motion.div>
                </div>

                <div className="lg:col-span-8 grid grid-cols-1 md:grid-cols-2 gap-6 print:gap-6 print:!block items-start">
                    {/* RISK PROFILE RADAR */}
                    {riskProfile.length > 0 && (
                        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.05 }} className="bg-white border border-gray-200 shadow-sm rounded-lg overflow-hidden print:break-inside-avoid print:shadow-none print:mb-6">
                            <div className="p-4 border-b border-gray-200 bg-gray-50">
                                <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Radar size={14} className="text-[#FF3B00]" /> Risk Profile</h3>
                            </div>
                            <RiskRadar axes={riskProfile} tone={themeColors.accent} measured={!isInconclusive} />
                        </motion.div>
                    )}

                    {/* INFRASTRUCTURE GRAPH — paired with Risk Profile above; both are
                        compact node/chart visuals that read well side by side. */}
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.12 }} className="bg-white border border-gray-200 shadow-sm rounded-lg overflow-hidden print:break-inside-avoid print:shadow-none print:mb-6">
                        <div className="p-4 border-b border-gray-200 bg-gray-50">
                            <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Network size={14} className="text-[#FF3B00]" /> Infrastructure Graph</h3>
                        </div>
                        <GraphWidget nodes={graphNodes} edges={graphEdges} originLabel={targetLabel} />
                    </motion.div>

                    {/* URLScan.io Sandbox Result */}
                    {urlscanData && !urlscanData.error && (
                        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15 }} className="md:col-span-2 bg-white border border-gray-200 shadow-sm overflow-hidden rounded-lg print:mb-6">
                            <div className="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                                <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Camera size={14} className="text-[#FF3B00]" /> URLScan Sandbox Result</h3>
                                {urlscanData.is_malicious && <span className="text-[9px] bg-red-900 text-[#FF3B00] px-2 py-1 font-mono uppercase tracking-widest animate-pulse rounded-sm">MALICIOUS</span>}
                            </div>
                            <div className="p-4 md:p-6">
                                {urlscanData.screenshot_url && (
                                    <div className="mb-6 rounded-lg border border-gray-200 shadow-sm overflow-hidden group">
                                        <div className="bg-gray-100 px-3 py-2 flex gap-1.5 border-b border-gray-200">
                                            <div className="w-2.5 h-2.5 rounded-full bg-red-400"></div>
                                            <div className="w-2.5 h-2.5 rounded-full bg-amber-400"></div>
                                            <div className="w-2.5 h-2.5 rounded-full bg-green-400"></div>
                                            <div className="ml-4 text-[9px] font-mono text-gray-500 truncate mt-0.5" title={urlscanData.page_title}>{urlscanData.page_title || "Target URL Captured"}</div>
                                        </div>
                                        <div className="relative">
                                            <img src={apiUrl(`/api/proxy/image?url=${encodeURIComponent(urlscanData.screenshot_url)}`)} alt="URLScan screenshot" className="w-full h-auto object-cover object-top" />
                                            <div className="absolute inset-0 bg-[#FF3B00]/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                                        </div>
                                    </div>
                                )}
                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-[10px] bg-gray-50 p-4 border border-gray-100 rounded-md">
                                    {urlscanData.page_title && <div className="min-w-0"><span className="text-gray-400 uppercase block mb-1">Title</span> <div className="text-gray-800 font-bold truncate" title={urlscanData.page_title}>{urlscanData.page_title}</div></div>}
                                    {urlscanData.page_ip && <div className="min-w-0"><span className="text-gray-400 uppercase block mb-1">IP</span> <div className="text-gray-800 truncate" title={urlscanData.page_ip}>{urlscanData.page_ip}</div></div>}
                                    {urlscanData.page_country && <div className="min-w-0"><span className="text-gray-400 uppercase block mb-1">Country</span> <div className="text-gray-800 truncate" title={urlscanData.page_country}>{urlscanData.page_country}</div></div>}
                                    {urlscanData.page_server && <div className="min-w-0"><span className="text-gray-400 uppercase block mb-1">Server</span> <div className="text-gray-800 truncate" title={urlscanData.page_server}>{urlscanData.page_server}</div></div>}
                                </div>
                                {/* Third parties the page loads. These used to render as one
                                    undifferentiated grey list, which read as "checked and fine"
                                    next to a clean score when in fact nothing had looked at them —
                                    that is how a flagged S3 bucket sat in a 0/100 report. Flagged,
                                    checked-clean and never-checked are now visibly different. */}
                                {resourceChain?.hosts?.length > 0 ? (
                                    <div className="mt-4 pt-4 border-t border-gray-100">
                                        <span className="text-[10px] font-mono text-gray-400 uppercase">
                                            Third-Party Resources ({resourceChain.hosts.length}):
                                        </span>
                                        <div className="flex flex-wrap gap-1.5 mt-2">
                                            {resourceChain.hosts.map((h: any) => {
                                                const mal = h.virustotal?.malicious || 0
                                                const flagged = mal >= 2
                                                const checked = h.checked || h.virustotal
                                                const cls = flagged
                                                    ? "bg-red-50 border-red-300 text-red-700 font-bold"
                                                    : checked
                                                        ? "bg-green-50 border-green-200 text-green-800"
                                                        : "bg-white border-gray-200 text-gray-500 border-dashed"
                                                const title = flagged
                                                    ? `${h.host} — flagged by ${mal} VirusTotal vendors`
                                                    : checked
                                                        ? `${h.host} — reputation checked, nothing found`
                                                        : `${h.host} — observed but NOT reputation checked${h.facets?.length ? ` (${h.facets.join(", ")})` : ""}`
                                                return (
                                                    <span key={h.host} title={title}
                                                        className={`text-[9px] px-2 py-1 rounded-md border font-mono shadow-sm truncate max-w-full ${cls}`}>
                                                        {flagged && "⚠ "}{h.host}{flagged && ` (${mal})`}
                                                    </span>
                                                )
                                            })}
                                        </div>
                                        <div className="mt-2 text-[9px] font-mono text-gray-400">
                                            Solid = reputation checked · Dashed = observed only, not checked
                                        </div>
                                    </div>
                                ) : urlscanData.outgoing_domains && urlscanData.outgoing_domains.length > 0 && (
                                    <div className="mt-4 pt-4 border-t border-gray-100">
                                        <span className="text-[10px] font-mono text-gray-400 uppercase">Outgoing Domains ({urlscanData.outgoing_domains.length}):</span>
                                        <div className="flex flex-wrap gap-1.5 mt-2">
                                            {urlscanData.outgoing_domains.map((d: string) => (
                                                <span key={d} className="text-[9px] bg-white px-2 py-1 rounded-md border border-gray-200 font-mono text-gray-600 shadow-sm truncate max-w-full">{d}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </motion.div>
                    )}

                    {/* URLScan info banner when sandbox is unavailable */}
                    {urlscanData && urlscanData.error && (
                        <motion.div initial={{ y: 10, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.15 }} className="md:col-span-2 flex items-start gap-3 px-4 py-3 bg-gray-50 border border-gray-200 text-gray-500">
                            <Info size={14} className="mt-0.5 shrink-0 text-gray-400" />
                            <div>
                                <p className="text-[10px] font-bold uppercase tracking-widest mb-0.5">Sandbox Skipped</p>
                                <p className="text-[10px] font-mono leading-relaxed">{urlscanData.error}</p>
                            </div>
                        </motion.div>
                    )}

                    {/* APK PERMISSIONS */}
                    {apkInfo && <ApkAnalysis apkInfo={apkInfo} />}

                    {/* ARCHIVE CONTENTS — also shown when nothing could be extracted,
                        which is exactly when the reader needs to know why. */}
                    {(archiveContents.length > 0 || archiveEncrypted.length > 0 || archiveTruncated || archiveUnreadable.length > 0 || archiveUnsupported) && (
                        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.25 }} className="bg-white border border-gray-200 shadow-sm rounded-lg overflow-hidden print:break-inside-avoid print:shadow-none">
                            <div className="p-4 border-b border-gray-200 bg-gray-50">
                                <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Archive size={14}/> Archive Contents {archiveContents.length > 0 ? `(${archiveContents.length} files)` : "(not examined)"}</h3>
                            </div>
                            <div className="p-4">
                                {archiveUnsupported && (
                                    <div className="mb-4 p-3 rounded-md border border-amber-300 bg-amber-50 text-[11px] text-amber-900">
                                        <div className="font-bold mb-1">{archiveUnsupported} archives cannot be opened by this scanner.</div>
                                        Nothing inside was extracted, hashed, YARA-scanned or analysed. A clean result here means
                                        the contents could not be read, not that they are safe — extract it and submit the contents
                                        individually.
                                    </div>
                                )}
                                {archiveEncrypted.length > 0 && (
                                    <div className="mb-4 p-3 rounded-md border border-amber-300 bg-amber-50 text-[11px] text-amber-900">
                                        <div className="font-bold mb-1">This archive is password-protected.</div>
                                        {archiveEncrypted.length} file(s) could not be extracted, so they were <strong>not scanned for malware</strong> —
                                        no hash lookup, no YARA rules and no file analysis ran against them. A clean result here means the
                                        contents could not be examined, not that they are safe.
                                        <div className="mt-2 font-mono text-[10px] text-amber-800 break-all">
                                            {archiveEncrypted.slice(0, 8).join(", ")}{archiveEncrypted.length > 8 ? ` +${archiveEncrypted.length - 8} more` : ""}
                                        </div>
                                    </div>
                                )}
                                {archiveTruncated && (
                                    <div className="mb-4 p-3 rounded-md border border-amber-300 bg-amber-50 text-[11px] text-amber-900">
                                        Only part of this archive was examined — {archiveTruncated}.
                                    </div>
                                )}
                                {archiveUnreadable.length > 0 && (
                                    <div className="mb-4 p-3 rounded-md border border-amber-300 bg-amber-50 text-[11px] text-amber-900">
                                        {archiveUnreadable.length} file(s) could not be read after extraction, commonly because antivirus
                                        quarantined them — they were <strong>not analysed</strong>.
                                    </div>
                                )}
                                <div className="space-y-1.5 max-h-64 print:max-h-none overflow-y-auto print:overflow-visible pr-2 print:pr-0">
                                    {archiveContents.map((f: any, i: number) => (
                                        <div key={i} className="flex items-center justify-between font-mono text-[10px] py-2 px-3 bg-gray-50 border border-gray-100 rounded-md">
                                            <div className="flex items-center gap-2 min-w-0">
                                                <Package size={12} className="text-gray-400 shrink-0"/>
                                                <span className="text-gray-700 truncate" title={f.name}>{f.name}</span>
                                            </div>
                                            <div className="flex items-center gap-3 shrink-0 ml-4">
                                                {f.is_pe && <span className="text-[8px] bg-amber-100 text-amber-800 border border-amber-200 px-1.5 py-0.5 rounded-sm uppercase font-bold">PE</span>}
                                                {f.ioc_count > 0 && <span className="text-[8px] text-[#FF3B00] font-bold">{f.ioc_count} IOCs</span>}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* FILE ENTROPY BY SECTION — shown for any uploaded file (not URL
                        submissions, where it's simply inapplicable) so a non-PE file
                        explains itself instead of the card silently disappearing. */}
                    {!submittedUrl && !interceptedUrl && (
                        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.27 }} className="bg-white border border-gray-200 shadow-sm rounded-lg overflow-hidden print:break-inside-avoid print:shadow-none">
                            <div className="p-4 border-b border-gray-200 bg-gray-50">
                                <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2"><Activity size={14} className="text-[#FF3B00]" /> File Entropy by Section</h3>
                            </div>
                            <div className="p-4 md:p-5">
                                {isPe && peSections.length > 0 ? (
                                    <EntropyChart sections={peSections} />
                                ) : (
                                    <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                                        This analysis only applies to Windows PE executables (.exe/.dll), which are broken into named sections like .text and .rsrc. &quot;{originalFilename}&quot; isn&apos;t a PE file, so there are no sections to chart.
                                    </p>
                                )}
                            </div>
                        </motion.div>
                    )}

                    {/* THREAT ORIGIN GEO-MAP */}
                    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }} className="md:col-span-2 bg-[#0d1117] border border-gray-800 shadow-sm overflow-hidden rounded-lg print:break-inside-avoid print:mb-6">
                        <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-[#0d1117]">
                            <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2 text-gray-300"><MapPin size={14} className="text-[#FF3B00]" /> Threat Origin</h3>
                            <div className="flex gap-4">
                                {geoLat && <span className="text-[10px] font-mono text-[#FF3B00] animate-pulse">◉ LIVE</span>}
                                {geoCountryCode && <span className="text-[10px] font-mono text-gray-500">{geoCountryCode}</span>}
                            </div>
                        </div>
                        <GeoMap lat={geoLat} lon={geoLon} city={geoCity} region={geoRegion} country={geoCountry} countryCode={geoCountryCode} isp={geoIsp} asn={geoAsn} ips={indicators.ips || []} />
                    </motion.div>
                </div>

                {/* PRINT-ONLY CLOSING FOOTER */}
                <div className="hidden print:flex print:col-span-12 items-center justify-between mt-10 pt-4 border-t border-gray-200 text-gray-400">
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 bg-[#FF3B00]" />
                        <span className="text-[9px] font-mono uppercase tracking-[0.2em]">MalScan Automated Threat Intelligence</span>
                    </div>
                    <span className="text-[9px] font-mono uppercase tracking-wider">Report ID: {id}</span>
                </div>
            </main>
        </div>
    )
}

export default function ReportPage() {
    return (
        <Suspense fallback={null}>
            <ReportContent />
        </Suspense>
    )
}