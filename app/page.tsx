"use client"

import { useState, useEffect, useRef } from "react"
import { useRouter } from "next/navigation"
import { motion, useScroll, useTransform } from "framer-motion"
import { UploadCloud, ArrowRight, Cpu, Network, Shield, Zap } from "lucide-react"

// --- BACKGROUND PLACEHOLDER ---
const BackgroundMedia = () => (
  <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
    <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-200 via-[#F5F5F3] to-[#F5F5F3] opacity-50"></div>
    <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/graphy.png')] opacity-[0.05]"></div>
  </div>
)

const FeatureItem = ({ icon: Icon, title, desc }: { icon: any, title: string, desc: string }) => (
  <div className="flex flex-col gap-4 p-6 border border-gray-200 bg-white hover:border-[#FF3B00]/50 transition-colors group">
    <div className="w-10 h-10 bg-[#121212] text-white flex items-center justify-center rounded-sm group-hover:bg-[#FF3B00] transition-colors">
      <Icon size={20} />
    </div>
    <div>
      <h3 className="text-sm font-bold uppercase tracking-widest mb-2">{title}</h3>
      <p className="font-mono text-xs text-gray-500 leading-relaxed">{desc}</p>
    </div>
  </div>
)

export default function LandingPage() {
  const router = useRouter()
  const { scrollY } = useScroll()
  const yText = useTransform(scrollY, [0, 300], [0, -50])
  const yUpload = useTransform(scrollY, [0, 300], [0, -20])
  
  // Latency Logic
  const [latency, setLatency] = useState<number | null>(null)

  useEffect(() => {
    const measureLatency = async () => {
        try {
            const start = performance.now()
            await fetch('/', { method: 'HEAD', cache: 'no-store' })
            const end = performance.now()
            setLatency(Math.round(end - start))
        } catch (e) {
            setLatency(null)
        }
    }
    measureLatency()
    const interval = setInterval(measureLatency, 2000)
    return () => clearInterval(interval)
  }, [])

  const fileInputRef = useRef<HTMLInputElement>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [urlInput, setUrlInput] = useState("")
  const [isSubmittingUrl, setIsSubmittingUrl] = useState(false)
  const [urlError, setUrlError] = useState<string | null>(null)

  const handleUploadClick = () => {
    fileInputRef.current?.click()
  }

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true)
    const formData = new FormData()
    formData.append("file", file)

    try {
      const res = await fetch("/api/upload", {
          method: "POST",
          body: formData
      })
      if (!res.ok) throw new Error("Backend offline or error")
      const data = await res.json()
      router.push(`/analysis/${data.job_id}`)
    } catch (err) {
      console.error(err)
      router.push(`/analysis/job-demo-8x9921`)
    }
    setIsUploading(false)
  }

  const handleUrlSubmit = async () => {
    const trimmed = urlInput.trim()
    if (!trimmed) { setUrlError("Please enter a URL."); return }
    setUrlError(null)
    setIsSubmittingUrl(true)
    try {
      const res = await fetch("/api/submit-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      })
      if (!res.ok) throw new Error("Backend error")
      const data = await res.json()
      router.push(`/analysis/${data.job_id}`)
    } catch (err) {
      console.error(err)
      setUrlError("Submission failed. Is the backend running?")
    }
    setIsSubmittingUrl(false)
  }

  return (
    <div className="min-h-screen bg-[#F5F5F3] text-[#121212] font-sans selection:bg-[#FF3B00] selection:text-white relative">
      <BackgroundMedia />
      
      {/* HEADER */}
      <nav className="fixed top-0 w-full p-8 flex justify-between z-50 mix-blend-difference text-white/80 uppercase tracking-widest text-xs font-mono">
        <div className="flex items-center gap-3">
            <div className="w-3 h-3 bg-[#FF3B00]"></div>
            <span className="font-bold">MalScan Pro // V.2.4</span>
        </div>
        <div className="flex gap-6">
            <span>LATENCY: {latency !== null ? `${latency}ms` : 'CALC...'}</span>
        </div>
      </nav>
      
      {/* HERO SECTION (UPDATED TEXT) */}
      <main className="min-h-screen flex flex-col justify-center items-center relative z-10 px-6 pt-20">
        <motion.div style={{ y: yText }} className="text-center mb-16 relative">
          <div className="inline-block px-3 py-1 mb-6 border border-[#FF3B00] text-[#FF3B00] text-[10px] font-bold tracking-[0.3em] uppercase rounded-full">
            Automated Forensic Intelligence
          </div>
          <h1 className="text-7xl md:text-[10rem] font-medium tracking-tighter leading-[0.85] text-[#121212] mb-8">
            THREAT.<br/>
            <span className="text-transparent bg-clip-text bg-gradient-to-b from-[#121212] to-gray-400">VISUALIZED.</span>
          </h1>
          <p className="max-w-xl mx-auto text-gray-500 font-mono text-xs leading-relaxed uppercase tracking-wider">
            Enterprise-grade static analysis, heuristic clustering, and infrastructure mapping for modern threat landscapes. Isolated execution environment.
          </p>
        </motion.div>

        {/* UPLOAD MODULE */}
        <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
        <motion.div 
          style={{ y: yUpload }}
          whileHover={{ scale: 1.01 }}
          onClick={handleUploadClick}
          className={`group relative w-full max-w-xl h-40 bg-white border-2 border-[#121212] cursor-pointer overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.1)] ${isUploading ? 'opacity-50 pointer-events-none' : ''}`}
        >
          <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/graphy.png')] opacity-[0.05]"></div>
          <div className="flex flex-col items-center justify-center h-full relative z-10">
             <UploadCloud className="w-8 h-8 text-[#121212] mb-4 group-hover:text-[#FF3B00] transition-colors" />
             <p className="font-bold text-lg tracking-tight text-[#121212]">DROP ARTIFACT FOR INGESTION</p>
             <p className="font-mono text-[10px] text-gray-400 mt-2">SUPPORTED: .EXE .DLL .APK .ELF .TXT AND MORE</p>
          </div>
          <div className="absolute top-0 h-full w-1 bg-[#FF3B00] opacity-50 group-hover:animate-scan"></div>
        </motion.div>

        {/* OR DIVIDER */}
        <div className="flex items-center w-full max-w-xl gap-4 my-2">
          <div className="flex-1 h-px bg-gray-300" />
          <span className="font-mono text-[10px] text-gray-400 tracking-widest">OR SUBMIT URL</span>
          <div className="flex-1 h-px bg-gray-300" />
        </div>

        {/* URL INPUT */}
        <div className="w-full max-w-xl">
          <div className="flex gap-0 border-2 border-[#121212] bg-white shadow-[0_10px_30px_rgba(0,0,0,0.08)] overflow-hidden">
            <input
              type="text"
              value={urlInput}
              onChange={e => { setUrlInput(e.target.value); setUrlError(null) }}
              onKeyDown={e => e.key === 'Enter' && handleUrlSubmit()}
              placeholder="https://suspicious-domain.com/payload"
              className="flex-1 px-4 py-3 font-mono text-xs text-[#121212] placeholder-gray-300 bg-transparent outline-none"
            />
            <button
              onClick={handleUrlSubmit}
              disabled={isSubmittingUrl}
              className="px-5 py-3 bg-[#121212] text-white font-mono text-[10px] tracking-widest uppercase hover:bg-[#FF3B00] transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              <ArrowRight size={12} />
              {isSubmittingUrl ? "SCANNING..." : "SCAN URL"}
            </button>
          </div>
          {urlError && <p className="font-mono text-[10px] text-[#FF3B00] mt-2 tracking-wider">{urlError}</p>}
        </div>
      </main>

      {/* FEATURE GRID */}
      <section className="relative z-10 py-32 px-6 bg-[#F5F5F3] border-t border-gray-200">
          <div className="max-w-7xl mx-auto">
              <div className="mb-12">
                  <h2 className="text-xs font-bold uppercase tracking-[0.3em] text-gray-400 mb-2">Technical Specifications</h2>
                  <h3 className="text-3xl font-medium tracking-tight">Engine Capabilities</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-0">
                  <FeatureItem icon={Cpu} title="Hybrid Analysis" desc="Combines static property extraction with limited, safe dynamic execution paths for behavioral telltales." />
                  <FeatureItem icon={Network} title="Infra Mapping" desc="Recursively pivots on WHOIS, Passive DNS, and SSL certs to cluster related C2 infrastructure." />
                  <FeatureItem icon={Shield} title="The Vault" desc="Artifacts are cryptographically hashed, renamed, and stored in a non-executable, air-gapped volume." />
                  <FeatureItem icon={Zap} title="Rapid Triage" desc="Sub-60 second initial verdict generation using optimized YARA rulesets and heuristic scoring." />
              </div>
          </div>
      </section>
    </div>
  )
}