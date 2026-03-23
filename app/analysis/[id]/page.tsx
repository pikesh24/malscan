"use client"

import { useState, useEffect, use } from "react"
import { useRouter } from "next/navigation"
import { motion } from "framer-motion"

// --- BACKGROUND PLACEHOLDER ---
const BackgroundMedia = () => (
  <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
    <div className="absolute inset-0 bg-[#121212] opacity-90"></div>
    <div className="absolute inset-0 opacity-20" 
         style={{ backgroundImage: 'linear-gradient(rgba(255,59,0,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,59,0,0.1) 1px, transparent 1px)', backgroundSize: '30px 30px' }}>
    </div>
  </div>
)

const TelemetryBlock = ({ label, value, color = "text-white" }: {label:string, value:string, color?:string}) => (
    <div className="mb-6 font-mono">
        <div className="text-[9px] text-gray-500 tracking-widest uppercase mb-1">{label}</div>
        <div className={`text-lg ${color}`}>{value}</div>
        <div className="w-full h-px bg-[#333] mt-2 relative overflow-hidden">
            <div className="absolute inset-0 bg-[#FF3B00] w-1/2 animate-pulse opacity-50"></div>
        </div>
    </div>
)

export default function AnalysisPage({ params }: { params: Promise<{ id: string }> }) {
  const router = useRouter()
  // 1. Unwrap params safely
  const resolvedParams = use(params)
  
  const [progress, setProgress] = useState(0)
  const [realStatus, setRealStatus] = useState("SUBMITTED")
  const steps = [
    "ALLOCATING_ISOLATED_SANDBOX", "MOUNTING_ARTIFACT_VOLUME", "CALCULATING_HASHES (SHA256/MD5)",
    "PE_HEADER_PARSING", "STRING_EXTRACTION & OBFUSCATION_CHECK", "YARA_RULE_MATCHING (v2024.01)",
    "API_IMPORT_RECONSTRUCTION", "QUERYING_PASSIVE_DNS_CLUSTERS", "GENERATING_FINAL_VERDICT"
  ]
  const [currentStep, setCurrentStep] = useState(0)

  // 2. LOGIC FIX: Only update the number here
  // 2. Real Polling mixed with visual progression
  useEffect(() => {
    let targetProgress = 10;
    
    // Fake the visual progress bar crawling towards the target step
    const visualInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= targetProgress) return targetProgress
        return prev + 0.8
      })
    }, 50)

    if (resolvedParams.id.includes('demo')) {
       targetProgress = 100;
       return () => clearInterval(visualInterval)
    }

    // Real API polling
    const pollInterval = setInterval(async () => {
        try {
            const res = await fetch(`/api/status/${resolvedParams.id}`)
            if (res.ok) {
                const data = await res.json()
                if (data.status === 'Completed' || data.status === 'Failed') {
                    setRealStatus(data.status === 'Failed' ? 'FAILED' : 'FINALIZING')
                    targetProgress = 100;
                } else if (data.status === 'Processing') {
                    setRealStatus('PROCESSING')
                    targetProgress = 60;
                } else if (data.status === 'Submitted') {
                    setRealStatus('QUEUED')
                    targetProgress = 20;
                }
            }
        } catch (e) {
            // Ignore for robust polling
        }
    }, 2000)

    return () => {
        clearInterval(visualInterval)
        clearInterval(pollInterval)
    }
  }, [resolvedParams.id])

  // 3. LOGIC FIX: Watch progress for navigation
  useEffect(() => {
    if (progress === 100) {
      router.push(`/report/${resolvedParams.id}`)
    }
  }, [progress, router, resolvedParams.id])

  // Update current step text based on progress
  useEffect(() => {
    setCurrentStep(Math.min(Math.floor((progress / 100) * steps.length), steps.length - 1))
  }, [progress, steps.length])

  return (
    <div className="h-screen bg-[#0A0A0A] text-white font-mono flex relative overflow-hidden">
      <BackgroundMedia />
      
      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col justify-center items-center relative z-10 border-r border-[#222]">
        <div className="w-full max-w-2xl px-6">
            <div className="flex justify-between items-end mb-8">
                <div>
                  <h2 className="text-xs font-bold tracking-widest text-[#666]">JOB ID</h2>
                  <p className="text-2xl text-[#FF3B00]">{resolvedParams.id.toUpperCase()}</p>
                </div>
                <div className="text-right"><h2 className="text-xs font-bold tracking-widest text-[#666]">STATUS</h2><p className="text-lg animate-pulse">{realStatus}</p></div>
            </div>
            <div className="w-full h-2 bg-[#222] mb-12 relative overflow-hidden border border-[#333]">
                <motion.div className="absolute top-0 left-0 h-full bg-[#FF3B00]" style={{ width: `${progress}%` }} transition={{ ease: "linear" }} />
            </div>
            <div className="space-y-2 h-64 overflow-y-auto border border-[#333] p-4 bg-[#000]/50 backdrop-blur-sm">
                {steps.map((step, i) => (
                    <motion.div key={step} initial={{ opacity: 0, x: -10 }} animate={{ opacity: i === currentStep ? 1 : 0.4, x: 0, color: i === currentStep ? "#FFF" : "#666" }} className="flex items-center gap-3 text-xs tracking-wider">
                        <span className="w-4 text-[#FF3B00]">{i === currentStep ? ">" : i < currentStep ? "✓" : ""}</span><span>{step}</span>{i === currentStep && <span className="animate-blink">_</span>}
                    </motion.div>
                ))}
            </div>
        </div>
      </div>

      {/* RIGHT SIDEBAR - LIVE TELEMETRY */}
      <div className="w-80 bg-[#121212] border-l border-[#222] relative z-10 p-6 hidden lg:block">
          <h3 className="text-xs font-bold tracking-[0.2em] text-[#FF3B00] mb-8 uppercase border-b border-[#333] pb-2">Live Telemetry</h3>
          <TelemetryBlock label="CPU Load (Sandbox)" value="84% / 4 Cores" />
          <TelemetryBlock label="Memory Usage" value="1.2GB / 4GB" />
          <TelemetryBlock label="Network I/O" value="↑ 12kbps ↓ 450kbps" color="text-[#FF3B00]" />
          <TelemetryBlock label="Active Threads" value="142" />
          <div className="mt-12 p-4 border border-[#333] bg-[#0A0A0A]">
              <div className="text-[9px] text-gray-500 tracking-widest uppercase mb-2">Engine Log</div>
              <div className="text-[10px] text-gray-400 space-y-1">
                  <p>[14:20:01] Spawning microVM...</p>
                  <p>[14:20:03] Injecting hooks...</p>
                  <p className="text-[#FF3B00]">[14:20:05] Anti-VM detected (CPUID)</p>
              </div>
          </div>
      </div>
    </div>
  )
}