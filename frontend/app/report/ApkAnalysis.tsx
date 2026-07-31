"use client"

import { useState, useRef } from "react"
import { motion } from "framer-motion"
import { Smartphone, AlertCircle } from "lucide-react"
import { getPermissionInfo, categorizePermissions, RISK_COLORS, RISK_BADGE } from "../../lib/android-permissions"

interface ApkAnalysisProps {
  apkInfo: {
    package?: string
    app_label?: string
    dangerous_permissions?: string[]
    permissions?: string[]
    is_apk?: boolean
  }
}

export default function ApkAnalysis({ apkInfo }: ApkAnalysisProps) {
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null)

  if (!apkInfo?.is_apk || (!apkInfo.package && !apkInfo.app_label && !apkInfo.dangerous_permissions?.length && !apkInfo.permissions?.length)) {
    return null
  }

  const allPermissions = [...(apkInfo.permissions || []), ...(apkInfo.dangerous_permissions || [])]
  const uniquePermissions = Array.from(new Set(allPermissions))
  const categorized = categorizePermissions(uniquePermissions)
  const dangerousSet = new Set(apkInfo.dangerous_permissions || [])


  return (
    <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.22 }} className="bg-white border border-gray-200 shadow-sm rounded-lg overflow-visible print:break-inside-avoid print:shadow-none">
      {/* Header */}
      <div className="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
        <h3 className="text-xs font-bold tracking-[0.2em] uppercase flex items-center gap-2">
          <Smartphone size={14} /> Android APK Analysis
        </h3>
        {apkInfo.dangerous_permissions?.length > 0 && (
          <span className="text-[9px] bg-red-900 text-red-300 px-2 py-1 font-mono uppercase tracking-widest rounded-sm flex items-center gap-1">
            <AlertCircle size={12} />
            {apkInfo.dangerous_permissions.length} High Risk
          </span>
        )}
      </div>

      <div className="p-4 space-y-4 relative">
        {/* App Info */}
        {(apkInfo.package || apkInfo.app_label) && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-[10px] bg-gray-50 p-3 rounded-md border border-gray-100">
            {apkInfo.app_label && (
              <div className="min-w-0">
                <span className="text-gray-500 uppercase text-[9px] block mb-1">App Name</span>
                <span className="text-gray-800 font-semibold block truncate" title={apkInfo.app_label}>
                  {apkInfo.app_label}
                </span>
              </div>
            )}
            {apkInfo.package && (
              <div className="min-w-0">
                <span className="text-gray-500 uppercase text-[9px] block mb-1">Package ID</span>
                <span className="text-gray-700 block truncate text-[9px]" title={apkInfo.package}>
                  {apkInfo.package}
                </span>
              </div>
            )}
          </div>
        )}

        {/* Permissions by Category */}
        {uniquePermissions.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-[10px] font-bold uppercase tracking-widest text-gray-700">
                Permissions ({uniquePermissions.length})
              </h4>
            </div>

            {Object.entries(categorized)
              .sort(([catA], [catB]) => {
                const hasHighRiskA = categorized[catA].some((p) => dangerousSet.has(p))
                const hasHighRiskB = categorized[catB].some((p) => dangerousSet.has(p))
                if (hasHighRiskA !== hasHighRiskB) return hasHighRiskB ? 1 : -1
                return catA.localeCompare(catB)
              })
              .map(([category, perms]) => {
                const hasHighRisk = perms.some((p) => dangerousSet.has(p))
                const isExpanded = expandedCategory === category

                return (
                  <div key={category} className="border border-gray-150 rounded-lg overflow-hidden bg-gray-50/50">
                    <button
                      onClick={() => setExpandedCategory(isExpanded ? null : category)}
                      className="w-full p-3 flex items-center justify-between hover:bg-gray-100 transition-colors text-left"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-[10px] font-bold uppercase tracking-widest text-gray-700">{category}</span>
                        <span className="text-[9px] text-gray-500">({perms.length})</span>
                        {hasHighRisk && (
                          <span className="text-[8px] bg-red-100 text-red-700 px-1.5 py-0.5 rounded-sm font-bold">
                            HIGH RISK
                          </span>
                        )}
                      </div>
                      <span className="text-gray-400 transition-transform" style={{ transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)" }}>
                        ▼
                      </span>
                    </button>

                    {isExpanded && (
                      <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="border-t border-gray-200 bg-white px-3 py-2 space-y-1.5 overflow-visible">
                        {perms.map((perm) => {
                          const info = getPermissionInfo(perm)
                          const isHigh = dangerousSet.has(perm)
                          const riskLevel = isHigh ? "high" : info.riskLevel
                          const Icon = info.icon

                          return (
                            <div key={perm} className="relative">
                              <div className={`p-2.5 rounded-md border ${RISK_COLORS[riskLevel]}`}>
                                <div className="flex items-start gap-2 mb-1.5">
                                  <Icon size={12} className="mt-0.5 shrink-0" />
                                  <div className="min-w-0 flex-1">
                                    <div className="text-[10px] font-bold">{info.name}</div>
                                  </div>
                                </div>
                                <p className="text-[8px] leading-snug opacity-90 pl-6">
                                  {info.description}
                                </p>
                              </div>
                            </div>
                          )
                        })}
                      </motion.div>
                    )}
                  </div>
                )
              })}
          </div>
        )}

        {/* Risk Summary */}
        {apkInfo.dangerous_permissions && apkInfo.dangerous_permissions.length > 0 && (
          <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
            <p className="text-[9px] text-red-700 font-semibold mb-2">⚠ High-Risk Permissions Detected</p>
            <p className="text-[8px] text-red-600 leading-relaxed">
              This app has {apkInfo.dangerous_permissions.length} dangerous permission{apkInfo.dangerous_permissions.length > 1 ? "s" : ""}. Hover over each permission to see what it can do. Legitimate apps rarely need all of these.
            </p>
          </div>
        )}
      </div>
    </motion.div>
  )
}
