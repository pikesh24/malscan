"use client"

import { useState } from "react"

type Axis = { key: string; label: string; value: number; description: string }

const CX = 160, CY = 160, R = 112

// Axes sitting at a true value of 0 all collapse to the exact center point —
// with only 1-2 axes carrying signal, the "polygon" through several
// coincident center points plus a couple of outliers renders as a spike
// instead of a shape. A small minimum radius keeps every vertex visible so
// the plot always reads as a closed shape; the value shown on hover is
// never floored, only the rendered position is.
const RADIUS_FLOOR = 0.14

function point(i: number, total: number, radius: number) {
    const angle = -Math.PI / 2 + i * ((2 * Math.PI) / total)
    return { x: CX + radius * Math.cos(angle), y: CY + radius * Math.sin(angle) }
}

function valueRadius(value: number) {
    const clamped = Math.max(0, Math.min(100, value)) / 100
    return (RADIUS_FLOOR + clamped * (1 - RADIUS_FLOOR)) * R
}

// `tone` keeps the plot in the same palette as the rest of the report: drawing
// a Clear result in alarm orange made an artifact with no risk at all look like
// risk on every axis. `measured` is false when the scan could not complete —
// every axis is then 0 for want of an answer, not because the answer was low,
// and a filled shape would assert five measurements nobody took.
export default function RiskRadar({ axes, tone = "#FF3B00", measured = true }: { axes: Axis[]; tone?: string; measured?: boolean }) {
    const [hovered, setHovered] = useState<number | null>(null)

    if (!axes || axes.length === 0) return null
    const n = axes.length

    // Straight polygon, deliberately not a smoothed spline: a Catmull-Rom
    // curve through points with very different radii (the common case — one
    // dominant axis, the rest near the floor) can overshoot past its control
    // points and self-intersect into a jumbled star. A straight polygon
    // through radial points can never self-intersect.
    const valuePoints = axes.map((a, i) => point(i, n, valueRadius(a.value)))
    const valuePath = valuePoints.map(p => `${p.x},${p.y}`).join(" ")
    const active = hovered !== null ? axes[hovered] : null

    return (
        <div className="p-4 md:p-5">
            <div className="relative w-full max-w-[380px] mx-auto">
                <svg viewBox="0 0 320 320" className="w-full h-auto overflow-visible">
                    {[0.25, 0.5, 0.75, 1].map(level => {
                        const pts = axes.map((_, i) => point(i, n, level * R))
                        return (
                            <polygon
                                key={level}
                                points={pts.map(p => `${p.x},${p.y}`).join(" ")}
                                fill="none" stroke="#e7e9ec" strokeWidth={1}
                            />
                        )
                    })}
                    {axes.map((_, i) => {
                        const p = point(i, n, R)
                        return <line key={i} x1={CX} y1={CY} x2={p.x} y2={p.y} stroke="#e7e9ec" strokeWidth={1} />
                    })}

                    {measured && (
                        <>
                            <polygon
                                points={valuePath}
                                fill={tone} fillOpacity={0.18} stroke={tone} strokeWidth={2.5} strokeLinejoin="round"
                                className="transition-all duration-700"
                            />
                            {valuePoints.map((p, i) => (
                                <circle
                                    key={i} cx={p.x} cy={p.y}
                                    r={hovered === i ? 5.5 : 4}
                                    fill={tone} stroke="white" strokeWidth={1.5}
                                    className="transition-all"
                                />
                            ))}
                        </>
                    )}

                    {axes.map((a, i) => {
                        const lp = point(i, n, R + 40)
                        const words = a.label.split(" ")
                        return (
                            <g
                                key={a.key}
                                onMouseEnter={() => setHovered(i)}
                                onMouseLeave={() => setHovered(null)}
                                className="cursor-default"
                            >
                                <circle cx={lp.x} cy={lp.y} r={28} fill="transparent" />
                                <text
                                    x={lp.x} y={lp.y - ((words.length - 1) * 5)}
                                    textAnchor="middle"
                                    fontSize={8.5}
                                    fontFamily="ui-monospace, monospace"
                                    fontWeight={hovered === i ? 700 : 600}
                                    fill={hovered === i ? tone : "#4b5563"}
                                    className="uppercase select-none transition-colors"
                                >
                                    {words.map((word, wi) => (
                                        <tspan key={wi} x={lp.x} dy={wi === 0 ? 0 : 10}>{word}</tspan>
                                    ))}
                                </text>
                            </g>
                        )
                    })}
                </svg>
            </div>
            <div className="mt-3 pt-3 border-t border-gray-100 min-h-[54px]">
                {!measured ? (
                    <p className="text-[10px] font-mono text-gray-500 leading-relaxed text-center pt-1">
                        Not measured — the scan could not complete. An empty plot here means
                        no answer was obtained, not that every axis came back low.
                    </p>
                ) : active ? (
                    <div className="pl-3 border-l-2 transition-colors" style={{ borderLeftColor: tone }}>
                        <div className="flex items-center justify-between mb-1">
                            <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: tone }}>{active.label}</span>
                            <span className="text-[10px] font-mono font-bold text-gray-700">{active.value}/100</span>
                        </div>
                        <p className="text-[10px] font-mono text-gray-500 leading-relaxed">{active.description}</p>
                    </div>
                ) : (
                    <p className="text-[9px] font-mono text-gray-400 uppercase tracking-wider text-center pt-1">Hover an axis for details</p>
                )}
            </div>
        </div>
    )
}
