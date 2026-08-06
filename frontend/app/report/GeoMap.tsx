"use client"

import "leaflet/dist/leaflet.css"
// Static imports, not require(). Leaflet touches `window` at module scope, which
// is why these were deferred — but the only importer loads this file through
// next/dynamic with ssr:false, so it never evaluates on the server and the
// deferral bought nothing.
import L from "leaflet"
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from "react-leaflet"

interface GeoMapProps {
    lat: number | null
    lon: number | null
    city?: string
    region?: string
    country?: string
    countryCode?: string
    isp?: string
    asn?: string
    ips?: string[]
}

// The `mounted` state that used to sit here delayed the first paint by a render
// to avoid a hydration mismatch. next/dynamic({ ssr: false }) already guarantees
// there is no server render to mismatch against, and supplies the loading state
// this branch was duplicating.
export default function GeoMap({ lat, lon, city, region, country, countryCode, isp, asn, ips }: GeoMapProps) {
    if (lat === null || lon === null) {
        return (
            <div className="w-full h-[340px] print:h-auto print:py-10 bg-[#0d1117] print:bg-white flex items-center justify-center font-mono text-xs text-gray-600 print:text-gray-400 tracking-widest">
                NO GEOLOCATION DATA AVAILABLE
            </div>
        )
    }

    return <GeoMapInner lat={lat} lon={lon} city={city} region={region} country={country} countryCode={countryCode} isp={isp} asn={asn} ips={ips} />
}

function GeoMapInner({ lat, lon, city, region, country, countryCode, isp, asn, ips }: GeoMapProps & { lat: number; lon: number }) {

    // Custom red icon for the marker
    const redIcon = new L.DivIcon({
        className: "",
        html: `
            <div style="position:relative;width:24px;height:24px;">
                <div style="position:absolute;inset:0;background:#FF3B00;border-radius:50%;opacity:0.3;animation:ping 1.5s cubic-bezier(0,0,0.2,1) infinite;"></div>
                <div style="position:absolute;inset:4px;background:#FF3B00;border-radius:50%;border:2px solid #0d1117;box-shadow:0 0 12px rgba(255,59,0,0.6);"></div>
            </div>
            <style>@keyframes ping{75%,100%{transform:scale(2.5);opacity:0}}</style>
        `,
        iconSize: [24, 24],
        iconAnchor: [12, 12],
        popupAnchor: [0, -16],
    })

    const locationLabel = [city, region, country].filter(Boolean).join(", ")

    return (
        <div className="w-full">
            {/* Map Area */}
            <div className="relative w-full h-[340px] overflow-hidden z-0">
                <MapContainer
                    center={[lat, lon]}
                    zoom={6}
                    scrollWheelZoom={true}
                    zoomControl={true}
                    style={{ height: "100%", width: "100%", background: "#0d1117" }}
                    attributionControl={false}
                >
                    <TileLayer
                        url="https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png"
                    />

                    {/* Outer pulse rings */}
                    <CircleMarker center={[lat, lon]} radius={40} pathOptions={{ color: "#FF3B00", fillColor: "#FF3B00", fillOpacity: 0.05, weight: 1, opacity: 0.2 }} />
                    <CircleMarker center={[lat, lon]} radius={25} pathOptions={{ color: "#FF3B00", fillColor: "#FF3B00", fillOpacity: 0.08, weight: 1, opacity: 0.3 }} />

                    {/* Main marker */}
                    <Marker position={[lat, lon]} icon={redIcon}>
                        <Popup>
                            <div style={{ fontFamily: "monospace", fontSize: "11px", lineHeight: "1.6", minWidth: "180px" }}>
                                <div style={{ fontWeight: "bold", color: "#FF3B00", marginBottom: "6px", letterSpacing: "0.1em", fontSize: "10px" }}>TARGET LOCATION</div>
                                <div><span style={{ color: "#888" }}>Location:</span> {locationLabel}</div>
                                <div><span style={{ color: "#888" }}>Coords:</span> {lat.toFixed(4)}, {lon.toFixed(4)}</div>
                                {isp && <div><span style={{ color: "#888" }}>ISP:</span> {isp}</div>}
                                {asn && <div><span style={{ color: "#888" }}>ASN:</span> {asn}</div>}
                                {ips && ips.length > 0 && <div><span style={{ color: "#888" }}>IP:</span> {ips[0]}</div>}
                            </div>
                        </Popup>
                    </Marker>
                </MapContainer>

                {/* HUD Overlay - top left */}
                <div className="absolute top-3 left-3 z-[1000] pointer-events-none">
                    <div className="bg-[#0d1117]/80 backdrop-blur-sm border border-gray-800 px-3 py-2 space-y-1">
                        <div className="text-[9px] font-mono text-[#FF3B00] tracking-[0.2em] font-bold">◉ THREAT ORIGIN</div>
                        <div className="text-[10px] font-mono text-gray-300">{locationLabel || "Unknown"}</div>
                        {countryCode && <div className="text-[10px] font-mono text-gray-500">{countryCode}</div>}
                    </div>
                </div>

                {/* HUD Overlay - bottom right coords */}
                <div className="absolute bottom-3 right-3 z-[1000] pointer-events-none">
                    <div className="bg-[#0d1117]/80 backdrop-blur-sm border border-gray-800 px-3 py-2">
                        <div className="text-[9px] font-mono text-gray-500 tracking-wider">{lat.toFixed(4)}°N  {lon.toFixed(4)}°E</div>
                    </div>
                </div>
            </div>

            {/* Info bar below map — the print-reliable replacement for the map itself */}
            <div className="bg-[#0d1117] print:bg-white border-t border-gray-800 print:border-gray-200 px-4 py-3 grid grid-cols-2 md:grid-cols-4 gap-3">
                <div>
                    <div className="text-[8px] font-mono text-gray-500 uppercase tracking-wider mb-0.5">Location</div>
                    <div className="text-[11px] font-mono text-gray-300 print:text-gray-700">{locationLabel || "N/A"}</div>
                </div>
                <div>
                    <div className="text-[8px] font-mono text-gray-500 uppercase tracking-wider mb-0.5">ISP</div>
                    <div className="text-[11px] font-mono text-gray-300 print:text-gray-700 truncate">{isp || "N/A"}</div>
                </div>
                <div>
                    <div className="text-[8px] font-mono text-gray-500 uppercase tracking-wider mb-0.5">ASN</div>
                    <div className="text-[11px] font-mono text-gray-300 print:text-gray-700 truncate">{asn || "N/A"}</div>
                </div>
                <div>
                    <div className="text-[8px] font-mono text-gray-500 uppercase tracking-wider mb-0.5">IP Address</div>
                    <div className="text-[11px] font-mono text-gray-300 print:text-gray-700">{ips?.[0] || "N/A"}</div>
                </div>
            </div>
        </div>
    )
}
