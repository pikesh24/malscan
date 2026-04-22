"use client"

import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'

// Fix for default Leaflet marker icons missing in Next.js
const customIcon = new L.Icon({
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});

export default function GeoMap({ ipData }: { ipData: any[] }) {
    // Default center to world view or the first IP's location
    const defaultCenter: [number, number] = ipData.length > 0 && ipData[0].lat ? [ipData[0].lat, ipData[0].lon] : [20, 0];
    const defaultZoom = ipData.length > 0 ? 3 : 2;

    return (
        <div style={{ height: '350px', width: '100%', zIndex: 0, position: 'relative' }}>
            <MapContainer center={defaultCenter} zoom={defaultZoom} style={{ height: '100%', width: '100%', borderRadius: '0.25rem' }}>
                <TileLayer
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                    url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                />
                {ipData.map((ip, index) => {
                    if (ip.lat && ip.lon) {
                        return (
                            <Marker key={index} position={[ip.lat, ip.lon]} icon={customIcon}>
                                <Popup>
                                    <div className="font-mono text-xs">
                                        <div className="font-bold border-b border-gray-200 pb-1 mb-1">IP: {ip.ip}</div>
                                        {ip.country && <div>Country: {ip.country}</div>}
                                        {ip.isp && <div>ISP: {ip.isp}</div>}
                                        {ip.asn && <div>ASN: {ip.asn}</div>}
                                    </div>
                                </Popup>
                            </Marker>
                        )
                    }
                    return null;
                })}
            </MapContainer>
        </div>
    )
}
