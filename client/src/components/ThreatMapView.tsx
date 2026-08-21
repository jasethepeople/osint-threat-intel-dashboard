import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";
import { SeverityBadge } from "./threat-ui";

type Observation = {
  id: number;
  label: string;
  latitude: string | number | null;
  longitude: string | number | null;
  confidence: string | number;
  threatId: number;
  title: string;
  cveId: string | null;
  severity: string;
  sourceUrl: string;
};

function markerColor(severity: string) {
  if (severity === "Critical") return "#DC2626";
  if (severity === "High" || severity === "Medium") return "#F59E0B";
  return "#42b883";
}

export default function ThreatMapView({ observations }: { observations: Observation[] }) {
  const safe = observations.filter(observation => observation.latitude !== null && observation.longitude !== null && Number.isFinite(Number(observation.latitude)) && Number.isFinite(Number(observation.longitude)));
  return <div className="h-[500px] overflow-hidden border border-primary/20 bg-black/40">
    <MapContainer center={[25, 10]} zoom={2} minZoom={2} scrollWheelZoom className="h-full w-full" worldCopyJump>
      <TileLayer attribution="&copy; OpenStreetMap contributors &copy; CARTO" url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" />
      {safe.map(observation => <CircleMarker key={observation.id} center={[Number(observation.latitude), Number(observation.longitude)]} radius={Math.max(7, Math.min(17, Math.round(Number(observation.confidence) * 16)))} pathOptions={{ color: markerColor(observation.severity), fillColor: markerColor(observation.severity), fillOpacity: 0.48, weight: 1.5 }}>
        <Popup>
          <div className="min-w-48">
            <p className="mb-1 font-mono text-[10px] uppercase tracking-widest text-[#F59E0B]">{observation.label}</p>
            <p className="font-mono text-xs font-semibold">{observation.cveId ?? "NEWS-DERIVED"}</p>
            <p className="mt-1 font-mono text-xs text-[#ded3bc]">{observation.title}</p>
            <div className="mt-3"><SeverityBadge severity={observation.severity} /></div>
            <a className="mt-3 block font-mono text-[10px] uppercase tracking-wider text-[#F59E0B] hover:underline" href={observation.sourceUrl} target="_blank" rel="noreferrer">Open source →</a>
          </div>
        </Popup>
      </CircleMarker>)}
    </MapContainer>
  </div>;
}
