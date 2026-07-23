/** Operator console (thin view over @mission/console-bff). M11.
 *  Fleet dashboard + lifecycle + the verified evidence timeline (D32). */
import { useEffect, useState } from "react";

interface FleetRow { id: string; state: string; subject: string }
interface TimelineRow { producer: string; evidence_type: string; verified: boolean; detail?: string }
const api = (p: string, init?: RequestInit) =>
  fetch(`/bff${p}`, { credentials: "include", ...init }).then((r) => r.json());

export function App() {
  const [fleet, setFleet] = useState<FleetRow[]>([]);
  const [timeline, setTimeline] = useState<TimelineRow[]>([]);
  useEffect(() => { api("/operator/fleet").then(setFleet); }, []);
  return (
    <main>
      <h1>Mission fleet</h1>
      {fleet.map((m) => (
        <div key={m.id}>
          {m.id} [{m.state}] {m.subject}
          <button onClick={() => api(`/operator/missions/${m.id}/timeline`).then(setTimeline)}>Timeline</button>
        </div>
      ))}
      <h2>Evidence timeline</h2>
      {timeline.map((r, i) => (
        <div key={i} style={{ color: r.verified ? "green" : "red" }}>
          {r.evidence_type} from {r.producer} — {r.verified ? "verified" : `FAILED: ${r.detail}`}
        </div>
      ))}
    </main>
  );
}
