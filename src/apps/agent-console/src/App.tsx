/** Agent console (thin view; agent service is its BFF, D35). M11.
 *  Discovery/catalog view + scenario runner trigger. */
import { useEffect, useState } from "react";

interface Service { id: string; display_name: string; connections: { status: string }[] }
const api = (p: string) => fetch(`/agent${p}`, { credentials: "include" }).then((r) => r.json());

export function App() {
  const [services, setServices] = useState<Service[]>([]);
  useEffect(() => { api("/catalog?type=mcp").then((c) => setServices(c.services ?? [])); }, []);
  return (
    <main>
      <h1>Reachable services</h1>
      {services.map((s) => (
        <div key={s.id}>{s.display_name} — {s.connections[0]?.status}</div>
      ))}
    </main>
  );
}
