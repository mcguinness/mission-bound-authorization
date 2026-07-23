/** Approver console (thin view over @mission/console-bff). M11.
 *  Renders the ARAP task queue and adjudicates; sessions/CSRF live in the BFF. */
import { useEffect, useState } from "react";

interface Task { id: string; mission_id: string; action: string; subject: string }
const api = (p: string, init?: RequestInit) =>
  fetch(`/bff${p}`, { credentials: "include", ...init }).then((r) => r.json());

export function App() {
  const [queue, setQueue] = useState<Task[]>([]);
  const refresh = () => api("/approver/queue").then(setQueue);
  useEffect(() => { refresh(); }, []);
  const decide = async (id: string, decision: "approve" | "deny") => {
    await api(`/approver/tasks/${id}/adjudicate`, {
      method: "POST", headers: { "content-type": "application/json", "x-csrf": window.__csrf ?? "" },
      body: JSON.stringify({ decision }),
    });
    refresh();
  };
  return (
    <main>
      <h1>Approvals</h1>
      {queue.length === 0 ? <p>Nothing pending.</p> : queue.map((t) => (
        <div key={t.id}>
          <code>{t.action}</code> for <b>{t.subject}</b> (mission {t.mission_id})
          <button onClick={() => decide(t.id, "approve")}>Approve</button>
          <button onClick={() => decide(t.id, "deny")}>Deny</button>
        </div>
      ))}
    </main>
  );
}
