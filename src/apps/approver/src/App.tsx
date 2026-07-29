/** Approver console (thin view over @mission/console-bff). M11.
 *  Renders the ARAP task queue and adjudicates; sessions/CSRF live in the BFF.
 *  A production-shaped reference view: it is not built by the demo (the runnable
 *  surface is demo/public/index.html); it illustrates how a real approver
 *  console consumes the BFF. */
import { useEffect, useState } from "react";

interface Task {
  id: string;
  mission_id: string;
  action: string;
  subject: string;
}

type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: T };

const api = <T,>(p: string, init?: RequestInit): Promise<T> =>
  fetch(`/bff${p}`, { credentials: "include", ...init }).then((r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json() as Promise<T>;
  });

export function App() {
  const [queue, setQueue] = useState<Load<Task[]>>({ status: "loading" });
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = () =>
    api<Task[]>("/approver/queue")
      .then((data) => setQueue({ status: "ready", data }))
      .catch((e) => setQueue({ status: "error", error: String(e.message ?? e) }));
  useEffect(() => {
    refresh();
  }, []);

  const decide = async (id: string, decision: "approve" | "deny") => {
    setBusy(id);
    try {
      await api(`/approver/tasks/${id}/adjudicate`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf": window.__csrf ?? "" },
        body: JSON.stringify({ decision }),
      });
      await refresh();
    } catch (e) {
      setQueue({ status: "error", error: String((e as Error).message ?? e) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="mb">
      <style>{CSS}</style>
      <header>
        <h1>Approvals</h1>
        <span className="sub">approver console</span>
      </header>

      {queue.status === "loading" && <p className="note">Loading queue…</p>}
      {queue.status === "error" && <p className="note bad">Couldn’t load the queue: {queue.error}</p>}
      {queue.status === "ready" && queue.data.length === 0 && <p className="note">Nothing pending.</p>}
      {queue.status === "ready" &&
        queue.data.map((t) => (
          <article key={t.id} className="card">
            <div className="row">
              <code className="id">{t.action}</code>
              <span className="ver">mission {t.mission_id}</span>
            </div>
            <div className="meta">
              requested for <b>{t.subject}</b>
            </div>
            <div className="actions">
              <button type="button" className="act primary" disabled={busy === t.id} onClick={() => decide(t.id, "approve")}>
                Approve
              </button>
              <button type="button" className="act" disabled={busy === t.id} onClick={() => decide(t.id, "deny")}>
                Deny
              </button>
            </div>
          </article>
        ))}
    </main>
  );
}

const CSS = `
:root{--bg:#fff;--fg:#1a1a2e;--muted:#6b6b80;--card:#f6f6fb;--border:#e4e4ef;--accent:#4f46e5}
@media (prefers-color-scheme:dark){:root{--bg:#111119;--fg:#e9e9f2;--muted:#9a9ab2;--card:#1b1b27;--border:#2b2b3c;--accent:#8b85f0}}
*{box-sizing:border-box}
.mb{max-width:640px;margin:0 auto;padding:2rem 1.25rem;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);min-height:100vh}
.mb header{display:flex;align-items:baseline;gap:.6rem;border-bottom:1px solid var(--border);padding-bottom:.6rem;margin-bottom:1.25rem}
.mb h1{font-size:1.35rem;margin:0}
.sub{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
.note{color:var(--muted);padding:.75rem 0}
.note.bad{color:#c02b3a}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:.85rem 1rem;margin-bottom:.7rem}
.row{display:flex;align-items:center;gap:.6rem}
.id{font-size:.9rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:color-mix(in srgb,var(--fg) 8%,transparent);padding:.05rem .35rem;border-radius:5px;font-size:.82em}
.ver{margin-left:auto;color:var(--muted);font-size:.8rem}
.meta{color:var(--muted);margin:.5rem 0 .6rem;font-size:.9rem}
.actions{display:flex;gap:.4rem}
.act{font:inherit;font-size:.82rem;border:1px solid var(--border);background:var(--bg);color:var(--fg);border-radius:7px;padding:.3rem .8rem;cursor:pointer}
.act:hover:not(:disabled){border-color:var(--accent)}
.act:disabled{opacity:.5;cursor:default}
.act.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
`;
