/** Agent console (thin view; the agent service is its BFF, D35). M11.
 *  Discovery/catalog view of reachable services. A production-shaped reference
 *  view: it is not built by the demo (the runnable surface is
 *  demo/public/index.html); it illustrates how a real agent console consumes
 *  the catalog. */
import { useEffect, useState } from "react";

// Mirror the catalog's CatalogService shape. The earlier local copy read only
// display_name + connections[0].status, dropping the binding type, categories,
// tags, and the request-access link.
interface Connection {
  profile: string;
  type: string;
  status: string;
  authorization_server: string;
}
interface Service {
  id: string;
  display_name: string;
  type: string;
  endpoint: string;
  categories?: string[];
  tags?: string[];
  links?: Array<{ rel: string; href: string }>;
  connections: Connection[];
}

type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: T };

const api = <T,>(p: string): Promise<T> =>
  fetch(`/agent${p}`, { credentials: "include" }).then((r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json() as Promise<T>;
  });

/** Connection status -> badge tone (@spec svc-connectivity-disco). */
const TONE: Record<string, string> = {
  connected: "ok",
  available: "warn",
  pending: "warn",
  unavailable: "bad",
};

export function App() {
  const [state, setState] = useState<Load<Service[]>>({ status: "loading" });

  useEffect(() => {
    api<{ services?: Service[] }>("/catalog?type=mcp")
      .then((c) => setState({ status: "ready", data: c.services ?? [] }))
      .catch((e) => setState({ status: "error", error: String(e.message ?? e) }));
  }, []);

  return (
    <main className="mb">
      <style>{CSS}</style>
      <header>
        <h1>Reachable services</h1>
        <span className="sub">agent console</span>
      </header>

      {state.status === "loading" && <p className="note">Discovering services…</p>}
      {state.status === "error" && <p className="note bad">Couldn’t load the catalog: {state.error}</p>}
      {state.status === "ready" && state.data.length === 0 && <p className="note">No reachable services.</p>}
      {state.status === "ready" &&
        state.data.map((s) => {
          const conn = s.connections[0];
          const request = s.links?.find((l) => /request|access/.test(l.rel));
          const hasTags = !!(s.categories?.length || s.tags?.length);
          return (
            <article key={s.id} className="card">
              <div className="row">
                <b>{s.display_name}</b>
                <span className="ver">{s.type}</span>
              </div>
              <div className="meta">
                {conn ? (
                  <>
                    binding <code>{conn.type}</code> ·{" "}
                    <span className={`badge ${TONE[conn.status] ?? "muted"}`}>{conn.status}</span>
                  </>
                ) : (
                  "no connection"
                )}
              </div>
              {hasTags && (
                <div className="tags">
                  {s.categories?.map((c) => (
                    <span key={c} className="tag">
                      {c}
                    </span>
                  ))}
                  {s.tags?.map((t) => (
                    <span key={t} className="tag">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
              {request && conn?.status !== "connected" && (
                <div className="req">
                  <a className="link" href={request.href}>
                    Request access →
                  </a>
                </div>
              )}
            </article>
          );
        })}
    </main>
  );
}

const CSS = `
:root{--bg:#fff;--fg:#1a1a2e;--muted:#6b6b80;--card:#f6f6fb;--border:#e4e4ef;--accent:#7c3aed;--ok:#178a4c;--warn:#b7791f;--bad:#c02b3a}
@media (prefers-color-scheme:dark){:root{--bg:#111119;--fg:#e9e9f2;--muted:#9a9ab2;--card:#1b1b27;--border:#2b2b3c;--accent:#a78bfa;--ok:#43c17a;--warn:#e0a84a;--bad:#f2647a}}
*{box-sizing:border-box}
.mb{max-width:680px;margin:0 auto;padding:2rem 1.25rem;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);min-height:100vh}
.mb header{display:flex;align-items:baseline;gap:.6rem;border-bottom:1px solid var(--border);padding-bottom:.6rem;margin-bottom:1.25rem}
.mb h1{font-size:1.35rem;margin:0}
.sub{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
.note{color:var(--muted);padding:.75rem 0}
.note.bad{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:.85rem 1rem;margin-bottom:.7rem}
.row{display:flex;align-items:center;gap:.6rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:color-mix(in srgb,var(--fg) 8%,transparent);padding:.05rem .35rem;border-radius:5px;font-size:.82em}
.badge{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em;padding:.15rem .5rem;border-radius:999px;color:#fff}
.badge.ok{background:var(--ok)}.badge.warn{background:var(--warn)}.badge.bad{background:var(--bad)}.badge.muted{background:var(--muted)}
.ver{margin-left:auto;color:var(--muted);font-size:.8rem}
.meta{color:var(--muted);margin:.5rem 0;font-size:.9rem}
.tags{display:flex;gap:.35rem;flex-wrap:wrap;margin-top:.4rem}
.tag{font-size:.72rem;color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:.1rem .5rem}
.req{margin-top:.5rem}
.link{background:none;border:none;color:var(--accent);cursor:pointer;padding:0;font:inherit;font-size:.85rem;text-decoration:none}
.link:hover{text-decoration:underline}
`;
