/** Operator console (thin view over @mission/console-bff). M11.
 *  Fleet dashboard + the verified evidence timeline (D32). A production-shaped
 *  reference view: it is not built by the demo (the runnable surface is
 *  demo/public/index.html); it illustrates how a real operator console consumes
 *  the BFF. */
import { useEffect, useState } from "react";

// Mirror console-bff's FleetRow / TimelineRow exactly. The earlier local copies
// dropped version, approver, predecessor (lineage) and the evidence digest.
interface FleetRow {
  id: string;
  state: string;
  version: number;
  subject: string;
  approver: string;
  predecessor?: string;
}
interface TimelineRow {
  producer: string;
  evidence_type: string;
  digest: string;
  verified: boolean;
  detail?: string;
}

type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: T };

const api = <T,>(p: string, init?: RequestInit): Promise<T> =>
  fetch(`/bff${p}`, { credentials: "include", ...init }).then((r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json() as Promise<T>;
  });

/** Map a mission state to a badge tone (@spec status#legal-transitions). */
const STATE_TONE: Record<string, string> = {
  active: "ok",
  completed: "ok",
  suspended: "warn",
  revoked: "bad",
  expired: "bad",
  cascaded: "bad",
  superseded: "muted",
};

export function App() {
  const [fleet, setFleet] = useState<Load<FleetRow[]>>({ status: "loading" });
  const [selected, setSelected] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<Load<TimelineRow[]>>({ status: "loading" });

  useEffect(() => {
    api<FleetRow[]>("/operator/fleet")
      .then((data) => setFleet({ status: "ready", data }))
      .catch((e) => setFleet({ status: "error", error: String(e.message ?? e) }));
  }, []);

  const openTimeline = (id: string) => {
    setSelected(id);
    setTimeline({ status: "loading" });
    api<TimelineRow[]>(`/operator/missions/${id}/timeline`)
      .then((data) => setTimeline({ status: "ready", data }))
      .catch((e) => setTimeline({ status: "error", error: String(e.message ?? e) }));
  };

  return (
    <main className="mb">
      <style>{CSS}</style>
      <header>
        <h1>Mission fleet</h1>
        <span className="sub">operator console</span>
      </header>

      {fleet.status === "loading" && <p className="note">Loading fleet…</p>}
      {fleet.status === "error" && <p className="note bad">Couldn’t load the fleet: {fleet.error}</p>}
      {fleet.status === "ready" && fleet.data.length === 0 && <p className="note">No missions.</p>}
      {fleet.status === "ready" &&
        fleet.data.map((m) => (
          <article key={m.id} className={`card${selected === m.id ? " sel" : ""}`}>
            <div className="row">
              <code className="id">{m.id}</code>
              <span className={`badge ${STATE_TONE[m.state] ?? "muted"}`}>{m.state}</span>
              <span className="ver">v{m.version}</span>
            </div>
            <div className="meta">
              subject <b>{m.subject}</b> · approved by <b>{m.approver}</b>
              {m.predecessor && (
                <>
                  {" · succeeds "}
                  <code>{m.predecessor}</code>
                </>
              )}
            </div>
            <button type="button" className="link" onClick={() => openTimeline(m.id)}>
              Evidence timeline →
            </button>
          </article>
        ))}

      {selected && (
        <section className="timeline">
          <h2>
            Evidence timeline <code>{selected}</code>
          </h2>
          {timeline.status === "loading" && <p className="note">Verifying feed…</p>}
          {timeline.status === "error" && <p className="note bad">Couldn’t load the timeline: {timeline.error}</p>}
          {timeline.status === "ready" && timeline.data.length === 0 && <p className="note">No evidence yet.</p>}
          {timeline.status === "ready" &&
            timeline.data.map((r, i) => (
              <div key={r.digest || i} className={`ev ${r.verified ? "ok" : "bad"}`}>
                <span className="dot" />
                <div>
                  <div className="ev-h">
                    <b>{r.evidence_type}</b> from {r.producer}
                  </div>
                  <div className="ev-d">
                    {r.verified ? "verified" : `FAILED: ${r.detail ?? "unverified"}`}
                    {r.digest && (
                      <>
                        {" · "}
                        <code className="dig">{r.digest.slice(0, 20)}…</code>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}
        </section>
      )}
    </main>
  );
}

const CSS = `
:root{--bg:#fff;--fg:#1a1a2e;--muted:#6b6b80;--card:#f6f6fb;--border:#e4e4ef;--accent:#0d9488;--ok:#178a4c;--warn:#b7791f;--bad:#c02b3a}
@media (prefers-color-scheme:dark){:root{--bg:#111119;--fg:#e9e9f2;--muted:#9a9ab2;--card:#1b1b27;--border:#2b2b3c;--accent:#2dd4bf;--ok:#43c17a;--warn:#e0a84a;--bad:#f2647a}}
*{box-sizing:border-box}
.mb{max-width:760px;margin:0 auto;padding:2rem 1.25rem;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--fg);background:var(--bg);min-height:100vh}
.mb header{display:flex;align-items:baseline;gap:.6rem;border-bottom:1px solid var(--border);padding-bottom:.6rem;margin-bottom:1.25rem}
.mb h1{font-size:1.35rem;margin:0}
.mb h2{font-size:1rem}
.sub{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.06em}
.note{color:var(--muted);padding:.75rem 0}
.note.bad{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:.85rem 1rem;margin-bottom:.7rem}
.card.sel{border-color:var(--accent)}
.row{display:flex;align-items:center;gap:.6rem}
.id{font-size:.9rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:color-mix(in srgb,var(--fg) 8%,transparent);padding:.05rem .35rem;border-radius:5px;font-size:.82em}
.badge{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em;padding:.15rem .5rem;border-radius:999px;color:#fff}
.badge.ok{background:var(--ok)}.badge.warn{background:var(--warn)}.badge.bad{background:var(--bad)}.badge.muted{background:var(--muted)}
.ver{margin-left:auto;color:var(--muted);font-size:.8rem}
.meta{color:var(--muted);margin:.5rem 0 .4rem;font-size:.9rem}
.link{background:none;border:none;color:var(--accent);cursor:pointer;padding:0;font:inherit;font-size:.85rem}
.link:hover{text-decoration:underline}
.timeline{margin-top:1.5rem}
.ev{display:flex;gap:.6rem;padding:.55rem 0;border-top:1px solid var(--border)}
.ev .dot{width:9px;height:9px;border-radius:50%;margin-top:.4rem;flex:none}
.ev.ok .dot{background:var(--ok)}.ev.bad .dot{background:var(--bad)}
.ev-h{font-size:.9rem}.ev-d{color:var(--muted);font-size:.82rem}
.ev.bad .ev-d{color:var(--bad)}
.dig{font-size:.75em}
`;
