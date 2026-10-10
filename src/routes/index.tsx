import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  audit, createVault, destroyVault, generatePassword, saveVault, strength, unlockVault, vaultExists,
  type Entry, type Session,
} from "@/lib/vault";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "14x27 Vault — Encrypted password manager" },
      { name: "description", content: "Store, generate and audit passwords. AES-256 encrypted on your device." },
      { property: "og:title", content: "14x27 Vault" },
      { property: "og:description", content: "Encrypted, on-device password manager with security audit." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: App,
});

const AUTO_LOCK_MS = 5 * 60 * 1000;
const CATEGORIES = ["Login", "Finance", "Social", "Work", "Other"];

function App() {
  const [ready, setReady] = useState(false);
  const [exists, setExists] = useState(false);
  const [session, setSession] = useState<Session | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);

  useEffect(() => { setExists(vaultExists()); setReady(true); }, []);

  const lock = useCallback(() => { setSession(null); setEntries([]); }, []);

  // auto-lock on inactivity / tab hidden
  useEffect(() => {
    if (!session) return;
    let t = setTimeout(lock, AUTO_LOCK_MS);
    const reset = () => { clearTimeout(t); t = setTimeout(lock, AUTO_LOCK_MS); };
    const vis = () => document.hidden && lock();
    ["pointerdown", "keydown"].forEach((e) => window.addEventListener(e, reset));
    document.addEventListener("visibilitychange", vis);
    return () => {
      clearTimeout(t);
      ["pointerdown", "keydown"].forEach((e) => window.removeEventListener(e, reset));
      document.removeEventListener("visibilitychange", vis);
    };
  }, [session, lock]);

  if (!ready) return null;
  if (!session)
    return (
      <Gate
        exists={exists}
        onOpen={(s, e) => { setSession(s); setEntries(e); setExists(true); }}
        onReset={() => { destroyVault(); setExists(false); }}
      />
    );
  return (
    <Vault
      entries={entries}
      onChange={async (next) => { setEntries(next); await saveVault(session, next); }}
      onLock={lock}
    />
  );
}

function Logo() {
  return (
    <div className="flex items-center gap-2 font-mono text-lg font-semibold">
      <span className="grid h-8 w-8 place-items-center rounded-md bg-primary text-primary-foreground glow">#</span>
      14x27
    </div>
  );
}

function Gate({ exists, onOpen, onReset }: {
  exists: boolean; onOpen: (s: Session, e: Entry[]) => void; onReset: () => void;
}) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const st = strength(pw);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    if (!exists) {
      if (pw.length < 10) return setErr("Use at least 10 characters.");
      if (pw !== confirm) return setErr("Passwords don't match.");
    }
    setBusy(true);
    try {
      if (exists) { const r = await unlockVault(pw); onOpen(r.session, r.entries); }
      else onOpen(await createVault(pw), []);
    } catch { setErr("Wrong master password."); }
    finally { setBusy(false); setPw(""); setConfirm(""); }
  }

  return (
    <main className="grid min-h-screen place-items-center px-4">
      <form onSubmit={submit} className="panel w-full max-w-sm space-y-5 p-7">
        <Logo />
        <div>
          <h1 className="text-2xl font-bold">{exists ? "Unlock your vault" : "Create your vault"}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {exists ? "Enter your master password." : "Your master password encrypts everything. It can't be recovered — don't forget it."}
          </p>
        </div>
        <input autoFocus type="password" className="field font-mono" placeholder="Master password"
          value={pw} onChange={(e) => setPw(e.target.value)} autoComplete={exists ? "current-password" : "new-password"} />
        {!exists && (
          <>
            <Meter pw={pw} />
            <input type="password" className="field font-mono" placeholder="Confirm password"
              value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
            <p className="text-xs text-muted-foreground">Strength: {st.label} · ~{st.bits} bits</p>
          </>
        )}
        {err && <p className="text-sm text-destructive" role="alert">{err}</p>}
        <button className="btn-primary w-full" disabled={busy}>{busy ? "Deriving key…" : exists ? "Unlock" : "Create vault"}</button>
        {exists && (
          <button type="button" className="w-full text-xs text-muted-foreground hover:text-destructive"
            onClick={() => confirm_("Erase the vault on this device? This cannot be undone.") && onReset()}>
            Forgot password? Erase vault
          </button>
        )}
        <p className="text-center font-mono text-[10px] text-muted-foreground">AES-256-GCM · PBKDF2 310k · on-device only</p>
      </form>
    </main>
  );
}
const confirm_ = (m: string) => window.confirm(m);

function Meter({ pw }: { pw: string }) {
  const { score } = strength(pw);
  const color = score < 2 ? "bg-destructive" : score < 3 ? "bg-warning" : "bg-success";
  return (
    <div className="flex gap-1" aria-hidden>
      {[0, 1, 2, 3].map((i) => (
        <div key={i} className={`h-1.5 flex-1 rounded-full ${pw && i < Math.max(1, score) ? color : "bg-muted"}`} />
      ))}
    </div>
  );
}

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const copy = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(id);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => { setCopied(null); navigator.clipboard.writeText("").catch(() => {}); }, 20000);
  };
  return { copied, copy };
}

type Tab = "vault" | "generator" | "audit";

function Vault({ entries, onChange, onLock }: {
  entries: Entry[]; onChange: (e: Entry[]) => Promise<void>; onLock: () => void;
}) {
  const [tab, setTab] = useState<Tab>("vault");
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("All");
  const [editing, setEditing] = useState<Entry | null>(null);
  const { copied, copy } = useCopy();
  const report = useMemo(() => audit(entries), [entries]);

  const list = entries
    .filter((e) => cat === "All" || e.category === cat)
    .filter((e) => `${e.title} ${e.username} ${e.url}`.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));

  const save = async (e: Entry) => {
    const next = entries.some((x) => x.id === e.id) ? entries.map((x) => (x.id === e.id ? e : x)) : [...entries, e];
    await onChange(next); setEditing(null);
  };
  const remove = async (id: string) => { await onChange(entries.filter((e) => e.id !== id)); setEditing(null); };
  const blank = (): Entry => ({ id: crypto.randomUUID(), title: "", username: "", password: generatePassword(20, { upper: true, digits: true, symbols: true }), url: "", notes: "", category: "Login", favorite: false, updatedAt: Date.now() });

  const exportBackup = () => {
    const raw = localStorage.getItem("14x27.vault")!;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([raw], { type: "application/json" }));
    a.download = `14x27-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
  };

  return (
    <div className="mx-auto min-h-screen max-w-3xl px-4 pb-28 pt-6">
      <header className="mb-6 flex items-center justify-between">
        <Logo />
        <div className="flex gap-2">
          <button className="btn-ghost" onClick={exportBackup} title="Download encrypted backup">Backup</button>
          <button className="btn-ghost" onClick={onLock}>Lock</button>
        </div>
      </header>

      {tab === "vault" && (
        <section className="space-y-4">
          <div className="flex gap-2">
            <input className="field" placeholder="Search vault…" value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="btn-primary shrink-0" onClick={() => setEditing(blank())}>+ Add</button>
          </div>
          <div className="flex flex-wrap gap-2">
            {["All", ...CATEGORIES].map((c) => (
              <button key={c} onClick={() => setCat(c)}
                className={`rounded-full px-3 py-1 text-xs font-medium ${cat === c ? "bg-primary text-primary-foreground" : "bg-secondary text-muted-foreground"}`}>{c}</button>
            ))}
          </div>
          {list.length === 0 ? (
            <div className="panel p-10 text-center text-muted-foreground">
              {entries.length ? "No matches." : "Your vault is empty. Add your first password."}
            </div>
          ) : (
            <ul className="space-y-2">
              {list.map((e) => {
                const s = strength(e.password).score;
                return (
                  <li key={e.id} className="panel flex items-center gap-3 p-3">
                    <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-accent font-mono font-semibold uppercase">{e.title[0] ?? "?"}</div>
                    <button className="min-w-0 flex-1 text-left" onClick={() => setEditing(e)}>
                      <p className="truncate font-semibold">{e.favorite && "★ "}{e.title || "Untitled"}</p>
                      <p className="truncate text-xs text-muted-foreground">{e.username || e.url || e.category}</p>
                    </button>
                    <span className={`h-2 w-2 rounded-full ${s < 2 ? "bg-destructive" : s < 3 ? "bg-warning" : "bg-success"}`} title={strength(e.password).label} />
                    {e.username && <button className="btn-ghost px-3 py-1.5 text-xs" onClick={() => copy(e.username, e.id + "u")}>{copied === e.id + "u" ? "✓" : "User"}</button>}
                    <button className="btn-ghost px-3 py-1.5 text-xs" onClick={() => copy(e.password, e.id)}>{copied === e.id ? "Copied" : "Copy"}</button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      )}

      {tab === "generator" && <Generator copy={copy} copied={copied} />}
      {tab === "audit" && <Audit report={report} total={entries.length} onOpen={setEditing} />}

      <nav className="fixed inset-x-0 bottom-0 border-t border-border bg-card/95 backdrop-blur">
        <div className="mx-auto flex max-w-3xl">
          {(["vault", "generator", "audit"] as Tab[]).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`flex-1 py-4 text-sm font-semibold capitalize ${tab === t ? "text-primary" : "text-muted-foreground"}`}>
              {t}{t === "audit" && report.score < 100 && entries.length > 0 ? ` · ${report.score}` : ""}
            </button>
          ))}
        </div>
      </nav>

      {editing && <Editor entry={editing} isNew={!entries.some((x) => x.id === editing.id)} onSave={save} onDelete={remove} onClose={() => setEditing(null)} />}
    </div>
  );
}

function Generator({ copy, copied }: { copy: (t: string, id: string) => void; copied: string | null }) {
  const [len, setLen] = useState(20);
  const [opts, setOpts] = useState({ upper: true, digits: true, symbols: true });
  const [pw, setPw] = useState("");
  useEffect(() => setPw(generatePassword(len, opts)), [len, opts]);
  const s = strength(pw);
  return (
    <section className="panel space-y-5 p-6">
      <h2 className="text-xl font-bold">Password generator</h2>
      <div className="break-all rounded-lg bg-background p-4 font-mono text-lg text-primary">{pw}</div>
      <Meter pw={pw} />
      <p className="text-xs text-muted-foreground">{s.label} · ~{s.bits} bits of entropy</p>
      <label className="block text-sm">Length: <span className="font-mono">{len}</span>
        <input type="range" min={8} max={64} value={len} onChange={(e) => setLen(+e.target.value)} className="mt-2 w-full accent-[var(--primary)]" />
      </label>
      <div className="flex flex-wrap gap-4 text-sm">
        {(["upper", "digits", "symbols"] as const).map((k) => (
          <label key={k} className="flex items-center gap-2 capitalize">
            <input type="checkbox" checked={opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.target.checked })} /> {k}
          </label>
        ))}
      </div>
      <div className="flex gap-2">
        <button className="btn-ghost flex-1" onClick={() => setPw(generatePassword(len, opts))}>Regenerate</button>
        <button className="btn-primary flex-1" onClick={() => copy(pw, "gen")}>{copied === "gen" ? "Copied" : "Copy"}</button>
      </div>
    </section>
  );
}

function Audit({ report, total, onOpen }: { report: ReturnType<typeof audit>; total: number; onOpen: (e: Entry) => void }) {
  const groups: [string, Entry[], string][] = [
    ["Weak passwords", report.weak, "text-destructive"],
    ["Reused passwords", report.reused, "text-warning"],
    ["Older than 6 months", report.old, "text-muted-foreground"],
  ];
  return (
    <section className="space-y-4">
      <div className="panel flex items-center gap-6 p-6">
        <div className="grid h-24 w-24 place-items-center rounded-full border-4 border-primary font-mono text-3xl font-bold glow">{report.score}</div>
        <div>
          <h2 className="text-xl font-bold">Security score</h2>
          <p className="text-sm text-muted-foreground">{total} items checked on-device. Nothing was sent anywhere.</p>
        </div>
      </div>
      {groups.map(([label, items, color]) => (
        <div key={label} className="panel p-4">
          <h3 className={`mb-2 font-semibold ${color}`}>{label} · {items.length}</h3>
          {items.length === 0 ? <p className="text-sm text-muted-foreground">All clear.</p> : (
            <ul className="space-y-1">
              {items.map((e) => (
                <li key={e.id}><button className="text-sm hover:text-primary" onClick={() => onOpen(e)}>{e.title || "Untitled"} →</button></li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </section>
  );
}

function Editor({ entry, isNew, onSave, onDelete, onClose }: {
  entry: Entry; isNew: boolean; onSave: (e: Entry) => void; onDelete: (id: string) => void; onClose: () => void;
}) {
  const [e, setE] = useState(entry);
  const [show, setShow] = useState(false);
  const set = <K extends keyof Entry>(k: K, v: Entry[K]) => setE({ ...e, [k]: v });
  return (
    <div className="fixed inset-0 z-50 grid place-items-end bg-background/80 backdrop-blur-sm sm:place-items-center" onClick={onClose}>
      <form className="panel w-full max-w-lg space-y-3 rounded-b-none p-6 sm:rounded-xl" onClick={(x) => x.stopPropagation()}
        onSubmit={(x) => { x.preventDefault(); if (e.title.trim()) onSave({ ...e, updatedAt: e.password !== entry.password || isNew ? Date.now() : entry.updatedAt }); }}>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold">{isNew ? "New item" : "Edit item"}</h2>
          <button type="button" className="text-xl" onClick={() => set("favorite", !e.favorite)} aria-label="Favorite">{e.favorite ? "★" : "☆"}</button>
        </div>
        <input required className="field" placeholder="Title (e.g. GitHub)" value={e.title} onChange={(x) => set("title", x.target.value)} />
        <input className="field" placeholder="Username or email" value={e.username} onChange={(x) => set("username", x.target.value)} />
        <div className="flex gap-2">
          <input className="field font-mono" type={show ? "text" : "password"} value={e.password} onChange={(x) => set("password", x.target.value)} />
          <button type="button" className="btn-ghost" onClick={() => setShow(!show)}>{show ? "Hide" : "Show"}</button>
          <button type="button" className="btn-ghost" onClick={() => set("password", generatePassword(20, { upper: true, digits: true, symbols: true }))} title="Generate">↻</button>
        </div>
        <Meter pw={e.password} />
        <input className="field" placeholder="Website" value={e.url} onChange={(x) => set("url", x.target.value)} />
        <select className="field" value={e.category} onChange={(x) => set("category", x.target.value)}>
          {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
        </select>
        <textarea className="field" rows={2} placeholder="Notes" value={e.notes} onChange={(x) => set("notes", x.target.value)} />
        <div className="flex gap-2 pt-2">
          {!isNew && <button type="button" className="btn-danger" onClick={() => confirm_("Delete this item?") && onDelete(e.id)}>Delete</button>}
          <button type="button" className="btn-ghost ml-auto" onClick={onClose}>Cancel</button>
          <button className="btn-primary">Save</button>
        </div>
      </form>
    </div>
  );
}
