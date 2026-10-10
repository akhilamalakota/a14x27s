// Client-side encrypted vault: PBKDF2-SHA256 (310k) -> AES-256-GCM. Nothing leaves the device.
export type Entry = {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  category: string;
  favorite: boolean;
  updatedAt: number;
};

type Stored = { v: 1; salt: string; iv: string; data: string; iterations: number };
const KEY = "14x27.vault";
const enc = new TextEncoder();
const dec = new TextDecoder();

const b64 = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b as ArrayBuffer)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(pw: string, salt: Uint8Array, iterations: number) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export type Session = { key: CryptoKey; salt: Uint8Array; iterations: number };

export const vaultExists = () => !!localStorage.getItem(KEY);

export async function createVault(pw: string): Promise<Session> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 310_000;
  const key = await deriveKey(pw, salt, iterations);
  const s = { key, salt, iterations };
  await saveVault(s, []);
  return s;
}

export async function unlockVault(pw: string): Promise<{ session: Session; entries: Entry[] }> {
  const raw = JSON.parse(localStorage.getItem(KEY)!) as Stored;
  const salt = unb64(raw.salt);
  const key = await deriveKey(pw, salt, raw.iterations);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(raw.iv) as BufferSource },
    key,
    unb64(raw.data) as BufferSource,
  );
  return { session: { key, salt, iterations: raw.iterations }, entries: JSON.parse(dec.decode(plain)) };
}

export async function saveVault(s: Session, entries: Entry[]) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    s.key,
    enc.encode(JSON.stringify(entries)),
  );
  const stored: Stored = { v: 1, salt: b64(s.salt), iv: b64(iv), data: b64(data), iterations: s.iterations };
  localStorage.setItem(KEY, JSON.stringify(stored));
}

export const destroyVault = () => localStorage.removeItem(KEY);

export function generatePassword(len: number, opts: { upper: boolean; digits: boolean; symbols: boolean }) {
  let set = "abcdefghijkmnopqrstuvwxyz";
  if (opts.upper) set += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (opts.digits) set += "23456789";
  if (opts.symbols) set += "!@#$%^&*()-_=+[]{};:,.?";
  const out: string[] = [];
  const buf = new Uint32Array(1);
  const limit = Math.floor(0xffffffff / set.length) * set.length;
  while (out.length < len) {
    crypto.getRandomValues(buf);
    const n = buf[0]!;
    if (n < limit) out.push(set.charAt(n % set.length));
  }
  return out.join("");
}

export function strength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string; bits: number } {
  if (!pw) return { score: 0, label: "Empty", bits: 0 };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  let bits = pw.length * Math.log2(pool || 1);
  if (/(.)\1{2,}/.test(pw) || /^(password|1234|qwerty|admin)/i.test(pw)) bits *= 0.5;
  const score = (bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4) as 0 | 1 | 2 | 3 | 4;
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"] as const;
  return { score, label: labels[score], bits: Math.round(bits) };
}

export function audit(entries: Entry[]) {
  const counts = new Map<string, number>();
  entries.forEach((e) => counts.set(e.password, (counts.get(e.password) ?? 0) + 1));
  const weak = entries.filter((e) => strength(e.password).score < 2);
  const reused = entries.filter((e) => (counts.get(e.password) ?? 0) > 1);
  const old = entries.filter((e) => Date.now() - e.updatedAt > 1000 * 60 * 60 * 24 * 180);
  const bad = new Set([...weak, ...reused, ...old].map((e) => e.id)).size;
  const score = entries.length ? Math.round(100 * (1 - bad / entries.length)) : 100;
  return { weak, reused, old, score };
}
