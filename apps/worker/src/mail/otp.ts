import { registrableDomain } from "./dnsbl.ts";
import type { ParsedEmail } from "./mime.ts";
import type { AuthResult } from "./spam.ts";

// One-time codes in inbound mail, found once at delivery so every client shows
// the same code for the same site. Two sources, strongest first:
//
// 1. The `OTP-Token` header (draft-goto-otp-token), the sender handing over
//    the code it also prints in the body, bound to the origin it's for:
//
//      OTP-Token: "123456"; origin="https://example.com"
//
//    The draft leaves authentication open, so we require it: the binding is a
//    claim about who the code is for, and an unauthenticated sender could
//    otherwise bind a code to any site it likes. It only counts when DMARC
//    passes and the origin shares the From domain's registrable domain.
// 2. Body heuristics, conservative because a false positive puts a wrong code
//    in somebody's AutoFill bar: the mail has to read like a verification
//    email, and a candidate has to sit next to a code word, alone on its line,
//    or in such a subject.

export interface Otp {
  code: string;
  /** Site the code is for: the bound origin's host, else the sender's domain. */
  domain: string;
  /** Set only when an authenticated `OTP-Token` header bound the code. */
  origin: string | null;
}

export function extractOtp(parsed: ParsedEmail, auth: AuthResult, body: string): Otp | null {
  const fromDomain = parsed.from?.address?.split("@").pop() ?? "";
  const token = otpTokenHeader(parsed);
  if (token && auth.dmarc === "pass") {
    const site = registrableDomain(token.host);
    if (site && site === registrableDomain(fromDomain)) {
      return { code: token.code, domain: token.host, origin: token.origin };
    }
  }
  const code = detectCode(parsed.subject ?? "", body);
  const domain = registrableDomain(fromDomain);
  return code && domain ? { code, domain, origin: null } : null;
}

// Generous for any real code, small enough that a hostile header can't stuff
// the row.
const MAX_CODE = 64;

/** The `OTP-Token` header per draft §3.2, before any trust decision. */
function otpTokenHeader(
  parsed: ParsedEmail,
): { code: string; origin: string; host: string } | null {
  // postal-mime only exposes the top-level header section (body-part headers
  // are ignored, §3.1) and has already unfolded the value (§3.2 step 2).
  const fields = (parsed.headers ?? []).filter((h) => h.key === "otp-token");
  if (fields.length !== 1) return null;
  const item = parseSfItem(fields[0]!.value);
  if (item?.bare.type !== "string") return null;
  const code = item.bare.value;
  if (!code || code.length > MAX_CODE) return null;
  const origin = item.params.get("origin");
  if (origin?.type !== "string") return null;
  const host = canonicalOriginHost(origin.value);
  return host ? { code, origin: origin.value, host } : null;
}

// ─── Body heuristics ────────────────────────────────────────────────────────

// Words that make a mail read like a verification email, English and German.
const KEYWORDS =
  /one[-\s]?time|single[-\s]use|verification|verify|verifizier|security|sicherheitscode|confirm|bestätig|c[oó]digo|authenticat|passcode|pass\s?code|\botp\b|\bpin\b|\bcode\b|zugangscode|einmal|2fa|two[-\s]?factor|log[-\s]?in|sign[-\s]?in|anmeld/gi;

// 4–8 digits (optionally split 3-3 / 4-4), or a 5–8 character uppercase token
// mixing at least one letter and one digit.
const NUM = String.raw`\d{3}[- ]\d{3}|\d{4}[- ]\d{4}|\d{4,8}`;
const ALNUM = String.raw`(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{5,8}`;
const TOKEN = new RegExp(String.raw`\b(?:${NUM}|${ALNUM})\b`, "g");
// A token that is the whole line, bar surrounding spaces/punctuation.
const ISOLATED = new RegExp(String.raw`^[^\p{L}\p{N}]*(?:${NUM}|${ALNUM})[^\p{L}\p{N}]*$`, "u");

// Placeholders and examples, never a real code.
const REJECTED = new Set(["000000", "111111", "123456", "12345678"]);
// How far (in characters) a code word may sit from a candidate.
const WINDOW = 60;

interface Candidate {
  code: string;
  score: number;
}

/** The most likely one-time code in a message, or null. */
export function detectCode(subject: string, body: string): string | null {
  if (subject.search(KEYWORDS) === -1 && body.search(KEYWORDS) === -1) return null;
  let best: Candidate | null = null;
  for (const c of [...candidates(subject, 40), ...candidates(body, 0)]) {
    if (!best || c.score > best.score) best = c;
  }
  return best?.code ?? null;
}

function candidates(text: string, bonus: number): Candidate[] {
  const keywords = [...text.matchAll(KEYWORDS)].map((m) => [m.index, m.index + m[0].length]);

  const out: Candidate[] = [];
  for (const m of text.matchAll(TOKEN)) {
    const start = m.index;
    const end = start + m[0].length;
    const code = m[0].replace(/[- ]/g, "");
    const lineStart = text.lastIndexOf("\n", start) + 1;
    const lineEnd = text.indexOf("\n", end);
    const isolated = ISOLATED.test(
      text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd).trim(),
    );
    if (!plausible(code, isolated)) continue;

    const distance = Math.min(...keywords.map(([k0, k1]) => Math.max(0, k0! - end, start - k1!)));
    if (!isolated && distance > WINDOW) continue;
    out.push({
      code,
      score:
        bonus +
        (isolated ? 30 : 0) +
        Math.max(0, WINDOW - distance / 2) +
        (code.length === 6 ? 20 : 0) +
        (/^\d+$/.test(code) ? 10 : 0),
    });
  }
  return out;
}

function plausible(code: string, isolated: boolean): boolean {
  if (REJECTED.has(code) || new Set(code).size === 1) return false;
  // A recent year reads as a code far too easily, unless it stands alone.
  return isolated || !/^(19|20)\d{2}$/.test(code);
}

// The host of an origin given in its ASCII serialization (RFC 6454 §6.2), or
// null. `URL.origin` reserializes canonically (lowercase, punycode, default
// port dropped, no path), so an exact round-trip is the canonical-form check.
// Only https: a recipient's mail client has no business binding codes to
// `http://localhost` or other loopback-trustworthy origins.
function canonicalOriginHost(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.origin !== value) return null;
  return url.hostname;
}

// ─── RFC 9651 Structured Field Item ─────────────────────────────────────────

type BareItem =
  | { type: "string" | "token" | "bytes" | "display"; value: string }
  | { type: "integer" | "decimal" | "date"; value: number }
  | { type: "boolean"; value: boolean };

interface SfItem {
  bare: BareItem;
  params: Map<string, BareItem>;
}

class SfParser {
  i = 0;
  constructor(readonly s: string) {}

  peek(): string {
    return this.s[this.i] ?? "";
  }

  skipSp(): void {
    while (this.s[this.i] === " ") this.i++;
  }

  // §4.2.3.1
  bareItem(): BareItem | null {
    const c = this.peek();
    if (c === "-" || isDigit(c)) return this.number();
    if (c === '"') return this.string();
    if (c === "*" || isAlpha(c)) return this.token();
    if (c === ":") return this.bytes();
    if (c === "?") return this.boolean();
    if (c === "@") {
      this.i++;
      const n = this.number();
      return n?.type === "integer" ? { type: "date", value: n.value } : null;
    }
    if (c === "%") return this.display();
    return null;
  }

  // §4.2.3.2
  params(): Map<string, BareItem> | null {
    const out = new Map<string, BareItem>();
    while (this.peek() === ";") {
      this.i++;
      this.skipSp();
      const key = this.key();
      if (!key) return null;
      let value: BareItem | null = { type: "boolean", value: true };
      if (this.peek() === "=") {
        this.i++;
        value = this.bareItem();
        if (!value) return null;
      }
      out.set(key, value);
    }
    return out;
  }

  // §4.2.3.3
  key(): string | null {
    const m = /^[a-z*][a-z0-9_\-.*]*/.exec(this.s.slice(this.i));
    if (!m) return null;
    this.i += m[0].length;
    return m[0];
  }

  // §4.2.4
  number(): BareItem | null {
    const m = /^-?(\d+)(?:\.(\d+))?/.exec(this.s.slice(this.i));
    if (!m) return null;
    const [whole, int = "", frac] = m;
    if (frac === undefined) {
      if (int.length > 15) return null;
    } else if (int.length > 12 || frac.length > 3) {
      return null;
    }
    this.i += whole.length;
    return { type: frac === undefined ? "integer" : "decimal", value: Number(whole) };
  }

  // §4.2.5
  string(): BareItem | null {
    this.i++;
    let out = "";
    while (this.i < this.s.length) {
      const c = this.s[this.i++]!;
      if (c === "\\") {
        const next = this.s[this.i++];
        if (next !== '"' && next !== "\\") return null;
        out += next;
      } else if (c === '"') {
        return { type: "string", value: out };
      } else if (c < " " || c > "~") {
        return null;
      } else {
        out += c;
      }
    }
    return null;
  }

  // §4.2.6
  token(): BareItem {
    const m = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*/.exec(this.s.slice(this.i))!;
    this.i += m[0].length;
    return { type: "token", value: m[0] };
  }

  // §4.2.7
  bytes(): BareItem | null {
    const m = /^:([A-Za-z0-9+/=]*):/.exec(this.s.slice(this.i));
    if (!m) return null;
    this.i += m[0].length;
    return { type: "bytes", value: m[1]! };
  }

  // §4.2.8
  boolean(): BareItem | null {
    const v = this.s[this.i + 1];
    if (v !== "0" && v !== "1") return null;
    this.i += 2;
    return { type: "boolean", value: v === "1" };
  }

  // §4.2.10
  display(): BareItem | null {
    if (this.s[this.i + 1] !== '"') return null;
    this.i += 2;
    const bytes: number[] = [];
    while (this.i < this.s.length) {
      const c = this.s[this.i++]!;
      if (c === '"') {
        try {
          const value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
            new Uint8Array(bytes),
          );
          return { type: "display", value };
        } catch {
          return null;
        }
      }
      if (c < " " || c > "~") return null;
      if (c === "%") {
        const hex = this.s.slice(this.i, this.i + 2);
        if (!/^[0-9a-f]{2}$/.test(hex)) return null;
        bytes.push(Number.parseInt(hex, 16));
        this.i += 2;
      } else {
        bytes.push(c.charCodeAt(0));
      }
    }
    return null;
  }
}

/** Parses a Structured Field Item (RFC 9651 §4.2, top-level type "item"). */
export function parseSfItem(value: string): SfItem | null {
  const p = new SfParser(value);
  p.skipSp();
  const bare = p.bareItem();
  if (!bare) return null;
  const params = p.params();
  if (!params) return null;
  p.skipSp();
  return p.i === value.length ? { bare, params } : null;
}

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}

function isAlpha(c: string): boolean {
  return (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");
}
