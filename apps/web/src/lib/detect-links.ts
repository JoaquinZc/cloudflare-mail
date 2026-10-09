// Detect magic sign-in links and shipment tracking in a message so the reader
// can open them without hunting through the body. Purely client-side and
// heuristic. Nothing is stored. One-time codes are found server-side at
// delivery (`otpCode` on the message), not here.

export interface DetectedLink {
  url: string;
  label: string;
}

export type Carrier = "UPS" | "USPS" | "FedEx" | "DHL";

export interface DetectedTracking {
  // Known carrier when we recognised the number/host; undefined for a generic
  // "track your order" link whose carrier is hidden behind a merchant redirect.
  carrier?: Carrier;
  // The tracking number, when we could read one out of the text/link.
  number?: string;
  // Carrier page to open (built from the number, or the link that was in the mail).
  url: string;
}

export interface Detected {
  links: DetectedLink[];
  tracking: DetectedTracking[];
}

const BEFORE = 60;
const AFTER = 40;

// Magic-link matching is deliberately strict: a sign-in keyword plus an
// auth-looking token (query param or path segment), and never an
// unsubscribe/support/preferences link. Better to miss than to mislabel a
// tracking URL as a login link.
const LINK_TEXT_KW =
  /(sign[-\s]?in|log[-\s]?in|magic|verify|verifizier|confirm|bestätig|activate|aktivier|reset|set (?:up|your) password|anmeld|einlogg)/i;
const LINK_URL_KW =
  /(magic|\/login|signin|sign-in|verify|confirm|activate|passwordless|one-?click|\/auth\/|\/session\/|\/invite\/)/i;
const AUTH_PARAM =
  /[?&](?:token|otp|magic|code|auth|confirmation[_-]?token|verification[_-]?token|login[_-]?token|access[_-]?token|k|key)=[A-Za-z0-9._~+/-]{12,}/i;
const AUTH_PATH =
  /\/(?:magic|login|signin|sign-in|verify|confirm|activate|auth|session|token|passwordless|invite)\/[A-Za-z0-9._~+/-]{16,}/i;
const EXCLUDE_LINK =
  /(unsubscribe|abmeld|opt[-_]?out|preferences|einstellungen|privacy|datenschutz|terms|impressum|\bsupport\b|\bhelp\b|\bhilfe\b|contact|kontakt|list-manage|mailto:)/i;

function isMagicLink(url: string, text: string): boolean {
  if (!/^https:\/\//i.test(url)) return false;
  if (EXCLUDE_LINK.test(url) || EXCLUDE_LINK.test(text)) return false;
  const keyword = LINK_TEXT_KW.test(text) || LINK_URL_KW.test(url);
  return keyword && (AUTH_PARAM.test(url) || AUTH_PATH.test(url));
}

function detectMagicLinks(links: { url: string; text: string }[]): DetectedLink[] {
  const seen = new Set<string>();
  const out: DetectedLink[] = [];
  for (const { url, text } of links) {
    if (seen.has(url) || !isMagicLink(url, text)) continue;
    seen.add(url);
    out.push({ url, label: text && text.length <= 40 ? text : "Sign in" });
    if (out.length >= 2) break;
  }
  return out;
}

// ── Shipment tracking ──────────────────────────────────────────────────────
// Detect carrier tracking numbers / links so the reader can jump straight to
// the tracking page. Keyword-gated and format specific to keep order numbers,
// invoices and phone numbers from matching.

// The message has to read like a shipping notification before we trust a bare
// run of digits (FedEx / USPS labels are otherwise indistinguishable from any
// long number).
const SHIP_KEYWORDS =
  /(track(?:ing)?|shipment|shipped|shipping|deliver|out for delivery|in transit|parcel|package|carrier|courier|way[-\s]?bill|\bawb\b|\bups\b|fedex|\busps\b|\bdhl\b|sendung|paket|versand|zustell|lieferung)/i;

const CARRIER_URL: Record<Carrier, (n: string) => string> = {
  UPS: (n) => `https://www.ups.com/track?loc=en_US&tracknum=${n}`,
  USPS: (n) => `https://tools.usps.com/go/TrackConfirmAction?tLabels=${n}`,
  FedEx: (n) => `https://www.fedex.com/fedextrack/?trknbr=${n}`,
  DHL: (n) => `https://www.dhl.com/en/express/tracking.html?tracking-id=${n}`,
};

// Resolve the carrier for an S10 (UPU) number from its country suffix / prefix.
function s10Carrier(n: string): Carrier {
  if (/US$/i.test(n)) return "USPS";
  if (/^J[DJ]/i.test(n)) return "DHL";
  return "USPS";
}

// Distinctive formats — safe to trust without nearby context.
const STRONG: { carrier: Carrier | ((n: string) => Carrier); re: RegExp }[] = [
  { carrier: "UPS", re: /\b1Z[0-9A-Z]{16}\b/gi },
  { carrier: s10Carrier, re: /\b[A-Z]{2}\d{9}[A-Z]{2}\b/gi },
  { carrier: "USPS", re: /\b(?:9[0-5])\d{18,24}\b/g },
  { carrier: "DHL", re: /\bJJ?D\d{18}\b/gi },
  { carrier: "DHL", re: /\b00340434\d{12}\b/g },
];

// Loose digit runs — only trusted when a tracking word sits right next to them.
// The format alone can't tell FedEx from DHL Paket (both use 12 and 20 digits),
// so the carrier the mail is from / talks about wins over this default.
const WEAK: { carrier: Carrier; re: RegExp }[] = [
  { carrier: "FedEx", re: /\b\d{12}\b|\b\d{15}\b|\b\d{20}\b/g },
  { carrier: "DHL", re: /\b\d{10,11}\b/g },
];

const CARRIER_NAMES: { carrier: Carrier; re: RegExp }[] = [
  { carrier: "UPS", re: /\bups\b/i },
  { carrier: "USPS", re: /\busps\b/i },
  { carrier: "FedEx", re: /\bfedex\b/i },
  { carrier: "DHL", re: /\bdhl\b/i },
];

// The carrier this mail is about: the sender's domain, else the only carrier
// named in it. Undefined when that's ambiguous.
function carrierHint(from: string, hay: string): Carrier | undefined {
  const domain = from.split("@").pop() ?? "";
  const bySender = CARRIER_HOSTS.find((c) => c.host.test(domain));
  if (bySender) return bySender.carrier;
  const named = CARRIER_NAMES.filter((c) => c.re.test(hay));
  return named.length === 1 ? named[0]?.carrier : undefined;
}

const TRACK_CTX = /(track|tracking|awb|waybill|sendung|shipment|parcel|package)/i;
const MAX_TRACKING = 3;

// Carrier tracking links already present in the mail (merchant emails routinely
// embed a "Track your package" carrier link).
const CARRIER_HOSTS: { carrier: Carrier; host: RegExp }[] = [
  { carrier: "UPS", host: /(^|\.)ups\.com$/i },
  { carrier: "USPS", host: /(^|\.)usps\.com$/i },
  { carrier: "FedEx", host: /(^|\.)fedex\.com$/i },
  { carrier: "DHL", host: /(^|\.)dhl\.[a-z.]+$/i },
];
const TRACK_LINK = /track|trknbr|tracknum|tLabels|awb|tracking[-_]?id|verfolg|piececode|idc=/i;
// Pull a number out of a carrier tracking link when it carries one.
const LINK_NUMBER =
  /(?:tracknum|trknbr|tLabels|awb|tracking[-_]?id|qtc_tLabels1|piececode|idc)=([0-9A-Z]{8,35})/i;
// Anchor text of a "track your order / Sendung verfolgen" button. Carrier is
// unknown here (the link is usually a merchant redirect) — we just open it.
const TRACK_TEXT = /(track|trace|verfolg|nachverfolg|sendungsverfolgung)/i;

const carrierOf = (c: Carrier | ((n: string) => Carrier), n: string): Carrier =>
  typeof c === "function" ? c(n) : c;

function detectTracking(
  from: string,
  subject: string,
  text: string,
  links: { url: string; text: string }[],
): DetectedTracking[] {
  const out = new Map<string, DetectedTracking>();
  const add = (carrier: Carrier | undefined, number: string | undefined, url: string) => {
    const key = number ?? url;
    if (!out.has(key)) out.set(key, { carrier, number, url });
  };

  // 1. Explicit carrier tracking links — trustworthy regardless of keywords.
  for (const { url, text: anchor } of links) {
    if (out.size >= MAX_TRACKING) break;
    let host: string;
    try {
      host = new URL(url).hostname;
    } catch {
      continue;
    }
    const hit = CARRIER_HOSTS.find((c) => c.host.test(host));
    if (!hit) continue;
    if (!TRACK_LINK.test(url) && !TRACK_TEXT.test(anchor)) continue;
    add(hit.carrier, url.match(LINK_NUMBER)?.[1], url);
  }

  const hay = `${subject}\n${text}`;
  if (!SHIP_KEYWORDS.test(hay)) return [...out.values()].slice(0, MAX_TRACKING);
  const hint = carrierHint(from, hay);

  // 1b. A "track your order / Sendung verfolgen" button on any host — carrier is
  // hidden behind the merchant's redirect, so we just open the link.
  for (const { url, text: anchor } of links) {
    if (out.size >= MAX_TRACKING) break;
    if (!/^https?:\/\//i.test(url) || out.has(url)) continue;
    if (EXCLUDE_LINK.test(url) || EXCLUDE_LINK.test(anchor)) continue;
    if (!TRACK_TEXT.test(anchor)) continue;
    add(undefined, url.match(LINK_NUMBER)?.[1], url);
  }

  // 2. Distinctive tracking-number formats anywhere in the body.
  for (const { carrier, re } of STRONG) {
    for (const m of hay.matchAll(re)) {
      if (out.size >= MAX_TRACKING) break;
      const n = m[0].toUpperCase();
      add(carrierOf(carrier, n), n, CARRIER_URL[carrierOf(carrier, n)](n));
    }
  }

  // 3. Loose digit runs, only when a tracking word is in the vicinity.
  for (const { carrier, re } of WEAK) {
    for (const m of hay.matchAll(re)) {
      if (out.size >= MAX_TRACKING) break;
      const i = m.index ?? 0;
      const ctx = hay.slice(Math.max(0, i - BEFORE), i + m[0].length + AFTER);
      if (!TRACK_CTX.test(ctx)) continue;
      const n = m[0];
      const c = hint ?? carrier;
      add(c, n, CARRIER_URL[c](n));
    }
  }

  return [...out.values()].slice(0, MAX_TRACKING);
}

const BLOCK = new Set([
  "P",
  "DIV",
  "BR",
  "TR",
  "TD",
  "TH",
  "LI",
  "UL",
  "OL",
  "TABLE",
  "SECTION",
  "HEADER",
  "FOOTER",
  "ARTICLE",
  "BLOCKQUOTE",
  "PRE",
  "H1",
  "H2",
  "H3",
  "H4",
  "H5",
  "H6",
]);

// Extract visible text + anchors from email HTML. Entities are decoded (so
// "&#128153;" becomes 💙, never the number 128153) and block boundaries become
// newlines (so a code in its own <p> stays isolated instead of gluing to
// neighbouring words).
function fromHtml(html: string): { text: string; links: { url: string; text: string }[] } {
  const doc = new DOMParser().parseFromString(html, "text/html");
  const links = [...doc.querySelectorAll("a[href]")].map((a) => ({
    url: a.getAttribute("href") ?? "",
    text: a.textContent?.trim() ?? "",
  }));
  let text = "";
  const walk = (node: Node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 3) {
        text += child.nodeValue ?? "";
      } else if (child.nodeType === 1) {
        const block = BLOCK.has((child as Element).tagName);
        if (block) text += "\n";
        walk(child);
        if (block) text += "\n";
      }
    }
  };
  walk(doc.body ?? doc.documentElement);
  return { text, links };
}

// Decode entities in a plain-text part (some senders leave "&#128153;" in it).
function decodeEntities(s: string): string {
  return new DOMParser().parseFromString(s, "text/html").body?.textContent ?? s;
}

const URL_RE = /https?:\/\/[^\s<>"')]+/gi;

export function detectLinks(input: {
  from?: string | null;
  subject?: string | null;
  text?: string | null;
  html?: string | null;
}): Detected {
  let body: string;
  let links: { url: string; text: string }[] = [];
  if (input.html) {
    const parsed = fromHtml(input.html);
    body = parsed.text;
    links = parsed.links;
  } else {
    body = decodeEntities(input.text ?? "");
    for (const m of body.matchAll(URL_RE)) links.push({ url: m[0], text: "" });
  }
  return {
    links: detectMagicLinks(links),
    tracking: detectTracking(input.from ?? "", input.subject ?? "", body, links),
  };
}
