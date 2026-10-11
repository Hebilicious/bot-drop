// bot-drop: a tiny Cloudflare Worker + R2 drop box for bot-generated reports.
// See README.md for the architecture and the Cloudflare Access setup.

const MAX_BYTES = 25 * 1024 * 1024; // 25 MB
const DEFAULT_TZ = "Asia/Bangkok";

const CONTENT_TYPES = {
  html: "text/html; charset=utf-8",
  htm: "text/html; charset=utf-8",
  txt: "text/plain; charset=utf-8",
  log: "text/plain; charset=utf-8",
  md: "text/markdown; charset=utf-8",
  csv: "text/csv; charset=utf-8",
  tsv: "text/tab-separated-values; charset=utf-8",
  json: "application/json; charset=utf-8",
  xml: "application/xml; charset=utf-8",
  css: "text/css; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  pdf: "application/pdf",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  avif: "image/avif",
  svg: "image/svg+xml",
  ico: "image/x-icon",
  mp3: "audio/mpeg",
  wav: "audio/wav",
  ogg: "audio/ogg",
  m4a: "audio/mp4",
  mp4: "video/mp4",
  webm: "video/webm",
  zip: "application/zip",
  gz: "application/gzip",
  tar: "application/x-tar",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
};

// CSP for everything served from /f/. The `sandbox` directive (without
// allow-same-origin) gives the document an opaque origin, so a report's own
// JavaScript runs but can't read the Access cookie or make credentialed,
// readable requests to /api. connect-src/form-action 'none' block fetch/XHR/
// WebSocket/beacons and form posts outright, so a report can't exfiltrate or
// call anything. Inline CSS/JS, data:/blob: assets and https images/fonts/
// scripts from CDNs still work, which is what self-contained reports need.
const FILE_CSP = [
  "sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads",
  "default-src 'none'",
  "script-src 'unsafe-inline' 'unsafe-eval' https: data: blob:",
  "style-src 'unsafe-inline' https: data:",
  "img-src https: data: blob:",
  "font-src https: data:",
  "media-src https: data: blob:",
  "connect-src 'none'",
  "form-action 'none'",
  "frame-src https: data: blob:",
  "base-uri 'none'",
].join("; ");

// CSP for the app's own pages (index / viewer). Only our inline script/style.
const APP_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline'",
  "style-src 'unsafe-inline'",
  "img-src data:",
  "connect-src 'self'",
  "frame-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err && err.stack ? err.stack : err);
      return json({ error: "internal error" }, 500);
    }
  },
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function handle(request, env) {
  const url = new URL(request.url);

  const identity = await authenticate(request, env, url);
  if (identity instanceof Response) return identity;

  const path = url.pathname;
  const method = request.method;

  // CSRF / sandbox-escape guard: anything that isn't GET/HEAD must come from a
  // client without an Origin (curl, bots) or from this very origin.
  if (method !== "GET" && method !== "HEAD") {
    const origin = request.headers.get("Origin");
    if (origin !== null && origin !== url.origin) {
      return json({ error: "cross-origin request refused" }, 403);
    }
  }

  if (path === "/api/health" && method === "GET") {
    return json({ ok: true, service: "bot-drop", identity: identity.label, time: new Date().toISOString() });
  }
  if (path === "/api/upload" && method === "POST") return upload(request, env, url, identity);
  if (path === "/api/list" && method === "GET") return listApi(env, url);
  if (path.startsWith("/api/files/")) {
    const key = keyFromPath(path, "/api/files/");
    if (method === "DELETE") return deleteFile(env, key);
    if (method === "GET") return fileInfo(env, key, url);
    return json({ error: "method not allowed" }, 405, { Allow: "GET, DELETE" });
  }
  if (path.startsWith("/f/") && (method === "GET" || method === "HEAD")) {
    return serveFile(request, env, keyFromPath(path, "/f/"), url);
  }
  if (path.startsWith("/v/") && method === "GET") {
    return viewerPage(env, keyFromPath(path, "/v/"));
  }
  if (path === "/" && method === "GET") return indexPage(env, url);
  if (path === "/favicon.ico") return new Response(null, { status: 204 });

  return json({ error: "not found" }, 404);
}

// ---------------------------------------------------------------- auth ----

async function authenticate(request, env, url) {
  // Local development only: honoured exclusively when the request is for
  // localhost/127.0.0.1, so setting it in production does nothing.
  const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (env.DEV_SKIP_ACCESS === "1" && localHost) {
    return { label: "dev-local (access check skipped)", email: null, service: null };
  }

  const teamDomain = normaliseTeamDomain(env.TEAM_DOMAIN);
  const aud = (env.POLICY_AUD || "").trim();
  if (!teamDomain || !aud) {
    return new Response("Access not configured", { status: 503, headers: { "Content-Type": "text/plain" } });
  }

  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return unauthorized("missing Cloudflare Access token");

  let payload;
  try {
    payload = await verifyAccessJwt(token, teamDomain, aud);
  } catch (e) {
    return unauthorized(`invalid Cloudflare Access token: ${e.message}`);
  }
  const email = payload.email || null;
  const service = payload.common_name || null; // service tokens carry the client id here
  return { label: email || (service ? `service:${service}` : payload.sub || "unknown"), email, service };
}

function unauthorized(msg) {
  return json({ error: msg }, 403);
}

function normaliseTeamDomain(v) {
  if (!v) return "";
  return v.trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

let certCache = { domain: null, fetchedAt: 0, keys: new Map() };
const CERT_TTL_MS = 60 * 60 * 1000;

async function getKey(teamDomain, kid) {
  const fresh = certCache.domain === teamDomain && Date.now() - certCache.fetchedAt < CERT_TTL_MS;
  if (fresh && certCache.keys.has(kid)) return certCache.keys.get(kid);
  // Unknown kid or stale cache: refetch (handles key rotation).
  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error(`could not fetch Access certs (${res.status})`);
  const body = await res.json();
  const keys = new Map();
  for (const jwk of body.keys || []) {
    if (jwk.kty !== "RSA" || !jwk.kid) continue;
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    keys.set(jwk.kid, key);
  }
  certCache = { domain: teamDomain, fetchedAt: Date.now(), keys };
  return keys.get(kid);
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

export async function verifyAccessJwt(token, teamDomain, aud) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed");
  const header = b64urlJson(parts[0]);
  if (header.alg !== "RS256") throw new Error("unexpected alg");
  const key = await getKey(teamDomain, header.kid);
  if (!key) throw new Error("unknown signing key");
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!ok) throw new Error("bad signature");
  const payload = b64urlJson(parts[1]);
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;
  if (typeof payload.exp !== "number" || payload.exp < now - skew) throw new Error("expired");
  if (typeof payload.nbf === "number" && payload.nbf > now + skew) throw new Error("not yet valid");
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) throw new Error("wrong audience");
  if (payload.iss !== `https://${teamDomain}`) throw new Error("wrong issuer");
  return payload;
}

// -------------------------------------------------------------- upload ----

function sanitizeBot(raw) {
  const s = (raw || "").toLowerCase().trim().replace(/[^a-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 64);
  return s;
}

function sanitizeName(raw) {
  let s = (raw || "").split(/[\\/]/).pop().trim();
  s = s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/-{2,}/g, "-").replace(/^[-.]+/, "");
  if (s.length > 120) {
    const dot = s.lastIndexOf(".");
    const ext = dot > 0 && s.length - dot <= 10 ? s.slice(dot) : "";
    s = s.slice(0, 120 - ext.length) + ext;
  }
  return s || "upload.bin";
}

function extOf(name) {
  const dot = name.lastIndexOf(".");
  return dot >= 0 ? name.slice(dot + 1).toLowerCase() : "";
}

function contentTypeFor(name) {
  return CONTENT_TYPES[extOf(name)] || "application/octet-stream";
}

function isHtml(ct) {
  return ct.startsWith("text/html");
}

function decodeEntities(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&");
}

function extractTitle(bytes) {
  const head = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 256 * 1024));
  const m = head.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return "";
  return decodeEntities(m[1]).replace(/\s+/g, " ").trim().slice(0, 300);
}

function pad(n, w = 2) {
  return String(n).padStart(w, "0");
}

async function upload(request, env, url, identity) {
  const declared = Number(request.headers.get("Content-Length") || "0");
  if (declared > MAX_BYTES) throw new HttpError(413, `file too large (max ${MAX_BYTES} bytes)`);

  const bot = sanitizeBot(url.searchParams.get("bot"));
  if (!bot) throw new HttpError(400, "missing or invalid ?bot=");

  let nameParam = url.searchParams.get("name");
  let bytes;
  const reqCt = (request.headers.get("Content-Type") || "").toLowerCase();
  if (reqCt.startsWith("multipart/form-data")) {
    const form = await request.formData();
    const file = form.get("file");
    if (!file || typeof file === "string") throw new HttpError(400, "multipart upload needs a 'file' field");
    bytes = new Uint8Array(await file.arrayBuffer());
    if (!nameParam) nameParam = file.name;
  } else {
    bytes = new Uint8Array(await request.arrayBuffer());
  }
  if (bytes.byteLength === 0) throw new HttpError(400, "empty body");
  if (bytes.byteLength > MAX_BYTES) throw new HttpError(413, `file too large (max ${MAX_BYTES} bytes)`);
  if (!nameParam) throw new HttpError(400, "missing ?name=");

  const name = sanitizeName(nameParam);
  const contentType = contentTypeFor(name);
  const now = new Date();
  const date = `${now.getUTCFullYear()}-${pad(now.getUTCMonth() + 1)}-${pad(now.getUTCDate())}`;
  const hms = `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;

  let key = `${bot}/${date}/${hms}-${name}`;
  if (await env.DROP.head(key)) {
    // Same bot, same name, same second: keep both.
    const rand = crypto.getRandomValues(new Uint8Array(3));
    const suffix = [...rand].map((b) => b.toString(16).padStart(2, "0")).join("");
    key = `${bot}/${date}/${hms}-${suffix}-${name}`;
  }

  const customMetadata = {
    bot,
    uploadedAt: now.toISOString(),
    originalName: name,
    uploader: identity.label.slice(0, 200),
  };
  if (isHtml(contentType)) {
    const title = extractTitle(bytes);
    if (title) customMetadata.title = title;
  }

  await env.DROP.put(key, bytes, {
    httpMetadata: { contentType },
    customMetadata,
  });

  return json(
    {
      key,
      size: bytes.byteLength,
      contentType,
      title: customMetadata.title || null,
      url: `${url.origin}/f/${encodeKey(key)}`,
      viewUrl: `${url.origin}/v/${encodeKey(key)}`,
    },
    201,
  );
}

// ---------------------------------------------------------------- list ----

function encodeKey(key) {
  return key.split("/").map(encodeURIComponent).join("/");
}

function keyFromPath(path, prefix) {
  const raw = path.slice(prefix.length);
  let key;
  try {
    key = raw.split("/").map(decodeURIComponent).join("/");
  } catch {
    throw new HttpError(400, "bad key encoding");
  }
  if (!key || key.split("/").some((seg) => seg === "" || seg === "." || seg === "..")) {
    throw new HttpError(400, "bad key");
  }
  return key;
}

function describe(obj, origin) {
  const m = obj.customMetadata || {};
  return {
    key: obj.key,
    bot: m.bot || obj.key.split("/")[0],
    title: m.title || null,
    name: m.originalName || obj.key.split("/").pop(),
    size: obj.size,
    contentType: (obj.httpMetadata && obj.httpMetadata.contentType) || null,
    uploadedAt: m.uploadedAt || obj.uploaded.toISOString(),
    uploader: m.uploader || null,
    url: `${origin}/f/${encodeKey(obj.key)}`,
    viewUrl: `${origin}/v/${encodeKey(obj.key)}`,
  };
}

async function listObjects(env, { prefix, max }) {
  const out = [];
  let cursor;
  do {
    const page = await env.DROP.list({
      prefix: prefix || undefined,
      cursor,
      limit: Math.min(1000, max - out.length),
      include: ["httpMetadata", "customMetadata"],
    });
    out.push(...page.objects);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor && out.length < max);
  return { objects: out, truncated: Boolean(cursor) };
}

async function listBots(env) {
  const bots = [];
  let cursor;
  do {
    const page = await env.DROP.list({ delimiter: "/", cursor, limit: 1000 });
    for (const p of page.delimitedPrefixes) bots.push(p.replace(/\/$/, ""));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return bots.sort();
}

function buildPrefix(url) {
  const bot = url.searchParams.get("bot");
  const prefix = url.searchParams.get("prefix") || "";
  if (bot) {
    const b = sanitizeBot(bot);
    if (!b) throw new HttpError(400, "invalid bot");
    return `${b}/${prefix}`;
  }
  return prefix;
}

async function listApi(env, url) {
  const limit = Math.max(1, Math.min(5000, Number(url.searchParams.get("limit")) || 200));
  const prefix = buildPrefix(url);
  // R2 lists in key order; we fetch then sort newest first. For a personal
  // drop box this is fine up to a few thousand objects per prefix.
  const { objects, truncated } = await listObjects(env, { prefix, max: 5000 });
  const files = objects
    .map((o) => describe(o, url.origin))
    .sort((a, b) => (a.uploadedAt < b.uploadedAt ? 1 : -1))
    .slice(0, limit);
  return json({ prefix, count: files.length, truncated: truncated || objects.length > limit, files });
}

async function fileInfo(env, key, url) {
  const obj = await env.DROP.head(key);
  if (!obj) return json({ error: "not found" }, 404);
  return json(describe(obj, url.origin));
}

async function deleteFile(env, key) {
  const obj = await env.DROP.head(key);
  if (!obj) return json({ error: "not found" }, 404);
  await env.DROP.delete(key);
  return json({ deleted: key });
}

// --------------------------------------------------------------- serve ----

async function serveFile(request, env, key, url) {
  const obj = request.method === "HEAD" ? await env.DROP.head(key) : await env.DROP.get(key);
  if (!obj) return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });
  const ct = (obj.httpMetadata && obj.httpMetadata.contentType) || contentTypeFor(key);
  const filename = key.split("/").pop();
  const download = url.searchParams.has("download");
  const headers = new Headers({
    "Content-Type": ct,
    "Content-Length": String(obj.size),
    "Content-Security-Policy": FILE_CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "private, max-age=300",
    ETag: obj.httpEtag,
    "Content-Disposition": `${download ? "attachment" : "inline"}; filename="${filename.replace(/"/g, "")}"`,
  });
  return new Response(request.method === "HEAD" ? null : obj.body, { headers });
}

// ---------------------------------------------------------------- html ----

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function zoneParts(iso, tz) {
  const d = new Date(iso);
  const f = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hour12: false,
  });
  const p = Object.fromEntries(f.formatToParts(d).map((x) => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour === "24" ? "00" : p.hour}:${p.minute}` };
}

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": APP_CSP,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "no-store",
    },
  });
}

const STYLE = `
:root{color-scheme:light dark;--fg:#1d1d1f;--mut:#6e6e73;--bg:#fafafa;--card:#fff;--bd:#e3e3e8;--acc:#0a66c2}
@media (prefers-color-scheme:dark){:root{--fg:#ececf1;--mut:#9a9aa3;--bg:#141416;--card:#1d1d20;--bd:#2c2c31;--acc:#5aa9ff}}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:14px 20px;border-bottom:1px solid var(--bd);background:var(--card);position:sticky;top:0}
header h1{font-size:18px;margin:0 12px 0 0}a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
main{max-width:980px;margin:0 auto;padding:12px 20px 40px}h2{font-size:14px;color:var(--mut);margin:22px 0 6px;text-transform:uppercase;letter-spacing:.04em}
.chip{display:inline-block;padding:3px 10px;border:1px solid var(--bd);border-radius:999px;font-size:13px;color:var(--fg)}.chip.on{background:var(--acc);border-color:var(--acc);color:#fff}
ul{list-style:none;margin:0;padding:0;background:var(--card);border:1px solid var(--bd);border-radius:10px}
li{display:flex;gap:12px;align-items:baseline;padding:9px 14px;border-top:1px solid var(--bd)}li:first-child{border-top:0}
.t{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.m{color:var(--mut);font-size:13px;white-space:nowrap}
.empty{color:var(--mut);padding:40px 0;text-align:center}
`;

async function indexPage(env, url) {
  const tz = env.DISPLAY_TZ || DEFAULT_TZ;
  const botFilter = url.searchParams.get("bot") ? sanitizeBot(url.searchParams.get("bot")) : "";
  const [bots, { objects, truncated }] = await Promise.all([
    listBots(env),
    listObjects(env, { prefix: botFilter ? `${botFilter}/` : "", max: 5000 }),
  ]);
  const files = objects.map((o) => describe(o, url.origin)).sort((a, b) => (a.uploadedAt < b.uploadedAt ? 1 : -1));

  const groups = new Map();
  for (const f of files) {
    const { date, time } = zoneParts(f.uploadedAt, tz);
    if (!groups.has(date)) groups.set(date, []);
    groups.get(date).push({ ...f, time });
  }

  const chips = [`<a class="chip${botFilter ? "" : " on"}" href="/">all</a>`]
    .concat(bots.map((b) => `<a class="chip${b === botFilter ? " on" : ""}" href="/?bot=${encodeURIComponent(b)}">${esc(b)}</a>`))
    .join(" ");

  let body = "";
  for (const [date, list] of groups) {
    body += `<h2>${esc(date)}</h2><ul>`;
    for (const f of list) {
      const label = f.title || f.name;
      body += `<li><span class="m">${esc(f.time)}</span><a class="t" href="/v/${esc(encodeKey(f.key))}" title="${esc(f.key)}">${esc(label)}</a>` +
        `<a class="m" href="/?bot=${encodeURIComponent(f.bot)}">${esc(f.bot)}</a><span class="m">${esc(fmtSize(f.size))}</span></li>`;
    }
    body += `</ul>`;
  }
  if (!files.length) body = `<p class="empty">Nothing here yet.</p>`;
  if (truncated) body += `<p class="m">Showing the first 5000 objects only.</p>`;

  return htmlResponse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>bot-drop${botFilter ? ` · ${esc(botFilter)}` : ""}</title><style>${STYLE}</style></head><body>
<header><h1><a href="/">bot-drop</a></h1>${chips}<span class="m" style="margin-left:auto">${files.length} file${files.length === 1 ? "" : "s"} · times ${esc(tz)}</span></header>
<main>${body}</main></body></html>`);
}

async function viewerPage(env, key) {
  const obj = await env.DROP.head(key);
  if (!obj) return htmlResponse(`<!doctype html><meta charset="utf-8"><title>Not found</title><p>Not found. <a href="/">Back</a></p>`, 404);
  const tz = env.DISPLAY_TZ || DEFAULT_TZ;
  const f = describe(obj, "");
  const { date, time } = zoneParts(f.uploadedAt, tz);
  const src = `/f/${encodeKey(key)}`;
  return htmlResponse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(f.title || f.name)} · bot-drop</title><style>${STYLE}
html,body{height:100%}body{display:flex;flex-direction:column}iframe{flex:1;border:0;width:100%;background:#fff}button{font:inherit;color:#c62828;background:none;border:1px solid var(--bd);border-radius:6px;padding:2px 10px;cursor:pointer}</style></head><body>
<header><h1><a href="/">bot-drop</a></h1><span class="t"><b>${esc(f.title || f.name)}</b></span>
<span class="m"><a href="/?bot=${encodeURIComponent(f.bot)}">${esc(f.bot)}</a> · ${esc(date)} ${esc(time)} · ${esc(fmtSize(f.size))}</span>
<a class="m" href="${esc(src)}" target="_blank" rel="noopener">open raw</a><a class="m" href="${esc(src)}?download=1">download</a><button id="del">delete</button></header>
<iframe src="${esc(src)}" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads" referrerpolicy="no-referrer"></iframe>
<script>
document.getElementById('del').onclick = async () => {
  if (!confirm('Delete this file?')) return;
  const r = await fetch(${JSON.stringify(`/api/files/${encodeKey(key)}`)}, { method: 'DELETE' });
  if (r.ok) location.href = '/'; else alert('Delete failed: ' + r.status);
};
</script></body></html>`);
}

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra },
  });
}
