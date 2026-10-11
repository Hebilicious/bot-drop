# bot-drop

A private drop box for reports made by Heb's Grok Bots. Bots upload files
(mostly self-contained HTML reports, up to 25 MB) over an API; Heb opens a
web page to browse and view them over https.

It is one Cloudflare Worker plus one R2 bucket, with Cloudflare Access in
front. No database, no build step, no runtime dependencies.

## How it works

```
 bot ──(CF-Access-Client-Id/Secret)──┐
                                     ▼
 Heb ──(email login)──► Cloudflare Access ──(Cf-Access-Jwt-Assertion)──► Worker ──► R2 bucket "bot-drop"
```

* **Cloudflare Access** guards the whole `bot-drop.<account>.workers.dev`
  hostname. Heb logs in with his email; bots send an Access service token.
* **The Worker** checks the Access JWT again (RS256, signing keys from
  `https://<TEAM_DOMAIN>/cdn-cgi/access/certs`, `aud` must equal
  `POLICY_AUD`, `iss` must equal `https://<TEAM_DOMAIN>`). If `TEAM_DOMAIN`
  or `POLICY_AUD` is not set, every request gets `503 Access not configured`,
  so a half-configured deploy fails closed.
* **R2** stores each file at `<bot>/<YYYY-MM-DD>/<HHMMSS>-<name>` (UTC) with
  its content type and metadata: `bot`, `uploadedAt`, `originalName`,
  `uploader` (the Access email or service-token id) and, for HTML, `title`
  taken from `<title>`.

## Endpoints

| Method | Path | What it does |
| --- | --- | --- |
| `POST` | `/api/upload?bot=<name>&name=<filename>` | Upload a file as the raw body, or as multipart field `file` (then `name` is optional). Max 25 MB. Returns `201 {key, size, contentType, title, url, viewUrl}`. |
| `GET` | `/api/list?bot=&prefix=&limit=` | JSON list, newest first. `prefix` is relative to the bot when `bot` is set (e.g. `bot=grocery-scout&prefix=2026-10`). `limit` defaults to 200 (max 5000). |
| `GET` | `/api/files/<key>` | JSON metadata for one file. |
| `DELETE` | `/api/files/<key>` | Delete a file. |
| `GET` | `/api/health` | `{ok, identity, time}`. Also handy for checking a token. |
| `GET` | `/` | Index page: newest first, grouped by date, filter by bot (`/?bot=...`). Shows title, bot, time and size. |
| `GET` | `/v/<key>` | Viewer page: a header (title, bot, time, open raw, download, delete) above the file in a sandboxed iframe. This is `viewUrl`. |
| `GET` | `/f/<key>` | The file itself, inline with its content type. Add `?download=1` to download it. This is `url`. |

Names are cleaned up: `bot` becomes lowercase `[a-z0-9._-]`, filenames keep
`[A-Za-z0-9._-]`. If the same bot uploads the same name in the same second,
a random 6-hex suffix keeps both files.

The index groups by the `DISPLAY_TZ` date (default `Asia/Bangkok`), while
keys use the UTC date, so files uploaded between 00:00 and 07:00 Bangkok time
appear under that Bangkok day but have the previous UTC day in their key.

### Why reports can't call the API

Everything under `/f/` is served with this header:

```
Content-Security-Policy: sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads;
  default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval' https: data: blob:;
  style-src 'unsafe-inline' https: data:; img-src https: data: blob:; font-src https: data:;
  media-src https: data: blob:; connect-src 'none'; form-action 'none'; frame-src https: data: blob:; base-uri 'none'
```

* The `sandbox` directive is used **without** `allow-same-origin`. The report
  gets an opaque origin, so its JavaScript runs but can't read cookies or
  storage for this host, and can't read responses from `/api`. This applies
  even when someone opens `/f/...` directly in a tab, not only in the viewer's
  iframe.
* `connect-src 'none'` and `form-action 'none'` block fetch, XHR,
  WebSockets, beacons and form posts, so a report can't call anything,
  including the API.
* The Worker also refuses any non-GET request whose `Origin` header is not
  this site's own origin (sandboxed pages send `Origin: null`), which covers
  write requests (upload/delete) even if a policy were loosened later.
* What still works: inline `<style>` and `<script>`, `data:`/`blob:` images
  and fonts, images/fonts/scripts from https CDNs, `alert`/`confirm`, links
  that open in a new tab, and downloads. What doesn't: a report that fetches
  its own data at runtime. Reports should be self-contained.
* SVG and other active formats get the same header, plus
  `X-Content-Type-Options: nosniff`.

## Setup

You need a Cloudflare account with Zero Trust turned on (the free plan is
fine), plus Node.js 22 or newer.

### 1. Install and log in

```sh
npm install
npx wrangler login
```

### 2. Create the R2 bucket

```sh
npx wrangler r2 bucket create bot-drop
```

### 3. Deploy

```sh
npx wrangler deploy
```

This prints the URL, `https://bot-drop.<account-subdomain>.workers.dev`.
Until steps 4 and 5 are done, every request gets `503 Access not configured`.

### 4. Put Cloudflare Access in front of it

1. **Turn on Access for the workers.dev URL.** In the dashboard go to
   *Workers & Pages → bot-drop → Settings → Domains & Routes*. On the
   `workers.dev` row choose *Enable Cloudflare Access*. This creates an
   Access application for `bot-drop.<account-subdomain>.workers.dev`.
   (Preview URLs are turned off in `wrangler.jsonc`, so no other hostname
   is exposed.)
2. **Allow Heb's email.** In *Zero Trust → Access → Applications →
   bot-drop → Policies*, edit or add a policy: Action **Allow**, Include
   **Emails** = Heb's address. Remove any wider rule the one-click setup
   added if it isn't what you want. One-time PIN login works by default;
   Google login is optional.
3. **Create a service token for the bots.** In *Zero Trust → Access →
   Service credentials → Service Tokens → Create service token* (for example
   `grok-bots`). Copy the **Client ID** and **Client Secret** right away,
   because the secret is shown only once. Choose an expiry (or none) and
   remember to rotate it.
4. **Let the token in.** On the bot-drop application add a second policy:
   Action **Service Auth**, Include **Service Token** = `grok-bots`. It has
   to be *Service Auth*. An *Allow* policy would send the bots to the login
   page.
5. **Collect two values:**
   * **Team domain**: *Zero Trust → Settings → Custom pages* (or the team
     name in Settings), e.g. `heb.cloudflareaccess.com`.
   * **Application Audience (AUD) tag**: *Zero Trust → Access →
     Applications → bot-drop → Overview / Basic information*.

### 5. Tell the Worker about Access

These are stored as Worker secrets, so they stay out of the repo and survive
redeploys:

```sh
npx wrangler secret put TEAM_DOMAIN   # e.g. heb.cloudflareaccess.com
npx wrangler secret put POLICY_AUD    # the AUD tag
```

### 6. Check it

```sh
# No credentials: Access should block this (302 to the login page or 403).
curl -si https://bot-drop.<account-subdomain>.workers.dev/api/health | head -1

# With the service token: 200 and identity "service:<client id>".
curl -s https://bot-drop.<account-subdomain>.workers.dev/api/health \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET"
```

Then open the URL in a browser, log in with the email, and you should see
the index.

## Uploading from a bot

```sh
export BOT_DROP_URL=https://bot-drop.<account-subdomain>.workers.dev
export CF_ACCESS_CLIENT_ID=...       # from step 4.3
export CF_ACCESS_CLIENT_SECRET=...

scripts/drop.sh grocery-scout reports/2026-10-11.html
```

Or use curl directly:

```sh
curl -sS --fail-with-body -X POST \
  -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" \
  -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" \
  --data-binary @report.html \
  "$BOT_DROP_URL/api/upload?bot=grocery-scout&name=report.html"
```

```json
{
  "key": "grocery-scout/2026-10-11/091223-report.html",
  "size": 498596,
  "contentType": "text/html; charset=utf-8",
  "title": "Beef deals – 11 Oct 2026",
  "url": "https://bot-drop.<account-subdomain>.workers.dev/f/grocery-scout/2026-10-11/091223-report.html",
  "viewUrl": "https://bot-drop.<account-subdomain>.workers.dev/v/grocery-scout/2026-10-11/091223-report.html"
}
```

Give Heb the `viewUrl`.

## Local development

```sh
cp .dev.vars.example .dev.vars   # sets DEV_SKIP_ACCESS=1
npm run dev                      # wrangler dev --local, R2 is simulated on disk
BOT_DROP_URL=http://localhost:8787 scripts/drop.sh test some.html
npm test                         # offline tests of the JWT check
npm run check                    # wrangler deploy --dry-run --outdir dist
```

`DEV_SKIP_ACCESS=1` turns off the Access check, but only for requests whose
host is `localhost`, `127.0.0.1` or `[::1]`. On a real hostname it does
nothing. Don't set it in production anyway.

## Limits

* 25 MB per file (the Worker reads the body into memory to get the title and
  size; Workers' request body limit on the free plan is 100 MB).
* Listing and the index read up to 5000 objects per view and sort them in
  the Worker. That's plenty for a personal drop box. Past that, add
  pagination or prune old files, e.g. with an R2 lifecycle rule.

## License

MIT, see [LICENSE](LICENSE).
