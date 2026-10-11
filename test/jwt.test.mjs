// Offline test of the Access JWT check: signs tokens with a local RSA key and
// serves its JWK from a mocked certs endpoint. Run: node test/jwt.test.mjs
import assert from "node:assert/strict";
import worker from "../src/index.js";

const TEAM = "example.cloudflareaccess.com";
const AUD = "test-aud-123";
const kp = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"]);
const jwk = { ...(await crypto.subtle.exportKey("jwk", kp.publicKey)), kid: "k1" };
let certFetches = 0;
globalThis.fetch = async (u) => {
  assert.equal(String(u), `https://${TEAM}/cdn-cgi/access/certs`);
  certFetches++;
  return new Response(JSON.stringify({ keys: [jwk] }));
};
const b64u = (b) => Buffer.from(b).toString("base64url");
async function sign(payload, header = { alg: "RS256", kid: "k1", typ: "JWT" }, key = kp.privateKey) {
  const data = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(data));
  return `${data}.${b64u(new Uint8Array(sig))}`;
}
const now = Math.floor(Date.now() / 1000);
const good = { aud: [AUD], iss: `https://${TEAM}`, exp: now + 300, iat: now, email: "heb@example.com" };
const env = { TEAM_DOMAIN: TEAM, POLICY_AUD: AUD, DROP: null };
const call = async (token, e = env, host = "bot-drop.x.workers.dev") => {
  const h = token ? { "Cf-Access-Jwt-Assertion": token } : {};
  const r = await worker.fetch(new Request(`https://${host}/api/health`, { headers: h }), e);
  return [r.status, await r.text()];
};

let [s, b] = await call(await sign(good));
assert.equal(s, 200, b); assert.match(b, /heb@example.com/);
[s, b] = await call(await sign({ ...good, email: undefined, common_name: "abc.access" }));
assert.equal(s, 200, b); assert.match(b, /service:abc.access/);
assert.equal((await call(null))[0], 403);
assert.equal((await call(await sign({ ...good, aud: ["other"] })))[0], 403);
assert.equal((await call(await sign({ ...good, iss: "https://evil.cloudflareaccess.com" })))[0], 403);
assert.equal((await call(await sign({ ...good, exp: now - 3600 })))[0], 403);
assert.equal((await call(await sign(good, { alg: "HS256", kid: "k1" })))[0], 403);
const other = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
assert.equal((await call(await sign(good, undefined, other.privateKey)))[0], 403);
const t = await sign(good); assert.equal((await call(t.slice(0, -4) + "AAAA"))[0], 403);
// Unconfigured -> 503; DEV_SKIP_ACCESS ignored off-localhost.
assert.equal((await call(await sign(good), { DROP: null }))[0], 503);
assert.equal((await call(null, { DROP: null, DEV_SKIP_ACCESS: "1" }))[0], 503);
assert.equal((await call(null, { DROP: null, DEV_SKIP_ACCESS: "1" }, "localhost:8787"))[0], 200);
// TEAM_DOMAIN given with scheme/trailing slash still works.
assert.equal((await call(await sign(good), { ...env, TEAM_DOMAIN: `https://${TEAM}/` }))[0], 200);
console.log(`jwt tests passed (cert fetches: ${certFetches})`);
