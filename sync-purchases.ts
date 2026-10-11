// =====================================================================
// sync-purchases  -  "Restore purchase".
// Asks Lemon Squeezy (server to server) for subscriptions (and old one-time orders) made with the signed-in user's
// VERIFIED email, checks each one, and switches Premium on or off. Also fixes a missed webhook.
// Body {"portal": true} returns a fresh link to Lemon Squeezy's page where the customer can cancel or change payment.
// =====================================================================
declare const Deno: any;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function corsFor(req: Request, env: any): { ok: boolean; headers: Record<string, string> } {
  const origin = req.headers.get("origin");
  const allowed = String(env.APP_ORIGIN ?? "").split(",").map((s: string) => s.trim()).filter(Boolean);
  const headers: Record<string, string> = {
    vary: "Origin",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, apikey, x-client-info",
    "access-control-max-age": "600",
  };
  if (!origin) return { ok: true, headers };
  if (allowed.includes(origin)) { headers["access-control-allow-origin"] = origin; return { ok: true, headers }; }
  return { ok: false, headers };
}
function reply(status: number, body: any, cors: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...cors } });
}
async function getUser(deps: any, jwt: string): Promise<any | null> {
  const env = deps.env;
  const res = await deps.fetch(`${env.SUPABASE_URL}/auth/v1/user`, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, authorization: `Bearer ${jwt}` },
  });
  if (!res.ok) return null;
  const u = await res.json();
  if (!u || typeof u.id !== "string" || !UUID_RE.test(u.id) || typeof u.email !== "string") return null;
  return u;
}
async function service(deps: any, path: string, init: any = {}): Promise<any> {
  const env = deps.env;
  const res = await deps.fetch(`${env.SUPABASE_URL}${path}`, {
    ...init,
    headers: { "content-type": "application/json", apikey: env.SUPABASE_SERVICE_ROLE_KEY,
               authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`, ...(init.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`database call ${path} failed with status ${res.status}`);
  return await res.json();
}
const rpc = (deps: any, name: string, args: any) =>
  service(deps, `/rest/v1/rpc/${name}`, { method: "POST", body: JSON.stringify(args) });

function planFor(env: any, variantId: any): "monthly" | "yearly" | null {
  const v = String(variantId);
  if (env.LS_VARIANT_MONTHLY && v === String(env.LS_VARIANT_MONTHLY)) return "monthly";
  if (env.LS_VARIANT_YEARLY && v === String(env.LS_VARIANT_YEARLY)) return "yearly";
  return null;
}
function isoOrNull(v: any): string | null {
  if (v === null || v === undefined || v === "") return null;
  const d = new Date(String(v));
  return isNaN(d.getTime()) ? null : d.toISOString();
}
const SUB_STATUSES = ["on_trial", "active", "paused", "past_due", "unpaid", "cancelled", "expired"];
const lsHeaders = (env: any) => ({ accept: "application/vnd.api+json", authorization: `Bearer ${env.LS_API_KEY}` });

export async function handleSync(req: Request, deps: any): Promise<Response> {
  const env = deps.env;
  const cors = corsFor(req, env);
  if (req.method === "OPTIONS") return new Response(null, { status: cors.ok ? 204 : 403, headers: cors.headers });
  if (!cors.ok) return reply(403, { error: "origin not allowed" }, cors.headers);
  if (req.method !== "POST") return reply(405, { error: "method not allowed" }, cors.headers);

  for (const n of ["LS_API_KEY", "LS_STORE_ID", "LS_VARIANT_MONTHLY", "LS_VARIANT_YEARLY", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]) {
    if (!env[n]) { console.error("missing setting: " + n); return reply(500, { error: "server not configured" }, cors.headers); }
  }

  const auth = req.headers.get("authorization") ?? "";
  const jwt = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const user = jwt ? await getUser(deps, jwt) : null;
  if (!user) return reply(401, { error: "please sign in" }, cors.headers);
  if (!user.email_confirmed_at && !user.confirmed_at) return reply(403, { error: "please confirm your email first" }, cors.headers);
  const myEmail = user.email.trim().toLowerCase();

  let wantPortal = false;
  try { wantPortal = (await req.json())?.portal === true; } catch { /* no body */ }

  try {
    if (!(await rpc(deps, "try_sync", { p_user: user.id }))) {
      return reply(429, { error: "please wait a few seconds and try again" }, cors.headers);
    }

    // ---- customer portal link (cancel / update card): only for MY OWN subscription ----
    if (wantPortal) {
      const mine = await service(deps, `/rest/v1/subscriptions?user_id=eq.${user.id}&select=sub_id&order=ls_updated_at.desc&limit=1`);
      const subId = Array.isArray(mine) && mine[0]?.sub_id ? String(mine[0].sub_id) : "";
      if (!/^\d{1,20}$/.test(subId)) return reply(404, { error: "no subscription found" }, cors.headers);
      const pr = await deps.fetch(`https://api.lemonsqueezy.com/v1/subscriptions/${subId}`, { headers: lsHeaders(env) });
      if (!pr.ok) { console.error("Lemon Squeezy subscription error, status " + pr.status); return reply(502, { error: "could not open the subscription page" }, cors.headers); }
      const link = String((await pr.json())?.data?.attributes?.urls?.customer_portal ?? "");
      let host = "";
      try { const u = new URL(link); if (u.protocol === "https:") host = u.hostname; } catch { /* invalid */ }
      if (!host || !(host === "lemonsqueezy.com" || host.endsWith(".lemonsqueezy.com"))) {
        console.error("unexpected portal url host: " + host);
        return reply(502, { error: "could not open the subscription page" }, cors.headers);
      }
      return reply(200, { portalUrl: link }, cors.headers);
    }

    // ---- subscriptions made with MY verified email ----
    let subsChecked = 0;
    {
      const q2 = new URLSearchParams();
      q2.set("filter[store_id]", String(env.LS_STORE_ID));
      q2.set("filter[user_email]", myEmail);
      q2.set("page[size]", "50");
      const sr = await deps.fetch(`https://api.lemonsqueezy.com/v1/subscriptions?${q2.toString()}`, { headers: lsHeaders(env) });
      if (!sr.ok) {
        console.error("Lemon Squeezy subscriptions error, status " + sr.status);
        return reply(502, { error: "could not check purchases right now" }, cors.headers);
      }
      const subs = (await sr.json())?.data ?? [];
      for (const o of Array.isArray(subs) ? subs : []) {
        const a = o?.attributes ?? {};
        if (o?.type !== "subscriptions" || o.id === undefined) continue;
        if (String(a.store_id) !== String(env.LS_STORE_ID)) continue;
        const plan = planFor(env, a.variant_id);
        if (!plan) continue;
        if (env.LS_PRODUCT_ID && String(a.product_id) !== String(env.LS_PRODUCT_ID)) continue;
        const isTest = a.test_mode === true;
        if (isTest && env.LS_TEST_MODE !== "true") continue;
        if (String(a.user_email ?? "").trim().toLowerCase() !== myEmail) continue;      // must be MY email
        if (!SUB_STATUSES.includes(String(a.status))) continue;
        const upd = isoOrNull(a.updated_at);
        if (!upd) continue;
        subsChecked++;
        await rpc(deps, "record_subscription", {
          p_event_key: `sync:${o.id}:${upd}`, p_event_name: "sync", p_sub_id: String(o.id), p_intent_id: null, p_email: myEmail,
          p_status: String(a.status), p_cancelled: a.cancelled === true, p_plan: plan, p_test: isTest, p_store: String(a.store_id),
          p_product: a.product_id !== undefined ? String(a.product_id) : null, p_variant: String(a.variant_id),
          p_renews: isoOrNull(a.renews_at), p_ends: isoOrNull(a.ends_at), p_ls_updated: upd,
        });
      }
    }

    let checked = 0;
    if (env.LS_VARIANT_ID) {
      const qs = new URLSearchParams();
      qs.set("filter[store_id]", String(env.LS_STORE_ID));
      qs.set("filter[user_email]", myEmail);
      qs.set("page[size]", "50");
      const res = await deps.fetch(`https://api.lemonsqueezy.com/v1/orders?${qs.toString()}`, {
        headers: { accept: "application/vnd.api+json", authorization: `Bearer ${env.LS_API_KEY}` },
      });
      if (!res.ok) {
        console.error("Lemon Squeezy orders error, status " + res.status);
        return reply(502, { error: "could not check purchases right now" }, cors.headers);
      }
      const list = (await res.json())?.data ?? [];
      for (const o of Array.isArray(list) ? list : []) {
        const a = o?.attributes ?? {};
        const item = a.first_order_item ?? {};
        const isTest = a.test_mode === true;
        if (o?.type !== "orders" || o.id === undefined) continue;
        if (String(a.store_id) !== String(env.LS_STORE_ID)) continue;
        if (String(item.variant_id) !== String(env.LS_VARIANT_ID)) continue;
        if (env.LS_PRODUCT_ID && String(item.product_id) !== String(env.LS_PRODUCT_ID)) continue;
        if (isTest && env.LS_TEST_MODE !== "true") continue;
        if (String(a.user_email ?? "").trim().toLowerCase() !== myEmail) continue;   // must be MY email
        const common = {
          p_order_id: String(o.id),
          p_order_uuid: a.identifier ? String(a.identifier).slice(0, 80) : null,
          p_email: myEmail, p_test: isTest, p_store: String(a.store_id),
          p_product: item.product_id !== undefined ? String(item.product_id) : null,
          p_variant: String(item.variant_id),
          p_amount: Number.isInteger(a.total) ? a.total : null,
          p_currency: a.currency ? String(a.currency).slice(0, 8) : null,
        };
        checked++;
        if (a.status === "paid") {
          await rpc(deps, "record_paid_order", { p_event_key: `sync:${o.id}`, p_intent_id: null, ...common });
        } else if (a.status === "refunded" || a.status === "fraudulent") {
          await rpc(deps, "record_refund", { p_event_key: `sync-refund:${o.id}`, ...common });
        }
      }

    }
    // also link any order the webhook stored without an account but with this verified email
    await rpc(deps, "link_unclaimed_for", { p_user: user.id });
    const ent = await service(deps, `/rest/v1/entitlements?user_id=eq.${user.id}&select=premium,premium_until`);
    const on = Array.isArray(ent) && ent[0]?.premium === true && (!ent[0].premium_until || new Date(ent[0].premium_until).getTime() > Date.now());
    return reply(200, { premium: on, ordersFound: checked + subsChecked }, cors.headers);
  } catch (e) {
    console.error("sync failed: " + (e as any)?.message);
    return reply(500, { error: "could not check purchases right now" }, cors.headers);
  }
}

if (typeof Deno !== "undefined" && typeof Deno.serve === "function") {
  const names = ["LS_API_KEY", "LS_STORE_ID", "LS_PRODUCT_ID", "LS_VARIANT_ID", "LS_VARIANT_MONTHLY", "LS_VARIANT_YEARLY", "LS_TEST_MODE", "APP_ORIGIN",
                 "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];
  Deno.serve((req: Request) => {
    const env: any = {};
    for (const n of names) env[n] = Deno.env.get(n);
    return handleSync(req, { env, fetch });
  });
}
