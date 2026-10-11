// =====================================================================
// create-checkout  -  creates a Lemon Squeezy hosted checkout for the SIGNED-IN user.
// The user id comes from the verified login token, never from the request body.
// "Verify JWT" can stay OFF: this function verifies the login itself.
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
  if (!origin) return { ok: true, headers };                       // not a browser (no CORS needed)
  if (allowed.includes(origin)) { headers["access-control-allow-origin"] = origin; return { ok: true, headers }; }
  return { ok: false, headers };
}

function reply(status: number, body: any, cors: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...cors } });
}

// Ask Supabase Auth who this login token belongs to.
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

export async function handleCheckout(req: Request, deps: any): Promise<Response> {
  const env = deps.env;
  const cors = corsFor(req, env);
  if (req.method === "OPTIONS") return new Response(null, { status: cors.ok ? 204 : 403, headers: cors.headers });
  if (!cors.ok) return reply(403, { error: "origin not allowed" }, cors.headers);
  if (req.method !== "POST") return reply(405, { error: "method not allowed" }, cors.headers);

  for (const n of ["LS_API_KEY", "LS_STORE_ID", "LS_VARIANT_MONTHLY", "LS_VARIANT_YEARLY", "APP_URL", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]) {
    if (!env[n]) { console.error("missing setting: " + n); return reply(500, { error: "server not configured" }, cors.headers); }
  }

  // 1) who is asking? (verified by Supabase Auth)
  const auth = req.headers.get("authorization") ?? "";
  const jwt = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  const user = jwt ? await getUser(deps, jwt) : null;
  if (!user) return reply(401, { error: "please sign in" }, cors.headers);
  if (!user.email_confirmed_at && !user.confirmed_at) return reply(403, { error: "please confirm your email first" }, cors.headers);

  // which plan?  only "monthly" or "yearly" are accepted
  let plan = "";
  try { plan = String((await req.json())?.plan ?? ""); } catch { /* no body */ }
  if (plan !== "monthly" && plan !== "yearly") return reply(400, { error: "choose monthly or yearly" }, cors.headers);
  const variantId = plan === "monthly" ? env.LS_VARIANT_MONTHLY : env.LS_VARIANT_YEARLY;

  try {
    // 2) already Premium? then there is nothing to buy
    const ent = await service(deps, `/rest/v1/entitlements?user_id=eq.${user.id}&select=premium,premium_until`);
    if (Array.isArray(ent) && ent[0]?.premium === true && (!ent[0].premium_until || new Date(ent[0].premium_until).getTime() > Date.now())) return reply(200, { alreadyPremium: true }, cors.headers);

    // 3) a random "intent" ties the coming payment to THIS user (max 5 per hour)
    const intent = await service(deps, "/rest/v1/rpc/new_checkout_intent", {
      method: "POST", body: JSON.stringify({ p_user: user.id, p_max: 5 }),
    });
    if (!intent) return reply(429, { error: "too many attempts, try again later" }, cors.headers);

    // 4) ask Lemon Squeezy for a hosted checkout
    const appUrl = String(env.APP_URL).replace(/\/+$/, "");
    const res = await deps.fetch("https://api.lemonsqueezy.com/v1/checkouts", {
      method: "POST",
      headers: {
        accept: "application/vnd.api+json",
        "content-type": "application/vnd.api+json",
        authorization: `Bearer ${env.LS_API_KEY}`,
      },
      body: JSON.stringify({
        data: {
          type: "checkouts",
          attributes: {
            checkout_data: { email: user.email, custom: { intent_id: String(intent) } },
            product_options: { redirect_url: `${appUrl}/?checkout=return` },
            test_mode: env.LS_TEST_MODE === "true",
          },
          relationships: {
            store: { data: { type: "stores", id: String(env.LS_STORE_ID) } },
            variant: { data: { type: "variants", id: String(variantId) } },
          },
        },
      }),
    });
    if (!res.ok) {
      console.error("Lemon Squeezy checkout error, status " + res.status);
      return reply(502, { error: "could not start checkout" }, cors.headers);
    }
    const j = await res.json();
    const url = String(j?.data?.attributes?.url ?? "");
    let host = "";
    try { const u = new URL(url); if (u.protocol === "https:") host = u.hostname; } catch { /* invalid */ }
    if (!host || !(host === "lemonsqueezy.com" || host.endsWith(".lemonsqueezy.com"))) {
      console.error("unexpected checkout url host: " + host);
      return reply(502, { error: "could not start checkout" }, cors.headers);
    }
    return reply(200, { url }, cors.headers);
  } catch (e) {
    console.error("checkout failed: " + (e as any)?.message);
    return reply(500, { error: "could not start checkout" }, cors.headers);
  }
}

if (typeof Deno !== "undefined" && typeof Deno.serve === "function") {
  const names = ["LS_API_KEY", "LS_STORE_ID", "LS_VARIANT_MONTHLY", "LS_VARIANT_YEARLY", "LS_TEST_MODE", "APP_URL", "APP_ORIGIN",
                 "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];
  Deno.serve((req: Request) => {
    const env: any = {};
    for (const n of names) env[n] = Deno.env.get(n);
    return handleCheckout(req, { env, fetch });
  });
}
