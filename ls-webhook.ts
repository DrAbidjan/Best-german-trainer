// =====================================================================
// ls-webhook  -  receives Lemon Squeezy subscription (and optional one-time order) events and switches Premium on or off.
// Only this server code (using the secret service key) can write purchases.
// Needs "Verify JWT" switched OFF (Lemon Squeezy does not send a Supabase login).
// The security here is the signature check below.
// =====================================================================
declare const Deno: any;

const enc = new TextEncoder();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function reply(status: number, body: any): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/i.test(hex)) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// HMAC-SHA256 of the RAW request body with the signing secret, compared with the X-Signature header.
async function signatureIsValid(raw: Uint8Array, sigHeader: string | null, secret: string): Promise<boolean> {
  if (!sigHeader) return false;
  const sig = hexToBytes(sigHeader.trim());
  if (!sig) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return await crypto.subtle.verify("HMAC", key, sig, raw);   // constant-time comparison
}

async function rpc(deps: any, name: string, args: any): Promise<any> {
  const { env } = deps;
  const res = await deps.fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${name}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify(args),
  });
  if (!res.ok) throw new Error(`database call ${name} failed with status ${res.status}`);
  return await res.json();
}

const SUB_STATUSES = ["on_trial", "active", "paused", "past_due", "unpaid", "cancelled", "expired"];
const SUB_EVENTS = ["subscription_created", "subscription_updated", "subscription_cancelled", "subscription_resumed",
                    "subscription_expired", "subscription_paused", "subscription_unpaused"];

function isoOrNull(v: any): string | null {
  if (v === null || v === undefined || v === "") return null;
  const d = new Date(String(v));
  return isNaN(d.getTime()) ? null : d.toISOString();
}

// Which plan does this Lemon Squeezy variant belong to?  null = not ours.
export function planForVariant(env: any, variantId: any): "monthly" | "yearly" | null {
  const v = String(variantId);
  if (env.LS_VARIANT_MONTHLY && v === String(env.LS_VARIANT_MONTHLY)) return "monthly";
  if (env.LS_VARIANT_YEARLY && v === String(env.LS_VARIANT_YEARLY)) return "yearly";
  return null;
}

async function handleSubscription(event: string, meta: any, data: any, attrs: any, deps: any): Promise<Response> {
  const env = deps.env;
  if (!SUB_EVENTS.includes(event)) return reply(200, { ok: true, result: "ignored_event" });
  if (data.type !== "subscriptions" || data.id === undefined || data.id === null) return reply(200, { ok: true, result: "ignored_not_a_subscription" });
  if (String(attrs.store_id) !== String(env.LS_STORE_ID)) {
    console.warn(`ignored: store ${attrs.store_id} is not ours`);
    return reply(200, { ok: true, result: "ignored_store" });
  }
  const plan = planForVariant(env, attrs.variant_id);
  if (!plan || (env.LS_PRODUCT_ID && String(attrs.product_id) !== String(env.LS_PRODUCT_ID))) {
    console.warn(`ignored: product ${attrs.product_id} / variant ${attrs.variant_id} is not a Premium plan`);
    return reply(200, { ok: true, result: "ignored_product" });
  }
  const isTest = attrs.test_mode === true || meta.test_mode === true;
  if (isTest && env.LS_TEST_MODE !== "true") {
    console.warn("ignored: test-mode subscription while LS_TEST_MODE is not true");
    return reply(200, { ok: true, result: "ignored_test_order" });
  }
  const status = String(attrs.status ?? "");
  if (!SUB_STATUSES.includes(status)) return reply(200, { ok: true, result: "ignored_status" });
  const updated = isoOrNull(attrs.updated_at);
  if (!updated) return reply(400, { error: "missing updated_at" });
  const subId = String(data.id);
  const intent = meta.custom_data?.intent_id;
  try {
    const result = await rpc(deps, "record_subscription", {
      p_event_key: `${event}:${subId}:${updated}`,
      p_event_name: event,
      p_sub_id: subId,
      p_intent_id: typeof intent === "string" && UUID_RE.test(intent) ? intent : null,
      p_email: String(attrs.user_email ?? "").trim().toLowerCase().slice(0, 254),
      p_status: status,
      p_cancelled: attrs.cancelled === true,
      p_plan: plan,
      p_test: isTest,
      p_store: String(attrs.store_id),
      p_product: attrs.product_id !== undefined ? String(attrs.product_id) : null,
      p_variant: String(attrs.variant_id),
      p_renews: isoOrNull(attrs.renews_at),
      p_ends: isoOrNull(attrs.ends_at),
      p_ls_updated: updated,
    });
    console.log(JSON.stringify({ event, subscription: subId, status, result }));
    return reply(200, { ok: true, result });
  } catch (e) {
    console.error("processing failed: " + (e as any)?.message);
    return reply(500, { error: "processing failed" });
  }
}

export async function handleWebhook(req: Request, deps: any): Promise<Response> {
  const env = deps.env;
  if (req.method !== "POST") return reply(405, { error: "method not allowed" });

  const needed = ["LS_WEBHOOK_SECRET", "LS_STORE_ID", "LS_VARIANT_MONTHLY", "LS_VARIANT_YEARLY", "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];
  for (const n of needed) {
    if (!env[n]) { console.error("missing setting: " + n); return reply(500, { error: "server not configured" }); }
  }

  // 1) read the raw bytes and verify the signature BEFORE looking at anything inside
  const raw = new Uint8Array(await req.arrayBuffer());
  if (raw.length === 0 || raw.length > 200_000) return reply(400, { error: "bad body size" });
  if (!(await signatureIsValid(raw, req.headers.get("x-signature"), env.LS_WEBHOOK_SECRET))) {
    console.warn("rejected: invalid signature");
    return reply(401, { error: "invalid signature" });
  }

  // 2) parse
  let body: any;
  try { body = JSON.parse(new TextDecoder().decode(raw)); } catch { return reply(400, { error: "invalid json" }); }
  const meta = body?.meta ?? {};
  const data = body?.data ?? {};
  const attrs = data?.attributes ?? {};
  const event = String(meta.event_name ?? "");

  // 3) only events we understand; everything else is acknowledged and ignored
  if (event.startsWith("subscription_")) return await handleSubscription(event, meta, data, attrs, deps);
  if (event !== "order_created" && event !== "order_refunded") return reply(200, { ok: true, result: "ignored_event" });
  if (data.type !== "orders" || data.id === undefined || data.id === null) return reply(200, { ok: true, result: "ignored_not_an_order" });
  // (one-time orders only count for the OPTIONAL old one-time product LS_VARIANT_ID; subscription first-payments arrive as subscription events)
  if (!env.LS_VARIANT_ID) return reply(200, { ok: true, result: "ignored_product" });

  // 4) is it OUR product?  (store, product, variant)
  const item = attrs.first_order_item ?? {};
  if (String(attrs.store_id) !== String(env.LS_STORE_ID)) {
    console.warn(`ignored: store ${attrs.store_id} is not ours`);
    return reply(200, { ok: true, result: "ignored_store" });
  }
  if (String(item.variant_id) !== String(env.LS_VARIANT_ID) ||
      (env.LS_PRODUCT_ID && String(item.product_id) !== String(env.LS_PRODUCT_ID))) {
    console.warn(`ignored: product ${item.product_id} / variant ${item.variant_id} is not the Premium product`);
    return reply(200, { ok: true, result: "ignored_product" });
  }

  // 5) test orders only count while LS_TEST_MODE is "true"
  const isTest = attrs.test_mode === true || meta.test_mode === true;
  if (isTest && env.LS_TEST_MODE !== "true") {
    console.warn("ignored: test-mode order while LS_TEST_MODE is not true");
    return reply(200, { ok: true, result: "ignored_test_order" });
  }

  const orderId = String(data.id);
  const email = String(attrs.user_email ?? "").trim().toLowerCase().slice(0, 254);
  const common = {
    p_order_id: orderId,
    p_order_uuid: attrs.identifier ? String(attrs.identifier).slice(0, 80) : null,
    p_email: email,
    p_test: isTest,
    p_store: String(attrs.store_id),
    p_product: item.product_id !== undefined ? String(item.product_id) : null,
    p_variant: String(item.variant_id),
    p_amount: Number.isInteger(attrs.total) ? attrs.total : null,
    p_currency: attrs.currency ? String(attrs.currency).slice(0, 8) : null,
  };

  try {
    let result: string;
    if (event === "order_created") {
      if (attrs.status !== "paid") {
        console.warn(`ignored: order ${orderId} has status ${attrs.status}`);
        return reply(200, { ok: true, result: "ignored_not_paid" });
      }
      const intent = meta.custom_data?.intent_id;
      result = await rpc(deps, "record_paid_order", {
        p_event_key: `order_created:${orderId}`,
        p_intent_id: typeof intent === "string" && UUID_RE.test(intent) ? intent : null,
        ...common,
      });
    } else {
      // order_refunded: partial refunds keep Premium; a full refund (or fraud flag) removes it
      if (attrs.status !== "refunded" && attrs.status !== "fraudulent") {
        return reply(200, { ok: true, result: "ignored_partial_refund" });
      }
      const { p_order_id, p_order_uuid, p_email, p_test, p_store, p_product, p_variant, p_amount, p_currency } = common;
      result = await rpc(deps, "record_refund", {
        p_event_key: `order_refunded:${orderId}`,
        p_order_id, p_order_uuid, p_email, p_test, p_store, p_product, p_variant, p_amount, p_currency,
      });
    }
    console.log(JSON.stringify({ event, order: orderId, result }));
    return reply(200, { ok: true, result });
  } catch (e) {
    // 500 makes Lemon Squeezy retry the delivery
    console.error("processing failed: " + (e as any)?.message);
    return reply(500, { error: "processing failed" });
  }
}

if (typeof Deno !== "undefined" && typeof Deno.serve === "function") {
  const names = ["LS_WEBHOOK_SECRET", "LS_STORE_ID", "LS_PRODUCT_ID", "LS_VARIANT_ID", "LS_VARIANT_MONTHLY", "LS_VARIANT_YEARLY", "LS_TEST_MODE",
                 "SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];
  Deno.serve((req: Request) => {
    const env: any = {};
    for (const n of names) env[n] = Deno.env.get(n);
    return handleWebhook(req, { env, fetch });
  });
}
