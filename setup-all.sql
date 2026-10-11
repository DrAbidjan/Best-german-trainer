-- =====================================================================
-- B2 Verb Trainer - database setup (run ONCE in Supabase > SQL Editor)
-- Everything that unlocks Premium is written ONLY by the server.
-- The app (browser) can never write purchases or entitlements.
-- =====================================================================

-- ---------- tables ----------

-- One row per user: does this user have Premium? (written only by server functions)
create table if not exists public.entitlements (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  premium    boolean not null default false,
  updated_at timestamptz not null default now()
);

-- One row per Lemon Squeezy order (server only; the browser cannot read this table).
create table if not exists public.purchases (
  order_id     text primary key,                 -- Lemon Squeezy order id
  order_uuid   text,
  user_id      uuid references auth.users(id) on delete set null,  -- null = not linked to an account yet
  email        text not null,                    -- buyer email from Lemon Squeezy (lowercase)
  status       text not null check (status in ('paid','refunded')),
  test_mode    boolean not null,
  store_id     text,
  product_id   text,
  variant_id   text not null,
  amount_cents integer,
  currency     text,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
create index if not exists purchases_email_idx on public.purchases (lower(email));
create index if not exists purchases_user_idx  on public.purchases (user_id);

-- Created by the server when a signed-in user starts a checkout. The random id travels
-- through Lemon Squeezy and comes back in the signed webhook, so we know WHICH user paid.
create table if not exists public.checkout_intents (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  order_id   text                                -- filled when an order uses this intent
);
create index if not exists checkout_intents_user_idx on public.checkout_intents (user_id, created_at);

-- Every webhook we handled. A repeated event is recognised here and ignored.
create table if not exists public.webhook_events (
  event_key   text primary key,
  event_name  text not null,
  order_id    text,
  outcome     text not null,
  received_at timestamptz not null default now()
);

-- Throttle for the "restore purchase" check
create table if not exists public.sync_throttle (
  user_id uuid primary key references auth.users(id) on delete cascade,
  last_at timestamptz not null default now()
);

-- Learning progress, one row per user (the app saves it here)
create table if not exists public.progress (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  data       jsonb not null,
  updated_at timestamptz not null default now(),
  constraint progress_is_object check (jsonb_typeof(data) = 'object'),
  constraint progress_size check (pg_column_size(data) < 300000)
);

-- The paid verbs. Only readable by users who have Premium (row level security below).
create table if not exists public.premium_content (
  key     text primary key,
  kind    text not null,
  payload jsonb not null
);

-- ---------- updated_at set by the server, not by the browser ----------
create or replace function public.touch_updated_at() returns trigger
language plpgsql as $$
begin new.updated_at := now(); return new; end $$;

drop trigger if exists progress_touch on public.progress;
create trigger progress_touch before insert or update on public.progress
  for each row execute function public.touch_updated_at();

-- ---------- row level security ----------
alter table public.entitlements     enable row level security;
alter table public.purchases        enable row level security;
alter table public.checkout_intents enable row level security;
alter table public.webhook_events   enable row level security;
alter table public.sync_throttle    enable row level security;
alter table public.progress         enable row level security;
alter table public.premium_content  enable row level security;

-- Start from zero access, then grant only what the app needs.
revoke all on public.entitlements, public.purchases, public.checkout_intents,
              public.webhook_events, public.sync_throttle, public.progress,
              public.premium_content from anon, authenticated;

-- entitlements: a signed-in user may READ only their own row. Nobody in the browser can write.
grant select on public.entitlements to authenticated;
drop policy if exists entitlements_read_own on public.entitlements;
create policy entitlements_read_own on public.entitlements
  for select to authenticated using (user_id = (select auth.uid()));

-- progress: a signed-in user may read and write only their own row.
grant select, insert, update on public.progress to authenticated;
drop policy if exists progress_select_own on public.progress;
drop policy if exists progress_insert_own on public.progress;
drop policy if exists progress_update_own on public.progress;
create policy progress_select_own on public.progress
  for select to authenticated using (user_id = (select auth.uid()));
create policy progress_insert_own on public.progress
  for insert to authenticated with check (user_id = (select auth.uid()));
create policy progress_update_own on public.progress
  for update to authenticated using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- premium_content: readable only if the user's own entitlement row says premium.
grant select on public.premium_content to authenticated;
drop policy if exists premium_content_read on public.premium_content;
create policy premium_content_read on public.premium_content
  for select to authenticated using (
    exists (select 1 from public.entitlements e
            where e.user_id = (select auth.uid()) and e.premium)
  );
-- (purchases, checkout_intents, webhook_events, sync_throttle: RLS on, no policy, no grant = server only)

-- ---------- server functions (security definer) ----------

-- Recalculate Premium for a user from their purchases.
create or replace function public.recompute_entitlement(p_user uuid) returns void
language sql security definer set search_path = public, pg_temp as $$
  insert into public.entitlements (user_id, premium, updated_at)
  values (p_user, exists (select 1 from public.purchases where user_id = p_user and status = 'paid'), now())
  on conflict (user_id) do update set premium = excluded.premium, updated_at = now();
$$;

-- Link not-yet-linked paid orders to a user when the order email equals the user's VERIFIED email.
create or replace function public.link_unclaimed_for(p_user uuid) returns integer
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_email text; v_n integer;
begin
  select lower(email) into v_email from auth.users
   where id = p_user and email_confirmed_at is not null;
  if v_email is null then return 0; end if;
  update public.purchases set user_id = p_user, updated_at = now()
   where user_id is null and lower(email) = v_email;
  get diagnostics v_n = row_count;
  perform public.recompute_entitlement(p_user);
  return v_n;
end $$;

-- Called by the webhook for order_created (and by "restore purchase"). Safe to call twice.
create or replace function public.record_paid_order(
  p_event_key text, p_order_id text, p_order_uuid text, p_intent_id uuid, p_email text,
  p_test boolean, p_store text, p_product text, p_variant text, p_amount integer, p_currency text
) returns text
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_p       public.purchases%rowtype;
  v_intent  public.checkout_intents%rowtype;
  v_user    uuid;
  v_email   text := lower(trim(coalesce(p_email, '')));
  v_outcome text;
begin
  perform pg_advisory_xact_lock(hashtextextended('order:' || p_order_id, 0));

  if exists (select 1 from public.webhook_events where event_key = p_event_key) then
    return 'duplicate';
  end if;

  select * into v_p from public.purchases where order_id = p_order_id;
  if not found then
    -- 1) which user started this checkout? (intent created by our server for a signed-in user)
    if p_intent_id is not null then
      select * into v_intent from public.checkout_intents
       where id = p_intent_id and order_id is null and created_at > now() - interval '30 days'
       for update;
      if found then
        v_user := v_intent.user_id;
        update public.checkout_intents set order_id = p_order_id where id = p_intent_id;
      end if;
    end if;
    -- 2) otherwise: an account whose VERIFIED email equals the buyer email
    if v_user is null and v_email <> '' then
      select id into v_user from auth.users
       where lower(email) = v_email and email_confirmed_at is not null limit 1;
    end if;
    insert into public.purchases (order_id, order_uuid, user_id, email, status, test_mode,
                                  store_id, product_id, variant_id, amount_cents, currency)
    values (p_order_id, p_order_uuid, v_user, v_email, 'paid', p_test,
            p_store, p_product, p_variant, p_amount, p_currency)
    returning * into v_p;
    v_outcome := case when v_user is null then 'unclaimed' else 'granted' end;
  else
    v_outcome := 'already_recorded';           -- (a refunded order is never switched back to paid)
    if v_p.user_id is null and v_p.status = 'paid' then
      select id into v_user from auth.users
       where lower(email) = lower(v_p.email) and email_confirmed_at is not null limit 1;
      if v_user is not null then
        update public.purchases set user_id = v_user, updated_at = now() where order_id = p_order_id;
        v_p.user_id := v_user;
        v_outcome := 'linked_by_email';
      end if;
    end if;
  end if;

  if v_p.user_id is not null then
    perform public.recompute_entitlement(v_p.user_id);
  end if;

  insert into public.webhook_events (event_key, event_name, order_id, outcome)
  values (p_event_key, 'order_created', p_order_id, v_outcome);
  return v_outcome;
end $$;

-- Called by the webhook for a FULL refund (and by "restore purchase" if a refund was missed).
create or replace function public.record_refund(
  p_event_key text, p_order_id text, p_order_uuid text, p_email text,
  p_test boolean, p_store text, p_product text, p_variant text, p_amount integer, p_currency text
) returns text
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_p public.purchases%rowtype; v_outcome text;
begin
  perform pg_advisory_xact_lock(hashtextextended('order:' || p_order_id, 0));

  if exists (select 1 from public.webhook_events where event_key = p_event_key) then
    return 'duplicate';
  end if;

  select * into v_p from public.purchases where order_id = p_order_id;
  if found then
    update public.purchases set status = 'refunded', updated_at = now() where order_id = p_order_id;
    if v_p.user_id is not null then perform public.recompute_entitlement(v_p.user_id); end if;
    v_outcome := 'refunded';
  else
    -- Refund arrived before we saw the order: remember it as refunded so a late
    -- "order_created" can never switch Premium on.
    insert into public.purchases (order_id, order_uuid, user_id, email, status, test_mode,
                                  store_id, product_id, variant_id, amount_cents, currency)
    values (p_order_id, p_order_uuid, null, lower(trim(coalesce(p_email, ''))), 'refunded', p_test,
            p_store, p_product, p_variant, p_amount, p_currency);
    v_outcome := 'refunded_unknown_order';
  end if;

  insert into public.webhook_events (event_key, event_name, order_id, outcome)
  values (p_event_key, 'order_refunded', p_order_id, v_outcome);
  return v_outcome;
end $$;

-- Create a checkout intent for a user (max p_max per hour). Returns null when over the limit.
create or replace function public.new_checkout_intent(p_user uuid, p_max integer) returns uuid
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_id uuid;
begin
  perform pg_advisory_xact_lock(hashtextextended('intent:' || p_user::text, 0));
  if (select count(*) from public.checkout_intents
       where user_id = p_user and created_at > now() - interval '1 hour') >= p_max then
    return null;
  end if;
  insert into public.checkout_intents (user_id) values (p_user) returning id into v_id;
  return v_id;
end $$;

-- Returns true if this user may run a purchase check now (once every 20 seconds).
create or replace function public.try_sync(p_user uuid) returns boolean
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_last timestamptz;
begin
  perform pg_advisory_xact_lock(hashtextextended('sync:' || p_user::text, 0));
  select last_at into v_last from public.sync_throttle where user_id = p_user;
  if v_last is not null and v_last > now() - interval '20 seconds' then return false; end if;
  insert into public.sync_throttle (user_id, last_at) values (p_user, now())
  on conflict (user_id) do update set last_at = now();
  return true;
end $$;

-- Functions the signed-in app may call (always about the caller only, via auth.uid()):
create or replace function public.claim_my_purchases() returns integer
language sql security definer set search_path = public, pg_temp as $$
  select public.link_unclaimed_for((select auth.uid()));
$$;

create or replace function public.my_purchases()
returns table (order_id text, status text, test_mode boolean, created_at timestamptz)
language sql security definer set search_path = public, pg_temp as $$
  select p.order_id, p.status, p.test_mode, p.created_at
    from public.purchases p
   where p.user_id = (select auth.uid())
   order by p.created_at desc;
$$;

-- ---------- who may run which function ----------
revoke all on function public.recompute_entitlement(uuid)  from public, anon, authenticated;
revoke all on function public.link_unclaimed_for(uuid)     from public, anon, authenticated;
revoke all on function public.record_paid_order(text,text,text,uuid,text,boolean,text,text,text,integer,text) from public, anon, authenticated;
revoke all on function public.record_refund(text,text,text,text,boolean,text,text,text,integer,text)         from public, anon, authenticated;
revoke all on function public.new_checkout_intent(uuid,integer) from public, anon, authenticated;
revoke all on function public.try_sync(uuid)                    from public, anon, authenticated;
revoke all on function public.claim_my_purchases()              from public, anon;
revoke all on function public.my_purchases()                    from public, anon;

grant execute on function public.recompute_entitlement(uuid)  to service_role;
grant execute on function public.link_unclaimed_for(uuid)     to service_role;
grant execute on function public.record_paid_order(text,text,text,uuid,text,boolean,text,text,text,integer,text) to service_role;
grant execute on function public.record_refund(text,text,text,text,boolean,text,text,text,integer,text)         to service_role;
grant execute on function public.new_checkout_intent(uuid,integer) to service_role;
grant execute on function public.try_sync(uuid)                    to service_role;
grant execute on function public.claim_my_purchases()              to authenticated;
grant execute on function public.my_purchases()                    to authenticated;
grant all on all tables in schema public to service_role;


-- =====================================================================
-- SUBSCRIPTIONS (monthly + yearly Premium, billed by Lemon Squeezy).
-- Run in Supabase > SQL Editor AFTER schema.sql and BEFORE chat.sql. Safe to run again.
-- Premium is on while a subscription is active, in a payment-retry period (past_due),
-- or cancelled but not yet ended (you keep access until the paid period ends).
-- Old one-time purchases (table purchases) still work and mean Premium for life.
-- =====================================================================

alter table public.entitlements add column if not exists premium_until timestamptz;   -- null = no end date (lifetime)

create table if not exists public.subscriptions (
  sub_id         text primary key,                 -- Lemon Squeezy subscription id
  user_id        uuid references auth.users(id) on delete set null,
  email          text not null,
  status         text not null check (status in ('on_trial','active','paused','past_due','unpaid','cancelled','expired')),
  cancelled      boolean not null default false,
  plan           text not null check (plan in ('monthly','yearly')),
  test_mode      boolean not null,
  store_id       text,
  product_id     text,
  variant_id     text not null,
  renews_at      timestamptz,
  ends_at        timestamptz,
  ls_updated_at  timestamptz not null,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);
create index if not exists subscriptions_user_idx  on public.subscriptions (user_id);
create index if not exists subscriptions_email_idx on public.subscriptions (lower(email));
alter table public.subscriptions enable row level security;
revoke all on public.subscriptions from anon, authenticated;     -- server only

-- Is this user Premium right now? (the one rule everything else uses)
create or replace function public.is_premium(p_user uuid) returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from public.entitlements e
                  where e.user_id = p_user and e.premium
                    and (e.premium_until is null or e.premium_until > now()));
$$;
revoke all on function public.is_premium(uuid) from public, anon;
grant execute on function public.is_premium(uuid) to authenticated;

-- Recalculate Premium from purchases (lifetime) and subscriptions.
create or replace function public.recompute_entitlement(p_user uuid) returns void
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_life boolean; v_until timestamptz;
begin
  select exists (select 1 from public.purchases where user_id = p_user and status = 'paid') into v_life;
  select max(case
           when s.status in ('active','on_trial','past_due') then coalesce(s.renews_at, now() + interval '40 days') + interval '10 days'
           when s.status = 'cancelled' and s.ends_at > now() then s.ends_at
         end)
    into v_until from public.subscriptions s where s.user_id = p_user;
  insert into public.entitlements (user_id, premium, premium_until, updated_at)
  values (p_user, v_life or coalesce(v_until > now(), false), case when v_life then null else v_until end, now())
  on conflict (user_id) do update
    set premium = excluded.premium, premium_until = excluded.premium_until, updated_at = now();
end $$;
revoke all on function public.recompute_entitlement(uuid) from public, anon, authenticated;

-- Link unclaimed subscriptions too, when the subscription email equals the user's VERIFIED email.
create or replace function public.link_unclaimed_for(p_user uuid) returns integer
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_email text; v_n integer; v_m integer;
begin
  select lower(email) into v_email from auth.users where id = p_user and email_confirmed_at is not null;
  if v_email is null then return 0; end if;
  update public.purchases set user_id = p_user, updated_at = now() where user_id is null and lower(email) = v_email;
  get diagnostics v_n = row_count;
  update public.subscriptions set user_id = p_user, updated_at = now() where user_id is null and lower(email) = v_email;
  get diagnostics v_m = row_count;
  perform public.recompute_entitlement(p_user);
  return v_n + v_m;
end $$;
revoke all on function public.link_unclaimed_for(uuid) from public, anon, authenticated;

-- Called by the webhook (and "restore") for every subscription event. Safe to call twice, in any order.
create or replace function public.record_subscription(
  p_event_key text, p_event_name text, p_sub_id text, p_intent_id uuid, p_email text,
  p_status text, p_cancelled boolean, p_plan text, p_test boolean, p_store text, p_product text, p_variant text,
  p_renews timestamptz, p_ends timestamptz, p_ls_updated timestamptz
) returns text
language plpgsql security definer set search_path = public, pg_temp as $$
declare
  v_s public.subscriptions%rowtype; v_intent public.checkout_intents%rowtype; v_user uuid;
  v_email text := lower(trim(coalesce(p_email, ''))); v_outcome text;
begin
  perform pg_advisory_xact_lock(hashtextextended('sub:' || p_sub_id, 0));
  if exists (select 1 from public.webhook_events where event_key = p_event_key) then return 'duplicate'; end if;
  if p_status not in ('on_trial','active','paused','past_due','unpaid','cancelled','expired') then raise exception 'bad_status'; end if;
  if p_plan not in ('monthly','yearly') then raise exception 'bad_plan'; end if;

  select * into v_s from public.subscriptions where sub_id = p_sub_id;
  if not found then
    if p_intent_id is not null then
      select * into v_intent from public.checkout_intents
       where id = p_intent_id and order_id is null and created_at > now() - interval '30 days' for update;
      if found then
        v_user := v_intent.user_id;
        update public.checkout_intents set order_id = 'sub:' || p_sub_id where id = p_intent_id;
      end if;
    end if;
    if v_user is null and v_email <> '' then
      select id into v_user from auth.users where lower(email) = v_email and email_confirmed_at is not null limit 1;
    end if;
    insert into public.subscriptions (sub_id, user_id, email, status, cancelled, plan, test_mode, store_id, product_id, variant_id,
                                      renews_at, ends_at, ls_updated_at)
    values (p_sub_id, v_user, v_email, p_status, coalesce(p_cancelled, false), p_plan, p_test, p_store, p_product, p_variant,
            p_renews, p_ends, p_ls_updated)
    returning * into v_s;
    v_outcome := case when v_user is null then 'unclaimed' else 'granted' end;
  elsif p_ls_updated < v_s.ls_updated_at then
    v_outcome := 'stale';                                   -- an older event arriving late: ignore its content
  else
    update public.subscriptions
       set status = p_status, cancelled = coalesce(p_cancelled, false), plan = p_plan, renews_at = p_renews, ends_at = p_ends,
           variant_id = p_variant, ls_updated_at = p_ls_updated, updated_at = now()
     where sub_id = p_sub_id returning * into v_s;
    v_outcome := 'updated';
    if v_s.user_id is null then
      select id into v_user from auth.users where lower(email) = lower(v_s.email) and email_confirmed_at is not null limit 1;
      if v_user is not null then
        update public.subscriptions set user_id = v_user where sub_id = p_sub_id;
        v_s.user_id := v_user; v_outcome := 'linked_by_email';
      end if;
    end if;
  end if;

  if v_s.user_id is not null then perform public.recompute_entitlement(v_s.user_id); end if;
  insert into public.webhook_events (event_key, event_name, order_id, outcome) values (p_event_key, p_event_name, 'sub:' || p_sub_id, v_outcome);
  return v_outcome;
end $$;
revoke all on function public.record_subscription(text,text,text,uuid,text,text,boolean,text,boolean,text,text,text,timestamptz,timestamptz,timestamptz) from public, anon, authenticated;

-- What the app shows about my subscription (never other people's)
create or replace function public.my_subscription()
returns table (plan text, status text, cancelled boolean, renews_at timestamptz, ends_at timestamptz, test_mode boolean)
language sql security definer set search_path = public, pg_temp as $$
  select s.plan, s.status, s.cancelled, s.renews_at, s.ends_at, s.test_mode
    from public.subscriptions s where s.user_id = (select auth.uid())
   order by (s.status in ('active','on_trial','past_due')) desc, s.ls_updated_at desc limit 1;
$$;
revoke all on function public.my_subscription() from public, anon;
grant execute on function public.my_subscription() to authenticated;

-- The paid verbs and the chat now follow the same rule (including the end date).
drop policy if exists premium_content_read on public.premium_content;
create policy premium_content_read on public.premium_content
  for select to authenticated using (public.is_premium((select auth.uid())));


-- =====================================================================
-- CHAT for Premium learners (group rooms by level).
-- Run this ONCE in Supabase > SQL Editor (after schema.sql and subscriptions.sql). Safe to run again.
-- Rules enforced by the DATABASE, not by the app:
--   * only signed-in users with Premium (entitlements.premium) can read or write
--   * a nickname and acceptance of the chat rules are needed before writing
--   * messages are 1-500 characters, max 1 message per 2 seconds and 15 per minute
--   * you can only delete your own messages; nobody can edit a message
--   * messages older than 30 days are removed automatically
--   * banned users can neither read nor write
--   * real user ids and emails are never shown to other users
-- =====================================================================

create table if not exists public.chat_profiles (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  nickname    text not null check (nickname ~ '^[A-Za-z0-9_]{3,20}$'),
  accepted_at timestamptz not null default now(),
  banned      boolean not null default false
);
create unique index if not exists chat_profiles_nick_ci on public.chat_profiles (lower(nickname));

create table if not exists public.chat_messages (
  id         bigint generated always as identity primary key,
  room       text not null check (room in ('a1','a2','b1','b2')),
  user_id    uuid not null references auth.users(id) on delete cascade default auth.uid(),
  nick       text not null,
  body       text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);
create index if not exists chat_messages_room_id on public.chat_messages (room, id desc);
create index if not exists chat_messages_created on public.chat_messages (created_at);
create index if not exists chat_messages_user_time on public.chat_messages (user_id, created_at desc);

create table if not exists public.chat_blocks (
  blocker uuid not null references auth.users(id) on delete cascade,
  blocked uuid not null references auth.users(id) on delete cascade,
  primary key (blocker, blocked)
);

create table if not exists public.chat_reports (
  id         bigint generated always as identity primary key,
  message_id bigint,
  reporter   uuid not null references auth.users(id) on delete cascade,
  author     uuid,
  nick       text,
  room       text,
  body       text,
  reason     text not null,
  created_at timestamptz not null default now(),
  unique (message_id, reporter)
);

alter table public.chat_profiles enable row level security;
alter table public.chat_messages enable row level security;
alter table public.chat_blocks   enable row level security;
alter table public.chat_reports  enable row level security;

revoke all on public.chat_profiles, public.chat_messages, public.chat_blocks, public.chat_reports from anon, authenticated;

-- helper: is this user allowed in the chat? (Premium, has accepted the rules, not banned)
create or replace function public.chat_allowed(p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.is_premium(p_user)
     and exists (select 1 from public.chat_profiles c where c.user_id = p_user and not c.banned);
$$;
revoke all on function public.chat_allowed(uuid) from public, anon;
grant execute on function public.chat_allowed(uuid) to authenticated;

-- own profile: read only (writing goes through chat_join)
grant select on public.chat_profiles to authenticated;
drop policy if exists chat_profiles_own on public.chat_profiles;
create policy chat_profiles_own on public.chat_profiles for select to authenticated using (user_id = (select auth.uid()));

-- messages: only some columns are visible (never user_id)
grant select (id, room, nick, body, created_at) on public.chat_messages to authenticated;
grant delete on public.chat_messages to authenticated;
drop policy if exists chat_messages_read on public.chat_messages;
create policy chat_messages_read on public.chat_messages for select to authenticated using (
  public.chat_allowed((select auth.uid()))
  and not exists (select 1 from public.chat_blocks b where b.blocker = (select auth.uid()) and b.blocked = chat_messages.user_id)
);
drop policy if exists chat_messages_delete_own on public.chat_messages;
create policy chat_messages_delete_own on public.chat_messages for delete to authenticated using (
  user_id = (select auth.uid()) and public.chat_allowed((select auth.uid()))
);
-- inserting happens ONLY through chat_send(), never directly

-- blocks: own rows only, via functions
grant select on public.chat_blocks to authenticated;
drop policy if exists chat_blocks_own on public.chat_blocks;
create policy chat_blocks_own on public.chat_blocks for select to authenticated using (blocker = (select auth.uid()));

-- join: choose a nickname and accept the rules (needs Premium)
create or replace function public.chat_join(p_nick text, p_accept boolean) returns text
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid();
begin
  if uid is null then raise exception 'not_signed_in'; end if;
  if not public.is_premium(uid) then raise exception 'premium_required'; end if;
  if p_accept is not true then raise exception 'rules_not_accepted'; end if;
  if p_nick is null or p_nick !~ '^[A-Za-z0-9_]{3,20}$' then raise exception 'bad_nickname'; end if;
  if exists (select 1 from public.chat_profiles c where c.user_id = uid and c.banned) then raise exception 'banned'; end if;
  begin
    insert into public.chat_profiles (user_id, nickname) values (uid, p_nick)
    on conflict (user_id) do update set nickname = excluded.nickname, accepted_at = now();
  exception when unique_violation then raise exception 'nickname_taken';
  end;
  return p_nick;
end $$;

-- send a message
create or replace function public.chat_send(p_room text, p_body text) returns bigint
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); nick_ text; b text := btrim(coalesce(p_body, '')); new_id bigint;
begin
  if uid is null then raise exception 'not_signed_in'; end if;
  if not public.chat_allowed(uid) then raise exception 'not_allowed'; end if;
  if p_room not in ('a1','a2','b1','b2') then raise exception 'bad_room'; end if;
  if char_length(b) < 1 or char_length(b) > 500 then raise exception 'bad_length'; end if;
  if exists (select 1 from public.chat_messages m where m.user_id = uid and m.created_at > now() - interval '2 seconds') then raise exception 'slow_down'; end if;
  if (select count(*) from public.chat_messages m where m.user_id = uid and m.created_at > now() - interval '1 minute') >= 15 then raise exception 'slow_down'; end if;
  select nickname into nick_ from public.chat_profiles where user_id = uid;
  insert into public.chat_messages (room, user_id, nick, body) values (p_room, uid, nick_, b) returning id into new_id;
  delete from public.chat_messages where created_at < now() - interval '30 days';
  return new_id;
end $$;

-- report a message (a copy is kept for you, the owner, even if the author deletes it)
create or replace function public.chat_report(p_id bigint, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); m public.chat_messages;
begin
  if uid is null or not public.chat_allowed(uid) then raise exception 'not_allowed'; end if;
  select * into m from public.chat_messages where id = p_id;
  if not found then raise exception 'not_found'; end if;
  insert into public.chat_reports (message_id, reporter, author, nick, room, body, reason)
  values (m.id, uid, m.user_id, m.nick, m.room, m.body, left(coalesce(nullif(btrim(p_reason), ''), 'other'), 200))
  on conflict (message_id, reporter) do nothing;
end $$;

-- block the author of a message (you will no longer see that person)
create or replace function public.chat_block(p_id bigint) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); a uuid;
begin
  if uid is null or not public.chat_allowed(uid) then raise exception 'not_allowed'; end if;
  select user_id into a from public.chat_messages where id = p_id;
  if a is null then raise exception 'not_found'; end if;
  if a = uid then raise exception 'cannot_block_self'; end if;
  insert into public.chat_blocks (blocker, blocked) values (uid, a) on conflict do nothing;
end $$;

create or replace function public.chat_unblock_all() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  delete from public.chat_blocks where blocker = auth.uid();
end $$;

revoke all on function public.chat_join(text, boolean), public.chat_send(text, text), public.chat_report(bigint, text),
  public.chat_block(bigint), public.chat_unblock_all() from public, anon;
grant execute on function public.chat_join(text, boolean), public.chat_send(text, text), public.chat_report(bigint, text),
  public.chat_block(bigint), public.chat_unblock_all() to authenticated;
