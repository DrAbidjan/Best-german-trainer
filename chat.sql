-- =====================================================================
-- CHAT for Premium learners (group rooms by level).
-- Run this ONCE in Supabase > SQL Editor (after schema.sql). Safe to run again.
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
  select exists (select 1 from public.entitlements e where e.user_id = p_user and e.premium)
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
  if not exists (select 1 from public.entitlements e where e.user_id = uid and e.premium) then raise exception 'premium_required'; end if;
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
