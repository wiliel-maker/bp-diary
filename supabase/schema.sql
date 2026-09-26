-- Схема базы для «Дневника давления».
-- Выполните этот файл целиком в Supabase → SQL Editor → New query → Run.
-- Повторный запуск безопасен: объекты пересоздаются.

-- ---------------------------------------------------------------------------
-- Профили пользователей
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id           uuid primary key references auth.users (id) on delete cascade,
  username     text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),
  display_name text,
  is_public    boolean not null default false,  -- открыт ли дневник другим пользователям
  show_notes   boolean not null default true,   -- показывать ли заметки в открытом дневнике
  created_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Измерения
-- ---------------------------------------------------------------------------
create table if not exists public.readings (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  systolic   integer not null check (systolic between 40 and 300),
  diastolic  integer not null check (diastolic between 20 and 200),
  pulse      integer check (pulse between 20 and 250),
  date       date not null,
  time       text check (time ~ '^\d{2}:\d{2}$'),
  period     text check (period in ('morning', 'evening')),
  arm        text check (arm in ('left', 'right')),
  date_time  text not null,                     -- 'YYYY-MM-DDTHH:MM', ключ сортировки
  note       text not null default '' check (char_length(note) <= 80),
  created_at timestamptz not null default now()
);

create index if not exists readings_user_date_time on public.readings (user_id, date_time desc);

-- ---------------------------------------------------------------------------
-- Профиль создаётся автоматически при регистрации.
-- Логин берётся из метаданных регистрации (username).
-- ---------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_username text;
begin
  v_username := lower(coalesce(nullif(trim(new.raw_user_meta_data ->> 'username'), ''), ''));
  if v_username !~ '^[a-z0-9_]{3,20}$' then
    v_username := 'user_' || substr(replace(new.id::text, '-', ''), 1, 10);
  end if;
  -- если логин занят, добавляем суффикс, чтобы регистрация не падала
  if exists (select 1 from public.profiles where username = v_username) then
    v_username := substr(v_username, 1, 14) || '_' || substr(replace(new.id::text, '-', ''), 1, 5);
  end if;

  insert into public.profiles (id, username, display_name)
  values (new.id, v_username, nullif(trim(new.raw_user_meta_data ->> 'display_name'), ''));
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Row Level Security: кто что видит и меняет
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.readings enable row level security;

drop policy if exists "profiles: read for signed-in users" on public.profiles;
create policy "profiles: read for signed-in users"
  on public.profiles for select
  to authenticated
  using (true);

drop policy if exists "profiles: update own" on public.profiles;
create policy "profiles: update own"
  on public.profiles for update
  to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- Свои записи: полный доступ. Чужие — только через функцию diary_of ниже,
-- которая сама проверяет настройки приватности.
drop policy if exists "readings: select own" on public.readings;
create policy "readings: select own"
  on public.readings for select
  to authenticated
  using (user_id = auth.uid());

drop policy if exists "readings: insert own" on public.readings;
create policy "readings: insert own"
  on public.readings for insert
  to authenticated
  with check (user_id = auth.uid());

drop policy if exists "readings: update own" on public.readings;
create policy "readings: update own"
  on public.readings for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

drop policy if exists "readings: delete own" on public.readings;
create policy "readings: delete own"
  on public.readings for delete
  to authenticated
  using (user_id = auth.uid());

-- ---------------------------------------------------------------------------
-- Функции для клиента
-- ---------------------------------------------------------------------------

-- Свободен ли логин (вызывается до регистрации, поэтому доступна anon).
create or replace function public.username_available(p_username text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select not exists (select 1 from public.profiles where username = lower(p_username));
$$;

-- Список всех пользователей. Счётчик и последняя дата видны только
-- для открытых дневников и для себя.
create or replace function public.list_profiles()
returns table (
  username       text,
  display_name   text,
  is_public      boolean,
  readings_count bigint,
  last_date      date
)
language sql
stable
security definer
set search_path = public
as $$
  select
    p.username,
    p.display_name,
    p.is_public,
    case when p.is_public or p.id = auth.uid()
         then (select count(*) from public.readings r where r.user_id = p.id) end,
    case when p.is_public or p.id = auth.uid()
         then (select max(r.date) from public.readings r where r.user_id = p.id) end
  from public.profiles p
  where auth.uid() is not null
  order by p.username;
$$;

-- Дневник конкретного пользователя.
-- readings = null, если дневник закрыт и это не владелец.
-- Заметки вырезаются, если владелец отключил show_notes.
create or replace function public.diary_of(p_username text)
returns table (
  username     text,
  display_name text,
  is_public    boolean,
  show_notes   boolean,
  is_owner     boolean,
  readings     jsonb
)
language sql
stable
security definer
set search_path = public
as $$
  select
    p.username,
    p.display_name,
    p.is_public,
    p.show_notes,
    p.id = auth.uid(),
    case when p.is_public or p.id = auth.uid() then
      coalesce((
        select jsonb_agg(jsonb_build_object(
          'id',        r.id,
          'systolic',  r.systolic,
          'diastolic', r.diastolic,
          'pulse',     r.pulse,
          'date',      r.date,
          'time',      r.time,
          'period',    r.period,
          'arm',       r.arm,
          'date_time', r.date_time,
          'note',      case when p.show_notes or p.id = auth.uid() then r.note else '' end
        ) order by r.date_time desc)
        from public.readings r
        where r.user_id = p.id
      ), '[]'::jsonb)
    end
  from public.profiles p
  where p.username = lower(p_username)
    and auth.uid() is not null;
$$;

-- Права на вызов функций
-- В Supabase execute выдаётся anon/authenticated автоматически, поэтому
-- отзываем явно и выдаём только нужным ролям.
revoke execute on function public.username_available(text) from public, anon, authenticated;
revoke execute on function public.list_profiles() from public, anon, authenticated;
revoke execute on function public.diary_of(text) from public, anon, authenticated;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

grant execute on function public.username_available(text) to anon, authenticated;
grant execute on function public.list_profiles() to authenticated;
grant execute on function public.diary_of(text) to authenticated;
