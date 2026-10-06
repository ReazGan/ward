-- Initial schema for Notesly.

create table if not exists profiles (
  id uuid primary key,
  email text,
  full_name text,
  bio text,
  role text default 'user',
  credits int default 0
);

create table if not exists notes (
  id uuid primary key,
  user_id uuid not null,
  title text,
  content text,
  is_public boolean default false,
  created_at timestamptz default now()
);

create table if not exists orders (
  id uuid primary key,
  user_id uuid not null,
  product text,
  amount int,
  status text default 'pending',
  created_at timestamptz default now()
);

create table if not exists posts (
  id uuid primary key,
  author text,
  title text,
  body text,
  published boolean default true
);

create table if not exists documents (
  id uuid primary key,
  title text,
  content text
);

create table if not exists invoices (
  id uuid primary key,
  user_id uuid not null,
  number text,
  amount int
);

create table if not exists processed_events (
  id text primary key
);

-- Profiles are private to their owner.
alter table profiles enable row level security;

create policy "profiles_select_own" on profiles
  for select to authenticated
  using ( (select auth.uid()) = id );

create policy "profiles_update_own" on profiles
  for update to authenticated
  using ( (select auth.uid()) = id )
  with check ( (select auth.uid()) = id );

-- Notes are private to their owner.
alter table notes enable row level security;

create policy "notes_select_own" on notes
  for select to authenticated
  using ( (select auth.uid()) = user_id );

create policy "notes_insert_own" on notes
  for insert to authenticated
  with check ( (select auth.uid()) = user_id );

create policy "notes_update_own" on notes
  for update to authenticated
  using ( (select auth.uid()) = user_id )
  with check ( (select auth.uid()) = user_id );

-- Internal documents, server reads them with the service key.
alter table documents enable row level security;

-- Invoices are private to their owner.
alter table invoices enable row level security;

create policy "invoices_select_own" on invoices
  for select to authenticated
  using ( (select auth.uid()) = user_id );
