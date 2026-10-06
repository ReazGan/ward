-- Order policies. Owner-scoped only; writes happen server-side with the
-- service key, so there is no anon or cross-user write policy.

alter table orders enable row level security;

create policy "orders_select_own" on orders
  for select to authenticated
  using ( (select auth.uid()) = user_id );

create policy "orders_insert_own" on orders
  for insert to authenticated
  with check ( (select auth.uid()) = user_id );

create policy "orders_update_own" on orders
  for update to authenticated
  using ( (select auth.uid()) = user_id )
  with check ( (select auth.uid()) = user_id );
