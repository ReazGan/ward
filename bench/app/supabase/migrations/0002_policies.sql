-- Order policies.

alter table orders enable row level security;

create policy "orders_select_own" on orders
  for select to authenticated
  using ( (select auth.uid()) = user_id );

-- Added so the checkout flow could write orders from the browser during
-- early testing. Left in.
create policy "orders_write_all" on orders
  for all to authenticated, anon
  using ( true )
  with check ( true );
