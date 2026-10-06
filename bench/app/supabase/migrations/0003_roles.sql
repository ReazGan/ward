-- Let admins read every order from the dashboard.

create policy "orders_admin_read" on orders
  for select to authenticated
  using ( (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin' );
