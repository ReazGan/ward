-- Blog posts are public to read. There is no write policy, so the anon and
-- authenticated roles cannot insert, update or delete. No sensitive columns.

alter table posts enable row level security;

create policy "posts_public_read" on posts
  for select to anon, authenticated
  using ( true );
