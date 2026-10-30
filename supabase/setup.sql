-- STRUD oyun dağıtımı. Supabase SQL Editor'de bir kez çalıştır.
-- Kurucu e-postası siteyle aynı olmalı.

-- 1) 'games' bucket'ı ÖZEL olsun.
update storage.buckets set public = false where id = 'games';

-- 2) Eski, bucket'ı herkese açan policy'leri temizle.
--    Önce bu sorguyla 'games' bucket'ına dokunan policy'leri GÖR, sonra adlarını aşağıda sil:
select policyname, cmd, qual, with_check from pg_policies
where schemaname = 'storage' and tablename = 'objects'
  and (coalesce(qual,'') ilike '%games%' or coalesce(with_check,'') ilike '%games%');
-- Çıkan her satır için (adı kendi çıktına göre yaz):
--   drop policy "POLICY ADI" on storage.objects;

-- 3) 'games' bucket'ı: yalnızca kurucu yükler / görür / siler. Başka hiç kimse (anon + giriş yapmış) erişemez.
create policy "games founder insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'games' and lower(auth.jwt() ->> 'email') = 'keremberber3761@gmail.com');
create policy "games founder select" on storage.objects for select to authenticated
  using (bucket_id = 'games' and lower(auth.jwt() ->> 'email') = 'keremberber3761@gmail.com');
create policy "games founder delete" on storage.objects for delete to authenticated
  using (bucket_id = 'games' and lower(auth.jwt() ->> 'email') = 'keremberber3761@gmail.com');

-- 4) Anahtar + parça yolları. Oyunu herkes listeler ama bu tabloyu yalnızca kurucu (ve Edge Function) görür.
create table if not exists public.game_secrets (
  game_id  text primary key,
  key      text  not null,
  manifest jsonb not null
);
alter table public.game_secrets enable row level security;
create policy "secrets founder insert" on public.game_secrets for insert to authenticated
  with check (lower(auth.jwt() ->> 'email') = 'keremberber3761@gmail.com');
create policy "secrets founder select" on public.game_secrets for select to authenticated
  using (lower(auth.jwt() ->> 'email') = 'keremberber3761@gmail.com');
create policy "secrets founder delete" on public.game_secrets for delete to authenticated
  using (lower(auth.jwt() ->> 'email') = 'keremberber3761@gmail.com');

-- 5) İndirme kayıtları (limit). Policy yok = sadece service role.
create table if not exists public.game_downloads (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  game       text not null,
  ip         text,
  created_at timestamptz not null default now()
);
create index if not exists game_downloads_user_game_time on public.game_downloads (user_id, game, created_at desc);
alter table public.game_downloads enable row level security;

-- 6) Downloader .exe'sinin duracağı HALKA AÇIK bucket (içinde gizli bir şey yok).
--    Sonra Dashboard > Storage > downloader'a STRUD-Downloader.exe dosyasını yükle.
insert into storage.buckets (id, name, public) values ('downloader', 'downloader', true)
on conflict (id) do update set public = true;
