// Supabase Edge Function: strud-download
//  { action: "list" }        -> yayınlanan oyunların listesi
//  { game: "<oyun id>" }     -> manifest + 1 saatlik imzalı parça bağlantıları + çözme anahtarı
// Anahtar ve parça yolları game_secrets tablosunda durur; yalnızca service role okur.
// Deploy: supabase functions deploy strud-download   (JWT doğrulaması AÇIK kalsın)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const BUCKET = Deno.env.get("STRUD_BUCKET") ?? "games";
const MAX_PER_DAY = 10; // aynı kullanıcı + aynı oyun, 24 saatte
const URL_TTL_SECONDS = 3600;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const userClient = createClient(url, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const { data: u, error: uErr } = await userClient.auth.getUser();
  const user = u?.user;
  if (uErr || !user) return json({ error: "unauthorized" }, 401);

  let body: { action?: string; game?: string };
  try { body = await req.json(); } catch { return json({ error: "bad_request" }, 400); }

  const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

  // --- Liste ---
  if (body.action === "list") {
    const { data: rows } = await admin.from("game_secrets").select("game_id");
    const ids = (rows ?? []).map((r: { game_id: string }) => r.game_id);
    if (!ids.length) return json({ games: [] });
    const { data: games } = await admin.from("games").select("id, title, files, created_at")
      .in("id", ids).order("created_at", { ascending: false });
    return json({
      games: (games ?? []).map((g: { id: unknown; title: string; files?: { size?: number }[] }) => ({
        id: String(g.id), title: g.title, size: g.files?.[0]?.size ?? 0,
      })),
    });
  }

  // --- İndirme ---
  const gameId = String(body.game ?? "");
  if (!gameId || gameId.length > 64) return json({ error: "bad_request" }, 400);

  const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count } = await admin.from("game_downloads").select("id", { count: "exact", head: true })
    .eq("user_id", user.id).eq("game", gameId).gte("created_at", since);
  if ((count ?? 0) >= MAX_PER_DAY) return json({ error: "rate_limited" }, 429);

  const { data: sec } = await admin.from("game_secrets").select("key, manifest")
    .eq("game_id", gameId).maybeSingle();
  if (!sec) return json({ error: "not_found" }, 404);
  const { data: g } = await admin.from("games").select("title").eq("id", gameId).maybeSingle();
  const m = sec.manifest;

  const paths: string[] = m.chunks.map((c: { path: string }) => c.path);
  const { data: signed, error: sErr } = await admin.storage.from(BUCKET).createSignedUrls(paths, URL_TTL_SECONDS);
  if (sErr || !signed) return json({ error: "sign_failed" }, 500);
  const byPath = new Map<string, string>();
  for (const s of signed) if (s.path && s.signedUrl) byPath.set(s.path, s.signedUrl);

  const chunks = m.chunks.map((c: { i: number; path: string; size: number; plainSize: number; sha256: string }) => ({
    i: c.i, url: byPath.get(c.path), size: c.size, plainSize: c.plainSize, sha256: c.sha256,
  }));
  if (chunks.some((c: { url?: string }) => !c.url)) return json({ error: "sign_failed" }, 500);

  await admin.from("game_downloads").insert({
    user_id: user.id,
    game: gameId,
    ip: req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null,
  });

  return json({
    game: g?.title ?? "Game",
    version: m.version,
    exe: m.exe,
    zipName: m.zipName,
    totalPlain: m.totalPlain,
    zipSha256: m.zipSha256 ?? "",
    key: sec.key,
    chunks,
  });
});
