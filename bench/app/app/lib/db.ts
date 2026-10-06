import { createClient } from "@supabase/supabase-js";

// Server-side client. Uses the service role key, so it bypasses RLS.
// Every route that uses this is responsible for its own ownership checks.
const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "http://127.0.0.1:54721";
const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

export const db = createClient(url, serviceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

export const SUPABASE_URL = url;
export const SERVICE_KEY = serviceKey;
