import { createClient } from "@supabase/supabase-js";

// Admin client for server code only. The service role key stays server-side,
// never behind a public env prefix.
const url = process.env.SUPABASE_URL || "http://127.0.0.1:54721";
const adminKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

export const supabaseAdmin = createClient(url, adminKey, {
  auth: { persistSession: false },
});
