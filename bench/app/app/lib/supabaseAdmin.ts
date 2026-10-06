import { createClient } from "@supabase/supabase-js";

// Admin client used by a couple of dashboard widgets.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL || "http://127.0.0.1:54721";
const adminKey = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY || "";

export const supabaseAdmin = createClient(url, adminKey, {
  auth: { persistSession: false },
});
