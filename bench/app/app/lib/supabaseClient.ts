"use client";
import { createClient } from "@supabase/supabase-js";

// Browser client. The anon key is meant to be public; RLS is the real gate.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL || "http://127.0.0.1:54721";
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";

export const supabase = createClient(url, anonKey);
