"use client";
import { useEffect, useState } from "react";
import { supabaseAdmin } from "@/app/lib/supabaseAdmin";

// Small widget that lists users on the admin dashboard.
export default function AdminWidget() {
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    supabaseAdmin
      .from("profiles")
      .select("id")
      .then(({ data }) => setCount((data || []).length));
  }, []);
  return <div>Users: {count ?? "..."}</div>;
}
