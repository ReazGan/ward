"use client";
import { useEffect, useState } from "react";

// Reads from the protected admin API instead of holding a service key.
export default function AdminWidget() {
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    fetch("/api/admin/users")
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => setCount(Array.isArray(d) ? d.length : 0))
      .catch(() => setCount(0));
  }, []);
  return <div>Users: {count ?? "..."}</div>;
}
