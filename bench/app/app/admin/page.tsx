"use client";
import { useEffect, useState } from "react";
import AdminWidget from "@/app/components/AdminWidget";

export default function AdminPage() {
  const [role, setRole] = useState<string | null>(null);
  const [users, setUsers] = useState<any[]>([]);

  useEffect(() => {
    fetch("/api/profile")
      .then((r) => r.json())
      .then((p) => setRole(p?.role || "user"));
    fetch("/api/admin/users")
      .then((r) => r.json())
      .then((d) => setUsers(Array.isArray(d) ? d : []));
  }, []);

  // client-side gate
  if (role && role !== "admin") {
    return <main style={{ padding: 32 }}><p>Admins only.</p></main>;
  }

  return (
    <main style={{ padding: 32, maxWidth: 720 }}>
      <h1>Admin</h1>
      <AdminWidget />
      <ul>
        {users.map((u) => (
          <li key={u.id}>{u.email} ({u.role})</li>
        ))}
      </ul>
    </main>
  );
}
