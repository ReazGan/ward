import { NextResponse } from "next/server";
import { prisma } from "@/app/lib/prisma";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const email = new URL(req.url).searchParams.get("email") || "";
  // parameterized tagged-template query; the value is bound, not interpolated
  const rows = await prisma.$queryRaw`SELECT id, email FROM profiles WHERE email = ${email}`;
  return NextResponse.json(rows);
}
