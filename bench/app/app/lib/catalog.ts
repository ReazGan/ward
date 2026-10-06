// Server-side product catalog. Prices live here, not in the request body.
export const CATALOG: Record<string, { name: string; amount: number }> = {
  pro: { name: "Pro plan", amount: 1900 },
  team: { name: "Team plan", amount: 4900 },
  notebook: { name: "Paper notebook", amount: 1200 },
};

export function priceFor(plan: string): number | null {
  const item = CATALOG[plan];
  return item ? item.amount : null;
}
