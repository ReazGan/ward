// Tiny stand-in for a Prisma client so the read-only routes compile and run
// without a database engine. The point is the call shape, not the storage.
type Row = Record<string, any>;

const PROFILES: Row[] = [
  { id: "seed", email: "seed@example.test", full_name: "Seed User" },
];
const INVOICES: Row[] = [];

export const prisma = {
  // tagged template: values are passed as parameters, never concatenated
  async $queryRaw(strings: TemplateStringsArray, ...values: any[]) {
    void strings;
    void values;
    return PROFILES;
  },
  invoice: {
    async findUnique({ where }: { where: { id: string } }) {
      return INVOICES.find((i) => i.id === where.id) || null;
    },
  },
};
