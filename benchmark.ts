// benchmark.ts
import { evaluateSql } from "./src/firewall/astFirewall";

interface TestCase {
  name: string;
  sql: string;
  expected: "allow" | "block";
}

const TEST_SUITE: TestCase[] = [
  // Original 12 Red-Team Bypass Attempts (MUST BLOCK)
  { name: "Unbounded DELETE", sql: "DELETE FROM users;", expected: "block" },
  { name: "Classic Tautology (1=1)", sql: "DELETE FROM users WHERE 1 = 1;", expected: "block" },
  { name: "Column Self-Comparison (id=id)", sql: "UPDATE users SET role = 'admin' WHERE id = id;", expected: "block" },
  { name: "Range Sweep Bypass (id > -1)", sql: "DELETE FROM users WHERE id > -1;", expected: "block" },
  { name: "Not-Equal Sweep (email != '')", sql: "DELETE FROM users WHERE email != 'impossible';", expected: "block" },
  { name: "IS NOT NULL Sweep", sql: "DELETE FROM users WHERE id IS NOT NULL;", expected: "block" },
  { name: "Boolean Column Mass Sweep", sql: "DELETE FROM users WHERE is_archived = false;", expected: "block" },
  { name: "OR-Branch Poisoning (id=5 OR 1=1)", sql: "DELETE FROM users WHERE id = 5 OR 1 = 1;", expected: "block" },
  { name: "LIKE Wildcard Sweep", sql: "DELETE FROM users WHERE email LIKE '%';", expected: "block" },
  { name: "CTE Destructive Wrapper", sql: "WITH d AS (DELETE FROM users) SELECT * FROM d;", expected: "block" },
  { name: "Multi-Statement Piggyback", sql: "SELECT * FROM users WHERE id = 1; DROP TABLE users;", expected: "block" },
  { name: "Destructive TRUNCATE", sql: "TRUNCATE TABLE audit_logs;", expected: "block" },

  // Claude CTO Review: 9 Additional Bypass Vectors (MUST BLOCK)
  { name: "Non-unique equality sweep", sql: "DELETE FROM orders WHERE status = 'pending';", expected: "block" },
  { name: "Boolean sweep via string", sql: "DELETE FROM users WHERE is_archived = 'false';", expected: "block" },
  { name: "Tenant-wide delete", sql: "DELETE FROM users WHERE tenant_id = 1;", expected: "block" },
  { name: "DELETE USING tautology", sql: "DELETE FROM users USING (SELECT 1 AS one) x WHERE x.one = 1;", expected: "block" },
  { name: "UPDATE FROM tautology", sql: "UPDATE users SET role = 'admin' FROM (SELECT 1 AS one) x WHERE x.one = 1;", expected: "block" },
  { name: "Upsert mass overwrite", sql: "INSERT INTO users (id, role) SELECT id, 'admin' FROM users ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role;", expected: "block" },
  { name: "DO block hides DELETE", sql: "DO $$BEGIN DELETE FROM users; END$$;", expected: "block" },
  { name: "DROP SCHEMA", sql: "DROP SCHEMA public CASCADE;", expected: "block" },
  { name: "Side-effect function", sql: "SELECT wipe_everything();", expected: "block" },

  // Original 4 + Claude 3 Legitimate Agent Queries (MUST ALLOW - Zero False Positives)
  { name: "Bounded Single-Row DELETE", sql: "DELETE FROM sessions WHERE session_id = 'abc-123';", expected: "allow" },
  { name: "Bounded PK UPDATE", sql: "UPDATE users SET last_login = NOW() WHERE id = 42;", expected: "allow" },
  { name: "Bounded Composite AND Clause", sql: "UPDATE orders SET status = 'shipped' WHERE id = 99 AND paid = true;", expected: "allow" },
  { name: "Bounded IN List", sql: "DELETE FROM notifications WHERE id IN (10, 11, 12);", expected: "allow" },
  { name: "Typed param ($1::uuid)", sql: "UPDATE users SET plan = 'pro' WHERE id = $1::uuid;", expected: "allow" },
  { name: "ANY array param", sql: "DELETE FROM notifications WHERE id = ANY($1);", expected: "allow" },
  { name: "Negative id (-5)", sql: "DELETE FROM t WHERE id = -5;", expected: "allow" },
];

console.log("### QueryShield AST Firewall — 28-Vector Red-Team Suite\n");
console.log("| Test Vector | SQL Payload | Expected | Actual | Rule Triggered | Latency (ms) |");
console.log("|---|---|---|---|---|---|");

let passed = 0;
for (const tc of TEST_SUITE) {
  const res = evaluateSql(tc.sql);
  const ok = res.decision === tc.expected;
  if (ok) passed++;
  const rules = res.violations.map((v) => v.rule).join(", ") || "NONE";
  console.log(
    `| ${tc.name} | \`${tc.sql}\` | **${tc.expected.toUpperCase()}** | ${
      ok ? "PASS" : "FAIL"
    } (${res.decision.toUpperCase()}) | \`${rules}\` | ${res.latencyMs.toFixed(3)}ms |`
  );
}

const latencies: number[] = [];
for (let i = 0; i < 1000; i++) {
  const sample = TEST_SUITE[i % TEST_SUITE.length];
  latencies.push(evaluateSql(sample.sql).latencyMs);
}
latencies.sort((a, b) => a - b);

const p50 = latencies[Math.floor(latencies.length * 0.5)];
const p95 = latencies[Math.floor(latencies.length * 0.95)];
const p99 = latencies[Math.floor(latencies.length * 0.99)];

console.log(`\n**Summary:** ${passed}/${TEST_SUITE.length} passed`);
console.log(
  `**Benchmark (1,000 AST Evaluations):** p50 = **${p50.toFixed(3)}ms** | p95 = **${p95.toFixed(
    3
  )}ms** | p99 = **${p99.toFixed(3)}ms**`
);