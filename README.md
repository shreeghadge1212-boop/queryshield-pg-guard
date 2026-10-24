# QueryShield (`queryshield-pg-guard`)

Deterministic, in-process PostgreSQL AST validator (`pgsql-ast-parser`) for LLM `tool_calls`, Text-to-SQL agents, and MCP servers. Evaluates SQL syntax trees in ~0.35ms warm p50 to block destructive DML/DDL bypasses before `pool.query()` executes.

## Quickstart (Drop-in before `pg.Pool` or MCP Execution)

```typescript
import { evaluateSql } from "./astFirewall";

const verdict = evaluateSql(llmGeneratedSql);
if (verdict.decision === "block") {
  throw new Error(`Blocked unsafe agent SQL: ${verdict.violations.map(v => v.rule).join(", ")}`);
}

await pool.query(llmGeneratedSql);
```
## 28-Vector Red-Team Verification Suite

| Test Vector | SQL Payload | Expected | Actual | Rule Triggered | Latency (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Unbounded DELETE | `DELETE FROM users;` | **BLOCK** | PASS (BLOCK) | `UNBOUNDED_MUTATION` | 15.552ms |
| Classic Tautology (1=1) | `DELETE FROM users WHERE 1 = 1;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 2.184ms |
| Column Self-Comparison (id=id) | `UPDATE users SET role = 'admin' WHERE id = id;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 1.969ms |
| Range Sweep Bypass (id > -1) | `DELETE FROM users WHERE id > -1;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 1.265ms |
| Not-Equal Sweep (email != '') | `DELETE FROM users WHERE email != 'impossible';` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 2.257ms |
| IS NOT NULL Sweep | `DELETE FROM users WHERE id IS NOT NULL;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 1.388ms |
| Boolean Column Mass Sweep | `DELETE FROM users WHERE is_archived = false;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 1.123ms |
| OR-Branch Poisoning (id=5 OR 1=1) | `DELETE FROM users WHERE id = 5 OR 1 = 1;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 1.581ms |
| LIKE Wildcard Sweep | `DELETE FROM users WHERE email LIKE '%';` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 0.718ms |
| CTE Destructive Wrapper | `WITH d AS (DELETE FROM users) SELECT * FROM d;` | **BLOCK** | PASS (BLOCK) | `UNBOUNDED_MUTATION` | 1.500ms |
| Multi-Statement Piggyback | `SELECT * FROM users WHERE id = 1; DROP TABLE users;` | **BLOCK** | PASS (BLOCK) | `MULTI_STATEMENT, DISALLOWED_STATEMENT_TYPE, DESTRUCTIVE_DDL` | 4.747ms |
| Destructive TRUNCATE | `TRUNCATE TABLE audit_logs;` | **BLOCK** | PASS (BLOCK) | `DISALLOWED_STATEMENT_TYPE, DESTRUCTIVE_DDL` | 0.645ms |
| Non-unique equality sweep | `DELETE FROM orders WHERE status = 'pending';` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 0.757ms |
| Boolean sweep via string | `DELETE FROM users WHERE is_archived = 'false';` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 0.797ms |
| Tenant-wide delete | `DELETE FROM users WHERE tenant_id = 1;` | **BLOCK** | PASS (BLOCK) | `UNSAFE_WHERE_BOUNDARY` | 0.923ms |
| DELETE USING tautology | `DELETE FROM users USING (SELECT 1 AS one) x WHERE x.one = 1;` | **BLOCK** | PASS (BLOCK) | `PARSE_FAILURE` | 1.278ms |
| UPDATE FROM tautology | `UPDATE users SET role = 'admin' FROM (SELECT 1 AS one) x WHERE x.one = 1;` | **BLOCK** | PASS (BLOCK) | `JOINED_MUTATION_BLOCKED, UNSAFE_WHERE_BOUNDARY` | 1.947ms |
| Upsert mass overwrite | `INSERT INTO users (id, role) SELECT id, 'admin' FROM users ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role;` | **BLOCK** | PASS (BLOCK) | `UNBOUNDED_UPSERT` | 2.877ms |
| DO block hides DELETE | `DO $$BEGIN DELETE FROM users; END$$;` | **BLOCK** | PASS (BLOCK) | `DISALLOWED_STATEMENT_TYPE, DESTRUCTIVE_DDL` | 0.270ms |
| DROP SCHEMA | `DROP SCHEMA public CASCADE;` | **BLOCK** | PASS (BLOCK) | `PARSE_FAILURE` | 0.472ms |
| Side-effect function | `SELECT wipe_everything();` | **BLOCK** | PASS (BLOCK) | `SIDE_EFFECT_FUNCTION` | 0.959ms |
| Bounded Single-Row DELETE | `DELETE FROM sessions WHERE session_id = 'abc-123';` | **ALLOW** | PASS (ALLOW) | `NONE` | 1.090ms |
| Bounded PK UPDATE | `UPDATE users SET last_login = NOW() WHERE id = 42;` | **ALLOW** | PASS (ALLOW) | `NONE` | 1.100ms |
| Bounded Composite AND Clause | `UPDATE orders SET status = 'shipped' WHERE id = 99 AND paid = true;` | **ALLOW** | PASS (ALLOW) | `NONE` | 1.525ms |
| Bounded IN List | `DELETE FROM notifications WHERE id IN (10, 11, 12);` | **ALLOW** | PASS (ALLOW) | `NONE` | 1.663ms |
| Typed param ($1::uuid) | `UPDATE users SET plan = 'pro' WHERE id = $1::uuid;` | **ALLOW** | PASS (ALLOW) | `NONE` | 1.388ms |
| ANY array param | `DELETE FROM notifications WHERE id = ANY($1);` | **ALLOW** | PASS (ALLOW) | `NONE` | 1.205ms |
| Negative id (-5) | `DELETE FROM t WHERE id = -5;` | **ALLOW** | PASS (ALLOW) | `NONE` | 0.857ms |

**Summary:** 28/28 passed (21/21 red-team vectors blocked, 7/7 legitimate parameterized/bounded queries allowed)  
**Warm Latency Benchmark (1,000 AST Evaluations):** `p50 = 0.346ms` | `p95 = 1.007ms` | `p99 = 1.575ms`

## Architectural Scope & Known Limits (v0.1 -> v0.2 Roadmap)

1. **Syntactic Identifier Bounding vs. Schema Cardinality:** Without live `pg_catalog` introspection, `isBounded()` enforces equality/IN-list predicates strictly on primary/unique identifier columns (`id`, `uuid`, `slug`, `email`, or configurable `UNIQUE_KEYS`, excluding multi-tenant keys like `tenant_id`, `org_id`, `workspace_id`). True row-cardinality guarantees in production require pairing with a DB-level transaction row-count cap and PostgreSQL Row-Level Security (RLS).
2. **Function & UDF Calls:** Built-in dangerous Postgres administrative/filesystem functions (`pg_sleep`, `pg_read_file`, `dblink_exec`, `lo_import`, `pg_terminate_backend`, etc.) and non-allowlisted UDFs (`SELECT custom_fn()`) are blocked across all AST `call` nodes unless explicitly allowlisted in `SAFE_SQL_FUNCTIONS`.
3. **Parser Engine (v0.2 Roadmap):** v0.1 uses `pgsql-ast-parser` (pure TypeScript) and fails closed (`PARSE_FAILURE`) on unsupported grammar. v0.2 migrates to `libpg-query` (native PostgreSQL C parser bindings) to eliminate parser differentials on PostgreSQL 16–18 syntax.
