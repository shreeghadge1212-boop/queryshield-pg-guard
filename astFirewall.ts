import { parse, Expr } from "pgsql-ast-parser";

export type Decision = "allow" | "block";

export interface PolicyViolation {
  rule: string;
  detail: string;
}

export interface PolicyVerdict {
  decision: Decision;
  violations: PolicyViolation[];
  evaluatedAt: number;
  latencyMs: number;
}

export interface FirewallConfig {
  uniqueKeys?: Set<string>;
  safeFunctions?: Set<string>;
}

const ALLOWED_TOP_LEVEL_STMTS = new Set([
  "select",
  "insert",
  "update",
  "delete",
  "with",
  "with recursive",
  "union",
  "values",
]);

const DESTRUCTIVE_DDL = new Set([
  "drop table",
  "drop index",
  "drop sequence",
  "drop schema",
  "drop database",
  "drop view",
  "truncate table",
  "alter table",
  "create function",
  "do",
]);

const BOUNDED_MUTATION = new Set(["update", "delete"]);
const SAFE_CONST_TYPES = new Set(["integer", "numeric", "string", "parameter"]);

// Multi-tenant & low-cardinality keys that must NEVER count as single-row bounds
const MULTI_TENANT_OR_SWEEP_KEYS = new Set([
  "tenant_id",
  "org_id",
  "organization_id",
  "workspace_id",
  "company_id",
  "account_id",
  "team_id",
  "project_id",
  "role_id",
  "plan_id",
  "status_id",
  "type_id",
  "category_id",
  "group_id",
  "country_id",
  "region_id",
]);

// Default explicit unique identifier columns (configurable via FirewallConfig.uniqueKeys)
export const DEFAULT_UNIQUE_KEYS = new Set([
  "id",
  "uuid",
  "guid",
  "slug",
  "email",
  "username",
  "pk",
  "token",
  "session_token",
  "api_key",
  "code",
]);

// Pure read-only SQL scalar & aggregate functions allowed across AST call nodes
export const DEFAULT_SAFE_SQL_FUNCTIONS = new Set([
  "now",
  "current_timestamp",
  "current_date",
  "version",
  "gen_random_uuid",
  "uuid_generate_v4",
  "coalesce",
  "nullif",
  "lower",
  "upper",
  "trim",
  "btrim",
  "ltrim",
  "rtrim",
  "length",
  "char_length",
  "substring",
  "replace",
  "concat",
  "concat_ws",
  "left",
  "right",
  "round",
  "floor",
  "ceil",
  "ceiling",
  "abs",
  "count",
  "sum",
  "avg",
  "min",
  "max",
  "date_trunc",
  "date_part",
  "extract",
  "age",
  "to_char",
  "to_date",
  "to_timestamp",
  "json_build_object",
  "jsonb_build_object",
  "json_agg",
  "jsonb_agg",
  "array_agg",
  "string_agg",
  "any",
]);

const DANGEROUS_PG_FUNCTIONS = new Set([
  "pg_sleep",
  "pg_read_file",
  "pg_read_binary_file",
  "pg_ls_dir",
  "pg_stat_file",
  "pg_terminate_backend",
  "pg_cancel_backend",
  "pg_reload_conf",
  "pg_rotate_logfile",
  "dblink",
  "dblink_exec",
  "dblink_connect",
  "lo_import",
  "lo_export",
  "query_to_xml",
]);

const MAX_AST_DEPTH = 64;

function walk(
  node: unknown,
  visit: (n: Record<string, unknown>) => void,
  depth = 0
): void {
  if (depth > MAX_AST_DEPTH) {
    throw new Error("AST_MAX_DEPTH_EXCEEDED");
  }
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit, depth + 1);
    return;
  }
  const obj = node as Record<string, unknown>;
  if (typeof obj.type === "string") visit(obj);
  for (const value of Object.values(obj)) {
    walk(value, visit, depth + 1);
  }
}

function unwrapOperand(node: any): any {
  let curr = node;
  let steps = 0;
  while (curr && typeof curr === "object" && steps < 8) {
    steps++;
    if (curr.type === "cast" && curr.operand) {
      curr = curr.operand;
      continue;
    }
    if (
      curr.type === "unary" &&
      (curr.op === "-" || curr.op === "+") &&
      curr.operand &&
      SAFE_CONST_TYPES.has(curr.operand.type)
    ) {
      return curr.operand;
    }
    break;
  }
  return curr;
}

function isValidBoundedColumnRef(
  refNode: any,
  targetTable?: string,
  uniqueKeys: Set<string> = DEFAULT_UNIQUE_KEYS
): boolean {
  if (!refNode || refNode.type !== "ref") return false;
  const colName = String(refNode.name || "").toLowerCase();
  if (!colName || colName === "*") return false;

  const refTable = refNode.table?.name
    ? String(refNode.table.name).toLowerCase()
    : null;
  if (refTable && targetTable && refTable !== targetTable.toLowerCase()) {
    return false;
  }

  // Block boolean flags and multi-tenant/low-cardinality keys
  if (
    colName.startsWith("is_") ||
    colName.startsWith("has_") ||
    MULTI_TENANT_OR_SWEEP_KEYS.has(colName)
  ) {
    return false;
  }

  // Allowlist check: must be in explicit unique keys or end with a unique key suffix
  if (uniqueKeys.has(colName)) return true;
  if (
    colName.endsWith("_id") ||
    colName.endsWith("_uuid") ||
    colName.endsWith("_key") ||
    colName.endsWith("_token")
  ) {
    return true;
  }

  return false;
}

function isSafeAnyExpression(rightNode: any): boolean {
  if (!rightNode || typeof rightNode !== "object") return false;
  if (rightNode.type === "call") {
    const fnName = String(rightNode.function?.name || "").toLowerCase();
    const args = Array.isArray(rightNode.args) ? rightNode.args : [];
    return (
      fnName === "any" &&
      args.length === 1 &&
      SAFE_CONST_TYPES.has(unwrapOperand(args[0])?.type)
    );
  }
  return false;
}

export function isBounded(
  e: Expr | undefined | null,
  targetTable?: string,
  uniqueKeys: Set<string> = DEFAULT_UNIQUE_KEYS
): boolean {
  if (!e || typeof e !== "object") return false;

  if (e.type === "binary") {
    if (e.op === "AND") {
      return (
        isBounded(e.left, targetTable, uniqueKeys) ||
        isBounded(e.right, targetTable, uniqueKeys)
      );
    }
    if (e.op === "OR") {
      return (
        isBounded(e.left, targetTable, uniqueKeys) &&
        isBounded(e.right, targetTable, uniqueKeys)
      );
    }
    if (e.op === "=" || (e.op as string) === "= ANY") {
      const left = unwrapOperand(e.left);
      const right = unwrapOperand(e.right);

      const leftIsRef = isValidBoundedColumnRef(left, targetTable, uniqueKeys);
      const rightIsRef = isValidBoundedColumnRef(right, targetTable, uniqueKeys);

      if (left?.type === "ref" && right?.type === "ref") return false;
      if (leftIsRef && isSafeAnyExpression(right)) return true;

      const leftIsConst = SAFE_CONST_TYPES.has(left?.type as string);
      const rightIsConst = SAFE_CONST_TYPES.has(right?.type as string);

      return (leftIsRef && rightIsConst) || (rightIsRef && leftIsConst);
    }
    if (e.op === "IN") {
      const left = unwrapOperand(e.left);
      const rightNode = e.right as any;
      if (
        isValidBoundedColumnRef(left, targetTable, uniqueKeys) &&
        rightNode?.type === "list" &&
        Array.isArray(rightNode.expressions)
      ) {
        return (
          rightNode.expressions.length > 0 &&
          rightNode.expressions.length <= 100 &&
          rightNode.expressions.every((item: any) =>
            SAFE_CONST_TYPES.has(unwrapOperand(item)?.type)
          )
        );
      }
      return false;
    }
  }
  return false;
}

export function evaluateSql(
  sql: string,
  config?: FirewallConfig
): PolicyVerdict {
  const start = performance.now();
  const violations: PolicyViolation[] = [];
  const uniqueKeys = config?.uniqueKeys ?? DEFAULT_UNIQUE_KEYS;
  const safeFunctions = config?.safeFunctions ?? DEFAULT_SAFE_SQL_FUNCTIONS;

  if (!sql || sql.length > 16384) {
    return {
      decision: "block",
      violations: [
        {
          rule: "PAYLOAD_LIMIT",
          detail: "SQL query empty or exceeds 16KB AST limit",
        },
      ],
      evaluatedAt: Date.now(),
      latencyMs: performance.now() - start,
    };
  }

  let statements: any[];
  try {
    statements = parse(sql);
  } catch (err) {
    return {
      decision: "block",
      violations: [
        {
          rule: "PARSE_FAILURE",
          detail: `SQL failed to parse: ${(err as Error).message}`,
        },
      ],
      evaluatedAt: Date.now(),
      latencyMs: performance.now() - start,
    };
  }

  if (statements.length === 0) {
    return {
      decision: "block",
      violations: [
        { rule: "EMPTY_STATEMENT", detail: "No valid SQL statement found" },
      ],
      evaluatedAt: Date.now(),
      latencyMs: performance.now() - start,
    };
  }

  if (statements.length > 1) {
    violations.push({
      rule: "MULTI_STATEMENT",
      detail: `${statements.length} statements in one payload`,
    });
  }

  for (const stmt of statements) {
    const topType = String(stmt?.type || "").toLowerCase();
    if (!ALLOWED_TOP_LEVEL_STMTS.has(topType)) {
      violations.push({
        rule: "DISALLOWED_STATEMENT_TYPE",
        detail: `Top-level statement type "${topType}" is not allowlisted`,
      });
    }
  }

  try {
    walk(statements, (node) => {
      const nodeType = String(node.type || "").toLowerCase();

      if (DESTRUCTIVE_DDL.has(nodeType)) {
        violations.push({
          rule: "DESTRUCTIVE_DDL",
          detail: `Blocked statement type "${nodeType}"`,
        });
      }

      // Check EVERY function call node across the entire AST (with or without FROM)
      if (nodeType === "call") {
        const fnName = String((node.function as any)?.name || "").toLowerCase();
        if (DANGEROUS_PG_FUNCTIONS.has(fnName)) {
          violations.push({
            rule: "DANGEROUS_FUNCTION_CALL",
            detail: `Blocked dangerous Postgres function "${fnName}()"`,
          });
        } else if (fnName && !safeFunctions.has(fnName)) {
          violations.push({
            rule: "UNTRUSTED_FUNCTION_CALL",
            detail: `Non-allowlisted function "${fnName}()" is blocked`,
          });
        }
      }

      if (nodeType === "insert" && node.onConflict) {
        const onConflict = node.onConflict as any;
        if (
          onConflict.do &&
          typeof onConflict.do === "object" &&
          Array.isArray(onConflict.do.sets)
        ) {
          const targetTable = String((node.into as any)?.name || "");
          if (
            !onConflict.do.where ||
            !isBounded(onConflict.do.where as Expr, targetTable, uniqueKeys)
          ) {
            violations.push({
              rule: "UNBOUNDED_UPSERT",
              detail:
                "ON CONFLICT DO UPDATE requires a bounded WHERE clause on the conflict update",
            });
          }
        }
      }

      if (BOUNDED_MUTATION.has(nodeType)) {
        const isJoinedUpdate = nodeType === "update" && Boolean(node.from);
        const isJoinedDelete =
          nodeType === "delete" && Boolean((node as any).using);
        if (isJoinedUpdate || isJoinedDelete) {
          violations.push({
            rule: "JOINED_MUTATION_BLOCKED",
            detail: `"${nodeType}" with FROM/USING join is disallowed`,
          });
        }

        const targetTable = String(
          nodeType === "update"
            ? (node.table as any)?.name || ""
            : (node.from as any)?.name || ""
        );
        const where = node.where as Expr | undefined;
        if (!where) {
          violations.push({
            rule: "UNBOUNDED_MUTATION",
            detail: `"${nodeType}" has no WHERE clause`,
          });
        } else if (!isBounded(where, targetTable, uniqueKeys)) {
          violations.push({
            rule: "UNSAFE_WHERE_BOUNDARY",
            detail: `"${nodeType}" WHERE clause is not syntactically bounded to a unique identifier`,
          });
        }
      }
    });
  } catch (walkErr: any) {
    violations.push({
      rule: "AST_WALK_LIMIT",
      detail: walkErr.message || "AST traversal limit exceeded",
    });
  }

  return {
    decision: violations.length === 0 ? "allow" : "block",
    violations,
    evaluatedAt: Date.now(),
    latencyMs: performance.now() - start,
  };
}