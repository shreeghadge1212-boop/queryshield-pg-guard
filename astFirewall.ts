import { parse, Statement, Expr } from "pgsql-ast-parser";

export type RuleViolationCode =
  | "EMPTY_OR_INVALID_SQL"
  | "MULTI_STATEMENT"
  | "PARSE_FAILURE"
  | "DISALLOWED_STATEMENT_TYPE"
  | "DESTRUCTIVE_DDL"
  | "UNBOUNDED_MUTATION"
  | "UNSAFE_WHERE_BOUNDARY"
  | "JOINED_MUTATION_BLOCKED"
  | "UNBOUNDED_UPSERT"
  | "SIDE_EFFECT_FUNCTION"
  | "MISSING_TENANT_ISOLATION"
  | "CROSS_TENANT_SPOOFING";

export interface RuleViolation {
  rule: RuleViolationCode;
  detail: string;
}

export interface FirewallVerdict {
  decision: "allow" | "block";
  violations: RuleViolation[];
  latencyMs: number;
}

export interface FirewallOptions {
  /** Enforce that every SELECT/UPDATE/DELETE filters by a tenant identifier column */
  requireTenantFilter?: boolean;
  /** Allowed column names for tenant scoping (default: tenant_id, org_id, organization_id, workspace_id) */
  tenantColumns?: string[];
  /** Optional strict session tenant ID to prevent cross-tenant spoofing (e.g. WHERE tenant_id = 'other_org') */
  expectedTenantId?: string | number;
}

const DEFAULT_TENANT_COLUMNS = new Set([
  "tenant_id",
  "org_id",
  "organization_id",
  "workspace_id",
]);

// High-cardinality primary/unique key identifiers permitted to bound single-row or batch mutations
const BOUNDED_KEY_COLUMNS = new Set([
  "id",
  "user_id",
  "account_id",
  "session_id",
  "ticket_id",
  "order_id",
  "notification_id",
  "item_id",
  "webhook_id",
  "uuid",
]);

// Dangerous administrative or side-effect functions blocked in SELECT / expressions
const BLOCKED_FUNCTIONS = new Set([
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
  "lo_import",
  "lo_export",
  "wipe_everything",
]);

function stripSqlCommentsAndLiterals(sql: string): string {
  return sql
    .replace(/--.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/'(?:''|[^'])*'/g, "''");
}

function splitTopLevelSemicolons(sql: string): string[] {
  const stripped = stripSqlCommentsAndLiterals(sql).trim();
  return stripped
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function evaluateSql(
  sql: string,
  options: FirewallOptions = {}
): FirewallVerdict {
  const start = performance.now();
  const violations: RuleViolation[] = [];

  const addViolation = (rule: RuleViolationCode, detail: string) => {
    if (!violations.some((v) => v.rule === rule)) {
      violations.push({ rule, detail });
    }
  };

  if (!sql || typeof sql !== "string" || !sql.trim()) {
    addViolation("EMPTY_OR_INVALID_SQL", "SQL payload is empty or non-string.");
    return {
      decision: "block",
      violations,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  }

  const strippedRaw = stripSqlCommentsAndLiterals(sql).trim();
  const segments = splitTopLevelSemicolons(sql);

  // 1. Multi-statement piggyback detection before/alongside AST parse
  if (segments.length > 1) {
    addViolation(
      "MULTI_STATEMENT",
      `Multiple SQL statements detected (${segments.length}).`
    );
  }

  // Pre-AST check for PL/pgSQL DO blocks or raw DDL keywords in multi-statement payloads
  for (const seg of segments) {
    const upper = seg.toUpperCase();
    if (/^DO\b/.test(upper)) {
      addViolation(
        "DISALLOWED_STATEMENT_TYPE",
        "Anonymous PL/pgSQL DO blocks are prohibited."
      );
      addViolation(
        "DESTRUCTIVE_DDL",
        "Procedural block execution rejected."
      );
    }
    if (/^(DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b/.test(upper)) {
      addViolation(
        "DISALLOWED_STATEMENT_TYPE",
        `Statement starting with DDL/admin keyword is prohibited.`
      );
      addViolation(
        "DESTRUCTIVE_DDL",
        "Destructive DDL or privilege mutation detected."
      );
    }
  }

  if (violations.length > 0) {
    return {
      decision: "block",
      violations,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  }

  // 2. Deterministic AST Parse (Fail-Closed on any parser failure)
  let ast: Statement[];
  try {
    ast = parse(sql);
  } catch (err: any) {
    addViolation(
      "PARSE_FAILURE",
      `Fail-closed AST parse error: ${err?.message || "Unsupported SQL syntax"}`
    );
    return {
      decision: "block",
      violations,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  }

  if (!ast || ast.length === 0) {
    addViolation("PARSE_FAILURE", "Parser returned zero AST statements.");
    return {
      decision: "block",
      violations,
      latencyMs: Number((performance.now() - start).toFixed(3)),
    };
  }

  if (ast.length > 1) {
    addViolation(
      "MULTI_STATEMENT",
      `AST contains ${ast.length} chained statements.`
    );
  }

  const tenantCols = options.tenantColumns
    ? new Set(options.tenantColumns.map((c) => c.toLowerCase()))
    : DEFAULT_TENANT_COLUMNS;

  // 3. Inspect every statement in the AST
  for (const stmt of ast) {
    inspectStatement(stmt, addViolation, options, tenantCols);
  }

  return {
    decision: violations.length > 0 ? "block" : "allow",
    violations,
    latencyMs: Number((performance.now() - start).toFixed(3)),
  };
}

function inspectStatement(
  stmt: any,
  addViolation: (rule: RuleViolationCode, detail: string) => void,
  options: FirewallOptions,
  tenantCols: Set<string>
): void {
  if (!stmt || typeof stmt !== "object") {
    addViolation("PARSE_FAILURE", "Invalid AST statement node.");
    return;
  }

  // Inspect CTEs (WITH ... AS (...)) recursively so destructive CTE wrappers are caught
  if (stmt.type === "with" && Array.isArray(stmt.bind)) {
    for (const cte of stmt.bind) {
      if (cte.statement) {
        inspectStatement(cte.statement, addViolation, options, tenantCols);
      }
    }
    if (stmt.in) {
      inspectStatement(stmt.in, addViolation, options, tenantCols);
    }
    return;
  }

  const stmtType = stmt.type;

  // Allow only SELECT, INSERT, UPDATE, DELETE
  if (
    stmtType !== "select" &&
    stmtType !== "insert" &&
    stmtType !== "update" &&
    stmtType !== "delete"
  ) {
    addViolation(
      "DISALLOWED_STATEMENT_TYPE",
      `Statement type '${stmtType}' is not permitted.`
    );
    addViolation(
      "DESTRUCTIVE_DDL",
      `Blocked non-DML statement '${stmtType}'.`
    );
    return;
  }

  // Check for side-effect functions across projections and WHERE clauses
  scanForBlockedFunctions(stmt, addViolation);

  // Check INSERT ... ON CONFLICT DO UPDATE (Upsert mass overwrite)
  if (stmtType === "insert") {
    if (stmt.insert && stmt.insert.type === "select") {
      if (stmt.onConflict && stmt.onConflict.do && stmt.onConflict.do !== "do nothing") {
        if (!stmt.insert.where || !isBoundedWhere(stmt.insert.where)) {
          addViolation(
            "UNBOUNDED_UPSERT",
            "INSERT ... SELECT with ON CONFLICT DO UPDATE lacks bounded WHERE clause."
          );
        }
      }
    }
    return;
  }

  // Check SELECT statements
  if (stmtType === "select") {
    if (options.requireTenantFilter) {
      enforceTenantScope(stmt.where, addViolation, options, tenantCols);
    }
    return;
  }

  // Check UPDATE and DELETE mutations
  if (stmtType === "update" || stmtType === "delete") {
    // Block UPDATE ... FROM or DELETE ... USING joined mutations
    // Block UPDATE ... FROM or DELETE ... USING joined mutations
    if ((stmtType === "update" && stmt.from) || (stmtType === "delete" && stmt.using)) {
      addViolation(
        "JOINED_MUTATION_BLOCKED",
        `${stmtType.toUpperCase()} with joined FROM/USING clause is blocked.`
      );
    }

    if (!stmt.where) {
      addViolation(
        "UNBOUNDED_MUTATION",
        `${stmtType.toUpperCase()} statement is missing a WHERE clause.`
      );
      return;
    }

    if (!isBoundedWhere(stmt.where)) {
      addViolation(
        "UNSAFE_WHERE_BOUNDARY",
        `${stmtType.toUpperCase()} WHERE clause does not deterministically bound a primary/unique key.`
      );
    }

    if (options.requireTenantFilter) {
      enforceTenantScope(stmt.where, addViolation, options, tenantCols);
    }
  }
}

function enforceTenantScope(
  whereExpr: Expr | undefined,
  addViolation: (rule: RuleViolationCode, detail: string) => void,
  options: FirewallOptions,
  tenantCols: Set<string>
): void {
  if (!whereExpr) {
    addViolation(
      "MISSING_TENANT_ISOLATION",
      "Query is missing a WHERE clause containing a mandatory tenant filter."
    );
    return;
  }

  const result = checkTenantExpr(whereExpr, tenantCols, options.expectedTenantId);
  if (result.spoofed) {
    addViolation(
      "CROSS_TENANT_SPOOFING",
      `Tenant filter value does not match authorized tenant '${options.expectedTenantId}'.`
    );
  } else if (!result.hasValidTenantFilter) {
    addViolation(
      "MISSING_TENANT_ISOLATION",
      `Query WHERE clause must enforce equality on one of: ${Array.from(tenantCols).join(", ")}.`
    );
  }
}

function checkTenantExpr(
  expr: any,
  tenantCols: Set<string>,
  expectedTenantId?: string | number
): { hasValidTenantFilter: boolean; spoofed: boolean } {
  if (!expr || typeof expr !== "object") {
    return { hasValidTenantFilter: false, spoofed: false };
  }

  if (expr.type === "binary") {
    const op = String(expr.op).toUpperCase();

    if (op === "AND") {
      const left = checkTenantExpr(expr.left, tenantCols, expectedTenantId);
      const right = checkTenantExpr(expr.right, tenantCols, expectedTenantId);
      return {
        hasValidTenantFilter:
          (left.hasValidTenantFilter || right.hasValidTenantFilter) &&
          !left.spoofed &&
          !right.spoofed,
        spoofed: left.spoofed || right.spoofed,
      };
    }

    // In an OR branch, BOTH sides must be tenant-scoped to prevent `(tenant_id = 'a' OR 1=1)`
    if (op === "OR") {
      const left = checkTenantExpr(expr.left, tenantCols, expectedTenantId);
      const right = checkTenantExpr(expr.right, tenantCols, expectedTenantId);
      return {
        hasValidTenantFilter: left.hasValidTenantFilter && right.hasValidTenantFilter,
        spoofed: left.spoofed || right.spoofed,
      };
    }

    if (op === "=") {
      const colName = extractColumnName(expr.left);
      const literalVal = extractScalarValue(expr.right);

      if (colName && tenantCols.has(colName) && isSafeScalarOrParam(expr.right)) {
        if (
          expectedTenantId !== undefined &&
          literalVal !== null &&
          String(literalVal) !== String(expectedTenantId)
        ) {
          return { hasValidTenantFilter: false, spoofed: true };
        }
        return { hasValidTenantFilter: true, spoofed: false };
      }
    }
  }

  return { hasValidTenantFilter: false, spoofed: false };
}

function isBoundedWhere(expr: any): boolean {
  if (!expr || typeof expr !== "object") return false;

  if (expr.type === "binary") {
    const op = String(expr.op).toUpperCase();

    if (op === "AND") {
      // If either side has a tautology, reject; otherwise require at least one bounded key
      if (isTautologyOrSweep(expr.left) || isTautologyOrSweep(expr.right)) {
        return false;
      }
      return isBoundedWhere(expr.left) || isBoundedWhere(expr.right);
    }

    if (op === "OR") {
      // Every branch of an OR must independently be safely bounded
      return isBoundedWhere(expr.left) && isBoundedWhere(expr.right);
    }

    if (op === "=") {
      const leftCol = extractColumnName(expr.left);
      const rightCol = extractColumnName(expr.right);

      // Block column self-comparison (e.g. WHERE id = id)
      if (leftCol && rightCol) return false;

      if (leftCol && BOUNDED_KEY_COLUMNS.has(leftCol)) {
        return isSafeScalarOrParam(expr.right);
      }
      return false;
    }

    if (op === "IN") {
      const leftCol = extractColumnName(expr.left);
      if (!leftCol || !BOUNDED_KEY_COLUMNS.has(leftCol)) return false;

      if (expr.right && expr.right.type === "list" && Array.isArray(expr.right.expressions)) {
        return (
          expr.right.expressions.length > 0 &&
          expr.right.expressions.length <= 100 &&
          expr.right.expressions.every((item: any) => isSafeScalarOrParam(item))
        );
      }
      return false;
    }
  }

  return false;
}

function isTautologyOrSweep(expr: any): boolean {
  if (!expr || typeof expr !== "object") return true;

  if (expr.type === "binary") {
    const op = String(expr.op).toUpperCase();
    if (op === "OR") {
      return isTautologyOrSweep(expr.left) || isTautologyOrSweep(expr.right);
    }
    if (op === "AND") {
      return isTautologyOrSweep(expr.left) || isTautologyOrSweep(expr.right);
    }
    if (op === "=") {
      const leftCol = extractColumnName(expr.left);
      const rightCol = extractColumnName(expr.right);
      if (leftCol && rightCol && leftCol === rightCol) return true;
      if (!leftCol && !rightCol) return true; // Constant comparison like 1 = 1
      return false;
    }
    if (["!=", "<>", ">", "<", ">=", "<=", "LIKE", "ILIKE"].includes(op)) {
      return true;
    }
  }

  if (expr.type === "unary") {
    const op = String(expr.op).toUpperCase();
    if (op.includes("NULL") || op === "NOT") return true;
  }

  return false;
}

function extractColumnName(node: any): string | null {
  if (!node || typeof node !== "object") return null;
  if (node.type === "ref" && typeof node.name === "string") {
    return node.name.toLowerCase();
  }
  return null;
}

function extractScalarValue(node: any): string | number | boolean | null {
  if (!node || typeof node !== "object") return null;
  if (
    node.type === "string" ||
    node.type === "integer" ||
    node.type === "numeric" ||
    node.type === "boolean"
  ) {
    return node.value;
  }
  return null;
}

function isSafeScalarOrParam(node: any): boolean {
  if (!node || typeof node !== "object") return false;

  if (node.type === "string") {
    const val = String(node.value).trim().toLowerCase();
    if (val === "true" || val === "false" || val === "%" || val === "") {
      return false;
    }
    return true;
  }

  if (node.type === "integer" || node.type === "numeric") {
    return true;
  }

  if (node.type === "parameter") {
    return true;
  }

  // Support typed parameters like $1::uuid
  if (node.type === "cast") {
    return isSafeScalarOrParam(node.operand);
  }

  // Support negative numbers like -5
  if (node.type === "unary" && (node.op === "-" || node.op === "+")) {
    return (
      node.operand &&
      (node.operand.type === "integer" || node.operand.type === "numeric")
    );
  }

  // Support ANY($1) array parameter binding
  if (
    node.type === "call" &&
    node.function &&
    String(node.function.name).toLowerCase() === "any" &&
    Array.isArray(node.args) &&
    node.args.length === 1
  ) {
    return isSafeScalarOrParam(node.args[0]);
  }

  if (node.type === "array select" && node.expr) {
    return isSafeScalarOrParam(node.expr);
  }

  return false;
}

function scanForBlockedFunctions(
  node: any,
  addViolation: (rule: RuleViolationCode, detail: string) => void
): void {
  if (!node || typeof node !== "object") return;

  if (node.type === "call" && node.function && typeof node.function.name === "string") {
    const fnName = node.function.name.toLowerCase();
    if (BLOCKED_FUNCTIONS.has(fnName)) {
      addViolation(
        "SIDE_EFFECT_FUNCTION",
        `Execution of administrative/side-effect function '${fnName}()' is blocked.`
      );
    }
  }

  for (const key of Object.keys(node)) {
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        scanForBlockedFunctions(item, addViolation);
      }
    } else if (child && typeof child === "object") {
      scanForBlockedFunctions(child, addViolation);
    }
  }
}
