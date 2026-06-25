// qbo.ts — QuickBooks Online access layer for the Recategorizer tool.
//
// Reuses the existing redhammer-qbo project's `qbo_tokens` table and Intuit
// app credentials (QBO_CLIENT_ID / QBO_CLIENT_SECRET / QBO_ENVIRONMENT).
// Token refresh mirrors the existing safe compare-and-swap pattern so this
// tool never clobbers the live MCP connection.

const PROD_BASE = "https://quickbooks.api.intuit.com";
const SANDBOX_BASE = "https://sandbox-quickbooks.api.intuit.com";
const TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
const MINOR_VERSION = "75";
const PROACTIVE_REFRESH_MS = 5 * 60 * 1000;

const CLIENT_ID = Deno.env.get("QBO_CLIENT_ID") ?? "";
const CLIENT_SECRET = Deno.env.get("QBO_CLIENT_SECRET") ?? "";
const ENVIRONMENT = Deno.env.get("QBO_ENVIRONMENT") ?? "production";
const API_BASE = ENVIRONMENT === "production" ? PROD_BASE : SANDBOX_BASE;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

// deno-lint-ignore no-explicit-any
type Any = any;

function sbHeaders(): HeadersInit {
  return {
    apikey: SERVICE_ROLE,
    Authorization: `Bearer ${SERVICE_ROLE}`,
    "Content-Type": "application/json",
  };
}

interface TokenRow {
  realm_id: string;
  access_token: string;
  refresh_token: string;
  access_token_expires_at: string;
  refresh_token_expires_at: string | null;
  company_name: string | null;
}

async function getTokenRow(realmId: string): Promise<TokenRow | null> {
  const url =
    `${SUPABASE_URL}/rest/v1/qbo_tokens?realm_id=eq.${encodeURIComponent(realmId)}&select=*`;
  const res = await fetch(url, { headers: sbHeaders() });
  if (!res.ok) throw new Error(`token read failed: ${res.status} ${await res.text()}`);
  const rows = (await res.json()) as TokenRow[];
  return rows[0] ?? null;
}

export async function listRealms(): Promise<{ realm_id: string; company_name: string | null }[]> {
  const url =
    `${SUPABASE_URL}/rest/v1/qbo_tokens?select=realm_id,company_name&order=company_name.asc`;
  const res = await fetch(url, { headers: sbHeaders() });
  if (!res.ok) throw new Error(`realm list failed: ${res.status}`);
  return await res.json();
}

// Compare-and-swap: only writes if the refresh_token still matches what we read,
// so two concurrent refreshes can't clobber each other.
async function casUpdate(
  realmId: string,
  expectedRefresh: string,
  rec: Record<string, unknown>,
): Promise<TokenRow | null> {
  const url = `${SUPABASE_URL}/rest/v1/qbo_tokens?realm_id=eq.${encodeURIComponent(realmId)}` +
    `&refresh_token=eq.${encodeURIComponent(expectedRefresh)}`;
  const res = await fetch(url, {
    method: "PATCH",
    headers: { ...sbHeaders(), Prefer: "return=representation" },
    body: JSON.stringify(rec),
  });
  if (!res.ok) throw new Error(`token CAS failed: ${res.status} ${await res.text()}`);
  const rows = (await res.json()) as TokenRow[];
  return rows[0] ?? null;
}

async function refreshToken(row: TokenRow): Promise<string> {
  const basic = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: row.refresh_token,
  });
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });
  if (!res.ok) {
    // Another process may have already rotated the token; re-read and use it.
    const fresh = await getTokenRow(row.realm_id);
    if (fresh && Date.parse(fresh.access_token_expires_at) - Date.now() > 0) {
      return fresh.access_token;
    }
    throw new Error(`token refresh failed: ${res.status} ${await res.text()}`);
  }
  const tok = (await res.json()) as Any;
  const now = Date.now();
  const rec = {
    access_token: tok.access_token,
    refresh_token: tok.refresh_token ?? row.refresh_token,
    access_token_expires_at: new Date(now + (tok.expires_in ?? 3600) * 1000).toISOString(),
    refresh_token_expires_at: tok.x_refresh_token_expires_in
      ? new Date(now + tok.x_refresh_token_expires_in * 1000).toISOString()
      : row.refresh_token_expires_at,
    updated_at: new Date(now).toISOString(),
  };
  const updated = await casUpdate(row.realm_id, row.refresh_token, rec);
  if (!updated) {
    // Concurrent rotation won the race; use whatever is current now.
    const fresh = await getTokenRow(row.realm_id);
    if (fresh) return fresh.access_token;
  }
  return rec.access_token;
}

async function getAccessToken(realmId: string): Promise<string> {
  const row = await getTokenRow(realmId);
  if (!row) throw new Error(`No QuickBooks connection found for realm ${realmId}`);
  const exp = Date.parse(row.access_token_expires_at);
  if (isNaN(exp) || exp - Date.now() < PROACTIVE_REFRESH_MS) {
    return await refreshToken(row);
  }
  return row.access_token;
}

export async function qbo(
  realmId: string,
  method: string,
  path: string,
  body?: unknown,
  extraQuery?: Record<string, string>,
): Promise<Any> {
  let token = await getAccessToken(realmId);
  const doFetch = async (tok: string) => {
    const url = new URL(
      `${API_BASE}/v3/company/${encodeURIComponent(realmId)}/${path.replace(/^\//, "")}`,
    );
    url.searchParams.set("minorversion", MINOR_VERSION);
    if (extraQuery) {
      for (const [k, v] of Object.entries(extraQuery)) url.searchParams.set(k, v);
    }
    return await fetch(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${tok}`,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  };
  let res = await doFetch(token);
  if (res.status === 401) {
    const row = await getTokenRow(realmId);
    if (row) {
      token = await refreshToken(row);
      res = await doFetch(token);
    }
  }
  const text = await res.text();
  let json: Any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  if (!res.ok) {
    throw new Error(`QBO ${res.status}: ${typeof json === "string" ? json : JSON.stringify(json)}`);
  }
  return json;
}

async function qboQuery(realmId: string, query: string): Promise<Any> {
  const res = await qbo(realmId, "GET", "query", undefined, { query });
  return res.QueryResponse ?? {};
}

async function queryAll(
  realmId: string,
  entity: string,
  fields: string,
  whereClause = "",
  orderBy = "",
  cap = 100000,
): Promise<Any[]> {
  const page = 1000;
  let start = 1;
  const out: Any[] = [];
  while (out.length < cap) {
    const q = `SELECT ${fields} FROM ${entity}${whereClause}${orderBy}` +
      ` STARTPOSITION ${start} MAXRESULTS ${page}`;
    const qr = await qboQuery(realmId, q);
    const arr = (qr[entity] ?? []) as Any[];
    out.push(...arr);
    if (arr.length < page) break;
    start += page;
  }
  return out;
}

export async function getRefData(realmId: string): Promise<Any> {
  const [accounts, items, customers, vendors] = await Promise.all([
    queryAll(realmId, "Account", "Id, Name, FullyQualifiedName, AccountType, AccountSubType, Active"),
    queryAll(realmId, "Item", "Id, Name, FullyQualifiedName, Type, Active"),
    queryAll(realmId, "Customer", "Id, DisplayName, Active"),
    queryAll(realmId, "Vendor", "Id, DisplayName, Active"),
  ]);
  return {
    accounts: accounts.map((a) => ({
      id: a.Id,
      name: a.FullyQualifiedName || a.Name,
      type: a.AccountType,
      subtype: a.AccountSubType,
      active: a.Active,
    })),
    items: items.map((i) => ({
      id: i.Id,
      name: i.FullyQualifiedName || i.Name,
      type: i.Type,
      active: i.Active,
    })),
    customers: customers.map((c) => ({ id: c.Id, name: c.DisplayName, active: c.Active })),
    vendors: vendors.map((v) => ({ id: v.Id, name: v.DisplayName, active: v.Active })),
  };
}

const ENTITY_PATH: Record<string, string> = {
  Purchase: "purchase",
  Bill: "bill",
  Invoice: "invoice",
};

function flatten(txn: Any, txnType: string): Any[] {
  const rows: Any[] = [];
  let friendly = txnType;
  let entityType = "";
  let entityId = "";
  let entityName = "";
  if (txnType === "Purchase") {
    friendly = txn.PaymentType === "Check" ? "Check" : "Expense";
    if (txn.EntityRef) {
      entityType = txn.EntityRef.type || "Vendor";
      entityId = txn.EntityRef.value;
      entityName = txn.EntityRef.name || "";
    }
  } else if (txnType === "Bill") {
    friendly = "Bill";
    if (txn.VendorRef) {
      entityType = "Vendor";
      entityId = txn.VendorRef.value;
      entityName = txn.VendorRef.name || "";
    }
  } else if (txnType === "Invoice") {
    friendly = "Invoice";
    if (txn.CustomerRef) {
      entityType = "Customer";
      entityId = txn.CustomerRef.value;
      entityName = txn.CustomerRef.name || "";
    }
  }
  const base = {
    txnType,
    friendlyType: friendly,
    txnId: txn.Id,
    syncToken: txn.SyncToken,
    txnDate: txn.TxnDate || "",
    total: txn.TotalAmt ?? 0,
    docNumber: txn.DocNumber || "",
    memo: txn.PrivateNote || "",
    entityType,
    entityId,
    entityName,
  };
  for (const line of (txn.Line || [])) {
    let kind = "other";
    let accountId = "", accountName = "", itemId = "", itemName = "";
    let lineCustomerId = "", lineCustomerName = "";
    let qty: Any = null, rate: Any = null;
    const dt = line.DetailType;
    if (dt === "AccountBasedExpenseLineDetail" && line.AccountBasedExpenseLineDetail) {
      const d = line.AccountBasedExpenseLineDetail;
      kind = "account";
      accountId = d.AccountRef?.value || "";
      accountName = d.AccountRef?.name || "";
      lineCustomerId = d.CustomerRef?.value || "";
      lineCustomerName = d.CustomerRef?.name || "";
    } else if (dt === "ItemBasedExpenseLineDetail" && line.ItemBasedExpenseLineDetail) {
      const d = line.ItemBasedExpenseLineDetail;
      kind = "item";
      itemId = d.ItemRef?.value || "";
      itemName = d.ItemRef?.name || "";
      lineCustomerId = d.CustomerRef?.value || "";
      lineCustomerName = d.CustomerRef?.name || "";
      qty = d.Qty ?? null;
      rate = d.UnitPrice ?? null;
    } else if (dt === "SalesItemLineDetail" && line.SalesItemLineDetail) {
      const d = line.SalesItemLineDetail;
      kind = "item";
      itemId = d.ItemRef?.value || "";
      itemName = d.ItemRef?.name || "";
      qty = d.Qty ?? null;
      rate = d.UnitPrice ?? null;
    } else {
      continue; // subtotal/discount/group lines: not editable, but preserved on save
    }
    rows.push({
      ...base,
      lineId: line.Id != null ? String(line.Id) : "",
      lineNum: line.LineNum ?? null,
      kind,
      accountId,
      accountName,
      itemId,
      itemName,
      amount: line.Amount ?? 0,
      qty,
      rate,
      lineDesc: line.Description || "",
      lineCustomerId,
      lineCustomerName,
    });
  }
  return rows;
}

async function fetchEntity(
  realmId: string,
  entity: string,
  whereClause: string,
  cap: number,
): Promise<Any[]> {
  return await queryAll(realmId, entity, "*", whereClause, " ORDERBY TxnDate DESC", cap);
}

export async function search(realmId: string, opts: Any): Promise<Any[]> {
  const allTypes = ["Check", "Expense", "Bill", "Invoice"];
  const types = new Set<string>(
    opts.types && opts.types.length ? opts.types : allTypes,
  );
  const cap = opts.max || 2000;
  const where = () => {
    const parts: string[] = [];
    if (opts.dateFrom) parts.push(`TxnDate >= '${opts.dateFrom}'`);
    if (opts.dateTo) parts.push(`TxnDate <= '${opts.dateTo}'`);
    return parts.length ? " WHERE " + parts.join(" AND ") : "";
  };
  const tasks: Promise<Any[]>[] = [];
  const labels: string[] = [];
  if (types.has("Check") || types.has("Expense")) {
    tasks.push(fetchEntity(realmId, "Purchase", where(), cap));
    labels.push("Purchase");
  }
  if (types.has("Bill")) {
    tasks.push(fetchEntity(realmId, "Bill", where(), cap));
    labels.push("Bill");
  }
  if (types.has("Invoice")) {
    tasks.push(fetchEntity(realmId, "Invoice", where(), cap));
    labels.push("Invoice");
  }
  const results = await Promise.all(tasks);
  let rows: Any[] = [];
  results.forEach((list, i) => {
    for (const txn of list) rows = rows.concat(flatten(txn, labels[i]));
  });
  const text = (opts.text || "").toLowerCase().trim();
  return rows.filter((r) => {
    if (!types.has(r.friendlyType)) return false;
    if (opts.vendorId) {
      if (r.entityType !== "Vendor" || r.entityId !== opts.vendorId) return false;
    }
    if (opts.customerId) {
      const headerMatch = r.entityType === "Customer" && r.entityId === opts.customerId;
      const lineMatch = r.lineCustomerId === opts.customerId;
      if (!headerMatch && !lineMatch) return false;
    }
    if (opts.accountId && r.accountId !== opts.accountId) return false;
    if (opts.itemId && r.itemId !== opts.itemId) return false;
    if (text) {
      const hay = `${r.docNumber} ${r.memo} ${r.lineDesc} ${r.entityName}`.toLowerCase();
      if (!hay.includes(text)) return false;
    }
    return true;
  });
}

export async function getTxn(realmId: string, txnType: string, txnId: string): Promise<Any> {
  const path = ENTITY_PATH[txnType];
  if (!path) throw new Error(`Unsupported transaction type: ${txnType}`);
  const res = await qbo(realmId, "GET", `${path}/${txnId}`);
  return res[txnType];
}

// Fields shared by AccountBasedExpenseLineDetail and ItemBasedExpenseLineDetail
// that should survive a conversion between the two.
const CARRYOVER = ["CustomerRef", "BillableStatus", "ClassRef", "TaxCodeRef", "MarkupInfo"];
function carryOver(from: Any, to: Any): Any {
  for (const k of CARRYOVER) {
    if (from && from[k] !== undefined) to[k] = from[k];
  }
  return to;
}

// QBO's expense form only renders a purchase line under "Item details" when the
// item line carries Qty and UnitPrice; a bare ItemRef (Amount only) is shown as a
// category line on the item's expense account instead. Backfill them so converted
// lines look exactly like natively-booked item lines.
function ensureItemQtyPrice(detail: Any, amount: Any): Any {
  if (detail.Qty == null) detail.Qty = 1;
  if (detail.UnitPrice == null) detail.UnitPrice = (Number(amount) || 0) / (Number(detail.Qty) || 1);
  return detail;
}

function applyChange(
  txnObj: Any,
  changed: Set<string>,
  targetKind: string,
  targetId: string,
  targetName: string,
): Any[] {
  return (txnObj.Line || []).map((line: Any) => {
    if (line.Id != null && changed.has(String(line.Id))) {
      const l = JSON.parse(JSON.stringify(line));
      if (targetKind === "account") {
        if (l.DetailType === "AccountBasedExpenseLineDetail" && l.AccountBasedExpenseLineDetail) {
          // Already a category line — just swap the account.
          l.AccountBasedExpenseLineDetail.AccountRef = { value: targetId, name: targetName };
        } else if (l.DetailType === "ItemBasedExpenseLineDetail" && l.ItemBasedExpenseLineDetail) {
          // Convert an item line back to a category (account) line. Amount lives
          // on the Line itself, so it is preserved automatically.
          const detail = carryOver(l.ItemBasedExpenseLineDetail, {
            AccountRef: { value: targetId, name: targetName },
          });
          l.DetailType = "AccountBasedExpenseLineDetail";
          l.AccountBasedExpenseLineDetail = detail;
          delete l.ItemBasedExpenseLineDetail;
        } else {
          throw new Error(
            `Line ${line.Id} can't take a category — invoices have no category lines.`,
          );
        }
      } else if (targetKind === "item") {
        if (l.DetailType === "ItemBasedExpenseLineDetail" && l.ItemBasedExpenseLineDetail) {
          l.ItemBasedExpenseLineDetail.ItemRef = { value: targetId, name: targetName };
          ensureItemQtyPrice(l.ItemBasedExpenseLineDetail, l.Amount);
        } else if (l.DetailType === "SalesItemLineDetail" && l.SalesItemLineDetail) {
          l.SalesItemLineDetail.ItemRef = { value: targetId, name: targetName };
          delete l.SalesItemLineDetail.ItemAccountRef; // let QBO derive the income account
        } else if (l.DetailType === "AccountBasedExpenseLineDetail" && l.AccountBasedExpenseLineDetail) {
          // The core purpose: convert a category (account) line to an item line.
          // QBO needs Qty + UnitPrice for its form to treat it as an item line.
          const detail = ensureItemQtyPrice(
            carryOver(l.AccountBasedExpenseLineDetail, {
              ItemRef: { value: targetId, name: targetName },
            }),
            l.Amount,
          );
          l.DetailType = "ItemBasedExpenseLineDetail";
          l.ItemBasedExpenseLineDetail = detail;
          delete l.AccountBasedExpenseLineDetail;
        } else {
          throw new Error(`Line ${line.Id} is not an item line, so an item can't be set on it.`);
        }
      }
      return l;
    }
    return line; // untouched lines are preserved byte-for-byte
  });
}

export async function previewTxn(realmId: string, req: Any): Promise<Any> {
  const obj = await getTxn(realmId, req.txnType, req.txnId);
  const changed = new Set<string>((req.changedLineIds || []).map(String));
  let after: Any[] = [];
  let error: string | null = null;
  try {
    after = applyChange(obj, changed, req.targetKind, req.targetId, req.targetName);
  } catch (e) {
    error = String((e as Error).message || e);
  }
  return {
    txnType: req.txnType,
    txnId: req.txnId,
    friendlyType: obj.PaymentType === "Check"
      ? "Check"
      : (req.txnType === "Purchase" ? "Expense" : req.txnType),
    docNumber: obj.DocNumber || "",
    txnDate: obj.TxnDate || "",
    entityName: obj.EntityRef?.name || obj.VendorRef?.name || obj.CustomerRef?.name || "",
    total: obj.TotalAmt ?? 0,
    syncToken: obj.SyncToken,
    changedLineIds: req.changedLineIds || [],
    before: obj.Line || [],
    after,
    error,
  };
}

async function logEdit(entry: Record<string, unknown>): Promise<void> {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/qbo_edit_log`, {
      method: "POST",
      headers: { ...sbHeaders(), Prefer: "return=minimal" },
      body: JSON.stringify(entry),
    });
  } catch (_) {
    // logging must never block a commit result
  }
}

export async function commitTxn(
  realmId: string,
  companyName: string | null,
  req: Any,
): Promise<Any> {
  // Re-fetch fresh to get the latest SyncToken and current lines.
  const obj = await getTxn(realmId, req.txnType, req.txnId);
  const before = JSON.parse(JSON.stringify(obj.Line || []));
  const changed = new Set<string>((req.changedLineIds || []).map(String));
  let after: Any[];
  try {
    after = applyChange(obj, changed, req.targetKind, req.targetId, req.targetName);
  } catch (e) {
    const msg = String((e as Error).message || e);
    await logEdit({
      realm_id: realmId,
      company_name: companyName,
      txn_type: req.txnType,
      txn_id: req.txnId,
      doc_number: obj.DocNumber || null,
      target_kind: req.targetKind,
      target_id: req.targetId,
      target_name: req.targetName,
      changed_line_ids: req.changedLineIds || [],
      before_lines: before,
      after_lines: before,
      sync_token_before: obj.SyncToken,
      result: "error",
      error_detail: msg,
    });
    return { txnId: req.txnId, txnType: req.txnType, result: "error", error: msg };
  }

  const updated = { ...obj, Line: after, sparse: false };
  const path = ENTITY_PATH[req.txnType];
  let result = "success";
  let error: string | null = null;
  let resp: Any = null;
  try {
    resp = await qbo(realmId, "POST", path, updated);
  } catch (e) {
    result = "error";
    error = String((e as Error).message || e);
  }
  await logEdit({
    realm_id: realmId,
    company_name: companyName,
    txn_type: req.txnType,
    txn_id: req.txnId,
    doc_number: obj.DocNumber || null,
    target_kind: req.targetKind,
    target_id: req.targetId,
    target_name: req.targetName,
    changed_line_ids: req.changedLineIds || [],
    before_lines: before,
    after_lines: after,
    sync_token_before: obj.SyncToken,
    result,
    error_detail: error,
  });
  return {
    txnId: req.txnId,
    txnType: req.txnType,
    docNumber: obj.DocNumber || "",
    result,
    error,
    newSyncToken: resp?.[req.txnType]?.SyncToken ?? null,
  };
}

export async function recentLog(realmId: string, limit = 100): Promise<Any[]> {
  const url = `${SUPABASE_URL}/rest/v1/qbo_edit_log?realm_id=eq.${encodeURIComponent(realmId)}` +
    `&select=created_at,txn_type,txn_id,doc_number,target_kind,target_name,changed_line_ids,result,error_detail` +
    `&order=created_at.desc&limit=${limit}`;
  const res = await fetch(url, { headers: sbHeaders() });
  if (!res.ok) return [];
  return await res.json();
}
