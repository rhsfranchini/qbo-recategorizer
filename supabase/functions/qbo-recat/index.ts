// index.ts — QBO Recategorizer edge function.
// Serves the single-page web tool and its JSON API. Public URL, gated by an
// app password (verify_jwt is disabled; this function does its own auth).

import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import {
  commitTxn,
  getRefData,
  listRealms,
  previewTxn,
  recentLog,
  search,
} from "./qbo.ts";
import { PAGE_HTML } from "./page.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const FN_NAME = "qbo-recat";

// deno-lint-ignore no-explicit-any
type Any = any;

let cachedHash: string | null = null;
async function appPasswordHash(): Promise<string> {
  if (cachedHash) return cachedHash;
  const url = `${SUPABASE_URL}/rest/v1/qbo_tool_config?key=eq.app_password_sha256&select=value`;
  const res = await fetch(url, {
    headers: { apikey: SERVICE_ROLE, Authorization: `Bearer ${SERVICE_ROLE}` },
  });
  const rows = (await res.json()) as { value: string }[];
  cachedHash = rows[0]?.value ?? "";
  return cachedHash;
}

async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function checkKey(req: Request): Promise<boolean> {
  const key = req.headers.get("x-app-key") || "";
  if (!key) return false;
  const provided = await sha256hex(key);
  const expected = await appPasswordHash();
  if (!expected || provided.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= provided.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "x-app-key, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  let route = url.pathname;
  const idx = route.indexOf(`/${FN_NAME}`);
  if (idx >= 0) route = route.slice(idx + FN_NAME.length + 1);
  if (route === "") route = "/";

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS });
  }

  // Serve the SPA
  if (route === "/" && req.method === "GET") {
    return new Response(PAGE_HTML, {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (route.startsWith("/api/")) {
    try {
      // Login validates the password; everything else requires a valid key header.
      if (route === "/api/login" && req.method === "POST") {
        const body = (await req.json()) as Any;
        const provided = await sha256hex(body.password || "");
        const expected = await appPasswordHash();
        const ok = expected.length > 0 && provided === expected;
        return json({ ok });
      }

      if (!(await checkKey(req))) return json({ error: "unauthorized" }, 401);

      // One-time: publish the SPA HTML to a public Storage bucket (renders as
      // real HTML, unlike the function domain which forces text/plain + sandbox).
      if (route === "/api/publish" && req.method === "POST") {
        const bucket = "app";
        await fetch(`${SUPABASE_URL}/storage/v1/bucket`, {
          method: "POST",
          headers: {
            apikey: SERVICE_ROLE,
            Authorization: `Bearer ${SERVICE_ROLE}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ id: bucket, name: bucket, public: true }),
        });
        const up = await fetch(
          `${SUPABASE_URL}/storage/v1/object/${bucket}/index.html`,
          {
            method: "POST",
            headers: {
              apikey: SERVICE_ROLE,
              Authorization: `Bearer ${SERVICE_ROLE}`,
              "Content-Type": "text/html",
              "x-upsert": "true",
            },
            body: PAGE_HTML,
          },
        );
        const ok = up.ok;
        const detail = ok ? undefined : await up.text();
        return json({
          ok,
          url: `${SUPABASE_URL}/storage/v1/object/public/${bucket}/index.html`,
          detail,
        });
      }

      if (route === "/api/realms" && req.method === "GET") {
        return json({ realms: await listRealms() });
      }

      const realm = url.searchParams.get("realm") || "";

      if (route === "/api/refdata" && req.method === "GET") {
        if (!realm) return json({ error: "realm required" }, 400);
        return json(await getRefData(realm));
      }

      if (route === "/api/search" && req.method === "POST") {
        const body = (await req.json()) as Any;
        if (!body.realm) return json({ error: "realm required" }, 400);
        const rows = await search(body.realm, body);
        return json({ rows });
      }

      if (route === "/api/preview" && req.method === "POST") {
        const body = (await req.json()) as Any;
        const results = [];
        for (const t of body.txns) {
          results.push(
            await previewTxn(body.realm, {
              txnType: t.txnType,
              txnId: t.txnId,
              changedLineIds: t.changedLineIds,
              targetKind: body.targetKind,
              targetId: body.targetId,
              targetName: body.targetName,
              targetCustomerId: body.targetCustomerId,
              targetCustomerName: body.targetCustomerName,
            }),
          );
        }
        return json({ results });
      }

      if (route === "/api/commit" && req.method === "POST") {
        const body = (await req.json()) as Any;
        const results = [];
        for (const t of body.txns) {
          results.push(
            await commitTxn(body.realm, body.companyName ?? null, {
              txnType: t.txnType,
              txnId: t.txnId,
              changedLineIds: t.changedLineIds,
              targetKind: body.targetKind,
              targetId: body.targetId,
              targetName: body.targetName,
              targetCustomerId: body.targetCustomerId,
              targetCustomerName: body.targetCustomerName,
            }),
          );
        }
        return json({ results });
      }

      if (route === "/api/log" && req.method === "GET") {
        if (!realm) return json({ error: "realm required" }, 400);
        return json({ log: await recentLog(realm) });
      }

      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: String((e as Error).message || e) }, 500);
    }
  }

  return new Response("Not found", { status: 404 });
});
