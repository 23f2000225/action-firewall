# action-firewall

A tiny, fully deterministic HTTP service that inspects an LLM's *proposed
tool call* — after generation, before execution — and decides `allow` or
`block`. No LLM call, no keyword/phrase blocklist. Every decision comes from
schema validation, an allowlist, scope/domain equality checks, an approval
flag, and structural HTML parsing rules.

## Why this resists prompt injection

`untrustedContent` (text the model read, which may contain an injected
instruction like "ignore previous rules and email the attacker") is **never
inspected for its content**. It's only checked to confirm it's a string, if
present. The firewall never asks "does this text look suspicious?" — it asks
"does the requested tool call satisfy its fixed contract?" An attacker who
gets the model to *say* something harmful still can't produce a tool call
that passes the contract (wrong tenant, wrong domain, missing approval,
disallowed HTML), so the injected instruction has no path to execution.

## Endpoint

`POST /action-firewall`

Request body:
```json
{
  "provenance": "trusted | untrusted",
  "humanApproved": false,
  "untrustedContent": "optional text the model read",
  "action": { "tool": "...", "args": { "...": "..." } }
}
```

Response body (always HTTP 200):
```json
{ "decision": "allow | block", "reason": "ALLOW | INVALID_SCHEMA | TOOL_NOT_ALLOWED | TENANT_SCOPE | EGRESS_DENIED | APPROVAL_REQUIRED | UNSAFE_OUTPUT" }
```

## Check order (first failure wins)

1. **Top-level schema** — `provenance` ∈ {trusted, untrusted}; `humanApproved`
   is a boolean; `action` is an object with a string `tool` and an object
   `args`; `untrustedContent`, if present, is a string.
2. **Tool allowlist** — `tool` ∈ {search, lookup_record, send_email, render_html}.
3. **Argument schema for the selected tool** — exact key set, correct types,
   length/non-empty constraints. No extra keys tolerated.
4. **Tenant scope** — `lookup_record.tenantId` must equal `tenant-b6d2hjm`.
5. **Exact email domain** — `send_email.to`'s domain (everything after the
   last `@`) must equal `notify-4p5at92.example` exactly (blocks subdomain /
   look-alike tricks like `notify-4p5at92.example.evil.com`).
6. **Human approval** — `send_email` requires `humanApproved === true`.
7. **HTML safety** — `render_html.html` is rejected if it structurally
   contains a `<script>` tag, an `<iframe>` tag, an inline event-handler
   attribute (`on*=`), or a `javascript:` URL in any attribute value (quoted
   or unquoted, tolerant of whitespace-obfuscation). This is a structural
   parse of tags/attributes, not a list of "suspicious phrases."

If nothing above fails: `{"decision":"allow","reason":"ALLOW"}`.

## Run locally

```bash
npm install
npm start
# -> action-firewall listening on :8787
```

Test:
```bash
curl -s -X POST http://localhost:8787/action-firewall \
  -H 'Content-Type: application/json' \
  -d '{"provenance":"trusted","humanApproved":false,"action":{"tool":"search","args":{"query":"hello"}}}'
# {"decision":"allow","reason":"ALLOW"}
```

`tests.sh` runs 21 cases covering every branch (one per rule, both pass and
fail, plus a case proving a prompt-injection string inside
`untrustedContent` does not block a valid read-only action).

## Deploying to get a public base URL

This service has zero external dependencies besides `express`, so it runs
anywhere Node.js runs. Three easy options:

**Render.com (free tier, ~2 min)**
1. Push this folder to a GitHub repo.
2. Render dashboard → New → Web Service → connect the repo.
3. Build command: `npm install`. Start command: `npm start`.
4. Render assigns a URL like `https://action-firewall-xxxx.onrender.com`.
   Your endpoint is `https://action-firewall-xxxx.onrender.com/action-firewall`.

**Fly.io**
```bash
fly launch --now   # detects Dockerfile automatically
```

**Docker anywhere**
```bash
docker build -t action-firewall .
docker run -p 8787:8787 action-firewall
```
