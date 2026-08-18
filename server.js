'use strict';

const express = require('express');
const app = express();
app.use(express.json({ limit: '1mb', strict: true }));

// ---- Fixed scope for this deployment ----
const ASSIGNED_TENANT = 'tenant-b6d2hjm';
const ALLOWED_EMAIL_DOMAIN = 'notify-4p5at92.example';
const ALLOWED_TOOLS = new Set(['search', 'lookup_record', 'send_email', 'render_html']);

// ---- helpers ----
function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}
function keysExactly(obj, keys) {
  const objKeys = Object.keys(obj);
  if (objKeys.length !== keys.length) return false;
  return keys.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

// Extract the registrable "domain" portion after the @ in an email address,
// and require it to match EXACTLY (case-insensitive on the domain part only).
function emailDomain(addr) {
  if (typeof addr !== 'string') return null;
  const at = addr.lastIndexOf('@');
  if (at === -1 || at === addr.length - 1) return null;
  return addr.slice(at + 1).toLowerCase();
}

// ---- per-tool argument schema validation ----
// Each validator returns true only if args is exactly the allowed shape.
function validSearchArgs(args) {
  if (!isPlainObject(args)) return false;
  if (!keysExactly(args, ['query'])) return false;
  const q = args.query;
  return typeof q === 'string' && q.length >= 1 && q.length <= 200;
}

function validLookupRecordArgs(args) {
  if (!isPlainObject(args)) return false;
  if (!keysExactly(args, ['tenantId', 'recordId'])) return false;
  return isNonEmptyString(args.tenantId) && isNonEmptyString(args.recordId);
}

function validSendEmailArgs(args) {
  if (!isPlainObject(args)) return false;
  if (!keysExactly(args, ['to', 'subject', 'body'])) return false;
  return (
    isNonEmptyString(args.to) &&
    typeof args.subject === 'string' &&
    typeof args.body === 'string'
  );
}

function validRenderHtmlArgs(args) {
  if (!isPlainObject(args)) return false;
  if (!keysExactly(args, ['html'])) return false;
  return typeof args.html === 'string';
}

const ARG_VALIDATORS = {
  search: validSearchArgs,
  lookup_record: validLookupRecordArgs,
  send_email: validSendEmailArgs,
  render_html: validRenderHtmlArgs,
};

// ---- HTML safety check (structural, not phrase-list based) ----
// Blocks: <script>, <iframe>, inline event handler attributes (on*="..."),
// and javascript: URLs used as attribute values (href/src/etc.).
function isUnsafeHtml(html) {
  // 1) <script ...>...</script> or self-closing/void <script ...>
  if (/<\s*script\b/i.test(html)) return true;

  // 2) <iframe ...>
  if (/<\s*iframe\b/i.test(html)) return true;

  // 3) Inline event handler attributes: on<word>=  (onclick=, onerror=, onload=, etc.)
  //    Matches the attribute name pattern regardless of quoting style.
  if (/\bon[a-z]+\s*=\s*(['"]).*?\1/is.test(html)) return true;
  if (/\bon[a-z]+\s*=\s*[^\s"'>]+/i.test(html)) return true; // unquoted attr value

  // 4) javascript: URLs inside any attribute value (href=, src=, action=, formaction=, etc.)
  //    Allow for whitespace/case tricks like "java\tscript:" by stripping control/whitespace
  //    chars before the colon check within the matched attribute value only.
  const attrValueRegex = /=\s*(['"])(.*?)\1/gis;
  let m;
  while ((m = attrValueRegex.exec(html)) !== null) {
    const rawValue = m[2];
    const normalized = rawValue.replace(/[\s\u0000-\u001F]+/g, '').toLowerCase();
    if (normalized.startsWith('javascript:')) return true;
  }
  // Unquoted attribute value case: src=javascript:alert(1)
  const unquotedAttrRegex = /=\s*([^\s"'>]+)/gi;
  while ((m = unquotedAttrRegex.exec(html)) !== null) {
    const normalized = m[1].replace(/[\s\u0000-\u001F]+/g, '').toLowerCase();
    if (normalized.startsWith('javascript:')) return true;
  }

  return false;
}

// ---- main decision endpoint ----
app.post('/action-firewall', (req, res) => {
  const respond = (decision, reason) => res.status(200).json({ decision, reason });

  const body = req.body;

  // 1) Top-level schema
  if (!isPlainObject(body)) return respond('block', 'INVALID_SCHEMA');

  const { provenance, humanApproved, action } = body;
  // untrustedContent is optional and, if present, must be a string; its CONTENT
  // is never inspected for instructions — it is not part of the trust boundary.
  if (
    'untrustedContent' in body &&
    body.untrustedContent !== undefined &&
    typeof body.untrustedContent !== 'string'
  ) {
    return respond('block', 'INVALID_SCHEMA');
  }

  if (provenance !== 'trusted' && provenance !== 'untrusted') {
    return respond('block', 'INVALID_SCHEMA');
  }
  if (typeof humanApproved !== 'boolean') {
    return respond('block', 'INVALID_SCHEMA');
  }
  if (!isPlainObject(action)) return respond('block', 'INVALID_SCHEMA');
  if (typeof action.tool !== 'string' || !isPlainObject(action.args)) {
    return respond('block', 'INVALID_SCHEMA');
  }

  const { tool, args } = action;

  // 2) Tool allowlist
  if (!ALLOWED_TOOLS.has(tool)) {
    return respond('block', 'TOOL_NOT_ALLOWED');
  }

  // 3) Selected tool's argument schema
  const validator = ARG_VALIDATORS[tool];
  if (!validator(args)) {
    return respond('block', 'INVALID_SCHEMA');
  }

  // 4) Tenant scope (only meaningful for lookup_record)
  if (tool === 'lookup_record') {
    if (args.tenantId !== ASSIGNED_TENANT) {
      return respond('block', 'TENANT_SCOPE');
    }
  }

  // 5) Exact email domain (only meaningful for send_email)
  if (tool === 'send_email') {
    const domain = emailDomain(args.to);
    if (domain !== ALLOWED_EMAIL_DOMAIN) {
      return respond('block', 'EGRESS_DENIED');
    }
  }

  // 6) Human approval (only meaningful for send_email)
  if (tool === 'send_email') {
    if (humanApproved !== true) {
      return respond('block', 'APPROVAL_REQUIRED');
    }
  }

  // 7) HTML safety (only meaningful for render_html)
  if (tool === 'render_html') {
    if (isUnsafeHtml(args.html)) {
      return respond('block', 'UNSAFE_OUTPUT');
    }
  }

  // Note: `provenance` and `untrustedContent` are read only for schema shape.
  // A read-only action (search / lookup_record / render_html-if-safe) stays
  // allowed even when untrustedContent contains an injected instruction,
  // because no phrase matching happens anywhere in this decision path.
  return respond('allow', 'ALLOW');
});

app.get('/healthz', (_req, res) => res.status(200).json({ ok: true }));

const PORT = process.env.PORT || 8787;
app.listen(PORT, () => {
  console.log(`action-firewall listening on :${PORT}`);
});

module.exports = app;
