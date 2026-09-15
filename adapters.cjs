'use strict';
/**
 * Assurance Run v0.1 — adapters. TWO, and no more until a paying customer
 * asks for a third.
 *
 * An adapter's only job is to retrieve and normalise into `observed`.
 * It never renders a verdict. It never decides what "close enough" means.
 * Comparison lives in the kernel so customer semantics cannot leak into it.
 *
 * Every adapter declares its own independence_class honestly. That field is
 * load-bearing: the kernel refuses AGREE on anything but independent_retrieval.
 */

const crypto = require('crypto');
const K = require('./kernel.cjs');

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

// ------------------------------------------------- adapter 1: public record
/**
 * Generic HTTP/public-record observation. We fetch the source ourselves,
 * so this is genuinely independent — and it is the only class that can
 * produce an AGREE.
 *
 * spec.source    absolute URL
 * spec.resource  optional dot-path into the JSON body to extract
 */
const httpPublic = {
  name: 'http_public',
  version: 'http_public/0.1',
  capture_method: 'direct_https_get',
  independence_class: K.INDEPENDENT,

  async observe(frozen) {
    const base = {
      attempted: true,
      source: frozen.source,
      observer: this.name,
      capture_method: this.capture_method,
      adapter_version: this.version,
      independence_class: this.independence_class,
    };

    let res, text;
    try {
      res = await fetch(frozen.source, { redirect: 'follow', signal: AbortSignal.timeout(25000) });
      text = await res.text();
    } catch (err) {
      return { ...base, reachable: false, observed_at: new Date().toISOString(),
        raw_digest: sha256('UNREACHABLE:' + err.message), error: err.message };
    }

    const observed_at = now();
    const raw_digest = sha256(text);

    if (!res.ok) {
      return { ...base, reachable: false, observed_at, raw_digest,
        http_status: res.status, error: 'HTTP_' + res.status };
    }

    let body;
    try { body = JSON.parse(text); }
    catch {
      // Not JSON. We do not guess at a schema we do not understand.
      return { ...base, reachable: true, schema_supported: false,
        observed_at, raw_digest, http_status: res.status };
    }

    const observed = frozen.resource ? pluck(body, frozen.resource) : body;
    if (observed === undefined) {
      return { ...base, reachable: true, observed: null, observed_at, raw_digest,
        http_status: res.status, note: 'resource path not present in response' };
    }

    return { ...base, reachable: true, observed, observed_at, raw_digest,
      http_status: res.status, source_version: res.headers.get('etag') || res.headers.get('last-modified') || null };
  },
};

function pluck(obj, dotPath) {
  return dotPath.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

// --------------------------------------------- adapter 2: counterparty report
/**
 * Evidence the counterparty captured and handed to us. Admissible, tamper-
 * evident, and structurally incapable of producing an AGREE — the kernel
 * downgrades a clean match here to INDETERMINATE / INSUFFICIENT_INDEPENDENCE.
 *
 * This exists so a pilot can run before OAuth is granted, WITHOUT letting the
 * resulting verdict overstate what we actually know.
 */
function counterpartyReport(payload, meta = {}) {
  const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return {
    name: 'counterparty_report',
    version: 'counterparty_report/0.1',
    capture_method: 'counterparty_supplied',
    independence_class: K.SELF_REPORTED,
    async observe(frozen) {
      return {
        attempted: true,
        reachable: true,
        observed: typeof payload === 'string' ? JSON.parse(payload) : payload,
        source: frozen.source,
        observer: meta.observer || 'counterparty',
        capture_method: 'counterparty_supplied',
        observed_at: meta.observed_at || new Date().toISOString(),
        raw_digest: sha256(raw),
        adapter_version: 'counterparty_report/0.1',
        independence_class: K.SELF_REPORTED,
        source_version: meta.source_version || null,
      };
    },
  };
}

// ----------------------------------------------------- adapter 3: base/x402
/**
 * The existing Base settlement observer, refactored behind the same interface.
 * Deliberately thin: it delegates to core/x402_settlement_truth.cjs rather
 * than reimplementing a second reader, because two derivations sharing one
 * index fail together and look like agreement.
 *
 * Its tri-state (PAID / ZERO_OBSERVED / UNKNOWN) maps onto the kernel's four:
 *   PAID           -> observed, comparable
 *   ZERO_OBSERVED  -> observed, comparable (a real zero over a stated scope)
 *   UNKNOWN        -> not resolved -> INDETERMINATE
 */
const baseX402 = {
  name: 'base_x402',
  version: 'base_x402/0.1',
  capture_method: 'indexer_plus_archive_eth_call',
  independence_class: K.INDEPENDENT,

  async observe(frozen, opts = {}) {
    const base = {
      attempted: true, source: frozen.source, observer: this.name,
      capture_method: this.capture_method, adapter_version: this.version,
      independence_class: this.independence_class,
    };
    // The EVM settlement reader is a separate component, not vendored here.
    // Point ASSURANCE_X402_TRUTH at it to exercise this adapter. Absent, this
    // returns INDETERMINATE -- a stranger cloning the repo gets an honest
    // "not wired", never a green from an adapter that never ran.
    const MODULE = process.env.ASSURANCE_X402_TRUTH;
    const now = () => opts.observed_at || frozen.observed_at || null;
    if (!MODULE) {
      return { ...base, reachable: false, observed_at: now(),
        raw_digest: sha256('X402_TRUTH_NOT_CONFIGURED'),
        error: 'ASSURANCE_X402_TRUTH not set; EVM settlement reader not wired' };
    }
    let truth;
    try {
      truth = require(MODULE);
    } catch (err) {
      return { ...base, reachable: false, observed_at: now(),
        raw_digest: sha256('MODULE_LOAD_FAILED:' + err.message), error: err.message };
    }
    if (typeof truth.observeAddress !== 'function') {
      // The underlying module does not expose a per-address entry point yet.
      // NOT a pass, NOT a failure — an unsupported shape.
      return { ...base, reachable: true, schema_supported: false,
        observed_at: now(),
        raw_digest: sha256('NO_OBSERVE_ADDRESS_EXPORT'),
        note: 'x402_settlement_truth exposes no observeAddress(); wire before use' };
    }
    const r = await truth.observeAddress(frozen.resource, frozen.window || {});
    const observed_at = new Date().toISOString();
    if (!r || r.state === 'UNKNOWN') {
      return { ...base, reachable: true, observed: null, observed_at,
        raw_digest: sha256(JSON.stringify(r || null)), note: 'rail out of scope or window unreadable' };
    }
    return { ...base, reachable: true, observed: r, observed_at,
      raw_digest: sha256(JSON.stringify(r)), counts_are_floor: !!r.counts_are_floor };
  },
};

module.exports = { httpPublic, counterpartyReport, baseX402 };
