#!/usr/bin/env node
'use strict';
/**
 * Assurance Run — rail adapters beyond the account-chain case.
 *
 * WHY THIS FILE EXISTS. The evaluator in kernel.cjs was written against an
 * EVM/x402 settlement rail, and a set of rules derived from one rail is a
 * house style, not a standard. These adapters run the SAME evaluator against
 * evidence systems with different trust models and different failure modes:
 *
 *   starknetFact   a state-proof system. Validity is a fact registered by a
 *                  STARK verifier, not a balance at an address. Read directly
 *                  from a public RPC, never from the anchoring party.
 *   hashChainLog   an append-only transparency log. Validity is a record's
 *                  position in a chain, not an on-chain transaction at all.
 *
 * Neither needs a new verdict, a new provenance field, or a special case in
 * the evaluator. If either had, the semantics would have been rail-specific
 * and we would want to know that before a working group adopts them.
 *
 * Every adapter here declares `independence_class: INDEPENDENT` ONLY because
 * it performs its own retrieval from a public endpoint the counterparty does
 * not control. An adapter that accepted a URL supplied by the party being
 * checked would be SELF_REPORTED no matter how the fetch was performed.
 */

const crypto = require('crypto');
const K = require('./kernel.cjs');

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

/**
 * starknet_keccak(name) = keccak256(name) masked to the low 250 bits.
 *
 * Pinned as a constant rather than computed, so this package has ZERO
 * dependencies and runs from a clean clone with no install. keccak256 is NOT
 * sha3-256 and the difference is silent, so a wrong local implementation would
 * produce a plausible-looking selector that resolves to no entry point -- which
 * reads like "the fact is not registered".
 *
 * Verified against @noble/hashes keccak_256 on 2026-09-15. `verifySelector()`
 * below re-derives it if a keccak implementation is available, and is called by
 * cross-rail.cjs; when none is installed it returns NOT_EVALUATED rather than
 * silently asserting the constant is right.
 */
const SELECTORS = {
  get_all_verifications_for_fact_hash:
    '0x3731d7667bf026b9960bf90daef8b575526345deb176f45e77fce4127cb8028',
};

const FELT_MASK = (1n << 250n) - 1n;

function starknetSelector(name) {
  if (!Object.prototype.hasOwnProperty.call(SELECTORS, name)) {
    throw new Error('SELECTOR_NOT_PINNED:' + name);
  }
  return SELECTORS[name];
}

/** Re-derive a pinned selector if any keccak is present. Never asserts blindly. */
function verifySelector(name) {
  let keccak = null;
  for (const mod of ['@noble/hashes/sha3.js', '@noble/hashes/sha3', 'js-sha3']) {
    try {
      const m = require(mod);
      keccak = m.keccak_256 || (m.keccak256 && ((b) => Buffer.from(m.keccak256.arrayBuffer(b))));
      if (keccak) break;
    } catch { /* not installed; that is a supported state */ }
  }
  if (!keccak) return { verdict: K.NOT_EVALUATED, reason: 'NO_KECCAK_AVAILABLE', name };
  const h = Buffer.from(keccak(Buffer.from(name, 'utf8'))).toString('hex');
  const derived = '0x' + (BigInt('0x' + h) & FELT_MASK).toString(16);
  return derived === SELECTORS[name]
    ? { verdict: K.AGREE, reason: 'SELECTOR_MATCHES_PINNED', name, derived }
    : { verdict: K.DISAGREE, reason: 'SELECTOR_DIFFERS_FROM_PINNED', name, derived, pinned: SELECTORS[name] };
}

/**
 * Starknet felts drop leading zeros on the wire: 0x066cfbb6… is returned as
 * 0x66cfbb6…. Comparing the padded form against the wire form yields a false
 * zero — the same silent-zero family as an indexer field-name mismatch.
 * Normalise BOTH sides before any comparison.
 */
function normFelt(h) {
  if (h === undefined || h === null) return null;
  const s = String(h).toLowerCase().replace(/^0x/, '').replace(/^0+/, '');
  return '0x' + (s === '' ? '0' : s);
}

/**
 * A felt252 is strictly below 2^252. A 256-bit hash is NOT a felt and cannot be
 * passed as one -- Starknet answers `invalid fp.Element encoding`, a -32602 that
 * is easy to log as "lookup failed" and read as "the fact is not registered".
 *
 * Found 2026-09-15 by this file's own known-answer control, which is the only
 * reason it was caught: the first adapter draft passed a raw sha256 digest
 * straight through. This is why a 256-bit digest is carried on Starknet as two
 * 128-bit limbs (digest_lo / digest_hi) rather than one value.
 *
 * Out of range is NOT_EVALUATED: the question was never asked, so it is neither
 * answered nor refuted.
 */
const FELT252_MAX = 1n << 252n;
function feltInRange(h) {
  try { return BigInt(normFelt(h)) < FELT252_MAX; } catch { return false; }
}

// --------------------------------------------------- adapter: Starknet fact
const STARKNET_SEPOLIA_RPC = 'https://starknet-sepolia.drpc.org';
// Integrity FactRegistry on Starknet Sepolia. `is_valid` does NOT exist on this
// contract (entry-point error); the working entrypoint is the one below.
const FACT_REGISTRY = '0x4ce7851f00b6c3289674841fd7a1b96b6fd41ed1edc248faccd672c26371b8c';

const starknetFact = {
  name: 'starknet_fact_registry',
  version: 'starknet_fact/0.1',
  capture_method: 'public_rpc_starknet_call',
  independence_class: K.INDEPENDENT,
  rail: 'starknet:SN_SEPOLIA',

  async observe(frozen, opts = {}) {
    const base = {
      attempted: true, source: frozen.source || STARKNET_SEPOLIA_RPC,
      observer: this.name, capture_method: this.capture_method,
      adapter_version: this.version, independence_class: this.independence_class,
      observed_at: opts.observed_at || frozen.observed_at || null,
    };

    const fact = frozen.resource;
    if (!fact) {
      return { ...base, reachable: true, observed: null,
        raw_digest: sha256('NO_FACT_SUPPLIED'), note: 'no fact hash in frozen.resource' };
    }

    if (!feltInRange(fact)) {
      // Never dispatch a call we know the chain will reject on encoding. A
      // -32602 here would be indistinguishable from a real lookup miss.
      return { ...base, reachable: true, schema_supported: false,
        raw_digest: sha256('OUT_OF_FELT_RANGE:' + String(fact)),
        note: 'value is >= 2^252 and is not a felt252; a 256-bit digest must be carried ' +
              'as two 128-bit limbs. Not asked, therefore not answered -- and specifically ' +
              'not evidence that the fact is unregistered.' };
    }

    // This endpoint intermittently answers -32601 "the method starknet_call does
    // not exist" for a method it demonstrably supports seconds earlier -- a
    // transport-level flake dressed as a capability statement. Retried a bounded
    // number of times BECAUSE a single such answer would otherwise be recorded as
    // a permanent fact about the rail. Retry is not persistence for its own sake;
    // it is refusing to let one flaky response become evidence.
    const req = {
      jsonrpc: '2.0', id: 1, method: 'starknet_call',
      params: [{
        contract_address: FACT_REGISTRY,
        entry_point_selector: starknetSelector('get_all_verifications_for_fact_hash'),
        calldata: [normFelt(fact)],
      }, 'latest'],
    };

    let body, lastErr = null, lastFault = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(STARKNET_SEPOLIA_RPC, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req), signal: AbortSignal.timeout(25000),
        });
        body = await res.json();
      } catch (err) {
        // Same rule as the HTTP adapter: only a named network failure licenses
        // a claim that the RPC endpoint was unreachable. Anything else is ours.
        lastFault = K.classifyFault(err);
        lastErr = lastFault.kind + ':' + lastFault.detail; body = null;
      }

      // A JSON-RPC error arrives as HTTP 200 with an `error` member. Treating that
      // as an empty result is how a rate limit becomes "the fact does not exist".
      if (body && body.error) {
        lastErr = 'RPC_ERROR_MEMBER: ' + JSON.stringify(body.error).slice(0, 200);
        const code = body.error.code;
        // -32602 is a real, deterministic answer about OUR input; do not retry it.
        if (code === -32602) break;
        body = null;
      }
      if (body) { lastErr = null; break; }
      if (attempt < 3) await new Promise((r) => setTimeout(r, 1200 * attempt));
    }

    if (!body) {
      // Unreachable is INDETERMINATE by the kernel's rules, never "not anchored".
      // But an RPC error member is the endpoint answering us, whereas a fault we
      // could not attribute to the wire is our own — those are different claims.
      const ours = lastFault && lastFault.instrument === true;
      const stamp = { ...base, raw_digest: sha256('RPC_ERROR:' + String(lastErr)),
        error: lastErr, attempts: 3, fault_kind: lastFault ? lastFault.kind : 'RPC_ERROR_MEMBER' };
      return ours ? { ...stamp, adapter_failed: true } : { ...stamp, reachable: false };
    }

    const result = (body && body.result) || [];
    const count = result.length ? Number(BigInt(result[0])) : 0;
    return {
      ...base, reachable: true, raw_digest: sha256(JSON.stringify(body)),
      observed: {
        // A count of zero here IS a real reading of the registry, not a scope
        // limit — this entrypoint answers for the whole registry. Reported as a
        // distinct state so a consumer never has to infer it from an empty list.
        state: count > 0 ? 'FACT_REGISTERED' : 'NO_VERIFICATIONS_FOR_FACT',
        verification_count: String(count),
        fact: normFelt(fact),
        verification_hash: result[1] ? normFelt(result[1]) : null,
        security_bits: result[2] ? String(BigInt(result[2])) : null,
      },
    };
  },
};

// ----------------------------------------------- adapter: hash-chain log
/**
 * An append-only log where each entry commits to its predecessor. No chain,
 * no RPC, no settlement — validity is structural. Recomputes the chain from
 * the entries themselves rather than trusting any published head value.
 */
const hashChainLog = {
  name: 'hash_chain_log',
  version: 'hash_chain/0.1',
  capture_method: 'recompute_chain_from_entries',
  independence_class: K.INDEPENDENT,
  rail: 'transparency-log',

  async observe(frozen, opts = {}) {
    const base = {
      attempted: true, source: frozen.source, observer: this.name,
      capture_method: this.capture_method, adapter_version: this.version,
      independence_class: this.independence_class, observed_at: opts.observed_at || frozen.observed_at || null,
    };

    const entries = frozen.resource;
    if (!Array.isArray(entries) || entries.length === 0) {
      return { ...base, reachable: true, observed: null, raw_digest: sha256('NO_ENTRIES'),
        note: 'no log entries supplied' };
    }

    let prev = 'genesis';
    let brokeAt = null;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      const expected = sha256(prev + '|' + K.canonical(e.payload));
      if (e.prev !== undefined && e.prev !== prev) { brokeAt = i; break; }
      if (e.digest !== undefined && e.digest !== expected) { brokeAt = i; break; }
      prev = expected;
    }

    return {
      ...base, reachable: true, raw_digest: sha256(K.canonical(entries)),
      observed: brokeAt === null
        ? { state: 'CHAIN_INTACT', head: prev, length: String(entries.length) }
        : { state: 'CHAIN_BROKEN', broke_at_index: String(brokeAt), length: String(entries.length) },
    };
  },
};

module.exports = { starknetFact, hashChainLog, starknetSelector, verifySelector, SELECTORS, normFelt, feltInRange,
  FELT252_MAX, FACT_REGISTRY, STARKNET_SEPOLIA_RPC };
