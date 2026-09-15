#!/usr/bin/env node
'use strict';
/**
 * Assurance Run — evidence semantics.
 *
 * The kernel answers one question: do two records describe the same event?
 * This module answers the three questions a bare evidence record cannot:
 *
 *   WHO   stood behind each part of the record (party roles)
 *   WHAT  supports each asserted lifecycle state (per-state evidence binding)
 *   WHICH other records this one depends on or replaces (typed references)
 *
 * SCOPE BOUNDARY, deliberately: nothing here knows about bonds, collateral,
 * escrow, challenge windows or slashing. Those are settlement mechanics and
 * belong downstream. This module only describes evidence. A record that
 * validates here says nothing about who owes whom — that is the point.
 *
 * Every function returns a kernel verdict, never a boolean. `true`/`false`
 * is the wrong shape for these questions: "this record does not assert a
 * capture relationship" is NOT_EVALUATED, and collapsing it to `false`
 * ("relationship invalid") is the same class of error as reading a gate
 * that never ran as a gate that passed.
 */

const K = require('./kernel.cjs');

// ------------------------------------------------------------- party roles
/**
 * Four roles, deliberately separable. The common case is that several
 * collapse onto one party — that is allowed and must be STATED, not assumed.
 *
 *   issuer    the party that emitted the record
 *   executor  the party that performed the action the record describes
 *   observer  the party that captured/measured the record's evidence
 *   verifier  the party that evaluated the evidence (optional)
 *
 * The distinction that matters is observer vs executor. When they are the
 * same party, the record is the executor's account of its own action. That
 * can be true and can be useful; it cannot be independent, and a format
 * with no way to express the difference forces every consumer to guess.
 */
const ROLES = ['issuer', 'executor', 'observer', 'verifier'];

/**
 * Derive the independence class from the role identities themselves rather
 * than trusting a self-declared label. An adapter that claims
 * `independent_retrieval` while naming itself as the executor is claiming
 * something the identities contradict, and the identities win.
 */
function captureRelationship(parties) {
  if (!parties || typeof parties !== 'object') {
    return { verdict: K.NOT_EVALUATED, reason: 'NO_PARTIES_ASSERTED' };
  }

  const present = ROLES.filter((r) => parties[r] !== undefined && parties[r] !== null && parties[r] !== '');
  if (!present.includes('observer') || !present.includes('executor')) {
    return {
      verdict: K.NOT_EVALUATED,
      reason: 'CAPTURE_RELATIONSHIP_UNSTATED',
      note: 'a record that does not name both observer and executor cannot be ' +
            'classified as independent or self-reported; absence is not independence',
      present,
    };
  }

  const same = String(parties.observer) === String(parties.executor);
  return {
    verdict: same ? K.INDETERMINATE : K.AGREE,
    reason: same ? 'OBSERVER_IS_EXECUTOR' : 'OBSERVER_DISTINCT_FROM_EXECUTOR',
    derived_independence_class: same ? K.SELF_REPORTED : K.INDEPENDENT,
    note: same
      ? 'the party that captured this evidence is the party that performed the action; ' +
        'this is the executor\'s account of itself'
      : null,
    parties: Object.fromEntries(present.map((r) => [r, parties[r]])),
  };
}

/**
 * Cross-check a declared independence class against the one the role
 * identities imply. Catches a record that claims more independence than its
 * own parties support. A record that declares LESS than it could is fine —
 * understating independence is never the dangerous direction.
 */
function checkDeclaredIndependence(parties, declared) {
  const rel = captureRelationship(parties);
  if (rel.verdict === K.NOT_EVALUATED) return rel;
  const derived = rel.derived_independence_class;

  if (declared === K.INDEPENDENT && derived !== K.INDEPENDENT) {
    return {
      verdict: K.DISAGREE,
      reason: 'DECLARED_INDEPENDENCE_CONTRADICTED_BY_PARTIES',
      declared,
      derived,
      note: 'the record declares independent retrieval while naming the same party ' +
            'as observer and executor',
    };
  }
  return { verdict: K.AGREE, reason: 'DECLARED_INDEPENDENCE_CONSISTENT', declared, derived };
}

// ------------------------------------------------- per-state evidence binding
/**
 * A lifecycle state as a bare string — `"state": "settled"` — asserts
 * something with nothing behind it. One anchor at the top of a record covers
 * one fact; it does not cover every state the record claims.
 *
 * Here each asserted state must name the evidence that supports THAT state.
 * States with no binding are reported as NOT_EVALUATED individually, so a
 * record with three states and one anchor reads as one supported and two
 * unevaluated rather than as three settled.
 *
 * The vocabulary is open on purpose: this validates the BINDING, not which
 * state names a given profile is allowed to use. Constraining the names is a
 * profile's job, not evidence semantics'.
 */
function bindStates(states, evidenceIndex) {
  if (!Array.isArray(states) || states.length === 0) {
    return { verdict: K.NOT_EVALUATED, reason: 'NO_STATES_ASSERTED', bindings: [] };
  }
  const index = evidenceIndex && typeof evidenceIndex === 'object' ? evidenceIndex : {};

  const bindings = states.map((s) => {
    const name = s && s.state;
    if (!name) return { state: null, verdict: K.NOT_EVALUATED, reason: 'STATE_UNNAMED' };

    const ref = s.evidence_digest;
    if (!ref) {
      return {
        state: name,
        verdict: K.NOT_EVALUATED,
        reason: 'STATE_ASSERTED_WITHOUT_EVIDENCE',
        note: 'this state is claimed but names no evidence; it is unevaluated, not settled',
      };
    }
    if (!Object.prototype.hasOwnProperty.call(index, ref)) {
      return {
        state: name, evidence_digest: ref,
        verdict: K.INDETERMINATE,
        reason: 'EVIDENCE_REFERENCED_BUT_ABSENT',
        note: 'the record names supporting evidence that is not present in this bundle; ' +
              'absent is not contradicted',
      };
    }
    const got = index[ref];
    const actual = K.sha256(K.canonical(got));
    if (actual !== ref) {
      return {
        state: name, evidence_digest: ref, computed_digest: actual,
        verdict: K.DISAGREE,
        reason: 'EVIDENCE_DIGEST_MISMATCH',
        note: 'the evidence present under this digest does not hash to it',
      };
    }
    return { state: name, evidence_digest: ref, verdict: K.AGREE, reason: 'STATE_EVIDENCE_BOUND' };
  });

  return { verdict: worst(bindings.map((b) => b.verdict)), reason: 'PER_STATE_BINDING', bindings };
}

// ------------------------------------------------------- typed references
/**
 * One overloaded `ref=` pointer cannot express the difference between "this
 * record checked a precondition before acting" and "this record replaces an
 * earlier one". Consumers cannot tell a lineage link from a correction, so
 * either every reference is treated as authoritative or none are.
 *
 * Typed instead. The relationship is part of the reference, not inferred:
 *
 *   verifies-precondition  a check performed BEFORE the action (the `ref=` slot)
 *   derives-from           this record was computed from that one
 *   settles                this record records settlement of that obligation
 *   corrects               this record fixes a factual error in that one
 *   supersedes             this record replaces that one wholesale
 *
 * `corrects` and `supersedes` are what let history stay append-only. A later
 * record changes the INTERPRETATION of an earlier one without editing it;
 * the earlier record remains exactly as issued and stays independently
 * verifiable. Silent mutation is the failure this prevents.
 */
const REF_TYPES = {
  'verifies-precondition': { pre_action: true, replaces: false },
  'derives-from': { pre_action: false, replaces: false },
  'settles': { pre_action: false, replaces: false },
  'corrects': { pre_action: false, replaces: true },
  'supersedes': { pre_action: false, replaces: true },
};

function checkRefs(refs) {
  if (refs === undefined || refs === null) {
    return { verdict: K.NOT_EVALUATED, reason: 'NO_REFS_ASSERTED', refs: [] };
  }
  if (!Array.isArray(refs)) {
    return { verdict: K.DISAGREE, reason: 'REFS_NOT_A_LIST' };
  }
  if (refs.length === 0) {
    return { verdict: K.NOT_EVALUATED, reason: 'NO_REFS_ASSERTED', refs: [] };
  }

  const checked = refs.map((r) => {
    if (!r || !r.type) return { verdict: K.NOT_EVALUATED, reason: 'REF_UNTYPED', ref: r };
    if (!Object.prototype.hasOwnProperty.call(REF_TYPES, r.type)) {
      // An unknown relationship is not a broken one. Same rule as an unknown
      // schema: never a pass, never a failure.
      return { verdict: K.NOT_EVALUATED, reason: 'REF_TYPE_UNSUPPORTED', type: r.type };
    }
    if (!r.target) return { verdict: K.DISAGREE, reason: 'REF_TYPE_WITHOUT_TARGET', type: r.type };
    return { verdict: K.AGREE, reason: 'REF_WELL_FORMED', type: r.type, target: r.target };
  });

  return { verdict: worst(checked.map((c) => c.verdict)), reason: 'TYPED_REFS', refs: checked };
}

/**
 * Resolve which record in a chain is currently authoritative, without
 * mutating any of them. A record that has been superseded or corrected is
 * still valid as issued — it is simply no longer the current interpretation.
 */
function currentInterpretation(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return { verdict: K.NOT_EVALUATED, reason: 'NO_RECORDS' };
  }
  const byId = new Map(records.map((r) => [r.id, r]));
  const replaced = new Set();
  for (const r of records) {
    for (const ref of r.refs || []) {
      const meta = REF_TYPES[ref.type];
      if (meta && meta.replaces && byId.has(ref.target)) replaced.add(ref.target);
    }
  }
  const live = records.filter((r) => !replaced.has(r.id));
  if (live.length === 0) {
    return { verdict: K.INDETERMINATE, reason: 'ALL_RECORDS_REPLACED_CYCLE' };
  }
  if (live.length > 1) {
    return {
      verdict: K.INDETERMINATE,
      reason: 'MULTIPLE_LIVE_RECORDS',
      note: 'more than one record is unreplaced; the chain does not determine a single ' +
            'current interpretation',
      live: live.map((r) => r.id),
    };
  }
  return {
    verdict: K.AGREE,
    reason: 'SINGLE_CURRENT_INTERPRETATION',
    current: live[0].id,
    superseded: [...replaced],
    note: 'superseded records remain valid as issued and independently verifiable',
  };
}

// ------------------------------------------------------------------ ordering
/**
 * Verdict severity for aggregation. NOT_EVALUATED outranks INDETERMINATE
 * deliberately: a bundle containing something nobody checked is a weaker
 * statement than one where every check ran and some were inconclusive.
 */
const ORDER = { [K.AGREE]: 0, [K.DISAGREE]: 3, [K.INDETERMINATE]: 1, [K.NOT_EVALUATED]: 2 };
function worst(verdicts) {
  let out = K.AGREE;
  for (const v of verdicts) if ((ORDER[v] ?? 3) > (ORDER[out] ?? 0)) out = v;
  return out;
}

module.exports = {
  ROLES, REF_TYPES,
  captureRelationship, checkDeclaredIndependence,
  bindStates, checkRefs, currentInterpretation, worst,
};
