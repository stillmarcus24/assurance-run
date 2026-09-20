#!/usr/bin/env node
'use strict';
/**
 * interop-matrix — what the four-state vocabulary actually costs, measured.
 *
 * wg-identity#21 and tsc#4 record four parties converged on the verdict
 * vocabulary `verified / contradicted / indeterminate / not-evaluated`. That
 * count is a count of agreement, not of emission. @TKCollective drew the
 * distinction himself at tsc#4 on 2026-09-20: his production verifier is
 * three-outcome while the term sits in draft-krausz-verification-state.
 *
 * This runner answers the question the charter vote actually turns on: for each
 * implementation named in that thread, which of the four states can it express
 * DISTINCTLY, and where does it collapse them. It reports how each row was
 * established, and it refuses to print a row whose evidence it did not obtain
 * in THIS run.
 *
 * The load-bearing column is the absence side. `indeterminate` (a check ran and
 * the evidence could not settle it) and `not-evaluated` (no valid check ran)
 * have different owners: the first is a fact about the world, the second is a
 * fact about the evaluator. An implementation that cannot separate them can
 * report its own instrument failure as a finding about someone else's system.
 * That is AC-11, and it is the defect this vocabulary exists to make impossible.
 *
 * HONESTY BOUNDARY, same as live-babyblueviper.cjs:
 *   - Executed and confirmed        -> AGREE
 *   - Read off pinned public source -> AGREE, method recorded as source_read
 *   - Could not execute / no public surface -> NOT_EVALUATED, never a DISAGREE
 *     about their system. Failing to reach an implementation is a statement
 *     about this runner, not about their code.
 *
 * Read-only. No key, no account, no write, no payment.
 *
 * CORRECTION, 2026-09-20 — the column was asserted, not measured.
 * @meloliva14 corrected the x402-measure row at tsc#4 and was right on every
 * point. Two defects, and the second is the serious one:
 *
 *   1. The row read the WRONG ARTIFACT. It grepped root-level *.py for a
 *      `NOT_ASSESSED` token and concluded "no verdict enum". x402-measure
 *      carries `manifest.verdict_vocabulary` in 33 of its 43 signed daily
 *      snapshots (2026-08-18 onward, Ed25519 over observation.json), and
 *      NOT_ASSESSED appears on 0 of 65,403 rows — it exists only as a local
 *      `= {"RATE_LIMITED"}` set inside two comparison scripts. We measured a
 *      source token and reported it as emitted behaviour.
 *
 *   2. Then the sibling audit: `distinguishes_absence` was a HARDCODED LITERAL
 *      in 4 of 4 gatherers. Three rows never derived the load-bearing column
 *      from anything at all. The one row that did derive it derived it from
 *      the wrong artifact. A matrix that prints "measured, not asserted" in its
 *      own header was asserting its only load-bearing column.
 *
 * The fix is not a better literal. Every row now declares its VOCABULARY, read
 * from the authoritative artifact and cited by path, and one shared classifier
 * below turns a vocabulary into the column. The classification rule is published
 * in the output so a reader can reject the RULE rather than having to take the
 * ROW on faith — and an implementation whose vocabulary the rule cannot classify
 * yields null, which is NOT_EVALUATED, not a default.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const K = require('./kernel.cjs');

const { AGREE, INDETERMINATE, NOT_EVALUATED } = K;

const UA = 'StillOS-assurance-run/interop-matrix (read-only; no key; no payment)';

/* ------------------------------------------------------------------ *
 * Subjects. Each carries the public surface it is established from.
 * ------------------------------------------------------------------ */

const SUBJECTS = [
  {
    id: 'assurance-run',
    operator: '@stillmarcus24',
    surface: 'https://github.com/stillmarcus24/assurance-run',
    kind: 'executable',
  },
  {
    id: 'elara-verify',
    operator: '@navigatorbuilds',
    surface: 'https://github.com/navigatorbuilds/elara-mesh',
    kind: 'source',
  },
  {
    id: 'x402-measure',
    operator: '@meloliva14',
    surface: 'https://github.com/meloliva14/x402-measure',
    kind: 'source',
  },
  {
    id: 'babyblueviper-verify-proof',
    operator: '@babyblueviper1',
    surface: 'https://api.babyblueviper.com',
    kind: 'live',
  },
  {
    id: 'draft-krausz-verification-state',
    operator: '@TKCollective',
    surface: 'https://datatracker.ietf.org/doc/draft-krausz-verification-state/',
    kind: 'specification',
  },
];

/* ------------------------------------------------------------------ *
 * THE CLASSIFIER. One rule, published, applied identically to every row.
 *
 * The column asks exactly one thing: can this implementation say
 * "a check ran and the evidence could not settle it" and
 * "no valid check ran"  — as two DIFFERENT values?
 *
 * So each declared value needs only three buckets:
 *   SETTLED   the check ran and reached an answer, either way
 *   WORLD     the check ran; the source did not settle it (their side)
 *   INSTRUMENT no valid check ran / not assessable by this prober (our side)
 *
 * Basis, strongest first. A value classified from the operator's OWN published
 * meaning outranks our reading of its name, and is recorded as such:
 *   operator_note — the vocabulary ships a meaning and the meaning decides it
 *   name_map      — our table below, stated in full so it can be disputed
 *   unclassified  — neither applies; the row cannot be decided and says so
 * ------------------------------------------------------------------ */

const SETTLED = 'SETTLED', WORLD = 'WORLD', INSTRUMENT = 'INSTRUMENT';

// Published so the rule is arguable. Names are matched case-insensitively.
const NAME_ROLES = {
  // settled — an answer was reached about the artifact
  AGREE: SETTLED, DISAGREE: SETTLED, VERIFIED: SETTLED, FAILED: SETTLED,
  OK: SETTLED, WARN: SETTLED, BLOCKED: SETTLED, V1: SETTLED,
  UNPARSEABLE: SETTLED, NO_402: SETTLED,
  // world — we asked; their side did not settle it
  INDETERMINATE: WORLD, UNREACHABLE: WORLD, TIMEOUT: WORLD, PARTIAL: WORLD,
  // instrument — no valid check ran, or this prober cannot assess it
  NOT_EVALUATED: INSTRUMENT, NOT_ASSESSED: INSTRUMENT, RATE_LIMITED: INSTRUMENT,
  NON_EVM: INSTRUMENT, UNKNOWN_NETWORK: INSTRUMENT,
};

/**
 * `vocabulary` is either an array of value names, or an object mapping each
 * value name to the operator's own one-line meaning. The second form is
 * strictly better evidence and we use it when it exists.
 */
function classifyVocabulary(vocabulary) {
  const withNotes = !Array.isArray(vocabulary);
  const names = withNotes ? Object.keys(vocabulary) : vocabulary;
  const roles = names.map((name) => {
    const note = withNotes ? String(vocabulary[name] || '') : '';
    // The operator's own words win. "not assessed" is a statement that THIS
    // prober did not evaluate it — instrument side, by their definition, not ours.
    if (/\bnot assessed\b/i.test(note)) {
      return { value: name, role: INSTRUMENT, basis: 'operator_note', note };
    }
    if (/\bno response\b|\btimed? ?out\b/i.test(note)) {
      return { value: name, role: WORLD, basis: 'operator_note', note };
    }
    const mapped = NAME_ROLES[String(name).toUpperCase()];
    if (mapped) return { value: name, role: mapped, basis: 'name_map', note: note || null };
    return { value: name, role: null, basis: 'unclassified', note: note || null };
  });

  const has = (r) => roles.filter((x) => x.role === r).map((x) => x.value);
  const world = has(WORLD), instrument = has(INSTRUMENT);
  const unclassified = roles.filter((x) => x.role === null).map((x) => x.value);

  // Decided only when the decision does not hinge on a value we could not place.
  let distinguishes = world.length > 0 && instrument.length > 0;
  if (!distinguishes && unclassified.length) distinguishes = null; // NOT_EVALUATED

  return { roles, world_side: world, instrument_side: instrument, unclassified, distinguishes };
}

/* ------------------------------------------------------------------ *
 * Evidence gatherers. Each returns {established, method, detail} and
 * never throws a conclusion about the subject on its own failure.
 * Each supplies a `vocabulary` + `vocabulary_source`; NONE decides the
 * column itself. That is the classifier's job, above, for every row.
 * ------------------------------------------------------------------ */

function sh(cmd, args, opts) {
  return execFileSync(cmd, args, { encoding: 'utf8', timeout: 120000, ...opts });
}

async function http(method, url) {
  try {
    const res = await fetch(url, { method, headers: { 'user-agent': UA }, signal: AbortSignal.timeout(20000) });
    const text = await res.text();
    return { ok: true, status: res.status, text };
  } catch (err) {
    return { ok: false, error: String(err && err.message || err) };
  }
}

/** assurance-run: execute the corpus in this tree. */
function gatherSelf() {
  try {
    const out = sh('node', [path.join(__dirname, 'selftest-semantics.cjs')], { cwd: __dirname });
    const held = /RESULT: all prohibitions held/.test(out);
    const cases = (out.match(/^\s+ok\s+SC-\d+/gm) || []).length;
    const head = sh('git', ['rev-parse', '--short', 'HEAD'], { cwd: __dirname }).trim();
    if (!held) return { established: false, method: 'executed', detail: 'selftest did not report all prohibitions held' };
    // The vocabulary is read from the kernel's own exports, not typed in here.
    // A literal list would go stale the moment the kernel changed and would be
    // the same asserted-column defect this file was corrected for.
    const vocabulary = [K.AGREE, K.DISAGREE, K.INDETERMINATE, K.NOT_EVALUATED]
      .filter((v) => typeof v === 'string');
    return {
      established: true,
      method: 'executed',
      pin: head,
      vocabulary,
      vocabulary_source: 'kernel.cjs exports (AGREE/DISAGREE/INDETERMINATE/NOT_EVALUATED)',
      detail: `${cases} semantic cases executed, all prohibitions held`,
    };
  } catch (err) {
    return { established: false, method: 'executed', detail: String(err && err.message || err) };
  }
}

/**
 * A peer repo, read at a pinned commit. Source-read only: this runner clones
 * shallow and reads text. It does NOT build, test or execute third-party code,
 * which is why the elara-verify row is a source_read rather than an execution.
 * A clone that cannot be obtained is NOT_EVALUATED, never a finding.
 */
function ensureClone(dir, remote) {
  if (fs.existsSync(path.join(dir, '.git'))) return true;
  try {
    fs.mkdirSync(path.dirname(dir), { recursive: true });
    sh('git', ['clone', '--depth', '1', '--quiet', remote, dir]);
    return true;
  } catch (_) {
    return false;
  }
}

function gatherSource(dir, extract, remote) {
  if (!fs.existsSync(dir) && remote) ensureClone(dir, remote);
  if (!fs.existsSync(dir)) {
    return { established: false, method: 'not_reachable', detail: `could not obtain ${remote || dir}; nothing was read` };
  }
  let pin = null;
  try { pin = sh('git', ['rev-parse', '--short', 'HEAD'], { cwd: dir }).trim(); } catch (_) {}
  try {
    const found = extract(dir);
    if (!found) return { established: false, method: 'source_read', detail: 'declared surface not found in the tree at this pin' };
    return { established: true, method: 'source_read', pin, ...found };
  } catch (err) {
    return { established: false, method: 'source_read', pin, detail: String(err && err.message || err) };
  }
}

function extractElara(dir) {
  const f = path.join(dir, 'crates/elara-verify/src/lib.rs');
  if (!fs.existsSync(f)) return null;
  const src = fs.readFileSync(f, 'utf8');
  const block = src.match(/pub enum Verdict \{([\s\S]*?)\}/);
  if (!block) return null;
  const states = block[1].split('\n').map(s => s.trim().replace(/,$/, ''))
    .filter(s => s && !s.startsWith('//'));
  // Attach each variant's own doc comment as its meaning, so the classifier
  // decides from THEIR words where they wrote any. The `Partial` docstring is
  // the whole absence-side question for this implementation.
  const vocabulary = {};
  for (const v of states) {
    const doc = src.match(new RegExp(`((?:\\s*///[^\\n]*\\n)+)\\s*${v}\\s*,`));
    vocabulary[v] = doc ? doc[1].replace(/\s*\/\/\/ ?/g, ' ').trim() : '';
  }
  return {
    vocabulary,
    vocabulary_source: 'crates/elara-verify/src/lib.rs — pub enum Verdict + variant doc comments',
    detail: `Verdict{${states.join(', ')}} in crates/elara-verify/src/lib.rs` +
      (/absent or pending evidence/.test(vocabulary.Partial || '')
        ? '; its own docstring assigns "absent or pending evidence" to the single Partial' : ''),
  };
}

/**
 * x402-measure. The vocabulary is the one the SIGNED SNAPSHOTS declare, not a
 * token grepped out of source. Each daily snapshot carries
 * `manifest.verdict_vocabulary` — value -> the operator's own one-line meaning —
 * and signature.json is Ed25519 over the exact bytes of observation.json.
 *
 * We read the newest snapshot that declares one, and we check the vocabulary
 * against the rows it governs: every emitted verdict must be a declared value.
 * The previous version of this row grepped `NOT_ASSESSED` out of root *.py and
 * reported it as emitted behaviour; it is carried by no row in the corpus.
 */
function extractX402Measure(dir) {
  const snapDir = path.join(dir, 'snapshots');
  if (!fs.existsSync(snapDir)) return null;
  const days = fs.readdirSync(snapDir).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();
  if (!days.length) return null;

  let chosen = null;
  const declaring = [];
  for (const day of days) {
    const obsFile = path.join(snapDir, day, 'observation.json');
    if (!fs.existsSync(obsFile)) continue;
    let obs; try { obs = JSON.parse(fs.readFileSync(obsFile, 'utf8')); } catch { continue; }
    const vocab = obs && obs.manifest && obs.manifest.verdict_vocabulary;
    if (vocab && typeof vocab === 'object') { declaring.push(day); chosen = { day, obs, vocab, obsFile }; }
  }
  if (!chosen) return null;

  // The signature covers observation.json by digest; recompute it rather than
  // cite it. A vocabulary read out of an unverified file is a vocabulary we
  // were handed, not one we established.
  let signed = false, sigDetail = 'no signature.json beside the snapshot';
  const sigFile = path.join(snapDir, chosen.day, 'signature.json');
  if (fs.existsSync(sigFile)) {
    try {
      const sig = JSON.parse(fs.readFileSync(sigFile, 'utf8'));
      const digest = crypto.createHash('sha256').update(fs.readFileSync(chosen.obsFile)).digest('hex');
      signed = sig.signs === 'observation.json' && digest === sig.payload_sha256;
      sigDetail = signed
        ? `${sig.algorithm} ${sig.key_id}, payload_sha256 recomputed here over ${sig.payload_bytes} bytes`
        : `signature.json does not commit to these bytes (signs=${sig.signs})`;
    } catch (e) { sigDetail = 'signature.json unreadable: ' + e.message; }
  }

  // Does every emitted verdict appear in that day's declared vocabulary?
  const rows = Array.isArray(chosen.obs.observations) ? chosen.obs.observations : [];
  const emitted = new Set(rows.map(r => r && r.verdict).filter(Boolean));
  const undeclared = [...emitted].filter(v => !(v in chosen.vocab));

  return {
    vocabulary: chosen.vocab,
    vocabulary_source: `snapshots/${chosen.day}/observation.json — manifest.verdict_vocabulary` +
      (signed ? ' (signature verified here)' : ' (SIGNATURE NOT VERIFIED)'),
    corroboration: {
      snapshots_total: days.length,
      snapshots_declaring_vocabulary: declaring.length,
      first_declaring: declaring[0],
      rows_in_read_snapshot: rows.length,
      verdicts_emitted: [...emitted].sort(),
      verdicts_undeclared: undeclared,
      signature_verified: signed,
    },
    detail: `${Object.keys(chosen.vocab).length} declared values in ` +
      `manifest.verdict_vocabulary on ${chosen.day}; ${declaring.length} of ${days.length} snapshots ` +
      `declare one (first ${declaring[0]}). ${sigDetail}. ${rows.length} rows in this snapshot emit ` +
      `${emitted.size} distinct verdicts, ${undeclared.length} of them undeclared.`,
  };
}

/**
 * The live endpoint: re-run the named reference vector rather than cite it.
 *
 * This implementation has no verdict enum to read — it answers with a boolean
 * `valid` plus sibling check fields — so the column cannot come from a declared
 * vocabulary. It comes from OBSERVED BEHAVIOUR instead: BB-08 tampers one byte
 * of a signed proof and records how the checks that could no longer run are
 * encoded. That finding's reason code is the evidence, and it is produced by a
 * live execution in this run, not written down here.
 *
 * UNRUN_CHECKS_ABSENT / _NULL  -> the two sides are separated
 * UNRUN_CHECKS_REPORT_FALSE    -> collapsed; a short-circuit filed as a finding
 * anything else                -> undecided, which is NOT_EVALUATED
 */
function gatherLiveVector() {
  try {
    const out = sh('node', [path.join(__dirname, 'live-babyblueviper.cjs')], { cwd: __dirname });
    const counts = out.match(/counts\s+(\{.*\})/);
    if (!counts) return { established: false, method: 'executed_live', detail: 'runner produced no counts line' };
    const parsed = JSON.parse(counts[1]);

    const m = out.match(/^\s*(AGREE|DISAGREE|INDETERMINATE|NOT_EVALUATED)\s+(UNRUN_CHECKS_\S+|TAMPER_READ_AS_VALID|MIXED_DOWNSTREAM_ENCODING|NO_EVENT_TO_TAMPER)/m);
    const verdict = m && m[1], reason = m && m[2];
    let distinguishes = null, basis = 'tamper case did not execute in this run';
    if (verdict === 'AGREE' && /^UNRUN_CHECKS_(ABSENT|NULL)/.test(reason)) {
      distinguishes = true;
      basis = `live tamper (BB-08) → ${reason}: checks that could no longer run are encoded ` +
        `${reason.replace('UNRUN_CHECKS_', '')}, never false`;
    } else if (reason === 'UNRUN_CHECKS_REPORT_FALSE') {
      distinguishes = false;
      basis = 'live tamper (BB-08) → unreached checks reported false: the two sides collapse';
    }

    return {
      established: true,
      method: 'executed_live',
      vocabulary: null,
      vocabulary_source: 'no verdict enum — boolean `valid` with sibling check fields',
      // Minted here, at the point the live run produced it. Downstream never
      // adds a mark it did not earn.
      distinguishes_absence: K.derived(distinguishes, basis),
      distinguishes_basis: basis,
      counts: parsed,
      detail: `no verdict enum; a boolean with sibling check fields. ${basis}.`,
    };
  } catch (err) {
    return { established: false, method: 'executed_live', detail: String(err && err.message || err) };
  }
}

/** A specification with no public executable surface is not a failing row. */
async function gatherSpec(url) {
  const res = await http('GET', 'https://datatracker.ietf.org/api/v1/doc/document/?name__contains=krausz-verification&format=json');
  if (!res.ok) {
    return { established: false, method: 'not_reachable', detail: `datatracker unreachable from this run: ${res.error}` };
  }
  let total = null;
  try { total = JSON.parse(res.text).meta.total_count; } catch (_) {}
  return {
    established: false,
    method: 'no_executable_surface',
    detail: total
      ? `draft is published (datatracker returns ${total} matching document) and carries the four-state term; ` +
        'no public implementation surface is named in wg-identity#21 or tsc#4, so nothing was executed'
      : 'datatracker returned no matching document from this run',
  };
}

/* ------------------------------------------------------------------ */

/**
 * Decide the column for one row. A gatherer that supplied a vocabulary is
 * classified by the published rule; one that could only observe behaviour
 * (the live endpoint) supplies the answer with its basis recorded. Neither
 * path lets a gatherer hand over a bare boolean with no justification.
 */
function decideRow(ev) {
  // Every return below wraps the column in K.derived(value, source). The gate at
  // publication refuses any row whose column arrives unwrapped, so a hardcoded
  // literal cannot reach the output — it fails the run instead of printing.
  if (!ev.established) {
    return { distinguishes: K.derived(null, `not established by this run (${ev.method})`),
      classification: null, basis: ev.method };
  }
  if (ev.vocabulary) {
    const c = classifyVocabulary(ev.vocabulary);
    const src = `classifyVocabulary() over ${Object.keys(ev.vocabulary).length || ev.vocabulary.length} ` +
      `declared values read from ${ev.vocabulary_source}`;
    return { distinguishes: K.derived(c.distinguishes, src), classification: c, basis: `classified from ${ev.vocabulary_source}` };
  }
  if (ev.distinguishes_absence !== undefined) {
    // Pass it through EXACTLY as the gatherer produced it. An earlier version of
    // this branch wrapped whatever arrived in K.derived(..., 'observed behaviour'),
    // which would have laundered a hardcoded literal into a derivation and made
    // the gate decorative. The mark has to be minted where the value is computed;
    // a bare literal stays bare and the gate rejects the run.
    return { distinguishes: ev.distinguishes_absence, classification: null,
      basis: ev.distinguishes_basis || 'observed behaviour' };
  }
  return { distinguishes: K.derived(null, 'no vocabulary and no observed behaviour'),
    classification: null, basis: 'no vocabulary and no observed behaviour' };
}

function verdictFor(ev, decided) {
  const d = K.isDerived(decided.distinguishes) ? decided.distinguishes.value : decided.distinguishes;
  const src = K.isDerived(decided.distinguishes) ? decided.distinguishes.source : 'undeclared';
  if (!ev.established) return K.derived(NOT_EVALUATED, `row not established: ${ev.method}`);
  if (d === true) return K.derived(AGREE, `column true via ${src}`);
  if (d === false) return K.derived(INDETERMINATE, `column false via ${src}`);
  // undecidable is never a default either way
  return K.derived(NOT_EVALUATED, `column undecidable via ${src}`);
}

async function main() {
  const peerRoot = process.env.INTEROP_CLONE_DIR || path.join(__dirname, '.peers');
  const evidence = {
    'assurance-run': gatherSelf(),
    'elara-verify': gatherSource(path.join(peerRoot, 'elara-mesh'), extractElara,
      'https://github.com/navigatorbuilds/elara-mesh.git'),
    'x402-measure': gatherSource(path.join(peerRoot, 'x402-measure'), extractX402Measure,
      'https://github.com/meloliva14/x402-measure.git'),
    'babyblueviper-verify-proof': gatherLiveVector(),
    'draft-krausz-verification-state': await gatherSpec(),
  };

  const rows = SUBJECTS.map(s => {
    const ev = evidence[s.id];
    const d = decideRow(ev);
    const vocabNames = ev.vocabulary
      ? (Array.isArray(ev.vocabulary) ? ev.vocabulary : Object.keys(ev.vocabulary)) : null;
    return {
      ...s,
      verdict: verdictFor(ev, d),
      established: ev.established === true,
      method: ev.method,
      pin: ev.pin || null,
      vocabulary: vocabNames,
      cardinality: vocabNames ? vocabNames.length : null,
      vocabulary_source: ev.vocabulary_source || null,
      distinguishes_absence: d.distinguishes,
      decided_by: d.basis,
      // The per-value classification is published so the RULE can be disputed
      // instead of the row having to be taken on trust.
      value_roles: d.classification
        ? d.classification.roles.map(r => ({ value: r.value, role: r.role, basis: r.basis }))
        : null,
      world_side: d.classification ? d.classification.world_side : null,
      instrument_side: d.classification ? d.classification.instrument_side : null,
      unclassified_values: d.classification ? d.classification.unclassified : null,
      corroboration: ev.corroboration || null,
      detail: ev.detail,
    };
  });

  // THE GATE. Nothing below this line may read a load-bearing field until the
  // gate has passed, because until then the value is still wrapped. Declared
  // here rather than inside the row builder so the list of what counts as
  // load-bearing is visible in one place and can be extended deliberately.
  const LOAD_BEARING = ['rows[].distinguishes_absence', 'rows[].verdict'];
  let provenance;
  try {
    provenance = K.sealDerived({ rows }, LOAD_BEARING);
  } catch (err) {
    if (err.code !== 'DERIVATION_GATE') throw err;
    console.error('\n  REFUSED TO PUBLISH\n');
    console.error('  ' + err.message.split('\n').join('\n  ') + '\n');
    process.exit(2);
  }

  // A "four-state emitter" is an implementation that can name both sides of the
  // absence split, whatever it calls them. Cardinality 4 and the literal token
  // NOT_EVALUATED were the old test, and it was a test of vocabulary fashion
  // rather than of capability — it would have failed every implementation that
  // reached the same distinction under different names. x402-measure is exactly
  // that case and the old test scored it wrong.
  const emitters = rows.filter(r => r.established && r.distinguishes_absence === true);
  const unreached = rows.filter(r => !r.established);
  const undecided = rows.filter(r => r.established && r.distinguishes_absence === null);

  const out = {
    corpus: 'assurance-run/interop-matrix',
    question: 'which implementations can express the four verification states distinctly, and where do they collapse',
    observed_at: new Date().toISOString(),
    // The rule is part of the output. A reader who rejects it can recompute
    // every row from value_roles without rerunning anything.
    classification_rule: {
      buckets: { SETTLED: 'the check ran and reached an answer',
        WORLD: 'the check ran; the source did not settle it',
        INSTRUMENT: 'no valid check ran, or not assessable by this prober' },
      column_is_true_when: 'the vocabulary carries at least one WORLD value AND at least one INSTRUMENT value',
      basis_precedence: ['operator_note', 'name_map', 'unclassified'],
      name_map: NAME_ROLES,
      undecidable_yields: 'null -> NOT_EVALUATED, never a default in either direction',
    },
    // Where each load-bearing value came from, recorded at the moment it was
    // computed. A field absent from here could not have been published: the
    // gate refuses the run rather than printing an undeclared value.
    derivation_gate: {
      enforced_paths: LOAD_BEARING,
      rule: 'a load-bearing field must arrive as derived(value, source) or the run fails before publication',
      proves: 'the value was produced by code that ran this run, with its artifact named',
      does_not_prove: 'that the derivation is correct — a wrong derivation still passes',
      provenance,
    },
    rows,
    summary: {
      subjects: rows.length,
      absence_side_distinct: emitters.map(r => r.id),
      absence_side_collapsed: rows.filter(r => r.distinguishes_absence === false).map(r => r.id),
      undecidable_by_this_rule: undecided.map(r => ({ id: r.id, unclassified: r.unclassified_values })),
      not_established_by_this_run: unreached.map(r => ({ id: r.id, why: r.method })),
    },
  };

  const dir = path.join(__dirname, 'verdicts');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `interop-matrix-${out.observed_at.slice(0, 10)}.json`);
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');

  const pad = (s, n) => String(s === null || s === undefined ? '—' : s).padEnd(n).slice(0, n);
  console.log('\n  four-state interop matrix — measured, not asserted');
  console.log(`  observed_at  ${out.observed_at}`);
  console.log(`  not established by this run: ${unreached.length} of ${rows.length}\n`);
  console.log(`  ${pad('implementation', 32)}${pad('verdict', 15)}${pad('states', 8)}${pad('absence split', 15)}method`);
  console.log(`  ${'-'.repeat(88)}`);
  for (const r of rows) {
    console.log(`  ${pad(r.id, 32)}${pad(r.verdict, 15)}${pad(r.cardinality, 8)}` +
      `${pad(r.distinguishes_absence === null ? '—' : (r.distinguishes_absence ? 'distinct' : 'COLLAPSED'), 15)}${r.method}`);
  }
  console.log('');
  for (const r of rows) {
    console.log(`  ${r.id}`);
    console.log(`    ${r.detail}`);
    console.log(`    decided by: ${r.decided_by}`);
    if (r.world_side) {
      console.log(`    world side: ${r.world_side.join(', ') || '(none)'}` +
        `  |  instrument side: ${r.instrument_side.join(', ') || '(none)'}` +
        (r.unclassified_values && r.unclassified_values.length
          ? `  |  unclassified: ${r.unclassified_values.join(', ')}` : ''));
    }
    console.log('');
  }
  console.log(`  absence side distinct: ${emitters.length ? emitters.map(r => r.id).join(', ') : 'none'}`);
  if (undecided.length) console.log(`  undecidable by this rule: ${undecided.map(r => r.id).join(', ')}`);
  console.log(`  written: ${file}\n`);
}

// Exported so the classifier can be pinned by known-answer fixtures in
// selftest.cjs. It was unreachable from any test until 2026-09-20, which is why
// a rule that decided every row in the matrix had zero cases against it.
module.exports = { classifyVocabulary, NAME_ROLES, SETTLED, WORLD, INSTRUMENT };

if (require.main === module) {
  main().catch(err => { console.error(err); process.exit(1); });
}
