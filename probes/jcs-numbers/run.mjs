#!/usr/bin/env node
// run.mjs — RFC 8785 number serialization: who inherits it and who must reimplement it.
//
// RFC 8785 §3.2.2.3 does not describe a number format. It defers to ECMAScript
// Number::toString. A JavaScript implementation therefore gets the required behaviour
// from the host and CANNOT FAIL these vectors. Every other host language has to
// reimplement double-to-shortest-round-trip, and the obvious primitive gets it wrong.
//
// Measured against Python's json.dumps: 7 of 11 diverge, in 6 classes.
// x402-foundation/x402#2887 named three of them (the exponent cases). The
// integer-valued-float and negative-zero classes are not in that thread.
//
// THE POINT FOR A CORPUS: a JS reference implementation validating this section is a
// null experiment. It passes by construction, so a green run says nothing about
// whether the vectors would catch a wrong reading. The control has to be non-JS.
//
//   node probes/jcs-numbers/run.mjs            # table
//   node probes/jcs-numbers/run.mjs selftest   # known-answer checks
//   node probes/jcs-numbers/run.mjs --python   # re-measure python live (needs python3)
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const HERE = new URL('.', import.meta.url).pathname;
const doc = JSON.parse(readFileSync(HERE + 'vectors.json', 'utf8'));

// Inputs are JSON TEXT on purpose. Passing a double through a JS String() conversion
// turns 1.0 into the integer 1 and silently hides four of the seven divergences —
// that mistake was made once while building this file and is why the inputs are text.
export const required = (jsonText) => JSON.stringify(JSON.parse(jsonText));

export function livePython() {
  const out = execFileSync('python3', [HERE + 'py_canon.py'],
    { input: readFileSync(HERE + 'inputs.txt', 'utf8'), encoding: 'utf8' });
  return out.trim().split('\n');
}

function main() {
  const live = process.argv.includes('--python') ? livePython() : null;
  console.log(doc.required_by + '\n');
  let div = 0;
  doc.vectors.forEach((v, i) => {
    const py = live ? live[i] : v.python_json_dumps;
    const d = py !== v.required;
    if (d) div++;
    console.log(`  ${d ? 'DIVERGES' : 'agrees  '}  ${v.json_text.padEnd(24)} required ${v.required.padEnd(24)} python ${py.padEnd(24)} ${v.class}`);
  });
  console.log(`\npython json.dumps diverges on ${div}/${doc.vectors.length}`);
  console.log(`classes: ${doc.summary.divergence_classes.join(' | ')}`);
  console.log(`\nnode JSON.stringify diverges on 0/${doc.vectors.length} — it IS the function the spec cites.`);
}

function selftest() {
  let pass = 0; let fail = 0;
  const t = (n, got, want) => {
    JSON.stringify(got) === JSON.stringify(want) ? pass++
      : (fail++, console.log(`  FAIL ${n}\n    got  ${JSON.stringify(got)}\n    want ${JSON.stringify(want)}`));
  };
  t('11 vectors', doc.vectors.length, 11);
  t('every stored `required` is reproducible from the JSON text',
    doc.vectors.every((v) => required(v.json_text) === v.required), true);
  t('python diverges on 7', doc.vectors.filter((v) => v.diverges).length, 7);
  t('6 divergence classes', doc.summary.divergence_classes.length, 6);
  // The four classes #2887 has NOT named.
  t('integer-valued float is a divergence class',
    doc.summary.divergence_classes.some((c) => /integer-valued float$/.test(c)), true);
  t('negative zero is a divergence class', doc.summary.divergence_classes.includes('negative zero'), true);
  t('1.0 must serialize as 1', required('1.0'), '1');
  t('-0.0 must serialize as 0', required('-0.0'), '0');
  t('3.0e2 must serialize as 300', required('3.0e2'), '300');
  t('1e-5 must serialize as 0.00001', required('1e-5'), '0.00001');
  t('1e-7 stays in e-notation', required('1e-7'), '1e-7');
  t('1e21 is the e-notation threshold', required('1e21'), '1e+21');
  // A JS implementation cannot fail this section — that is the finding, asserted.
  t('a JS implementation passes every vector by construction',
    doc.vectors.every((v) => required(v.json_text) === v.required), true);
  t('our canonicalJson was correct on all 11', doc.summary.stillos_correct, 11);
  t('the String()-conversion trap is recorded', /String\(\) conversion/.test(doc.note), true);
  if (process.argv.includes('--python')) {
    const live = livePython();
    t('live python reproduces the stored divergence count',
      doc.vectors.filter((v, i) => live[i] !== v.required).length, 7);
  }
  console.log(`selftest: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

process.argv[2] === 'selftest' ? selftest() : main();
