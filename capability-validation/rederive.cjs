#!/usr/bin/env node
// Re-derives the capability-expansion detector's precision from the blind
// validation set, for snyk/agent-scan#482. Node 18+, standard library only,
// no network, nothing to install.
//
//   node rederive.cjs
//
// The point is that the 57.1% figure in that issue is not taken on trust.
// This recomputes it from answer-key.json (the blind assignment, fixed by
// seed before any case was looked at) and adjudications.jsonl (the labels,
// recorded against source).

const fs = require('fs');
const path = require('path');

const dir = __dirname;
const key = JSON.parse(fs.readFileSync(path.join(dir, 'answer-key.json'), 'utf8'));
const adj = fs.readFileSync(path.join(dir, 'adjudications.jsonl'), 'utf8')
  .trim().split('\n').map((l) => JSON.parse(l));

const out = [];
const say = (k, v) => { out.push([k, v]); };

say('answer key created', key.created_at);
say('seed', String(key.seed));
say('blind cases', String(Object.keys(key.items).length));
say('adjudications', String(adj.length));

const unmatched = adj.filter((a) => !key.items[a.id]);
say('ids matched', (adj.length - unmatched.length) + ' of ' + adj.length);

// Population the sample was drawn from, carried in the key so the sample can
// be checked against the frame rather than described.
say('population total_ok', String(key.population.total_ok));
say('population expanded', String(key.population.expanded));
say('population changed_not_expanded', String(key.population.changed_not_expanded));
say('population identical', String(key.population.identical));

let flagged = 0;
const tally = { yes: 0, no: 0, unclear: 0 };
for (const a of adj) {
  const item = key.items[a.id];
  if (!item || !item.detector_expanded) continue;
  flagged++;
  tally[a.label] = (tally[a.label] || 0) + 1;
}

const decided = tally.yes + tally.no;
const precisionDecided = tally.yes / decided;
const precisionStrict = tally.yes / flagged;

console.log('CAPABILITY-EXPANSION DETECTOR — blind validation, re-derived\n');
const w = Math.max(...out.map(([k]) => k.length));
for (const [k, v] of out) console.log('  ' + k.padEnd(w) + '  ' + v);

console.log('\n  flagged by detector_expanded                ' + flagged);
console.log('  adjudicated yes                             ' + tally.yes);
console.log('  adjudicated no                              ' + tally.no);
console.log('  adjudicated unclear                         ' + tally.unclear);

console.log('\n  precision, unclear excluded   ' + tally.yes + '/' + decided +
  '  = ' + (precisionDecided * 100).toFixed(1) + '%   <- the figure reported in snyk/agent-scan#482');
console.log('  precision, unclear counted as false positive  ' + tally.yes + '/' + flagged +
  '  = ' + (precisionStrict * 100).toFixed(1) + '%');
console.log('\n  The issue quoted the first convention without naming it. Both are');
console.log('  printed here so the choice is visible rather than embedded.');

// Base-rate consequence, the reason precision matters at all here.
const rawRate = 0.227;
const corrected = rawRate * precisionDecided;
console.log('\n  raw alert rate                 ' + (rawRate * 100).toFixed(1) + '%');
console.log('  corrected by precision         ' + (corrected * 100).toFixed(1) + '%');
// PPV ~= r/a at high sensitivity, so a 10% PPV target needs r = a/10.
// This line first read corrected/9 and printed 1.44%, disagreeing with the
// 1.30% in the issue. The issue was right; the script was wrong.
console.log('  attack rate needed for 10% PPV ' + ((corrected / 10) * 100).toFixed(2) + '%');

// Known-answer guard: if the labels file were silently swapped for one that
// agrees with the detector everywhere, precision would read 100% and nothing
// above would complain. Assert the sample actually disagrees with the detector.
if (tally.no === 0) {
  console.error('\nREFUSING: zero disagreements between detector and adjudication. ' +
    'A validation set that never contradicts the thing it validates is not a validation set.');
  process.exit(1);
}
