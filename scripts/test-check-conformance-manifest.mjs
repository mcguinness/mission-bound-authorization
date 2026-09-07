#!/usr/bin/env node
import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { extractTitles, matchingDeclarations, collectedPathMatches, segmentOk, parseCollectedTests } from './test-title-paths.mjs';

const matches = (source, name) => matchingDeclarations(extractTitles(source), name);
const suite = (body) => `describe("real suite title (@spec example)", () => { ${body} });`;
const leaf = 'a sufficiently specific real test';
const citation = `real suite title > ${leaf}`;

test('collection JSON ignores package-manager diagnostics without treating them as tests', () => {
  assert.deepEqual(parseCollectedTests('[WARN] diagnostic\nDone\n[\n {"name":"real test", "file":"test.ts"}\n]\n'), [{ name: 'real test', file: 'test.ts' }]);
  assert.deepEqual(parseCollectedTests('diagnostic\n[]\n'), []);
  assert.throws(() => parseCollectedTests('[WARN] not an array of tests'));
});

test('an exact leaf and containing ancestor match a real callback', () => {
  assert.equal(matches(suite(`it("${leaf}", () => {});`), citation).length, 1);
  assert.equal(matches(suite(`test.only("${leaf}", function () {});`), citation).length, 1);
});
test('leaf substrings, nonexistent leaves, punctuation and short segments refuse', () => {
  const src = suite(`it("${leaf}", () => {});`);
  for (const name of ['real suite title > ;', 'short > ' + leaf, 'real suite title > sufficiently specific', 'real suite title > not an actual test']) {
    assert.equal(matches(src, name).length, 0, name);
  }
  assert.equal(segmentOk('...........'), false);
});
test('same leaf in the wrong sibling or wrong nesting depth cannot satisfy a citation', () => {
  const src = suite(`it("${leaf}", () => {});`) + `describe("other suite title", () => { it("another real test", () => {}); });`;
  assert.equal(matches(src, `other suite title > ${leaf}`).length, 0);
  assert.equal(matches(src, leaf).length, 0);
});
test('conditional aliases and Vitest import aliases resolve', () => {
  for (const prefix of ['const d = up ? describe : describe.skip;', 'import { describe as d } from "vitest";']) {
    assert.equal(matches(prefix + suite(`it("${leaf}", () => {});`).replace('describe(', 'd('), citation).length, 1);
  }
});
test('shadowed, reassigned, foreign and ambiguous aliases cannot fabricate suites', () => {
  for (const src of [
    'const d = describe; function fake(d) { ' + suite(`it("${leaf}", () => {});`).replace('describe(', 'd(') + ' }',
    'let d = describe; d = fake; ' + suite(`it("${leaf}", () => {});`).replace('describe(', 'd('),
    'import { describe } from "not-vitest";' + suite(`it("${leaf}", () => {});`),
    'const d = up ? describe : other;' + suite(`it("${leaf}", () => {});`).replace('describe(', 'd('),
    suite(`const it = fake; it("${leaf}", () => {});`),
  ]) assert.equal(matches(src, citation).length, 0, src);
});
test('comments, strings and regex literals do not contribute declarations', () => {
  for (const src of [
    `// ${suite(`it("${leaf}", () => {});`)}`,
    `/* ${suite(`it("${leaf}", () => {});`)} */`,
    `const example = ${JSON.stringify(suite(`it("${leaf}", () => {});`))};`,
    `const regex = /describe("real suite title", () => { it("${leaf}", () => {}); })/;`,
  ]) assert.equal(matches(src, citation).length, 0);
});
test('nested interpolation is a single title wildcard, not a suite callback', () => {
  const src = 'describe(`artifact kind: ${pick({key: "}", nested: `x${value}`})}`, () => { it("' + leaf + '", () => {}); });';
  assert.equal(matches(src, 'artifact kind: record > ' + leaf).length, 1);
});
test('each templates match their citations and substituted full runner paths', () => {
  const src = 'describe.each([1,2])("artifact kind %s", () => { it.each([1,2])("handles case %s at index %#", () => {}); });';
  const found = matches(src, 'artifact kind %s > handles case %s at index %#');
  assert.equal(found.length, 1);
  assert.equal(collectedPathMatches(found[0], 'artifact kind invoice > handles case one at index 0'), true);
  assert.equal(collectedPathMatches(found[0], 'wrong ancestor > handles case one at index 0'), false);
  assert.equal(collectedPathMatches(found[0], 'artifact kind invoice > handles case one at index label'), false);
});
test('static percent placeholders remain literal and unsupported call idioms refuse', () => {
  const src = suite('it("static percent %s title", () => {});');
  const [found] = matches(src, 'real suite title > static percent %s title');
  assert.equal(collectedPathMatches(found, 'real suite title (@spec example) > static percent spoof title'), false);
  assert.equal(matches(suite(`it.unsupported("${leaf}", () => {});`), citation).length, 0);
});
test('unbalanced or unterminated syntax has no substring fallback', () => {
  assert.throws(() => extractTitles('describe("unfinished'));
  assert.throws(() => extractTitles('describe("suite title", () => {'));
});

test('all current repository mappings pass the structural rule unchanged', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'conformance-manifest.json'), 'utf8'));
  const cache = new Map();
  for (const row of manifest.requirements) for (const mapping of row.tests) {
    const file = path.join(root, mapping.file);
    if (!cache.has(file)) cache.set(file, extractTitles(fs.readFileSync(file, 'utf8')));
    assert.ok(matchingDeclarations(cache.get(file), mapping.name).length, `${row.id}: ${mapping.file} > ${mapping.name}`);
  }
});

test('the real CLI exits nonzero for a fabricated punctuation mapping', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mission-conformance-citation-'));
  try {
    fs.mkdirSync(path.join(dir, 'scripts'));
    for (const file of ['check-conformance-manifest.mjs', 'test-title-paths.mjs']) {
      fs.copyFileSync(path.join(root, 'scripts', file), path.join(dir, 'scripts', file));
    }
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'conformance-manifest.json'), 'utf8'));
    const row = manifest.requirements.find((r) => r.coverage === 'tested' && r.tests.length);
    row.tests = [{ ...row.tests[0], file: 'fixture.test.ts', name: citation }];
    manifest.requirements = [row];
    manifest.source.specs = { [row.spec]: manifest.source.specs[row.spec] };
    fs.copyFileSync(path.join(root, row.spec), path.join(dir, row.spec));
    fs.writeFileSync(path.join(dir, 'fixture.test.ts'), suite(`it("${leaf}", () => {});`));
    const run = () => {
      fs.writeFileSync(path.join(dir, 'conformance-manifest.json'), JSON.stringify(manifest));
      return spawnSync(process.execPath, [path.join(dir, 'scripts/check-conformance-manifest.mjs')], {
        cwd: dir, encoding: 'utf8', env: { ...process.env, CI: '' },
      });
    };
    const good = run();
    assert.equal(good.status, 0, good.stdout + good.stderr);
    row.tests[0].name = 'real suite title > ;';
    const bad = run();
    assert.equal(bad.status, 1, bad.stdout + bad.stderr);
    assert.match(bad.stdout + bad.stderr, /missing-test.*degenerate segment/);
  } finally {
    // Only the freshly allocated fixture directory owned by this test.
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
