// A deliberately bounded, dependency-free test-declaration reader. This is
// citation validation, not a TypeScript parser or proof that a test executes.
const MODIFIERS = new Set(['skip', 'only', 'concurrent', 'sequential', 'todo', 'fails']);
const BASES = new Set(['describe', 'it', 'test']);
const escapeRE = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function segmentOk(text) {
  return typeof text === 'string' && text.length >= 8 && /[A-Za-z0-9]/.test(text);
}

export function wildcardPattern(text, dynamic = false) {
  return text.split(/(\0|%[sdifjoO#])/).map((part) => {
    if (part === '\0') return '.+';
    if (dynamic && /^%[sdifjoO#]$/.test(part)) return part === '%#' ? '\\d+' : '.+';
    return escapeRE(part);
  }).join('');
}

export function tokenize(src) {
  const tokens = [];
  let i = 0;
  function quoted(quote) {
    const start = i++;
    let value = '';
    while (i < src.length) {
      const c = src[i++];
      if (c === quote) return { kind: 'string', value, start, end: i };
      if (c === '\\') {
        const e = src[i++];
        const simple = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', '0': '\0' };
        if (e === '\n') continue;
        if (e === 'x' || e === 'u') {
          const n = e === 'x' ? 2 : 4;
          const hex = src.slice(i, i + n);
          if (!new RegExp(`^[0-9a-fA-F]{${n}}$`).test(hex)) throw new Error('unsupported string escape');
          value += String.fromCharCode(parseInt(hex, 16)); i += n;
        } else value += simple[e] ?? e;
      } else if (quote === '`' && c === '$' && src[i] === '{') {
        i++;
        scan(true); // nested strings/comments/templates cannot terminate this interpolation
        value += '\0';
      } else value += c;
    }
    throw new Error(`unterminated string at ${start}`);
  }
  function scan(interpolation = false) {
    const out = [];
    let braces = 0;
    while (i < src.length) {
      if (/\s/.test(src[i])) { i++; continue; }
      const start = i;
      const c = src[i];
      if (c === '/' && src[i + 1] === '/') {
        while (i < src.length && src[i] !== '\n') i++;
        continue;
      }
      if (c === '/' && src[i + 1] === '*') {
        const end = src.indexOf('*/', i + 2);
        if (end < 0) throw new Error(`unterminated comment at ${i}`);
        i = end + 2; continue;
      }
      if (c === '"' || c === "'" || c === '`') { out.push(quoted(c)); continue; }
      // A regex at an expression-start cannot contribute declaration-looking tokens.
      const prev = out.at(-1)?.value;
      if (c === '/' && (!prev || ['=', '(', '[', '{', ',', ':', ';', '?', '!', '=>', 'return', '&&', '||'].includes(prev))) {
        i++; let inClass = false; let closed = false;
        while (i < src.length) {
          const r = src[i++];
          if (r === '\\') { i++; continue; }
          if (r === '[') inClass = true;
          if (r === ']') inClass = false;
          if (r === '/' && !inClass) { closed = true; break; }
          if (r === '\n') break;
        }
        if (!closed) throw new Error(`unsupported or unterminated regex at ${start}`);
        while (/[a-z]/i.test(src[i] ?? '') && i < src.length) i++;
        out.push({ kind: 'regex', value: '<regex>', start, end: i }); continue;
      }
      if (interpolation && c === '}' && braces === 0) { i++; return out; }
      if (c === '{') braces++;
      if (c === '}') braces--;
      const word = /^[A-Za-z_$][\w$]*/.exec(src.slice(i));
      const op = /^(=>|===|!==|==|!=|\?\.|&&|\|\||\+\+|--)/.exec(src.slice(i));
      const value = word?.[0] ?? op?.[0] ?? c;
      i += value.length;
      out.push({ kind: word ? 'id' : 'punct', value, start, end: i });
    }
    if (interpolation) throw new Error('unterminated template interpolation');
    return out;
  }
  tokens.push(...scan());
  return tokens;
}

export function extractTitles(src) {
  const t = typeof src === 'string' ? tokenize(src) : src;
  const pairs = new Map();
  const stack = [];
  const parents = new Map([[0, null]]);
  let scope = 0;
  for (let i = 0; i < t.length; i++) {
    t[i].scope = scope;
    const v = t[i].value;
    if (['(', '[', '{'].includes(v) && t[i].kind === 'punct') {
      stack.push(i);
      if (v === '{') { parents.set(i + 1, scope); scope = i + 1; }
    } else if ([')', ']', '}'].includes(v) && t[i].kind === 'punct') {
      const open = stack.pop();
      if (open === undefined || '([{'.indexOf(t[open].value) !== ')]}'.indexOf(v)) {
        throw new Error(`unbalanced delimiters at ${t[i].start}`);
      }
      pairs.set(open, i); pairs.set(i, open);
      if (v === '}') scope = parents.get(scope);
    }
  }
  if (stack.length) throw new Error('unclosed delimiter');

  const bindings = new Map();
  const key = (s, name) => `${s}:${name}`;
  const declare = (s, name, expr) => bindings.set(key(s, name), { scope: s, expr });
  for (let i = 0; i < t.length; i++) {
    if (t[i].value !== 'import' || t[i + 1]?.value !== '{') continue;
    const end = pairs.get(i + 1);
    if (end === undefined || t[end + 1]?.value !== 'from') continue;
    const vitest = t[end + 2]?.value === 'vitest';
    for (let j = i + 2; j < end; j++) {
      if (t[j].kind !== 'id') continue;
      const original = j;
      const alias = t[j + 1]?.value === 'as' ? j + 2 : j;
      if (!vitest || !BASES.has(t[original].value)) declare(0, t[alias].value, null);
      else if (alias !== original) declare(0, t[alias].value, [original, original + 1]);
      j = alias;
    }
  }
  // Lexical declarations shadow test globals even if their initializer is not
  // a recognized test alias. Unknown/reassigned aliases resolve to nothing.
  for (let i = 0; i < t.length; i++) {
    if (['const', 'let', 'var', 'function', 'class'].includes(t[i].value) && t[i + 1]?.kind === 'id') {
      const name = t[i + 1].value;
      let end = i + 2;
      while (end < t.length && ![';', ','].includes(t[end].value)) {
        if (pairs.has(end) && ['(', '[', '{'].includes(t[end].value)) end = pairs.get(end);
        end++;
      }
      declare(t[i].scope, name, t[i + 2]?.value === '=' ? [i + 3, end] : null);
    }
    // Ordinary function and arrow parameters shadow within their body.
    if (t[i].value === '{') {
      let close = i - 1;
      if (t[close]?.value === '=>') close--;
      if (t[close]?.value === ')' && pairs.has(close)) {
        const open = pairs.get(close);
        const before = t[open - 1]?.value;
        const functionLike = t[i - 1]?.value === '=>' || before === 'function' || t[open - 2]?.value === 'function';
        if (functionLike) {
          for (let j = open + 1; j < close; j++) {
            if (t[j].kind === 'id' && (j === open + 1 || t[j - 1].value === ',')) declare(i + 1, t[j].value, null);
          }
        }
      } else if (t[i - 1]?.value === '=>' && t[i - 2]?.kind === 'id') {
        declare(i + 1, t[i - 2].value, null);
      }
    }
  }
  function lookup(name, s, visited = new Set()) {
    for (let p = s; p !== null && p !== undefined; p = parents.get(p)) {
      const k = key(p, name);
      if (bindings.has(k)) {
        if (visited.has(k)) return null;
        visited.add(k);
        const b = bindings.get(k);
        return b.expr ? resolveExpr(...b.expr, b.scope, visited) : null;
      }
    }
    return BASES.has(name) ? name : null;
  }
  function resolveExpr(a, b, s, seen) {
    while (t[a]?.value === '(' && pairs.get(a) === b - 1) { a++; b--; }
    let q = -1;
    for (let j = a; j < b; j++) {
      if (t[j].value === '?') { q = j; break; }
      if (pairs.has(j) && ['(', '[', '{'].includes(t[j].value)) j = pairs.get(j);
    }
    if (q >= 0) {
      const colon = t.findIndex((x, j) => j > q && j < b && x.value === ':');
      if (colon < 0) return null;
      const left = resolveExpr(q + 1, colon, s, new Set(seen));
      return left && left === resolveExpr(colon + 1, b, s, new Set(seen)) ? left : null;
    }
    if (t[a]?.kind !== 'id') return null;
    for (let j = a + 1; j < b; j += 2) {
      if (t[j]?.value !== '.' || !MODIFIERS.has(t[j + 1]?.value)) return null;
    }
    return lookup(t[a].value, s, seen);
  }
  for (let i = 0; i < t.length - 1; i++) {
    if (t[i].kind === 'id' && ['=', '++', '--'].includes(t[i + 1].value) && !['const', 'let', 'var'].includes(t[i - 1]?.value)) {
      for (let p = t[i].scope; p !== null && p !== undefined; p = parents.get(p)) {
        if (bindings.has(key(p, t[i].value))) { bindings.get(key(p, t[i].value)).expr = null; break; }
      }
    }
  }

  const declarations = [];
  for (let i = 0; i < t.length; i++) {
    if (t[i].kind !== 'id' || ['.', '?.'].includes(t[i - 1]?.value)) continue;
    const base = lookup(t[i].value, t[i].scope);
    if (!base) continue;
    let j = i + 1; let dynamic = false; let unsupported = false;
    while (t[j]?.value === '.') {
      const mod = t[j + 1]?.value; j += 2;
      if (mod === 'each') {
        dynamic = true;
        if (t[j]?.value === '<') { while (j < t.length && t[j].value !== '>') j++; j++; }
        if (t[j]?.value !== '(' || !pairs.has(j)) { unsupported = true; break; }
        j = pairs.get(j) + 1;
      } else if (!MODIFIERS.has(mod)) { unsupported = true; break; }
    }
    if (unsupported || t[j]?.value !== '(' || t[j + 1]?.kind !== 'string') continue;
    const end = pairs.get(j);
    if (end === undefined || t[j + 2]?.value !== ',') continue;
    const title = { text: t[j + 1].value, dynamic: dynamic || t[j + 1].value.includes('\0') };
    let body;
    for (let k = j + 3; k < end; k++) {
      if (t[k].value === '=>' && t[k + 1]?.value === '{') { body = k + 1; break; }
      if (t[k].value === 'function') {
        let p = k + 1;
        while (p < end && t[p].value !== '(') p++;
        const close = pairs.get(p);
        if (close !== undefined && t[close + 1]?.value === '{') body = close + 1;
        break;
      }
      if (pairs.has(k) && ['(', '[', '{'].includes(t[k].value)) k = pairs.get(k);
    }
    if (body === undefined) continue;
    declarations.push({ isLeaf: base !== 'describe', ...title, start: i, body, end: pairs.get(body) });
  }
  return declarations.filter((d) => d.isLeaf).map((leaf) => ({
    ...leaf,
    path: [...declarations.filter((s) => !s.isLeaf && s.body < leaf.start && leaf.start < s.end), leaf]
      .map(({ text, dynamic }) => ({ text, dynamic })),
  }));
}

export function matchingDeclarations(titles, name) {
  const segments = name.split(' > ');
  if (!segments.every(segmentOk)) return [];
  return titles.filter(({ path }) => path.length === segments.length && path.every((source, i) => {
    const cited = segments[i];
    if (source.text === cited) return true; // raw it.each templates are valid citations
    const pattern = wildcardPattern(source.text, source.dynamic);
    if (i === path.length - 1) return new RegExp(`^${pattern}$`, 's').test(cited);
    return new RegExp(pattern, 's').test(cited) || (!source.dynamic && source.text.includes(cited));
  }));
}

export function collectedPathMatches(declaration, runnerName) {
  const pattern = declaration.path.map((s) => wildcardPattern(s.text, s.dynamic)).join(' > ');
  return new RegExp(`^${pattern}$`, 's').test(runnerName);
}

/** Package-manager diagnostics may precede Vitest's JSON (including [WARN]). */
export function parseCollectedTests(output) {
  const start = /^\s*\[(?:\s*\{|\s*\])/m.exec(output);
  if (!start) throw new Error('runner did not return a JSON test array');
  const records = JSON.parse(output.slice(start.index));
  if (!Array.isArray(records)) throw new Error('runner did not return a JSON test array');
  return records;
}
