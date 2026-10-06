#!/usr/bin/env node
/**
 * Every Alpine expression in the templates is one the build in use can evaluate.
 *
 * The page runs `@alpinejs/csp`, the build of Alpine that parses an expression
 * itself where the standard build compiles it with `new Function()`. That is
 * what lets the Content-Security-Policy go without 'unsafe-eval'. It has two
 * limits the standard build does not:
 *
 *   - a smaller grammar: one expression, no arrow function, no template
 *     literal, no `delete`, no `if`;
 *   - nothing outside the component: `Object`, `window`, `CertMate` and every
 *     function of the page are undefined inside an expression.
 *
 * Both fail in the browser, at the moment the expression is evaluated, and an
 * expression inside an `x-if` or an `x-for` over an empty list is evaluated
 * only when someone's data makes it so. So they are checked here, all of them,
 * before the page is ever loaded:
 *
 *   1. static/js/alpine.min.js is the file the lockfile's package ships;
 *   2. each expression goes through that package's own parser;
 *   3. each name an expression starts from is a key of a component the
 *      template is inside, a loop variable or one of Alpine's `$` magics.
 *      The components are read by loading the files that register them.
 *
 *   node scripts/check_alpine_expressions.mjs        (after `npm ci`)
 */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PACKAGE = path.join(ROOT, 'node_modules', '@alpinejs', 'csp', 'dist');
const VENDORED = path.join(ROOT, 'static', 'js', 'alpine.min.js');
const TEMPLATES = path.join(ROOT, 'templates');
const SCRIPTS = path.join(ROOT, 'static', 'js');

const problems = [];
const say = (where, what) => problems.push(`${where}: ${what}`);

// 1. The vendored file is the package's.
if (!fs.existsSync(PACKAGE)) {
  console.error('node_modules/@alpinejs/csp is missing: run `npm ci` first');
  process.exit(2);
}
if (!fs.readFileSync(VENDORED).equals(fs.readFileSync(path.join(PACKAGE, 'cdn.min.js')))) {
  say('static/js/alpine.min.js', 'is not node_modules/@alpinejs/csp/dist/cdn.min.js; copy it from there');
}

// 2. The package's parser, taken from the unminified build of the same version.
const lines = fs.readFileSync(path.join(PACKAGE, 'module.cjs.js'), 'utf8').split('\n');
const from = lines.findIndex((l) => l.startsWith('// packages/csp/src/parser.js'));
const to = lines.findIndex((l) => l.startsWith('// packages/csp/src/evaluator.js'));
if (from < 0 || to < from) {
  console.error('the parser is not where it was in @alpinejs/csp: this check has lost its subject');
  process.exit(2);
}
const sandbox = vm.createContext({ HTMLIFrameElement: class {}, HTMLScriptElement: class {} });
vm.runInContext(`${lines.slice(from, to).join('\n')}
globalThis.parse = (expression) => new Parser(new Tokenizer(expression).tokenize()).parse();`, sandbox);
const parse = sandbox.parse;

// The names an expression starts from: `a` in `a.b[c].d(e)` is one, and so are `c` and `e`.
function roots(node, found = new Set()) {
  if (!node || typeof node !== 'object') return found;
  if (Array.isArray(node)) { node.forEach((n) => roots(n, found)); return found; }
  if (node.type === 'Identifier') { found.add(node.name); return found; }
  if (node.type === 'MemberExpression') {
    roots(node.object, found);
    if (node.computed) roots(node.property, found);
    return found;
  }
  if (node.type === 'ObjectExpression') {
    for (const p of node.properties || []) { if (p.computed) roots(p.key, found); roots(p.value, found); }
    return found;
  }
  for (const [key, value] of Object.entries(node)) if (key !== 'type') roots(value, found);
  return found;
}

// 3. The components, read from the files that register them.
const components = {};
for (const file of fs.readdirSync(SCRIPTS).sort()) {
  const source = fs.readFileSync(path.join(SCRIPTS, file), 'utf8');
  if (!file.endsWith('.js') || file.endsWith('.min.js') || !source.includes('Alpine.data(')) continue;
  const anything = new Proxy(function () {}, {
    get: (_target, key) => (key === Symbol.toPrimitive ? () => '' : anything), apply: () => anything, construct: () => anything,
  });
  const starts = [];
  const page = {
    window: {}, CertMate: anything, addDebugLog() {}, fetch: anything, navigator: {}, crypto: {}, setTimeout() {},
    location: { hash: '' }, history: {},
    document: { addEventListener(type, fn) { if (type === 'alpine:init') starts.push(fn); }, getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] },
    Alpine: { data(name, factory) { components[name] = { file, keys: new Set(Object.getOwnPropertyNames(factory.call({}))) }; }, store() {} },
  };
  try {
    vm.runInContext(source, vm.createContext(page));
    starts.forEach((fn) => fn());
  } catch (error) {
    say(`static/js/${file}`, `could not be loaded to read its components: ${error.message}`);
  }
}

// The templates: which includes which, and what each declares.
const ATTRIBUTE = /(?<![\w-])(x-data|x-show|x-if|x-for|x-model(?:\.[\w.]+)?|x-text|x-html|x-init|x-effect|x-bind:[\w.-]+|x-on:[\w.:-]+|:[a-zA-Z][\w.-]*|@[a-z][\w.:-]*)\s*=\s*"([^"]*)"/gs;
// `&amp;` last: decoded first, `&amp;lt;` would come out as `<` and not as the `&lt;` it stands for.
const decode = (s) => s.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
function* templates(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* templates(full);
    else if (entry.name.endsWith('.html')) yield path.relative(TEMPLATES, full);
  }
}
const pages = {};
for (const name of templates(TEMPLATES)) {
  // Inside `{% raw %}` a `{{` is the browser's, not Jinja's.
  const text = fs.readFileSync(path.join(TEMPLATES, name), 'utf8').replace(/\{%-?\s*raw\s*-?%\}([\s\S]*?)\{%-?\s*endraw\s*-?%\}/g, (_all, inner) => inner.replace(/\{\{/g, '\u0001\u0001').replace(/\}\}/g, '\u0002\u0002'));
  const page = { includes: [], declared: new Set(), loops: new Set(), expressions: [] };
  for (const m of text.matchAll(/\{%-?\s*include\s+['"]([^'"]+)['"]/g)) page.includes.push(m[1]);
  for (const m of text.matchAll(ATTRIBUTE)) {
    const attribute = m[1];
    const expression = decode(m[2]).replace(/\u0001\u0001/g, '{{').replace(/\u0002\u0002/g, '}}').trim();
    if (!expression) continue;
    const line = text.slice(0, m.index).split('\n').length;
    page.expressions.push({ attribute, expression, line });
  }
  pages[name] = page;
}

let seen = 0;
for (const [name, page] of Object.entries(pages)) {
  for (const item of page.expressions) {
    const where = `templates/${name}:${item.line} [${item.attribute}]`;
    const shown = item.expression.replace(/\s+/g, ' ').slice(0, 110);
    seen += 1;
    if (item.attribute === 'x-html') { say(where, `x-html is not available in this build: ${shown}`); continue; }
    let toParse = [item.expression];
    if (item.attribute === 'x-for') {
      const loop = item.expression.match(/^\s*\(?\s*([^)]*?)\s*\)?\s+(?:in|of)\s+([\s\S]+)$/);
      if (!loop) { say(where, `not a loop: ${shown}`); continue; }
      loop[1].split(',').forEach((v) => page.loops.add(v.trim()));
      toParse = [loop[2]];
    } else if (item.attribute.startsWith('x-model')) {
      toParse.push(`${item.expression} = __value`);
    }
    item.names = new Set();
    for (const expression of toParse) {
      try {
        const ast = parse(expression);
        roots(ast, item.names);
        if (item.attribute === 'x-data' && ast.type === 'ObjectExpression') {
          for (const p of ast.properties || []) page.declared.add(p.key && (p.key.name || p.key.value));
        }
      } catch (error) {
        say(where, `${error.message}: ${shown}`);
        item.names = null;
        break;
      }
    }
    if (item.attribute === 'x-data' && item.names) {
      for (const used of item.names) {
        if (components[used]) components[used].keys.forEach((k) => page.declared.add(k));
        else say(where, `"${used}" is not a component registered with Alpine.data(): ${shown}`);
      }
      item.names = null;
    }
  }
}

// What a template may name: its own components and loops, and those of every template that includes it.
function inherited(name, trail = new Set()) {
  const allowed = new Set([...pages[name].declared, ...pages[name].loops]);
  trail.add(name);
  for (const [other, page] of Object.entries(pages)) {
    if (!trail.has(other) && page.includes.includes(name)) inherited(other, trail).forEach((n) => allowed.add(n));
  }
  return allowed;
}
const LITERALS = new Set(['true', 'false', 'null', 'undefined', '__value']);
for (const [name, page] of Object.entries(pages)) {
  const allowed = inherited(name);
  for (const item of page.expressions) {
    for (const used of item.names || []) {
      if (used.startsWith('$') || LITERALS.has(used) || allowed.has(used)) continue;
      say(`templates/${name}:${item.line} [${item.attribute}]`,
        `"${used}" is not a key of a component this template is in, a loop variable or a magic: ${item.expression.replace(/\s+/g, ' ').slice(0, 110)}`);
    }
  }
}
if (problems.length) {
  console.error(`${problems.length} problem(s) with the Alpine expressions:\n`);
  for (const p of problems) console.error(`  - ${p}`);
  console.error('\nThe build of Alpine in use is @alpinejs/csp: an expression is parsed, not compiled, and reaches');
  console.error('nothing outside its component. Move what it needs into a method or a getter of the component.');
  process.exit(1);
}
console.log(`Alpine expressions OK: ${seen} in ${Object.keys(pages).length} templates, ${Object.keys(components).length} components, all evaluable by @alpinejs/csp.`);
