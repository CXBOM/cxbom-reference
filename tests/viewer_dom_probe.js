// Runs site/viewer/cxbom_view.html's own script against a minimal DOM and
// reports what it produced. Owner: ATACE Working Group.
//
// Why this exists: tests/test_site_viewer.py used to assert that certain
// strings appeared in the viewer's source, which a mutation that empties the
// segment-button loop survives untouched. Executing the real script and
// reading the real nodes it appends is the only way a test can tell the
// difference. The engine is node, not a browser: the site suite must not make
// every contributor install Chromium to run a unit test.
//
// The shim implements exactly the DOM surface the viewer touches. Anything it
// does not implement is left undefined on purpose, so an unimplemented call
// throws and the test fails loudly instead of passing on a silent no-op.
//
// Usage: node tests/viewer_dom_probe.js <input.json>
//   input.json = {"document": <parsed static tree>, "script": <script source>}
// Prints one JSON object on stdout. Exits non-zero if the viewer's script
// throws, which is itself a result the calling test reports.
'use strict';

const fs = require('fs');
const vm = require('vm');

const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const FOCUSABLE_TAGS = ['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA'];

// Set while a focus dispatch is being observed, to learn which already-existing
// container the tooltip code writes into. Discovering the live region by
// watching the appends is what makes the aria-live assertion behavioural: it
// checks the node that actually received the text, not a node the test named.
let observing = null;

class TextNode {
  constructor(data) {
    this.nodeType = 3;
    this.data = String(data);
    this.parentNode = null;
  }
  get textContent() { return this.data; }
}

class Element {
  constructor(tag) {
    this.nodeType = 1;
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.parentNode = null;
    this.attrs = {};
    this.className = '';
    this.style = {};
    this.listeners = {};
    this.tabIndex = undefined;
    this.hidden = undefined;
    this.bornDuringObservation = observing !== null;
  }

  get firstChild() { return this.childNodes[0] || null; }

  append(...kids) {
    if (observing && !this.bornDuringObservation) observing.appendTargets.add(this);
    for (const kid of kids) {
      const node = kid && kid.nodeType ? kid : new TextNode(kid);
      if (node.parentNode) node.parentNode.removeChild(node);
      node.parentNode = this;
      this.childNodes.push(node);
    }
  }

  appendChild(kid) { this.append(kid); return kid; }

  removeChild(kid) {
    const at = this.childNodes.indexOf(kid);
    if (at < 0) throw new Error('removeChild: not a child');
    this.childNodes.splice(at, 1);
    kid.parentNode = null;
    return kid;
  }

  setAttribute(name, value) { this.attrs[String(name)] = String(value); }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attrs, name) ? this.attrs[name] : null;
  }
  hasAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attrs, name); }

  get classList() {
    const owner = this;
    const parts = () => owner.className.split(/\s+/).filter(Boolean);
    return {
      add(...names) {
        const have = parts();
        for (const n of names) if (!have.includes(n)) have.push(n);
        owner.className = have.join(' ');
      },
      remove(...names) {
        owner.className = parts().filter(p => !names.includes(p)).join(' ');
      },
      contains(name) { return parts().includes(name); },
    };
  }

  get textContent() {
    return this.childNodes.map(c => c.textContent).join('');
  }
  set textContent(value) {
    this.childNodes.forEach(c => { c.parentNode = null; });
    this.childNodes = [];
    this.append(new TextNode(value));
  }

  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }
  removeEventListener(type, fn) {
    const list = this.listeners[type] || [];
    const at = list.indexOf(fn);
    if (at >= 0) list.splice(at, 1);
  }

  // Layout is the browser's job. Zeros are enough: every caller uses the rect
  // only to place the tooltip, which this harness does not assert on.
  getBoundingClientRect() {
    return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0, x: 0, y: 0 };
  }

  focus() { focusCalls.push(this); }
  blur() { focusCalls.push(this); }
}

const focusCalls = [];

function hydrate(spec) {
  if (spec.text !== undefined) return new TextNode(spec.text);
  const el = new Element(spec.tag);
  el.attrs = Object.assign({}, spec.attrs);
  if (el.attrs.class !== undefined) el.className = el.attrs.class;
  if (el.attrs.hidden !== undefined) el.hidden = true;
  for (const child of spec.children || []) {
    const node = hydrate(child);
    node.parentNode = el;
    el.childNodes.push(node);
  }
  return el;
}

const documentNode = new Element('#document');
const htmlNode = hydrate(input.document);
htmlNode.parentNode = documentNode;
documentNode.childNodes.push(htmlNode);

function walk(node, visit) {
  if (node.nodeType !== 1) return;
  visit(node);
  for (const child of node.childNodes) walk(child, visit);
}

function byId(id) {
  let found = null;
  walk(htmlNode, n => { if (!found && n.attrs.id === id) found = n; });
  return found;
}

function firstTag(tag) {
  let found = null;
  walk(htmlNode, n => { if (!found && n.tagName === tag) found = n; });
  return found;
}

const document = {
  nodeType: 9,
  documentElement: htmlNode,
  body: firstTag('BODY'),
  head: firstTag('HEAD'),
  createElement: tag => new Element(tag),
  // The trust-ring diagram builds SVG nodes in the SVG namespace. The shim does
  // not distinguish namespaces; it only needs to return an element whose class
  // and data-* attributes the viz assertions read back through setAttribute.
  createElementNS: (_ns, tag) => new Element(tag),
  createTextNode: data => new TextNode(data),
  getElementById: byId,
  addEventListener: (type, fn) => documentNode.addEventListener(type, fn),
  removeEventListener: (type, fn) => documentNode.removeEventListener(type, fn),
};

// Bubbling matters here: the Escape handler is registered on the document, so a
// keydown dispatched at the focused button must travel up to reach it. A shim
// that dispatched straight at the document would pass even if the handler were
// attached to a node that is not an ancestor of the buttons.
function dispatch(target, type, extra) {
  const event = Object.assign({ type, target, preventDefault() {}, stopPropagation() {} }, extra || {});
  let node = target;
  while (node) {
    const list = node.listeners && node.listeners[type];
    if (list) for (const fn of list.slice()) fn.call(node, event);
    node = node.parentNode;
  }
}

class NotInRenderPath {
  constructor() {
    throw new Error('the static render path must not construct this');
  }
}

const sandbox = {
  document,
  console,
  Math, JSON, Object, Array, String, Number, Boolean, Date, RegExp, Error, Set, Map, isNaN,
  parseInt, parseFloat,
  getComputedStyle: () => ({ color: 'rgb(51, 51, 51)' }),
  matchMedia: query => ({ matches: false, media: query, addEventListener() {}, removeEventListener() {} }),
  requestAnimationFrame: () => 0,
  cancelAnimationFrame: () => {},
  FileReader: NotInRenderPath,
  alert: () => { throw new Error('alert is not part of the static render path'); },
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.devicePixelRatio = 2;
sandbox.addEventListener = () => {};
sandbox.removeEventListener = () => {};

vm.runInNewContext(input.script, sandbox, { filename: 'cxbom_view.html', timeout: 20000 });

// ---- report ----

function isFocusable(el) {
  if (el.hidden === true || el.attrs.hidden !== undefined) return false;
  if (typeof el.tabIndex === 'number') return el.tabIndex >= 0;
  if (el.tagName === 'A') return el.attrs.href !== undefined;
  if (FOCUSABLE_TAGS.includes(el.tagName)) return el.attrs.disabled === undefined;
  return false;
}

function describe(el) {
  return {
    tag: el.tagName,
    id: el.attrs.id || '',
    className: el.className || '',
    type: el.attrs.type || '',
    tabIndex: el.tabIndex === undefined ? null : el.tabIndex,
    text: el.textContent,
  };
}

const tabOrder = [];
walk(htmlNode, n => { if (isFocusable(n)) tabOrder.push(describe(n)); });

const keyHolder = byId('segkeys');
const segkeys = keyHolder ? keyHolder.childNodes.filter(n => n.nodeType === 1).map(describe) : null;

// Focus each produced button, then press Escape on it, and report what the
// page did in response.
const focusProbes = [];
if (keyHolder) {
  for (const button of keyHolder.childNodes.filter(n => n.nodeType === 1)) {
    observing = { appendTargets: new Set() };
    dispatch(button, 'focus', {});
    const written = [...observing.appendTargets];
    observing = null;

    const live = written.length === 1 ? written[0] : null;
    // Read the open state before Escape, or the two readings collapse into one.
    const classWhileOpen = live ? live.className : null;
    const textWhileOpen = live ? live.textContent : null;
    const beforeEscape = focusCalls.length;
    dispatch(button, 'keydown', { key: 'Escape' });
    focusProbes.push({
      buttonText: button.textContent,
      writtenContainerCount: written.length,
      liveAttrs: live ? live.attrs : null,
      liveClassWhileOpen: classWhileOpen,
      liveText: textWhileOpen,
      liveClassAfterEscape: live ? live.className : null,
      // A handler that moved focus would have to call focus() or blur() on
      // something. Counting those calls is what this harness can honestly see;
      // it cannot see the browser's own focus ring.
      focusCallsDuringEscape: focusCalls.length - beforeEscape,
    });
  }
}

// The inline schema-validation status region, as the page left it after the
// initial render of the embedded reference record. Snapshotting the node the
// page actually writes into keeps the validation assertions behavioural, the
// same way focusProbes watches the live region the focus handler writes into.
function snapshotValidation() {
  const box = byId('validation');
  if (!box) return null;
  const items = [];
  walk(box, n => { if (n.tagName === 'LI') items.push(n.textContent); });
  return { className: box.className, attrs: box.attrs, text: box.textContent, items };
}

const validation = snapshotValidation();

// The concentric trust-ring diagram, as the page's draw step built it. Each
// component arc is a node tagged data-id / data-ring, the flagged wedge carries
// data-inversion, and the connector reaching the core carries data-role=inversion.
// Reading the real nodes keeps the viz assertions behavioural, like focusProbes.
function snapshotViz() {
  const svg = byId('rings');
  if (!svg) return null;
  const marks = [];
  let inversionMarked = false;
  walk(svg, n => {
    if (Object.prototype.hasOwnProperty.call(n.attrs, 'data-id')) {
      marks.push({
        id: n.attrs['data-id'],
        ring: Number(n.attrs['data-ring']),
        inversion: n.attrs['data-inversion'] === 'true',
      });
    }
    if (n.attrs['data-role'] === 'inversion') inversionMarked = true;
  });
  // The label is aria-label if present, else the text of the nodes aria-labelledby
  // points at (the svg's <title>/<desc>), resolved the way an AT would.
  let label = svg.attrs['aria-label'] || '';
  if (!label) {
    const ids = (svg.attrs['aria-labelledby'] || '').split(/\s+/).filter(Boolean);
    const parts = [];
    walk(svg, n => { if (ids.includes(n.attrs.id)) parts.push(n.textContent); });
    label = parts.join(' ');
  }
  const legendBox = byId('legend');
  const legend = legendBox
    ? legendBox.childNodes.filter(c => c.nodeType === 1).map(c => c.textContent)
    : [];
  return {
    tag: svg.tagName,
    role: svg.attrs.role || '',
    label,
    marks,
    inversionMarked,
    legend,
  };
}

const viz = snapshotViz();

// Optional load actions, each run against the page's own entry points (the same
// functions the file-load, drop and example buttons call), with the validation
// region and full document text captured after each. alert() throws in this
// sandbox, so an action that reached the removed modal path fails here loudly.
const actionResults = [];
for (const act of (Array.isArray(input.actions) ? input.actions : [])) {
  if (act.type === 'loadText') sandbox.applyText(act.text);
  else if (act.type === 'loadExample') sandbox.loadExample(act.key);
  else if (act.type === 'loadReference') sandbox.loadExample(null);
  else throw new Error('unknown probe action: ' + act.type);
  actionResults.push({ action: act, validation: snapshotValidation(), documentText: htmlNode.textContent });
}

process.stdout.write(JSON.stringify({
  segkeys,
  tabOrder,
  focusProbes,
  documentText: htmlNode.textContent,
  validation,
  viz,
  actionResults,
}));
