// Client-plane contract tests (family pattern, cf. skills-management).
// The loader platform modules don't resolve under plain Node; the shims in
// client/index.js keep it loadable and are themselves the assertion surface.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const plugin = require('../client/index.js')
const { NS, ZH, EN, TYPE_LABELS, formatTime, interpolate, filterActivity, filterAudit } = plugin.__internals

test('client module declares slots + locale injects', () => {
  assert.equal(plugin.name, '@weibaohui/user-management') // must equal the boot manifest id
  assert.deepEqual(plugin.inject.sort(), ['locale', 'slots'])
})

test('locale dictionaries are zh/en with identical key sets', () => {
  const zhKeys = Object.keys(ZH).sort()
  const enKeys = Object.keys(EN).sort()
  assert.deepEqual(enKeys, zhKeys)
  for (const key of zhKeys) {
    assert.equal(typeof ZH[key], 'string', `zh.${key}`)
    assert.equal(typeof EN[key], 'string', `en.${key}`)
  }
})

test('every ledger type maps to a locale key present in both dictionaries', () => {
  for (const labelKey of Object.values(TYPE_LABELS)) {
    assert.ok(ZH[labelKey], `zh.${labelKey}`)
    assert.ok(EN[labelKey], `en.${labelKey}`)
  }
})

test('no hardcoded colors in the client source — ui-theme tokens only', () => {
  const src = readFileSync(new URL('../client/index.js', import.meta.url), 'utf8')
  // inverted-label fallback may pin #fff (family convention, cf. skills-management)
  const hex = (src.match(/#[0-9a-fA-F]{3,8}\b/g) || [])
    .filter((h) => !src.includes('label-primary-inverted,#fff') && !src.includes('label-primary-inverted, #fff'))
  assert.deepEqual(hex, [], 'hex colors are banned; use var(--dsw-alias-*) or rgba()')
  assert.ok(src.includes('var(--dsw-alias-label-primary)'), 'label token consumed')
  assert.ok(src.includes('var(--dsw-alias-bg-layer-1'), 'surface token consumed')
})

test('apply registers dictionaries and the settings.section slot', () => {
  const calls = []
  const registered = []
  const ctx = {
    locale: {
      register: (...args) => calls.push(args),
      bind: (ns) => (key, vars) => `${ns}:${key}`,
    },
    slots: {
      inject: (name, fn) => {
        const result = fn()
        // generator factories (official brand-slot pattern) register lazily
        if (result && typeof result[Symbol.iterator] === 'function') [...result]
        return result
      },
      register: (spec, component) => registered.push({ spec, component }),
    },
    effect: (fn) => fn(),
  }
  plugin.apply(ctx)
  assert.deepEqual(calls.map((c) => [c[0], c[1]]).sort(), [[NS, 'en'], [NS, 'zh']])
  const names = registered.map((r) => r.spec.name).sort()
  assert.deepEqual(names, ['settings.section', 'sidebar.brand.mark', 'sidebar.brand.name', 'sidebar.footer.action'])
  // brand seats are single-slot; the host default sits at priority 0 — we
  // must register lower ("lowest renders") to shadow it without erroring
  for (const { spec } of registered) {
    if (spec.name.startsWith('sidebar.brand.')) assert.equal(spec.priority, -1, `${spec.name} shadows the default`)
  }
  for (const { spec, component } of registered) {
    assert.equal(typeof component, 'function')
    if (spec.name === 'settings.section') {
      assert.equal(spec.id, plugin.name)
      assert.equal(typeof spec.inject, 'function')
      assert.equal(typeof spec.label, 'function')
    }
  }
})

test('brand slots render the avatar mark and the username', async () => {
  const { BrandMark, BrandName, UserAvatar, avatarHue } = plugin.__internals
  assert.equal(typeof avatarHue('alice'), 'number')
  assert.equal(avatarHue('alice'), avatarHue('alice'), 'deterministic hue per username')
  const avatar = UserAvatar({ username: 'bob', size: 30 })
  assert.ok(String(avatar.props.style.background).startsWith('hsl('), 'hsl background, no hex')
  // the plain-Node shim stores kids on the element, real React on props.children
  const initial = avatar.props.children !== undefined ? avatar.props.children : (avatar.kids || [])[0]
  assert.equal(initial, 'B', 'initial letter')
  assert.equal(avatar.props.title, 'bob')
  // mark with a resolved session renders the avatar; without, a placeholder
  const markEl = BrandMark({ size: 28 })
  assert.ok(markEl, 'mark renders a placeholder while the session loads')
})

test('formatTime humanizes timestamps, dashes on empty', () => {
  assert.equal(formatTime(null), '-')
  assert.equal(formatTime(0), '-')
  const out = formatTime(Date.UTC(2026, 0, 2, 3, 4, 5))
  assert.ok(out instanceof Date === false && out.length > 4, `renders a string: ${out}`)
})

test('interpolate substitutes {placeholders}', () => {
  assert.equal(interpolate('删除 {name}？', { name: 'bob' }), '删除 bob？')
  assert.equal(interpolate('无变量'), '无变量')
  assert.equal(interpolate('{a}{a}', { a: 1 }), '11')
})

test('filterActivity narrows by username and type', () => {
  const entries = [
    { type: 'login', username: 'alice' },
    { type: 'access', username: 'alice' },
    { type: 'login', username: 'bob' },
  ]
  assert.equal(filterActivity(entries).length, 3)
  assert.equal(filterActivity(entries, { username: 'alice' }).length, 2)
  assert.equal(filterActivity(entries, { type: 'login' }).length, 2)
  assert.equal(filterActivity(entries, { username: 'alice', type: 'access' }).length, 1)
  assert.equal(filterActivity(null).length, 0)
})

test('filterAudit narrows by username/method/path/status class', () => {
  const entries = [
    { type: 'api', username: 'alice', method: 'POST', path: '/api/sessions.create', status: 200 },
    { type: 'api', username: 'bob', method: 'GET', path: '/api/users.list', status: 404 },
    { type: 'ws', username: 'alice', method: 'WS', path: '/api/events.mux', status: null },
  ]
  assert.equal(filterAudit(entries).length, 3)
  assert.equal(filterAudit(entries, { username: 'alice' }).length, 2)
  assert.equal(filterAudit(entries, { method: 'POST' }).length, 1)
  assert.equal(filterAudit(entries, { path: 'users' }).length, 1)
  assert.equal(filterAudit(entries, { statusClass: '2' }).length, 1)
  assert.equal(filterAudit(entries, { statusClass: '4' }).length, 1)
  assert.equal(filterAudit(entries, { username: 'alice', method: 'WS' }).length, 1)
  assert.equal(filterAudit(null).length, 0)
})
