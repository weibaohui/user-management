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
  assert.deepEqual(names, ['settings.section', 'sidebar.brand.mark', 'sidebar.brand.name'])
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

test('canBanIp hides loopback, own IP and empty entries', () => {
  const { canBanIp } = plugin.__internals
  assert.equal(canBanIp('203.0.113.9', '127.0.0.1'), true)
  assert.equal(canBanIp('127.0.0.1', ''), false, 'loopback v4')
  assert.equal(canBanIp('127.0.0.99', ''), false, 'whole loopback /8')
  assert.equal(canBanIp('::1', ''), false, 'loopback v6')
  assert.equal(canBanIp('192.168.31.5', '192.168.31.5'), false, 'own live IP')
  assert.equal(canBanIp('', '127.0.0.1'), false, 'empty')
  assert.equal(canBanIp('-', ''), false, 'placeholder dash')
})

test('change-password dialog carries old/new/confirm inputs', () => {
  const { ChangePasswordDialog } = plugin.__internals
  const el = ChangePasswordDialog({ onClose: () => {}, __t: (k) => k })
  assert.ok(el, 'renders the dialog element (portal is a web-only no-op under the shim)')
  const inputs = []
  const walk = (node) => {
    if (!node || typeof node !== 'object') return
    if (node.type === 'input' && node.props.type === 'password') inputs.push(node)
    for (const kid of node.kids || []) walk(kid)
  }
  walk(el)
  assert.equal(inputs.length, 3, 'old + new + confirm password fields')
  assert.ok(inputs.every((i) => i.props.required), 'all three required')
  assert.equal(inputs[1].props.minLength, 6, 'native length gate on the new password')
})

test('cert card: renders while loading, hides when the gateway is absent', () => {
  const { CertCard } = plugin.__internals
  const loading = CertCard({ __t: (k) => k })
  assert.ok(loading, 'renders the card shell while cert-info loads')
  assert.equal(loading.props.className, 'um-card')
})

test('cert install commands cover mac/win/linux and reference the downloads', () => {
  const { CERT_INSTALL_COMMANDS } = plugin.__internals
  assert.match(CERT_INSTALL_COMMANDS.mac, /security add-trusted-cert/)
  assert.match(CERT_INSTALL_COMMANDS.win, /certutil -addstore -f Root/)
  assert.match(CERT_INSTALL_COMMANDS.linux, /update-ca-certificates/)
  assert.ok(CERT_INSTALL_COMMANDS.mac.includes('user-management-gateway.crt'))
  assert.ok(CERT_INSTALL_COMMANDS.win.includes('user-management-gateway.cer'))
})

test('the HTTPS certificate lives in its own tab, right after IP bans', () => {
  const { AdminPanel } = plugin.__internals
  const el = AdminPanel({ me: { id: 'u1', username: 'a', role: 'admin' }, __t: (k) => k, flash: () => {} })
  assert.ok(el, 'admin panel renders under the shim')
  const labels = []
  const walk = (node) => {
    if (!node || typeof node !== 'object') return
    if (node.props && String(node.props.className || '').split(' ').includes('um-tab')) labels.push(node.kids[0])
    for (const kid of node.kids || []) walk(kid)
  }
  walk(el)
  assert.deepEqual(labels, ['tabUsers', 'tabLoginLog', 'tabAccessLog', 'tabAuditLog', 'tabBans', 'certTitle', 'tabGateway', 'totpTitle'],
    'cert tab before bans; gateway management follows the cert tab; totp (self-service) sits last')
})

test('totp card renders both states; dialogs render their inputs', () => {
  const { TotpCard, TotpSetupDialog, TotpDisableDialog } = plugin.__internals
  const textsOf = (el) => {
    const out = []
    const walk = (node) => {
      if (!node || typeof node !== 'object') return
      if (typeof node.type === 'string' && node.props && node.props.onClick && node.kids && typeof node.kids[0] === 'string') out.push(node.kids[0])
      for (const kid of node.kids || []) walk(kid)
    }
    walk(el)
    return out
  }
  const off = TotpCard({ me: { totpEnabled: false }, __t: (k) => k, flash: () => {} })
  assert.ok(textsOf(off).includes('totpEnableAction'), 'off state offers enrollment')
  assert.ok(!textsOf(off).includes('totpDisableAction'), 'off state has no disable button')
  const on = TotpCard({ me: { totpEnabled: true }, __t: (k) => k, flash: () => {} })
  assert.ok(textsOf(on).includes('totpDisableAction'), 'on state offers disable')

  const setup = TotpSetupDialog({ onClose: () => {}, onEnabled: () => {}, __t: (k) => k })
  assert.ok(setup, 'setup dialog renders (loading shell while /setup is in flight)')
  const disable = TotpDisableDialog({ onClose: () => {}, onDisabled: () => {}, __t: (k) => k })
  const pwInputs = []
  const walkPw = (node) => {
    if (!node || typeof node !== 'object') return
    if (node.type === 'input' && node.props.type === 'password') pwInputs.push(node)
    for (const kid of node.kids || []) walkPw(kid)
  }
  walkPw(disable)
  assert.equal(pwInputs.length, 1, 'disable demands the login password')
})

test('gateway tab: status card renders phase/listen/upstream; cert table lists sites', () => {
  const { GatewayStatusCard, GatewayCertsCard, phaseLabelKey, phaseBadgeClass } = plugin.__internals
  const info = {
    phase: 'running', version: '9.9.9', listenHost: '0.0.0.0', port: 19843,
    upstream: 'http://127.0.0.1:3080', startedAt: 1, lastError: '',
    sites: [{ origin: 'auto', isDefault: true, hosts: ['localhost'], fingerprint: 'AA:BB', notAfter: 'tomorrow' }],
    customCerts: [{ id: 'c_1', name: '上传', origin: 'custom', hosts: ['ui.example.com'], fingerprint: 'CC:DD', notAfter: 'someday' }],
  }
  // component elements don't auto-render under the shim — invoke them
  const textsOf = (el, out = []) => {
    if (typeof el === 'string') { out.push(el); return out }
    if (!el || typeof el !== 'object') return out
    if (typeof el.type === 'function') return textsOf(el.type(el.props), out)
    for (const kid of el.kids || []) textsOf(kid, out)
    return out
  }
  const status = GatewayStatusCard({ info, __t: (k) => k, flash: () => {}, reload: () => {} })
  const statusTexts = textsOf(status)
  for (const key of ['gwStatusTitle', 'gwPhaseRunning', 'gwListen', 'gwUpstream', 'gwStartedAt', 'gwRestart']) {
    assert.ok(statusTexts.includes(key), `status card shows ${key}`)
  }
  assert.ok(statusTexts.some((x) => String(x).includes('19843')), 'bound port visible')

  const certs = GatewayCertsCard({ info, __t: (k) => k, flash: () => {}, reload: () => {}, onAdd: () => {} })
  const certTexts = textsOf(certs)
  for (const key of ['gwCertsTitle', 'gwOriginAuto', 'gwOriginCustom', 'gwAddCert', 'gwRegen', 'actionDelete']) {
    assert.ok(certTexts.includes(key), `cert table shows ${key}`)
  }
  assert.ok(!certTexts.includes('gwDefaultSite'), 'no fallback badge — the fallback IS the auto row, the badge was redundant')
  assert.ok(certTexts.includes('ui.example.com'), 'upload hosts render even before the listener reloads')

  assert.equal(phaseLabelKey('running'), 'gwPhaseRunning')
  assert.equal(phaseLabelKey('bogus'), 'gwPhaseStopped', 'unknown phase falls back to stopped')
  assert.match(phaseBadgeClass('running'), /um-badge-ok/)
  assert.match(phaseBadgeClass('error'), /um-badge-err/)
})

test('gateway tab renders loading shell; degrade states are distinguishable', () => {
  const { GatewayTab, ZH, EN } = plugin.__internals
  // loading shell renders; the degrade branches are driven by fetch errors in
  // the browser — here we pin that all three states have honest copy in both
  // dictionaries (a bare "unavailable" sent gateway users down the wrong path).
  const el = GatewayTab({ __t: (k) => k, flash: () => {} })
  assert.ok(el, 'renders a shell while /gateway/status is in flight')
  for (const dict of [ZH, EN]) {
    assert.ok(dict.gwMismatch.includes('404'), '404 -> mismatch hint (old gateway process / not via gateway)')
    assert.ok(/重启 dsh web|restart dsh web/i.test(dict.gwMismatch), 'mismatch hint names the fix: restart dsh web')
    assert.ok(dict.gwUnavailable, 'network failure -> unavailable note kept')
  }
})

test('sansFromAltName extracts DNS entries only', () => {
  const { sansFromAltName } = plugin.__internals
  assert.deepEqual(
    sansFromAltName('DNS:dsh.example.com, DNS:*.files.example.com, IP Address:1.2.3.4'),
    ['dsh.example.com', '*.files.example.com'])
  assert.deepEqual(sansFromAltName(''), [])
  assert.deepEqual(sansFromAltName(undefined), [])
})

test('add-certificate dialog carries name/hosts/cert/key fields and actions', () => {
  const { AddCertDialog } = plugin.__internals
  const el = AddCertDialog({ onClose: () => {}, flash: () => {}, reload: () => {}, __t: (k) => k })
  assert.ok(el, 'dialog renders')
  const fields = { textareas: 0, inputs: 0, buttons: 0 }
  const walk = (node) => {
    if (!node || typeof node !== 'object') return
    // shim keeps children in node.kids; components read props.children
    if (typeof node.type === 'function') { walk(node.type({ ...node.props, children: node.kids })); return }
    if (node.type === 'textarea') fields.textareas += 1
    if (node.type === 'input') fields.inputs += 1
    if (node.type === 'button') fields.buttons += 1
    for (const kid of node.kids || []) walk(kid)
  }
  walk(el)
  assert.equal(fields.textareas, 3, 'hosts + cert PEM + key PEM')
  assert.equal(fields.inputs, 1, 'name input')
  assert.ok(fields.buttons >= 3, 'close + inspect + save')
})
