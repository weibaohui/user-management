// Gate tests: pure decisions (gateDecision/parseCookies/isPublicPath/...) +
// the gateway-core HTTPS listener (Host allow-list, login → session cookie,
// unauth 302/401, reverse-proxy passthrough). The old shared-server
// attachGate/installFallbackGate machinery is gone — the gateway listener IS
// the gate now.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

// self-signed certificate on the gateway listener — trust it for the test process
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const require = createRequire(import.meta.url)
const {
  gateDecision,
  createDecider,
  parseCookies,
  isDocumentRequest,
  isStaticAsset,
  isAuditableRequest,
  isPublicPath,
  PUBLIC_PATHS,
} = await import('../src/gate.js')
const { createStore, normalizeIp } = require('../src/store.js')
const plugin = require('../src/index.js')
const { handleApi, sessionCookie, clearedCookie } = plugin.__internals
const { renderLoginPage } = require('../src/login-page.js')
const { createGateway } = require('../src/gateway-core.js')

const DOC = { method: 'GET', accept: 'text/html,application/xhtml+xml' }
const XHR = { method: 'GET', accept: '*/*' }

test('gateDecision: allow authenticated / public paths; redirect documents; 401 the rest', () => {
  assert.deepEqual(gateDecision({ ...DOC, path: '/', sessionValid: true }), { action: 'allow' })
  for (const path of PUBLIC_PATHS) {
    assert.equal(gateDecision({ ...XHR, path, sessionValid: false }).action, 'allow', path)
  }
  assert.deepEqual(gateDecision({ ...DOC, path: '/', sessionValid: false }), { action: 'redirect', location: '/login' })
  assert.deepEqual(gateDecision({ ...DOC, path: '/some/spa/route', sessionValid: false }), { action: 'redirect', location: '/login' })
  assert.equal(gateDecision({ ...XHR, path: '/api/foo', sessionValid: false }).action, 'unauthorized')
  assert.equal(gateDecision({ method: 'POST', accept: '', path: '/dsh-tasks/api', sessionValid: false }).action, 'unauthorized')
  assert.equal(gateDecision({ method: 'POST', accept: 'text/html', path: '/', sessionValid: false }).action, 'unauthorized')
})

test('parseCookies / isDocumentRequest / isPublicPath', () => {
  assert.deepEqual(parseCookies('a=1; um_session=tok; b=%20x'), { a: '1', um_session: 'tok', b: ' x' })
  assert.deepEqual(parseCookies(''), {})
  assert.deepEqual(parseCookies(undefined), {})
  assert.ok(isDocumentRequest('GET', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'))
  assert.ok(!isDocumentRequest('GET', 'application/json'))
  assert.ok(!isDocumentRequest('POST', 'text/html'))
  assert.ok(isPublicPath('/login'))
  assert.ok(isPublicPath('/user-management/api/login'))
  assert.ok(!isPublicPath('/user-management/api/users'))
  assert.ok(!isPublicPath('/'))
})

test('static assets are excluded from the audit, API calls are not', () => {
  assert.ok(isStaticAsset('/plugins/@weibaohui/x/client.js'))
  assert.ok(isStaticAsset('/assets/index-9a3f.css'))
  assert.ok(isStaticAsset('/favicon.ico'))
  assert.ok(!isStaticAsset('/api/sessions.create'))
  assert.ok(!isStaticAsset('/dsh-tasks/api'))
  assert.ok(!isAuditableRequest('GET', 'text/html', '/'))
  assert.ok(!isAuditableRequest('GET', '*/*', '/assets/app.js'))
  assert.ok(isAuditableRequest('POST', 'application/json', '/api/sessions.create'))
  assert.ok(isAuditableRequest('GET', '*/*', '/dsh-tasks/api'))
})

test('createDecider: banned IP is denied 403 before any session work — login page included', async () => {
  const banned = new Set(['198.51.100.9'])
  const decider = createDecider({
    resolveSession: async () => ({ user: { username: 'u' } }), // even valid sessions must not save a banned IP
    getClientIp: (req) => normalizeIp((req.socket && req.socket.remoteAddress) || ''),
    isBanned: (ip) => banned.has(ip),
  })
  const decision = await decider({ url: '/login', method: 'GET', headers: {}, socket: { remoteAddress: '198.51.100.9' } })
  assert.equal(decision.action, 'forbidden')
  const apiDecision = await decider({ url: '/api/x', method: 'POST', headers: { cookie: 'um_session=good' }, socket: { remoteAddress: '::ffff:198.51.100.9' } })
  assert.equal(apiDecision.action, 'forbidden', 'v6-mapped ban addresses match')
})

test('gateway-core: Host allow-list, login flow, unauth 302/401, proxy passthrough', async () => {
  // mock upstream = the loopback dsh webserver
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`inner:${req.url}`)
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upstreamPort = upstream.address().port

  const home = mkdtempSync(join(tmpdir(), 'um-gw-'))
  const store = createStore({ home })
  await store.load()
  const clientIp = (req) => '127.0.0.1'
  const deps = { store, clientIp }
  const decider = createDecider({
    resolveSession: async (token) => store.resolveSession(token),
    getClientIp: clientIp,
    isBanned: (ip) => store.isBanned(ip),
    onAccess: () => {},
  })
  const auditHooks = { onApiRequest: () => {}, onWsOpen: () => {} }
  const gw = createGateway({
    listenHost: '127.0.0.1',
    port: 0,
    upstream: `http://127.0.0.1:${upstreamPort}`,
    sites: [{ hosts: ['localhost'] }],
    certsDir: join(home, 'certs'),
    title: 'DSH 控制台',
    decider,
    handleApi,
    renderLoginPage,
    deps,
    clearedCookie,
    auditHooks,
    log: () => {},
    warn: () => {},
  })
  const port = await gw.start()
  const base = `https://localhost:${port}`
  const baseIp = `https://127.0.0.1:${port}`

  try {
    // Host not in the allow-list → 421 (127.0.0.1 is not 'localhost')
    const unknown = await fetch(`${baseIp}/`, { redirect: 'manual' })
    assert.equal(unknown.status, 421)

    // unauthenticated document navigation → 302 /login
    const redirected = await fetch(`${base}/`, { headers: { accept: 'text/html,application/xhtml+xml' }, redirect: 'manual' })
    assert.equal(redirected.status, 302)
    assert.equal(redirected.headers.get('location'), '/login')

    // /login page (register tab is default on a fresh system)
    const loginPage = await fetch(`${base}/login`)
    assert.equal(loginPage.status, 200)
    assert.ok((await loginPage.text()).includes('注册'))

    // unauthenticated API/XHR → 401
    const denied = await fetch(`${base}/api/foo`, { headers: { accept: 'application/json' } })
    assert.equal(denied.status, 401)

    // register the first admin → session cookie
    const reg = await fetch(`${base}/user-management/api/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'boss', password: 'secret1' }),
    })
    assert.equal(reg.status, 200)
    const regBody = await reg.json()
    assert.equal(regBody.user.role, 'admin')
    const setCookie = reg.headers.get('set-cookie') || ''
    const cookie = setCookie.split(';')[0]
    assert.ok(cookie.startsWith('um_session='))

    // authed document navigation → proxied to the loopback upstream
    const authed = await fetch(`${base}/`, { headers: { accept: 'text/html,application/xhtml+xml', cookie }, redirect: 'manual' })
    assert.equal(authed.status, 200)
    assert.equal(await authed.text(), 'inner:/')

    // authed API/XHR → proxied too
    const proxiedApi = await fetch(`${base}/api/sessions.create`, { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}' })
    assert.equal(proxiedApi.status, 200)
    assert.equal(await proxiedApi.text(), 'inner:/api/sessions.create')

    // /logout clears the cookie + bounces to /login (send the cookie so the
    // server drops the session, not just the client cookie)
    const out = await fetch(`${base}/logout`, { redirect: 'manual', headers: { cookie } })
    assert.equal(out.status, 302)
    assert.equal(out.headers.get('location'), '/login')
    assert.ok((out.headers.get('set-cookie') || '').includes('Max-Age=0'))

    // the session is dropped server-side — the old cookie no longer authenticates
    const after = await fetch(`${base}/`, { headers: { accept: 'text/html,application/xhtml+xml', cookie }, redirect: 'manual' })
    assert.equal(after.status, 302)
  } finally {
    gw.stop()
    upstream.close()
    upstream.closeAllConnections()
    rmSync(home, { recursive: true, force: true })
  }
})
