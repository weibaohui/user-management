// Gate tests: pure decisions + end-to-end listener re-ordering on a real
// node:http server (the hard gate) and the degraded route gateway.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'

const {
  gateDecision,
  createDecider,
  attachGate,
  installFallbackGate,
  installGate,
  parseCookies,
  isDocumentRequest,
  isStaticAsset,
  isAuditableRequest,
  isPublicPath,
  PUBLIC_PATHS,
} = await import('../src/gate.js')

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
}

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
  // document POSTs are not "navigations that can be redirected"… but HTML forms
  // do navigate; only GET/HEAD count as documents, everything else 401s.
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
  assert.ok(!isAuditableRequest('GET', 'text/html', '/')) // document → access ledger instead
  assert.ok(!isAuditableRequest('GET', '*/*', '/assets/app.js')) // asset
  assert.ok(isAuditableRequest('POST', 'application/json', '/api/sessions.create'))
  assert.ok(isAuditableRequest('GET', '*/*', '/dsh-tasks/api'))
})

test('attachGate: end-to-end on a real server — redirect, 401, passthrough, upgrade deny', async () => {
  const hits = []
  const server = http.createServer((req, res) => {
    hits.push(req.url)
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`inner:${req.url}`)
  })
  let upgradeHit = null
  server.on('upgrade', (req, socket) => {
    upgradeHit = req.url
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
  })
  const port = await listen(server)

  const decider = createDecider({
    resolveSession: async (token) => (token === 'good' ? { user: { username: 'u' } } : null),
  })
  const accesses = []
  const auditCalls = []
  const wsCalls = []
  const dispose = attachGate(server, decider, {
    onApiRequest: (req, session, path, status) => auditCalls.push({ path, status, username: session && session.user.username }),
    onWsOpen: (req, session, path) => wsCalls.push({ path, username: session && session.user.username }),
  })

  // unauthenticated document → 302 /login (undici sends no Accept by default)
  const redirected = await fetch(`http://127.0.0.1:${port}/`, {
    redirect: 'manual',
    headers: { accept: 'text/html,application/xhtml+xml' },
  })
  assert.equal(redirected.status, 302)
  assert.equal(redirected.headers.get('location'), '/login')

  // unauthenticated XHR → 401 JSON
  const denied = await fetch(`http://127.0.0.1:${port}/api/foo`, { headers: { accept: 'application/json' } })
  assert.equal(denied.status, 401)

  // public path passes through to the inner handler
  const loginPage = await fetch(`http://127.0.0.1:${port}/login`)
  assert.equal(loginPage.status, 200)
  assert.equal(await loginPage.text(), 'inner:/login')

  // valid session → passthrough
  const authed = await fetch(`http://127.0.0.1:${port}/whatever`, { headers: { cookie: 'um_session=good' } })
  assert.equal(authed.status, 200)
  assert.equal(await authed.text(), 'inner:/whatever')

  // audited: an authed API call lands in the audit hook with its status
  const apiCall = await fetch(`http://127.0.0.1:${port}/api/sessions.create`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: 'um_session=good' },
    body: '{}',
  })
  assert.equal(apiCall.status, 200)
  await new Promise((r) => setTimeout(r, 10))
  const apiAudit = auditCalls.find((c) => c.path === '/api/sessions.create')
  assert.ok(apiAudit, 'API request audited')
  assert.equal(apiAudit.status, 200)
  assert.equal(apiAudit.username, 'u')
  // assets are never audited
  await fetch(`http://127.0.0.1:${port}/assets/app.js`, { headers: { cookie: 'um_session=good' } })
  await new Promise((r) => setTimeout(r, 10))
  assert.equal(auditCalls.find((c) => c.path === '/assets/app.js'), undefined, 'static asset not audited')

  // WebSocket upgrade without a session is denied at the socket level
  const denyResult = await new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1')
    let buf = ''
    let timer = null
    const finish = (result) => {
      clearTimeout(timer)
      socket.destroy()
      resolve(result)
    }
    socket.on('data', (d) => {
      buf += d.toString()
      finish({ response: buf.split('\r\n')[0], upgradeHit })
    })
    socket.on('error', () => finish({ response: buf.split('\r\n')[0] || 'destroyed', upgradeHit }))
    socket.on('connect', () => {
      socket.write('GET /api/events.mux HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    })
    timer = setTimeout(() => finish({ response: buf.split('\r\n')[0] || 'destroyed', upgradeHit }), 500)
  })
  assert.equal(denyResult.upgradeHit, null, 'inner upgrade listener never called without a session')
  assert.ok(denyResult.response.includes('401'), `socket denied: ${denyResult.response}`)

  // an authed WS upgrade reaches the inner listener and the audit hook
  const wsResult = await new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1')
    let buf = ''
    let timer = null
    const finish = (result) => {
      clearTimeout(timer)
      socket.destroy()
      resolve(result)
    }
    socket.on('data', (d) => {
      buf += d.toString()
      finish(buf.split('\r\n')[0])
    })
    socket.on('error', () => finish(buf.split('\r\n')[0] || 'destroyed'))
    socket.on('connect', () => {
      socket.write('GET /api/events.mux HTTP/1.1\r\nHost: x\r\nCookie: um_session=good\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    })
    timer = setTimeout(() => finish(buf.split('\r\n')[0] || 'timeout'), 500)
  })
  assert.ok(wsResult.includes('101'), `authed upgrade passes: ${wsResult}`)
  assert.deepEqual(wsCalls, [{ path: '/api/events.mux', username: 'u' }])

  // dispose restores the original wiring — everything passes again
  dispose()
  const after = await fetch(`http://127.0.0.1:${port}/`, {
    redirect: 'manual',
    headers: { accept: 'text/html,application/xhtml+xml', cookie: 'um_session=good' },
  })
  assert.equal(after.status, 200)
  server.close()
  server.closeAllConnections()
})

test('installFallbackGate: route-level gateway wraps the captured fallback', async () => {
  let webServer
  const inner = (req, res) => { res.writeHead(200); res.end('fallback') }
  const registered = []
  webServer = {
    fallback: inner,
    register: (route) => registered.push(route),
  }
  const decider = createDecider({ resolveSession: async (token) => token === 'good' })
  const dispose = installFallbackGate(webServer, decider)
  assert.equal(registered.length, 1)
  assert.equal(registered[0].path, '/')

  const res = await new Promise((resolve) => {
    const fakeRes = {
      writeHead(status, headers) { this.status = status; this.headers = headers },
      end(body) { this.body = body; resolve(this) },
    }
    registered[0].handler({ method: 'GET', url: '/', headers: { accept: 'text/html' } }, fakeRes)
  })
  assert.equal(res.status, 302)

  const ok = await new Promise((resolve) => {
    const fakeRes = {
      writeHead(status) { this.status = status },
      end(body) { this.body = body; resolve(this) },
    }
    registered[0].handler({ method: 'GET', url: '/', headers: { accept: 'text/html', cookie: 'um_session=good' } }, fakeRes)
  })
  assert.equal(ok.status, 200)
  assert.equal(ok.body, 'fallback')
  dispose()
})

test('installGate prefers the hard gate, degrades when the server is unreachable', async () => {
  const decider = createDecider({ resolveSession: async () => false })
  // no webServer.server → degraded mode
  const degraded = installGate({ fallback: null, register: () => {} }, decider)
  assert.equal(degraded.mode, 'fallback')
  degraded.dispose()
  // a real server → hard gate
  const server = http.createServer(() => {})
  const hard = installGate({ server }, decider)
  assert.equal(hard.mode, 'server')
  hard.dispose()
  server.close()
})

test('banned IP is denied 403 before any session work — login page included', async () => {
  const banned = new Set(['198.51.100.9'])
  const server = http.createServer((req, res) => { res.writeHead(200); res.end('inner') })
  const port = await listen(server)
  const decider = createDecider({
    resolveSession: async () => ({ user: { username: 'u' } }), // even valid sessions must not save a banned IP
    getClientIp: (req) => req.socket.remoteAddress.replace(/^::ffff:/, ''),
    isBanned: (ip) => banned.has(ip),
  })
  const dispose = attachGate(server, decider)

  const blocked = await fetch(`http://127.0.0.1:${port}/login`, { redirect: 'manual' })
  assert.equal(blocked.status, 200, 'loopback is not on the ban list — passes')

  // simulate a banned source via the decider contract directly
  const decision = await decider({ url: '/login', method: 'GET', headers: {}, socket: { remoteAddress: '198.51.100.9' } })
  assert.equal(decision.action, 'forbidden')
  // and for an API path with a session cookie — still forbidden
  const apiDecision = await decider({ url: '/api/x', method: 'POST', headers: { cookie: 'um_session=good' }, socket: { remoteAddress: '::ffff:198.51.100.9' } })
  assert.equal(apiDecision.action, 'forbidden', 'v6-mapped ban addresses match')

  dispose()
  server.close()
  server.closeAllConnections()
})
