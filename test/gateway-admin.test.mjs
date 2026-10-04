// Gateway management API (/user-management/api/gateway/*): the admin-only
// permission matrix over a real http server, driven through handleApi with a
// real cert store + a real createGatewayManager (temp dirs, real selfsigned
// pairs). The listener lifecycle itself is stubbed (rebuild counter) — the
// listener swap is covered by gateway-cert/gateway-core tests.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync, existsSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import selfsigned from 'selfsigned'

const { createStore } = await import('../src/store.js')
const { SESSION_COOKIE, parseCookies } = await import('../src/gate.js')
const plugin = (await import('../src/index.js')).default
const { handleApi, createGatewayManager } = plugin.__internals
const { createCertStore } = await import('../src/cert-store.js')

function makePair(cn, sans = []) {
  return selfsigned.generate(
    [{ name: 'commonName', value: cn }],
    { days: 365, keySize: 2048, algorithm: 'sha256', extensions: [{ name: 'subjectAltName', altNames: sans.map((value) => ({ type: 2, value })) }] },
  )
}

let home, store, server, port, deps, adminCookie, userCookie, rebuilds

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), 'um-gwadmin-'))
  store = createStore({ home })
  await store.load()
  rebuilds = []
  const certsDir = join(home, 'user-management', 'certs')
  const certStore = createCertStore({ dir: join(certsDir, 'custom') })
  const lifecycle = () => ({ version: 'test', phase: 'running', port: 19843, sites: [], listenHost: '0.0.0.0', upstream: 'http://127.0.0.1:3080' })
  deps = {
    store,
    clientIp: () => '127.0.0.1',
    autoActivate: () => true,
    gateway: createGatewayManager({
      certStore,
      certsDir,
      lifecycle,
      rebuild: (force) => { rebuilds.push(force) },
    }),
  }
  server = http.createServer((req, res) => {
    handleApi(req, res, deps).catch((error) => {
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: String(error && error.message) }))
      } else {
        res.end()
      }
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = server.address().port

  // one admin + one plain user session
  const admin = await store.createUser({ username: 'root', password: 'secret-pass', role: 'admin' })
  await store.createUser({ username: 'jane', password: 'secret-pass', role: 'user' })
  adminCookie = cookieOf(await call('/login', { method: 'POST', body: { username: 'root', password: 'secret-pass' } }))
  userCookie = cookieOf(await call('/login', { method: 'POST', body: { username: 'jane', password: 'secret-pass' } }))
  assert.ok(adminCookie && userCookie, 'both sessions minted')
  assert.equal(admin.role, 'admin')
})

afterEach(() => {
  server.close()
  server.closeAllConnections()
  rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
})

function call(path, { method = 'GET', body, cookie } = {}) {
  const headers = {}
  if (body !== undefined) headers['content-type'] = 'application/json'
  if (cookie) headers.cookie = cookie
  return fetch(`http://127.0.0.1:${port}/user-management/api${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  }).then(async (res) => ({ status: res.status, data: await res.json().catch(() => ({})), headers: res.headers }))
}

function cookieOf(res) {
  const raw = res.headers.get('set-cookie') || ''
  const match = new RegExp(`${SESSION_COOKIE}=([^;]+)`).exec(raw)
  return match ? `${SESSION_COOKIE}=${match[1]}` : ''
}

test('gateway endpoints are admin-only: 401 anonymous, 403 plain user', async () => {
  for (const [method, path] of [
    ['GET', '/gateway/status'],
    ['POST', '/gateway/certs'],
    ['DELETE', '/gateway/certs/c_nope'],
    ['POST', '/gateway/certs/regenerate'],
    ['POST', '/gateway/restart'],
  ]) {
    const anon = await call(path, { method, body: method === 'POST' ? {} : undefined })
    assert.equal(anon.status, 401, `${method} ${path} anonymous`)
    const plain = await call(path, { method, cookie: userCookie, body: method === 'POST' ? {} : undefined })
    assert.equal(plain.status, 403, `${method} ${path} non-admin`)
  }
})

test('without deps.gateway the endpoints 404 (bare harness compatibility)', async () => {
  const saved = deps.gateway
  deps.gateway = null
  const res = await call('/gateway/status', { cookie: adminCookie })
  assert.equal(res.status, 404)
  deps.gateway = saved
})

test('status reports lifecycle + stored custom certs (empty at first)', async () => {
  const res = await call('/gateway/status', { cookie: adminCookie })
  assert.equal(res.status, 200)
  assert.equal(res.data.phase, 'running')
  assert.deepEqual(res.data.sites, [])
  assert.deepEqual(res.data.customCerts, [])
})

test('addCert dryRun validates + inspects WITHOUT persisting or rebuilding', async () => {
  const pems = makePair('dry.example.com', ['dry.example.com'])
  const res = await call('/gateway/certs', {
    method: 'POST', cookie: adminCookie,
    body: { name: 'dry', hosts: ['dry.example.com'], cert: pems.cert, key: pems.private, dryRun: true },
  })
  assert.equal(res.status, 200)
  assert.equal(res.data.dryRun, true)
  assert.match(res.data.info.subjectAltName, /DNS:dry\.example\.com/)
  assert.equal(res.data.info.expired, false)
  assert.deepEqual(rebuilds, [], 'dry run never rebuilds')
  const status = await call('/gateway/status', { cookie: adminCookie })
  assert.deepEqual(status.data.customCerts, [], 'dry run never persists')
})

test('addCert happy path persists, logs activity and requests a forced rebuild', async () => {
  const pems = makePair('live.example.com', ['live.example.com'])
  const res = await call('/gateway/certs', {
    method: 'POST', cookie: adminCookie,
    body: { name: 'live', hosts: ['live.example.com'], cert: pems.cert, key: pems.private },
  })
  assert.equal(res.status, 200)
  assert.equal(res.data.ok, true)
  assert.match(res.data.cert.id, /^c_/)
  assert.deepEqual(rebuilds, [true], 'a saved cert schedules a forced rebuild')
  const status = await call('/gateway/status', { cookie: adminCookie })
  assert.equal(status.data.customCerts.length, 1)
  assert.equal(status.data.customCerts[0].name, 'live')
  const activity = await store.listActivity({ types: ['gateway_cert_add'], limit: 10 })
  assert.equal(activity.length, 1)
  assert.match(activity[0].detail, /cert=live/)
})

test('addCert rejects a mismatched pair with 400 and the server message', async () => {
  const good = makePair('ok.example.com', ['ok.example.com'])
  const other = makePair('other.example.com', ['other.example.com'])
  const res = await call('/gateway/certs', {
    method: 'POST', cookie: adminCookie,
    body: { hosts: ['ok.example.com'], cert: good.cert, key: other.private },
  })
  assert.equal(res.status, 400)
  assert.match(res.data.error, /不匹配/)
  assert.deepEqual(rebuilds, [])
})

test('removeCert deletes and rebuilds; unknown id 404s', async () => {
  const pems = makePair('gone.example.com', ['gone.example.com'])
  const added = await call('/gateway/certs', {
    method: 'POST', cookie: adminCookie,
    body: { hosts: ['gone.example.com'], cert: pems.cert, key: pems.private },
  })
  const id = added.data.cert.id
  rebuilds.length = 0
  const missing = await call(`/gateway/certs/c_missing`, { method: 'DELETE', cookie: adminCookie })
  assert.equal(missing.status, 404)
  const res = await call(`/gateway/certs/${id}`, { method: 'DELETE', cookie: adminCookie })
  assert.equal(res.status, 200)
  assert.deepEqual(rebuilds, [true])
  const status = await call('/gateway/status', { cookie: adminCookie })
  assert.deepEqual(status.data.customCerts, [])
})

test('regenerate deletes only the certsDir root pairs (uploads untouched) and rebuilds', async () => {
  const certsDir = join(home, 'user-management', 'certs')
  const { mkdirSync } = await import('node:fs')
  mkdirSync(certsDir, { recursive: true })
  writeFileSync(join(certsDir, 'localhost.crt'), 'auto crt', 'utf8')
  writeFileSync(join(certsDir, 'localhost.key'), 'auto key', 'utf8')
  const pems = makePair('kept.example.com', ['kept.example.com'])
  const added = await call('/gateway/certs', {
    method: 'POST', cookie: adminCookie,
    body: { hosts: ['kept.example.com'], cert: pems.cert, key: pems.private },
  })
  rebuilds.length = 0
  const res = await call('/gateway/certs/regenerate', { method: 'POST', cookie: adminCookie })
  assert.equal(res.status, 200)
  assert.equal(res.data.removed, 2, 'the two auto pair files are gone')
  assert.equal(existsSync(join(certsDir, 'localhost.crt')), false)
  assert.equal(existsSync(join(certsDir, 'localhost.key')), false)
  const customDir = join(certsDir, 'custom')
  assert.deepEqual(readdirSync(customDir).filter((name) => name.includes(added.data.cert.id)).length, 2, 'uploaded pair survives')
  assert.deepEqual(rebuilds, [true])
})

test('restart requests a forced rebuild without blocking the response', async () => {
  const res = await call('/gateway/restart', { method: 'POST', cookie: adminCookie })
  assert.equal(res.status, 200)
  assert.equal(res.data.restarting, true)
  assert.deepEqual(rebuilds, [true])
})
