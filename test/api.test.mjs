// API tests: the full permission matrix over a real http server.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { createStore } = require('../src/store.js')
const { SESSION_COOKIE } = require('../src/gate.js')
const plugin = require('../src/index.js')
const { handleApi } = plugin.__internals

let home, store, server, port, deps

beforeEach(async () => {
  home = mkdtempSync(join(tmpdir(), 'um-api-'))
  store = createStore({ home })
  await store.load()
  deps = { store, clientIp: () => '127.0.0.1' }
  server = http.createServer((req, res) => {
    handleApi(req, res, deps).catch((error) => {
      res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: String(error && error.message) }))
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  port = server.address().port
})

afterEach(() => {
  server.close()
  server.closeAllConnections()
  rmSync(home, { recursive: true, force: true })
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
  const match = new RegExp(`${SESSION_COOKIE}=([^;]*)`).exec(raw)
  return match ? `${SESSION_COOKIE}=${match[1]}` : null
}

test('permission matrix: anonymous / plain user / admin across every endpoint', async () => {
  // ── anonymous ──
  assert.equal((await call('/session')).data.user, null)
  assert.equal((await call('/users')).status, 401)
  assert.equal((await call('/activity')).status, 401)
  assert.equal((await call('/me/password', { method: 'POST', body: {} })).status, 401)

  // ── first registration → admin, second → plain user ──
  const regA = await call('/register', { method: 'POST', body: { username: 'boss', password: 'secret1' } })
  assert.equal(regA.status, 200)
  assert.equal(regA.data.user.role, 'admin')
  const adminCookie = cookieOf(regA)
  assert.ok(adminCookie)

  const regB = await call('/register', { method: 'POST', body: { username: 'alice', password: 'secret1' } })
  assert.equal(regB.data.user.role, 'user')
  const userCookie = cookieOf(regB)
  const alice = regB.data.user

  // duplicate register
  assert.equal((await call('/register', { method: 'POST', body: { username: 'ALICE', password: 'secret1' } })).status, 400)
  // bad username / short password
  assert.equal((await call('/register', { method: 'POST', body: { username: 'x!', password: 'secret1' } })).status, 400)
  assert.equal((await call('/register', { method: 'POST', body: { username: 'carol', password: '12345' } })).status, 400)

  // ── session echo ──
  assert.equal((await call('/session', { cookie: adminCookie })).data.user.username, 'boss')
  assert.equal((await call('/session', { cookie: userCookie })).data.user.username, 'alice')
  assert.equal((await call('/session', { cookie: `${SESSION_COOKIE}=forged` })).data.user, null)

  // ── login ──
  const bad = await call('/login', { method: 'POST', body: { username: 'boss', password: 'nope' } })
  assert.equal(bad.status, 401)
  const good = await call('/login', { method: 'POST', body: { username: 'BOSS', password: 'secret1' } })
  assert.equal(good.status, 200)
  assert.ok(cookieOf(good))

  // ── users list scoping ──
  const adminView = await call('/users', { cookie: adminCookie })
  assert.equal(adminView.data.users.length, 2)
  const userView = await call('/users', { cookie: userCookie })
  assert.deepEqual(userView.data.users.map((u) => u.username), ['alice'])
  // no hash material ever leaks
  assert.deepEqual(Object.keys(userView.data.users[0]).sort(), ['createdAt', 'id', 'lastLoginAt', 'role', 'username'])

  // ── admin actions are admin-only ──
  assert.equal((await call(`/users/${alice.id}/reset-password`, { method: 'POST', cookie: userCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}/role`, { method: 'POST', body: { role: 'admin' }, cookie: userCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE', cookie: userCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE' })).status, 403)

  // ── reset password: temp password works, old sessions die ──
  const oldAliceSession = await call('/login', { method: 'POST', body: { username: 'alice', password: 'secret1' } })
  const oldAliceCookie = cookieOf(oldAliceSession)
  const reset = await call(`/users/${alice.id}/reset-password`, { method: 'POST', cookie: adminCookie })
  assert.equal(reset.status, 200)
  assert.match(reset.data.tempPassword, /^[A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{4}$/)
  assert.equal((await call('/session', { cookie: oldAliceCookie })).data.user, null, 'pre-reset session is killed')
  const withTemp = await call('/login', { method: 'POST', body: { username: 'alice', password: reset.data.tempPassword } })
  assert.equal(withTemp.status, 200, 'temp password logs in')
  assert.equal((await call('/login', { method: 'POST', body: { username: 'alice', password: 'secret1' } })).status, 401, 'old password dead')

  // ── role change: self-change blocked, target re-login enforced ──
  assert.equal((await call(`/users/${regA.data.user.id}/role`, { method: 'POST', body: { role: 'user' }, cookie: adminCookie })).status, 403)
  const promote = await call(`/users/${alice.id}/role`, { method: 'POST', body: { role: 'admin' }, cookie: adminCookie })
  assert.equal(promote.status, 200)
  assert.equal(promote.data.user.role, 'admin')
  const tempCookie = cookieOf(withTemp)
  assert.equal((await call('/session', { cookie: tempCookie })).data.user, null, 'promoted user sessions dropped')

  // ── delete: self-delete blocked, last-admin handled at store level ──
  assert.equal((await call(`/users/${regA.data.user.id}`, { method: 'DELETE', cookie: adminCookie })).status, 403)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE', cookie: adminCookie })).status, 200)
  assert.equal((await call('/users', { cookie: adminCookie })).data.users.length, 1)
  assert.equal((await call(`/users/${alice.id}`, { method: 'DELETE', cookie: adminCookie })).status, 404)

  // ── password self-service ──
  const regC = await call('/register', { method: 'POST', body: { username: 'carol', password: 'secret1' } })
  const carolCookie = cookieOf(regC)
  const carolExtra = await call('/login', { method: 'POST', body: { username: 'carol', password: 'secret1' } })
  const carolExtraCookie = cookieOf(carolExtra)
  const wrongOld = await call('/me/password', { method: 'POST', body: { oldPassword: 'nope', newPassword: 'newpass1' }, cookie: carolCookie })
  assert.equal(wrongOld.status, 400)
  const changed = await call('/me/password', { method: 'POST', body: { oldPassword: 'secret1', newPassword: 'newpass1' }, cookie: carolCookie })
  assert.equal(changed.status, 200)
  assert.equal((await call('/session', { cookie: carolExtraCookie })).data.user, null, 'other sessions die on password change')
  assert.equal((await call('/session', { cookie: carolCookie })).data.user.username, 'carol', 'current session survives')
  assert.equal((await call('/login', { method: 'POST', body: { username: 'carol', password: 'newpass1' } })).status, 200)

  // ── activity visibility ──
  const adminLog = await call('/activity?limit=100', { cookie: adminCookie })
  const types = new Set(adminLog.data.entries.map((e) => e.type))
  for (const expected of ['register', 'login', 'login_failed', 'reset_password', 'role_change', 'delete_user', 'password_change']) {
    assert.ok(types.has(expected), `admin sees ${expected}`)
  }
  const userLog = await call('/activity?limit=100', { cookie: carolCookie })
  for (const entry of userLog.data.entries) {
    assert.equal(entry.userId, regC.data.user.id, 'plain users only see their own entries')
    assert.ok(['login', 'login_failed', 'logout', 'password_change'].includes(entry.type), `plain users never see ${entry.type}`)
  }

  // ── logout ──
  const out = await call('/logout', { method: 'POST', cookie: carolCookie })
  assert.equal(out.status, 200)
  assert.equal((await call('/session', { cookie: carolCookie })).data.user, null)

  // ── unknown route ──
  assert.equal((await call('/nope', { cookie: adminCookie })).status, 404)
})
