// The cordis `user-management` identity service: apply() must provide it,
// and its resolvers must map a live session cookie → public user (dead
// cookies and disabled users → null). apply() is exercised with
// `enabled: false` so the gateway lifecycle (real binds, health-check
// timers) stays out of the test process.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

let home

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'um-id-'))
})

afterEach(() => {
  rmSync(home, { recursive: true, force: true })
})

function makeStore() {
  const { createStore } = require('../src/store.js')
  const store = createStore({ home })
  return store.load().then(() => store)
}

function applyWith(config) {
  const plugin = require('../src/index.js')
  const provided = []
  const disposers = []
  process.env.DSH_HOME = home
  try {
    plugin.apply({
      provide: (name, value) => provided.push({ name, value }),
      effect: (fn) => disposers.push(fn),
      on: () => () => {},
      webServer: { register: () => {}, fallback: undefined, server: null },
    }, config)
  } finally {
    process.env.DSH_HOME = ''
  }
  return { plugin, provided, disposers }
}

test('apply provides the `user-management` service with both resolvers', () => {
  const { provided } = applyWith({ enabled: false })
  const entry = provided.find((p) => p.name === 'user-management')
  assert.ok(entry, 'service provided under the exact name')
  assert.equal(typeof entry.value.resolveRequest, 'function')
  assert.equal(typeof entry.value.resolveToken, 'function')
})

test('resolveRequest maps a live session cookie to the public user', async () => {
  const store = await makeStore()
  const alice = await store.createUser({ username: 'alice', password: 'secret1' })
  const { token } = await store.createSession(store.findUserByUsername('alice'))

  const { createIdentityService } = require('../src/index.js').__internals
  const service = createIdentityService({ store, ready: Promise.resolve() })
  const resolved = await service.resolveRequest({ headers: { cookie: `um_session=${token}; other=x` } })
  assert.equal(resolved.username, 'alice')
  assert.equal(resolved.id, alice.id)
  assert.deepEqual(Object.keys(resolved).sort(), ['createdAt', 'disabled', 'id', 'lastLoginAt', 'role', 'username'], 'no hash material')
})

test('resolveRequest returns null for anonymous / forged / malformed cookies', async () => {
  const store = await makeStore()
  const { createIdentityService } = require('../src/index.js').__internals
  const service = createIdentityService({ store, ready: Promise.resolve() })
  assert.equal(await service.resolveRequest({ headers: {} }), null)
  assert.equal(await service.resolveRequest({ headers: { cookie: 'um_session=forged' } }), null)
  assert.equal(await service.resolveRequest({ headers: { cookie: 'other=1' } }), null)
  assert.equal(await service.resolveRequest({}), null)
})

test('resolveToken works and disabled users stop resolving', async () => {
  const store = await makeStore()
  await store.createUser({ username: 'boss', password: 'secret1', role: 'admin' })
  const alice = await store.createUser({ username: 'alice', password: 'secret1' })
  const { token } = await store.createSession(store.findUserByUsername('alice'))
  const { createIdentityService } = require('../src/index.js').__internals
  const service = createIdentityService({ store, ready: Promise.resolve() })

  assert.equal((await service.resolveToken(token)).username, 'alice')
  await store.setDisabled(store.findUserByUsername('alice'), true)
  assert.equal(await service.resolveToken(token), null, 'disabled user resolves to null')
  assert.equal(await service.resolveToken(undefined), null)
})

test('the applied service resolves a user seeded before apply (end-to-end shape)', async () => {
  const store = await makeStore()
  await store.createUser({ username: 'boss', password: 'secret1', role: 'admin' })
  const { token } = await store.createSession(store.findUserByUsername('boss'))

  const { provided } = applyWith({ enabled: false })
  const service = provided.find((p) => p.name === 'user-management').value
  const resolved = await service.resolveRequest({ headers: { cookie: `um_session=${token}` } })
  assert.equal(resolved.username, 'boss', 'the apply-scoped store loaded the seeded state')
  assert.equal(resolved.role, 'admin')
})
