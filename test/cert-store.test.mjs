// Unit tests for the custom-certificate store behind the gateway management
// UI: add/list/remove round trip, persistence across reload, 0600 key
// material, PEM pair validation (parse / key match / TLS load) and host
// normalization. Real selfsigned pairs, real temp dirs — no mocks.
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync, statSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import selfsigned from 'selfsigned'

const { createCertStore, inspectCertPair, normalizeHosts, CertStoreError } = await import('../src/cert-store.js')

function makePair(cn, sans = []) {
  return selfsigned.generate(
    [{ name: 'commonName', value: cn }],
    {
      days: 365, keySize: 2048, algorithm: 'sha256',
      extensions: [{ name: 'subjectAltName', altNames: sans.map((value) => ({ type: 2, value })) }],
    },
  )
}

let home, store

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'um-certs-'))
  store = createCertStore({ dir: join(home, 'custom') })
})

afterEach(() => {
  rmSync(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
})

test('add persists files + manifest; list returns keyless metadata', async () => {
  const pems = makePair('dsh.example.com', ['dsh.example.com', '*.files.example.com'])
  const record = await store.add({ name: '主域名', hosts: ['dsh.example.com', '*.files.example.com'], cert: pems.cert, key: pems.private, by: 'admin' })
  assert.equal(record.name, '主域名')
  assert.match(record.fingerprint, /^[0-9A-F:]{95}$/)
  assert.equal(record.createdBy, 'admin')
  assert.ok(existsSync(join(home, 'custom', `${record.id}.crt`)))
  const keyStat = statSync(join(home, 'custom', `${record.id}.key`))
  assert.equal(keyStat.mode & 0o777, 0o600, 'private key material is 0600')
  const items = await store.list()
  assert.equal(items.length, 1)
  assert.equal(items[0].id, record.id)
  assert.equal(items[0].hosts.join(','), 'dsh.example.com,*.files.example.com')
  // metadata never carries PEM bodies
  assert.ok(!JSON.stringify(items).includes('PRIVATE KEY'))
  assert.ok(!JSON.stringify(items).includes('BEGIN CERTIFICATE'))
})

test('listSites yields resolveSites-ready descriptors with file paths + origin custom', async () => {
  const pems = makePair('a.example.com', ['a.example.com'])
  const record = await store.add({ hosts: ['a.example.com'], cert: pems.cert, key: pems.private })
  const sites = await store.listSites()
  assert.equal(sites.length, 1)
  assert.equal(sites[0].id, record.id)
  assert.equal(sites[0].origin, 'custom')
  assert.equal(sites[0].hosts.join(','), 'a.example.com')
  // pemOf normalizes CRLF (selfsigned emits \r\n) and pins a trailing \n
  assert.equal(readFileSync(sites[0].cert, 'utf8'), pems.cert.replace(/\r\n/g, '\n').trim() + '\n')
  assert.ok(existsSync(sites[0].key))
})

test('persistence: a fresh store instance reads the same manifest', async () => {
  const pems = makePair('b.example.com', ['b.example.com'])
  const record = await store.add({ hosts: ['b.example.com'], cert: pems.cert, key: pems.private })
  const second = createCertStore({ dir: join(home, 'custom') })
  const items = await second.list()
  assert.equal(items.length, 1)
  assert.equal(items[0].id, record.id)
})

test('remove deletes files + manifest entry and reports unknown ids', async () => {
  const pems = makePair('c.example.com', ['c.example.com'])
  const record = await store.add({ hosts: ['c.example.com'], cert: pems.cert, key: pems.private })
  assert.equal(await store.remove(record.id), true)
  assert.equal(await store.remove(record.id), false, 'second remove is a miss')
  assert.equal((await store.list()).length, 0)
  assert.equal(existsSync(join(home, 'custom', `${record.id}.crt`)), false)
  assert.equal(existsSync(join(home, 'custom', `${record.id}.key`)), false)
})

test('rejects mismatched pairs, garbage PEM and missing hosts', async () => {
  const good = makePair('good.example.com', ['good.example.com'])
  const other = makePair('other.example.com', ['other.example.com'])
  await assert.rejects(
    () => store.add({ hosts: ['good.example.com'], cert: good.cert, key: other.private }),
    (e) => e instanceof CertStoreError && e.code === 'bad_pair',
  )
  await assert.rejects(
    () => store.add({ hosts: ['good.example.com'], cert: 'not a pem', key: good.private }),
    (e) => e instanceof CertStoreError && e.code === 'bad_pair',
  )
  await assert.rejects(
    () => store.add({ hosts: [], cert: good.cert, key: good.private }),
    (e) => e instanceof CertStoreError && e.code === 'bad_hosts',
  )
  await assert.rejects(
    () => store.add({ hosts: ['*'], cert: good.cert, key: good.private }),
    (e) => e instanceof CertStoreError && e.code === 'bad_hosts',
    'bare * would present one cert to every SNI name',
  )
})

test('rejects a second cert claiming an occupied host (SNI first-match ambiguity)', async () => {
  const first = makePair('dup.example.com', ['dup.example.com'])
  const second = makePair('dup.example.com', ['dup.example.com'])
  await store.add({ hosts: ['dup.example.com'], cert: first.cert, key: first.private })
  await assert.rejects(
    () => store.add({ hosts: ['dup.example.com'], cert: second.cert, key: second.private }),
    (e) => e instanceof CertStoreError && e.code === 'host_conflict',
  )
})

test('corrupt manifest degrades to an empty list (gateway keeps booting)', async () => {
  const pems = makePair('d.example.com', ['d.example.com'])
  await store.add({ hosts: ['d.example.com'], cert: pems.cert, key: pems.private })
  const { writeFileSync } = await import('node:fs')
  writeFileSync(join(home, 'custom', 'meta.json'), '{broken json', 'utf8')
  const second = createCertStore({ dir: join(home, 'custom') })
  assert.deepEqual(await second.list(), [])
})

test('inspectCertPair reports SANs / validity / expired without persisting', () => {
  const pems = makePair('e.example.com', ['e.example.com', 'alt.example.com'])
  const verdict = inspectCertPair(pems.cert, pems.private)
  assert.equal(verdict.ok, true)
  assert.match(verdict.info.subjectAltName, /DNS:e\.example\.com/)
  assert.match(verdict.info.subjectAltName, /DNS:alt\.example\.com/)
  assert.equal(verdict.info.expired, false)
  assert.match(verdict.info.fingerprint, /^[0-9A-F:]{95}$/)
})

test('normalizeHosts lowercases, dedupes, drops blanks, refuses junk', () => {
  assert.deepEqual(normalizeHosts(['  DSH.Example.COM ', '', 'dsh.example.com']), ['dsh.example.com'])
  assert.throws(() => normalizeHosts('nope'), CertStoreError)
  assert.throws(() => normalizeHosts(['bad host!']), CertStoreError)
  assert.throws(() => normalizeHosts(['']), CertStoreError)
  assert.deepEqual(normalizeHosts(['192.168.1.5', '*.wild.com']), ['192.168.1.5', '*.wild.com'])
})
