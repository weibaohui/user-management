// Unit tests for cert SAN entry mapping (IPv4/IPv6/DNS) + the allLocalIPs
// interface filter (the auto-sites default). Both are pure functions testable
// with stubs — no real network needed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { sanEntries } = require('../src/certs.js')
const { allLocalIPs } = require('../src/index.js').__internals

test('sanEntries: IPv4 -> type 7, IPv6 -> type 7, hostname -> type 2', () => {
  const out = sanEntries(['100.79.247.70', 'fd7a:115c:a1e0::a73a:f747', 'dsh.example.com', 'localhost'], 'localhost')
  const byHost = Object.fromEntries(out.map((e) => [e.ip || e.value, e.type]))
  assert.equal(byHost['100.79.247.70'], 7, 'IPv4 literal -> type 7')
  assert.equal(byHost['fd7a:115c:a1e0::a73a:f747'], 7, 'IPv6 literal -> type 7 (iPAddress)')
  assert.equal(byHost['dsh.example.com'], 2, 'hostname -> type 2')
  assert.equal(byHost['localhost'], 2, 'localhost -> type 2 (DNS)')
})

test('sanEntries: dedups + merges primary + drops "*"', () => {
  const out = sanEntries(['*', '100.79.247.70', '100.79.247.70'], '100.79.247.70')
  assert.equal(out.length, 1, 'primary + the one explicit host collapse; "*" is dropped')
  assert.deepEqual(out[0], { type: 7, ip: '100.79.247.70' })
})

test('sanEntries: a hex-only hostname (no colon) is DNS, not IPv6', () => {
  const out = sanEntries(['cafe'], 'cafe')
  assert.deepEqual(out[0], { type: 2, value: 'cafe' })
})

test('allLocalIPs: skips lo/internal/vEthernet/fe80/::1/169.254., keeps IPv4+IPv6', () => {
  const stub = {
    lo: [
      { address: '127.0.0.1', family: 'IPv4', internal: true },
      { address: '::1', family: 'IPv6', internal: true },
    ],
    eth0: [
      { address: '192.168.1.5', family: 'IPv4', internal: false },
      { address: '169.254.1.1', family: 'IPv4', internal: false }, // APIPA -> skip
      { address: 'fe80::1', family: 'IPv6', internal: false }, // link-local -> skip
      { address: 'fd7a:115c:a1e0::1', family: 'IPv6', internal: false }, // non-link-local v6 -> keep
    ],
    tailscale0: [{ address: '100.79.247.70', family: 'IPv4', internal: false }],
    vEthernet: [{ address: '172.22.0.1', family: 'IPv4', internal: false }], // virtual -> skip
  }
  const ips = allLocalIPs(stub)
  assert.ok(ips.includes('192.168.1.5'), 'keeps eth0 IPv4')
  assert.ok(ips.includes('100.79.247.70'), 'keeps tailscale IPv4')
  assert.ok(ips.includes('fd7a:115c:a1e0::1'), 'keeps non-link-local IPv6')
  assert.ok(!ips.includes('127.0.0.1'), 'skips loopback v4')
  assert.ok(!ips.includes('::1'), 'skips loopback v6')
  assert.ok(!ips.includes('169.254.1.1'), 'skips APIPA')
  assert.ok(!ips.includes('fe80::1'), 'skips link-local v6')
  assert.ok(!ips.includes('172.22.0.1'), 'skips vEthernet (virtual)')
})

test('allLocalIPs: empty/loopback-only interfaces -> []', () => {
  assert.deepEqual(allLocalIPs({}), [])
  assert.deepEqual(allLocalIPs({ lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }] }), [])
})

// ── auto-sites: sslip.io / nip.io SAN aliases ─────────────────────────────

test('autoSiteHosts: localhost + every IP + its sslip.io/nip.io aliases', () => {
  const { autoSiteHosts } = require('../src/index.js').__internals
  const hosts = autoSiteHosts(['100.79.247.70', 'fd7a:115c:a1e0::1'])
  assert.deepEqual(hosts, [
    'localhost',
    '100.79.247.70',
    'fd7a:115c:a1e0::1',
    '100.79.247.70.sslip.io', '100.79.247.70.nip.io',
    'fd7a:115c:a1e0::1.sslip.io', // ugly but valid: aliases work for v6 too
    'fd7a:115c:a1e0::1.nip.io',
  ])
  assert.deepEqual(autoSiteHosts([]), ['localhost'])
  assert.deepEqual(autoSiteHosts(), ['localhost'])
})

// SAN coverage of the auto-site list: every host must land in the SAN set
test('generated cert SAN covers the sslip.io/nip.io aliases', () => {
  const { sanEntries } = require('../src/certs.js')
  const { autoSiteHosts } = require('../src/index.js').__internals
  const hosts = autoSiteHosts(['100.79.247.70'])
  const out = sanEntries(hosts, 'localhost')
  const names = out.map((e) => e.ip || e.value)
  assert.ok(names.includes('100.79.247.70.sslip.io'), 'sslip.io alias as DNS SAN')
  assert.ok(names.includes('100.79.247.70.nip.io'), 'nip.io alias as DNS SAN')
  assert.ok(names.includes('100.79.247.70'), 'raw IP as iPAddress SAN')
})
