// Unit tests for resolveSites — the v0.5.4 MERGE semantics that fold
// configured (cert-less) site hosts into the auto-enumerated self-signed
// site instead of replacing the auto list. resolveSites is a pure function
// (autoIps is a parameter — no real network needed).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { resolveSites } = require('../src/index.js').__internals
const { sanEntries } = require('../src/certs.js')

// A representative local NIC set: one LAN IPv4, one Tailscale IPv4, one
// non-link-local IPv6. allLocalIPs would return exactly these.
const LOCAL_IPS = ['192.168.1.5', '100.79.247.70', 'fd7a:115c:a1e0::1']
const AUTO_HOSTS = [
  'localhost',
  '192.168.1.5', '100.79.247.70', 'fd7a:115c:a1e0::1',
  '192.168.1.5.sslip.io', '192.168.1.5.nip.io',
  '100.79.247.70.sslip.io', '100.79.247.70.nip.io',
  'fd7a:115c:a1e0::1.sslip.io', 'fd7a:115c:a1e0::1.nip.io',
]

// ── empty cfg.sites = pure auto (zero-config default, unchanged) ──────────

test('resolveSites: empty cfg.sites -> single self-signed site, pure auto hosts', () => {
  const sites = resolveSites({}, LOCAL_IPS)
  assert.equal(sites.length, 1, 'one site (no configured domain sites)')
  assert.deepEqual(sites[0], { hosts: AUTO_HOSTS, cert: '', key: '' })
})

test('resolveSites: null/missing cfg -> pure auto', () => {
  assert.deepEqual(resolveSites(null, LOCAL_IPS)[0].hosts, AUTO_HOSTS)
  assert.deepEqual(resolveSites({ sites: [] }, LOCAL_IPS)[0].hosts, AUTO_HOSTS)
})

test('resolveSites: no local IPs -> auto site is just localhost', () => {
  const sites = resolveSites({}, [])
  assert.deepEqual(sites, [{ hosts: ['localhost'], cert: '', key: '' }])
})

// ── MERGE: cert-less configured hosts fold into the self-signed site ───────

test('resolveSites: cert-less configured site hosts merge into self-signed site', () => {
  // A NAT'd public IP that no local NIC owns (the v0.5.4 motivating case).
  const sites = resolveSites({ sites: [{ hosts: ['111.228.30.150'] }] }, LOCAL_IPS)
  assert.equal(sites.length, 1, 'still one site — no cert/key -> not an SNI split')
  assert.deepEqual(sites[0].cert, '')
  assert.deepEqual(sites[0].key, '')
  const hosts = sites[0].hosts
  // every auto host survives
  for (const h of AUTO_HOSTS) assert.ok(hosts.includes(h), `auto host kept: ${h}`)
  // the configured public IP is added (not replacing the auto list)
  assert.ok(hosts.includes('111.228.30.150'), 'configured public IP merged in')
  assert.equal(hosts.length, AUTO_HOSTS.length + 1, 'de-duped: +1 new host only')
})

test('resolveSites: multiple cert-less sites merge all hosts (de-duped)', () => {
  const sites = resolveSites({
    sites: [
      { hosts: ['111.228.30.150', '192.168.1.5'] }, // 2nd host is already auto -> dedup
      { hosts: ['203.0.113.7'] },
    ],
  }, LOCAL_IPS)
  assert.equal(sites.length, 1)
  const hosts = sites[0].hosts
  assert.ok(hosts.includes('111.228.30.150'))
  assert.ok(hosts.includes('203.0.113.7'))
  // '192.168.1.5' appears exactly once (auto + configured collapse)
  assert.equal(hosts.filter((h) => h === '192.168.1.5').length, 1, 'deduped')
})

// ── cert/key sites stay independent SNI sites (real domain certs) ─────────

test('resolveSites: cert/key site preserved as independent SNI site', () => {
  const sites = resolveSites({
    sites: [{ hosts: ['dsh.example.com'], cert: '/c/fullchain.pem', key: '/c/privkey.pem' }],
  }, LOCAL_IPS)
  assert.equal(sites.length, 2, 'self-signed auto site + one domain SNI site')
  // site 0 = self-signed auto (localhost + local IPs + aliases), untouched
  assert.deepEqual(sites[0], { hosts: AUTO_HOSTS, cert: '', key: '' })
  // site 1 = the domain cert site, verbatim
  assert.deepEqual(sites[1], { hosts: ['dsh.example.com'], cert: '/c/fullchain.pem', key: '/c/privkey.pem' })
})

test('resolveSites: mix — bare-host site merges, cert site stays independent', () => {
  const sites = resolveSites({
    sites: [
      { hosts: ['111.228.30.150'] },                                                // bare -> merge
      { hosts: ['dsh.example.com'], cert: '/c/fullchain.pem', key: '/c/privkey.pem' }, // cert -> SNI
    ],
  }, LOCAL_IPS)
  assert.equal(sites.length, 2)
  assert.equal(sites[0].cert, '', 'first site is the self-signed default')
  assert.ok(sites[0].hosts.includes('111.228.30.150'), 'bare configured host merged into self-signed site')
  assert.ok(sites[0].hosts.includes('100.79.247.70'), 'auto hosts still present alongside configured')
  assert.deepEqual(sites[1], { hosts: ['dsh.example.com'], cert: '/c/fullchain.pem', key: '/c/privkey.pem' })
})

// ── SAN coverage: the merged hosts land in the self-signed cert SAN ────────

test('SAN covers localhost + localIPs + sslip/nip aliases + configured public IP', () => {
  const sites = resolveSites({ sites: [{ hosts: ['111.228.30.150'] }] }, ['100.79.247.70'])
  const selfSigned = sites[0]
  const entries = sanEntries(selfSigned.hosts, 'localhost')
  const names = entries.map((e) => e.ip || e.value)
  for (const name of [
    'localhost',
    '100.79.247.70', '100.79.247.70.sslip.io', '100.79.247.70.nip.io',
    '111.228.30.150', // the configured NAT public IP, as an iPAddress SAN
  ]) {
    assert.ok(names.includes(name), `self-signed cert SAN covers ${name}`)
  }
  // the configured public IP is an IP (type 7), not a DNS (type 2) entry
  const pub = entries.find((e) => e.ip === '111.228.30.150')
  assert.deepEqual(pub, { type: 7, ip: '111.228.30.150' }, 'public IP -> iPAddress SAN')
})
