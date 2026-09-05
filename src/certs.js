'use strict'

/**
 * TLS material for one gateway site: loads a supplied certificate pair, or
 * generates a self-signed one (persisted under the certs dir so the
 * fingerprint stays stable across restarts — regenerating every boot would
 * break any client that pinned or trusted the previous cert). Self-signed
 * certs are issued for 100 years (days 36500). Persisted certs are NOT
 * regenerated automatically: to pick up a new expiry or a changed SAN set,
 * delete the cert/key files under the certs dir and restart.
 *
 * Ported from dsh-gateway (clarknu/dsh-gateway) lib/certs.js, adapted to
 * CommonJS. SANs cover every host the site declares, as DNS or IP entries
 * (IPv4 + IPv6), so modern browsers (which validate against the SAN list,
 * not the CN) accept the self-signed certificate for each configured name.
 */

const { existsSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs')
const { join } = require('node:path')
const selfsigned = require('selfsigned')

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/
// IPv6 literal: hex digits + colons only, and must contain at least one colon
// (so a hex-only hostname like "cafe" is not misread as an IPv6 address).
const IPV6_RE = /^[0-9a-fA-F:]+$/

/** Load the configured PEM pair, or generate + persist a self-signed one. */
function loadOrCreateSiteCert({ cert, key, hosts }, certsDir, log) {
  if (cert && key) {
    const crt = readFileSync(cert, 'utf8')
    const prv = readFileSync(key, 'utf8')
    return { cert: crt, key: prv, auto: false }
  }
  if (!certsDir) {
    throw new Error('user-management: certsDir is required to generate self-signed certificates')
  }
  const primary = (hosts || []).find((h) => h && h !== '*') || 'localhost'
  const safe = primary.replace(/[^A-Za-z0-9._-]/g, '_')
  mkdirSync(certsDir, { recursive: true })
  const crtPath = join(certsDir, `${safe}.crt`)
  const keyPath = join(certsDir, `${safe}.key`)
  if (existsSync(crtPath) && existsSync(keyPath)) {
    return {
      cert: readFileSync(crtPath, 'utf8'),
      key: readFileSync(keyPath, 'utf8'),
      auto: true,
      certPath: crtPath,
      keyPath: keyPath,
    }
  }
  const pems = selfsigned.generate(
    [{ name: 'commonName', value: primary }],
    {
      days: 36500,
      keySize: 2048,
      algorithm: 'sha256',
      extensions: [
        {
          name: 'subjectAltName',
          altNames: sanEntries(hosts, primary),
        },
        { name: 'basicConstraints', cA: false },
        { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
        { name: 'extKeyUsage', serverAuth: true },
      ],
    },
  )
  writeFileSync(crtPath, pems.cert, 'utf8')
  writeFileSync(keyPath, pems.private, { encoding: 'utf8', mode: 0o600 })
  if (typeof log === 'function') {
    log(
      `user-management: generated a self-signed certificate for ${JSON.stringify(hosts || [primary])} ` +
        `(${crtPath}) — point cert/key at a CA-signed pair in settings for public hostnames`,
    )
  }
  return { cert: pems.cert, key: pems.private, auto: true, certPath: crtPath, keyPath: keyPath }
}

/** node-forge SAN entries: type 2 = DNS, type 7 = iPAddress (IPv4 or IPv6 literal). */
function sanEntries(hosts, primary) {
  const names = [...new Set([...(hosts || []), primary].filter((h) => h && h !== '*'))]
  return names.map((h) => {
    if (IPV4_RE.test(h)) return { type: 7, ip: h }
    if (IPV6_RE.test(h) && h.includes(':')) return { type: 7, ip: h }
    return { type: 2, value: h }
  })
}

module.exports = { loadOrCreateSiteCert, sanEntries }
