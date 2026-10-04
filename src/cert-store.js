'use strict'

/**
 * Custom-certificate store for the gateway management UI.
 *
 * Certificates pasted/uploaded through the settings panel persist under
 * `$DSH_HOME/user-management/certs/custom/` — one `<id>.crt` + `<id>.key`
 * (0600) pair per entry plus a `meta.json` manifest — so they survive
 * restarts and merge into the gateway's SNI site list independently of the
 * settings-document `sites[]` file-path config (which stays the
 * infrastructure-as-code path; this store is the UI path).
 *
 * The private keys never leave the server: GET responses expose metadata
 * (fingerprint / validity / SANs), never the key PEM. Pair integrity is
 * validated BEFORE persisting (inspectCertPair): the cert must parse, the
 * key must load, and both must share the same public key — a mismatched
 * pair would only surface as handshake failures at request time otherwise.
 */

import fsP from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { createPublicKey, X509Certificate } from 'node:crypto'
import { createSecureContext } from 'node:tls'
import { join } from 'node:path'

const META_FILE = 'meta.json'

/** Label: one DNS label (letters/digits/hyphens, not starting/ending on a
 *  hyphen). */
const LABEL = '[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
/** Host whitelist entries: DNS names (incl. multi-label `*.example.com`
 *  wildcards), IPs (v4 dotted / v6 literal). Lowercased + trimmed; `*` alone
 *  is refused — a catch-all custom site would shadow nothing today but is
 *  one config slip away from presenting the wrong cert to every SNI name. */
const HOST_RE = new RegExp(`^(?:\\*(?:\\.${LABEL})+|${LABEL}(?:\\.${LABEL})*|\\d{1,3}(?:\\.\\d{1,3}){3}|\\[[0-9a-f:]+\\]|[0-9a-f:]+)$`)

class CertStoreError extends Error {
  constructor(code, message) {
    super(message)
    this.code = code
  }
}

/** Normalize + validate a hosts array; throws `bad_hosts` on garbage. */
function normalizeHosts(hosts) {
  if (!Array.isArray(hosts)) throw new CertStoreError('bad_hosts', 'hosts 必须是字符串数组')
  const out = []
  for (const raw of hosts) {
    const host = String(raw || '').trim().toLowerCase()
    if (host === '') continue
    if (host === '*' || host.length > 253 || !HOST_RE.test(host)) {
      throw new CertStoreError('bad_hosts', `非法的主机名：${String(raw).slice(0, 80)}`)
    }
    if (!out.includes(host)) out.push(host)
  }
  if (out.length === 0) throw new CertStoreError('bad_hosts', '至少填写一个主机名')
  return out
}

function pemOf(value) {
  const text = String(value || '').trim()
  if (!text) throw new CertStoreError('bad_cert', '证书或私钥为空')
  if (!text.includes('-----BEGIN')) {
    throw new CertStoreError('bad_cert', '不是 PEM 文本（缺少 -----BEGIN 头）')
  }
  return text.replace(/\r\n/g, '\n') + '\n'
}

function spkiOf(key) {
  try {
    // X509Certificate.publicKey is already a KeyObject (createPublicKey
    // refuses to re-wrap it); PEM strings go through createPublicKey.
    const keyObject = typeof key === 'string' ? createPublicKey(key) : key
    return keyObject.export({ type: 'spki', format: 'pem' })
  } catch { return null }
}

/**
 * Validate a PEM cert+key pair WITHOUT touching disk.
 * Returns { ok:true, cert: pem, key: pem, info } or { ok:false, error }.
 * info: subject, san, notBefore, notAfter, fingerprint, expired, dnsNames.
 */
function inspectCertPair(certValue, keyValue, now = () => Date.now()) {
  let cert
  let keyPem
  try {
    cert = new X509Certificate(pemOf(certValue))
    keyPem = pemOf(keyValue)
  } catch (error) {
    return { ok: false, error: error instanceof CertStoreError ? error.message : `证书解析失败：${error && error.message}` }
  }
  const certSpki = spkiOf(cert.publicKey)
  const keySpki = spkiOf(keyPem)
  if (!certSpki || !keySpki || certSpki !== keySpki) {
    return { ok: false, error: '证书与私钥不匹配（公钥不一致）' }
  }
  try {
    // Full integration check — fails on key formats node:crypto accepts but
    // TLS cannot load (and on certs whose chain the server would reject).
    createSecureContext({ cert: pemOf(certValue), key: keyPem })
  } catch (error) {
    return { ok: false, error: `证书对无法用于 TLS：${error && error.message}` }
  }
  const notAfterMs = Date.parse(cert.validTo)
  return {
    ok: true,
    cert: pemOf(certValue),
    key: keyPem,
    info: {
      subject: cert.subject,
      subjectAltName: cert.subjectAltName || '',
      fingerprint: cert.fingerprint256,
      notBefore: cert.validFrom,
      notAfter: cert.validTo,
      expired: Number.isFinite(notAfterMs) ? notAfterMs <= now() : false,
    },
  }
}

/**
 * Create the custom-cert store rooted at `<certsDir>/custom`.
 * load() is idempotent; every other method awaits it, so callers may fire
 * list/add/remove before the initial read completes.
 */
function createCertStore({ dir, now = () => Date.now() } = {}) {
  if (!dir) throw new Error('user-management cert-store: dir is required')
  const metaFile = join(dir, META_FILE)
  let manifest = { version: 1, items: [] }
  let readyPromise = null

  const writeChain = { meta: Promise.resolve() }

  function atomicWrite(file, content) {
    return fsP.mkdir(dir, { recursive: true }).then(() => {
      const temp = join(dir, `.${randomBytes(6).toString('hex')}.tmp`)
      return fsP.writeFile(temp, content, { encoding: 'utf8', mode: 0o600 })
        .then(() => fsP.rename(temp, file))
    })
  }

  function persistMeta() {
    const run = writeChain.meta.then(() => atomicWrite(metaFile, JSON.stringify(manifest, null, 2)))
    writeChain.meta = run.catch(() => {})
    return run
  }

  /** A broken/corrupt manifest must not take the gateway down: start empty
   *  (the raw files stay on disk; re-adding the cert overwrites them). */
  async function load() {
    if (readyPromise) return readyPromise
    readyPromise = (async () => {
      await fsP.mkdir(dir, { recursive: true })
      try {
        const raw = await fsP.readFile(metaFile, 'utf8')
        const doc = JSON.parse(raw)
        if (doc && Array.isArray(doc.items)) manifest = { version: 1, items: doc.items.filter((it) => it && it.id) }
      } catch { /* missing or corrupt -> empty */ }
      return manifest
    })()
    return readyPromise
  }

  async function list() {
    await load()
    return manifest.items.map((it) => ({ ...it }))
  }

  /** Site descriptors for resolveSites — cert/key as PATHS (gateway-core
   *  reads files through certs.js), tagged origin:'custom' so the UI can
   *  tell UI-managed certs from settings-file ones. */
  async function listSites() {
    await load()
    return manifest.items.map((it) => ({
      id: it.id,
      name: it.name || '',
      origin: 'custom',
      hosts: [...(it.hosts || [])],
      cert: join(dir, `${it.id}.crt`),
      key: join(dir, `${it.id}.key`),
    }))
  }

  function get(id) {
    return manifest.items.find((it) => it.id === id) || null
  }

  /** Validate + persist a new pair. Returns the public metadata record. */
  async function add({ name, hosts, cert, key, by }) {
    const safeHosts = normalizeHosts(hosts)
    const verdict = inspectCertPair(cert, key, now)
    if (!verdict.ok) throw new CertStoreError('bad_pair', verdict.error)
    await load()
    for (const item of manifest.items) {
      const overlap = (item.hosts || []).filter((h) => safeHosts.includes(h))
      if (overlap.length > 0) {
        throw new CertStoreError('host_conflict', `主机名已被其他证书占用（${overlap.join(', ')}）——同名主机只会命中先注册的证书`)
      }
    }
    const id = `c_${now().toString(36)}_${randomBytes(4).toString('hex')}`
    await fsP.mkdir(dir, { recursive: true })
    await fsP.writeFile(join(dir, `${id}.crt`), verdict.cert, { encoding: 'utf8', mode: 0o600 })
    await fsP.writeFile(join(dir, `${id}.key`), verdict.key, { encoding: 'utf8', mode: 0o600 })
    const record = {
      id,
      name: String(name || '').trim().slice(0, 80) || safeHosts[0],
      hosts: safeHosts,
      fingerprint: verdict.info.fingerprint,
      notAfter: verdict.info.notAfter,
      subject: verdict.info.subject,
      expired: verdict.info.expired,
      createdAt: now(),
      createdBy: by || '',
    }
    manifest.items.push(record)
    await persistMeta()
    return { ...record }
  }

  /** Remove a pair (files + manifest entry). Returns true when it existed. */
  async function remove(id) {
    await load()
    const index = manifest.items.findIndex((it) => it.id === id)
    if (index === -1) return false
    manifest.items.splice(index, 1)
    for (const suffix of ['.crt', '.key']) {
      try { await fsP.rm(join(dir, `${id}${suffix}`), { force: true }) } catch { /* best effort */ }
    }
    await persistMeta()
    return true
  }

  return { load, list, listSites, get, add, remove }
}

export {
  createCertStore,
  inspectCertPair,
  normalizeHosts,
  CertStoreError,
  HOST_RE,
}
