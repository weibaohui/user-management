'use strict'

/**
 * The user-management gateway server: one node:https listener that
 * terminates TLS (SNI-selected per-site certificates, self-signed where none
 * are supplied), enforces a Host allow-list, runs the user-management
 * store-backed auth gate, serves /login + /user-management/api/* locally,
 * and reverse-proxies everything else — WebSocket upgrades included — to the
 * loopback dsh webserver.
 *
 * Adapted from dsh-gateway (clarknu/dsh-gateway) lib/gateway-core.js. The
 * dsh-gateway flat-users HMAC auth is replaced by user-management's store:
 * the routing defers to a `decider` (see src/gate.js createDecider) for the
 * allow/redirect/401/403 decision, and to `handleApi` for the local API.
 *
 * Cordis-free by design: the plugin wrapper (src/index.js) owns config
 * resolution + lifecycle + hot-reload + self-heal; this module is testable
 * standalone.
 */

const { createServer: createHttpsServer } = require('node:https')
const { createSecureContext } = require('node:tls')
const { X509Certificate } = require('node:crypto')
const { createProxy } = require('./proxy')
const { loadOrCreateSiteCert } = require('./certs')
const {
  SESSION_COOKIE,
  LOGIN_PAGE_PATH,
  API_PREFIX,
  parseCookies,
  isAuditableRequest,
  sendUnauthorized,
  sendForbidden,
} = require('./gate')

/**
 * Create a gateway from resolved options. Returns { start, stop, port }.
 *
 * options: {
 *   listenHost, port, upstream, sites, certsDir, title,
 *   decider,           // async (req) => { action, session?, path? }
 *   handleApi,         // async (req, res, deps)
 *   renderLoginPage,   // ({ hasUsers, title }) => html
 *   deps,              // { store, clientIp } for handleApi
 *   clearedCookie,     // () => string  (for /logout)
 *   auditHooks,        // { onApiRequest(req, session, path, status), onWsOpen(req, session, path) }
 *   log(msg), warn(msg), onError(err)
 * }
 */
function createGateway(options) {
  const log = typeof options.log === 'function' ? options.log : () => {}
  const warn = typeof options.warn === 'function' ? options.warn : log
  const proxy = createProxy(options.upstream)

  const sites = (options.sites || [{ hosts: ['localhost'] }]).map((site) => ({
    hosts: (site.hosts || []).map((h) => String(h).toLowerCase()),
    cert: site.cert || '',
    key: site.key || '',
  }))
  if (sites.length === 0) sites.push({ hosts: [], cert: '', key: '' })

  const allowList = new Set(sites.flatMap((s) => s.hosts))
  const allowAll = allowList.size === 0
  if (allowAll) {
    warn('user-management: no hosts configured — accepting every Host header (set sites[].hosts to restrict)')
  }

  const contexts = sites.map((site) => {
    const { cert, key } = loadOrCreateSiteCert(site, options.certsDir, log)
    return {
      hosts: site.hosts,
      context: createSecureContext({ cert, key }),
      certPem: cert,
      keyPem: key,
    }
  })
  const defaultSite = contexts[0]

  /** Host matching: exact, bare wildcard, or *.example.com wildcard. */
  function hostMatches(pattern, host) {
    if (pattern === host || pattern === '*') return true
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1)
      return host.endsWith(suffix) && host.length > suffix.length
    }
    return false
  }

  /** Strip port and brackets from a Host header value; lowercase. */
  function normalizeHost(header) {
    if (!header) return ''
    let host = String(header).trim().toLowerCase()
    if (host.startsWith('[')) {
      const end = host.indexOf(']')
      return end === -1 ? host : host.slice(1, end)
    }
    const colon = host.lastIndexOf(':')
    return colon === -1 ? host : host.slice(0, colon)
  }

  function selectContext(servername) {
    const name = (servername || '').toLowerCase()
    for (const entry of contexts) {
      if (entry.hosts.some((h) => hostMatches(h, name))) return entry.context
    }
    return defaultSite.context
  }

  function hostAllowed(host) {
    if (allowAll) return true
    for (const pattern of allowList) {
      if (hostMatches(pattern, host)) return true
    }
    return false
  }

  const send = (res, status, headers, body) => {
    res.writeHead(status, headers)
    res.end(body)
  }
  const redirect = (res, location, extraHeaders) =>
    send(res, 302, Object.assign({ Location: location, 'cache-control': 'no-store' }, extraHeaders || {}), '')

  /** Wire the operation-audit hook to fire when the response completes. */
  function wireAudit(req, res, session, path) {
    const method = (req.method || 'GET').toUpperCase()
    if (typeof options.auditHooks.onApiRequest === 'function' && isAuditableRequest(method, req.headers && req.headers.accept, path)) {
      res.on('finish', () => {
        try { options.auditHooks.onApiRequest(req, session, path, res.statusCode) } catch { /* audit must never break the gate */ }
      })
    }
  }

  async function handleRequest(req, res) {
    const host = normalizeHost(req.headers.host)
    if (!hostAllowed(host)) {
      return send(res, 421, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }, 'user-management: unknown host')
    }

    const url = new URL(req.url || '/', `https://${req.headers.host || 'localhost'}`)
    const path = url.pathname
    const method = (req.method || 'GET').toUpperCase()

    // The decider runs for every request: it checks IP bans first (403,
    // login page included), resolves the session, and returns the gate
    // decision. /login + /logout stay public but are still subject to bans.
    let decision
    try {
      decision = await options.decider(req)
    } catch {
      return sendUnauthorized(res)
    }
    if (decision.action === 'forbidden') return sendForbidden(res)

    // /login — standalone login/register page (register tab is default on a
    // fresh system; first registrant becomes admin). Authed users bounce to /.
    if (path === LOGIN_PAGE_PATH) {
      if (method !== 'GET' && method !== 'HEAD') {
        return send(res, 405, { 'content-type': 'text/plain; charset=utf-8', allow: 'GET, HEAD' }, 'method not allowed')
      }
      if (decision.session) return redirect(res, '/')
      const html = options.renderLoginPage({
        hasUsers: options.deps.store.listUsers().length > 0,
        title: options.title || 'DSH 控制台',
      })
      return send(res, 200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }, html)
    }

    // /logout — clear the cookie + drop the server session, back to /login.
    if (path === '/logout') {
      const cookies = parseCookies(req.headers && req.headers.cookie)
      const token = cookies[SESSION_COOKIE]
      if (token) {
        try { await options.deps.store.dropSession(token) } catch { /* best effort */ }
      }
      return redirect(res, LOGIN_PAGE_PATH, { 'Set-Cookie': options.clearedCookie() })
    }

    // /user-management/api/* — handled locally by the existing API (login,
    // register, session, self-service, admin user-mgmt, audit, bans). The
    // decider already gated non-public sub-paths (401 anonymous); handleApi
    // re-checks authority too.
    if (path === API_PREFIX || path.startsWith(`${API_PREFIX}/`)) {
      if (decision.action !== 'allow') {
        if (decision.action === 'redirect') return redirect(res, decision.location || LOGIN_PAGE_PATH)
        return sendUnauthorized(res)
      }
      wireAudit(req, res, decision.session, path)
      try {
        await options.handleApi(req, res, options.deps)
      } catch (error) {
        if (!res.headersSent) send(res, 500, { 'content-type': 'application/json; charset=utf-8' }, JSON.stringify({ error: String((error && error.message) || error) }))
        else res.end()
      }
      return
    }

    // Everything else (the SPA, dsh /api, /plugins, static) is proxied to
    // the loopback dsh webserver — but only past the auth gate.
    if (decision.action === 'allow') {
      wireAudit(req, res, decision.session, path)
      return proxy.handleRequest(req, res)
    }
    if (decision.action === 'redirect') return redirect(res, decision.location || LOGIN_PAGE_PATH)
    return sendUnauthorized(res)
  }

  function handleUpgrade(req, socket, head) {
    const host = normalizeHost(req.headers.host)
    if (!hostAllowed(host)) {
      socket.end('HTTP/1.1 421 Misdirected Request\r\nConnection: close\r\n\r\n')
      return
    }
    Promise.resolve()
      .then(() => options.decider(req))
      .then((decision) => {
        if (decision.action === 'allow') {
          if (typeof options.auditHooks.onWsOpen === 'function') {
            try { options.auditHooks.onWsOpen(req, decision.session, decision.path) } catch { /* audit must never break the gate */ }
          }
          return proxy.handleUpgrade(req, socket, head)
        }
        try {
          socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
        } catch { /* socket may already be gone */ }
        socket.destroy()
      })
      .catch(() => {
        try { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n') } catch {}
        socket.destroy()
      })
  }

  let server = null
  let boundPort = null

  async function start() {
    // The default site's cert/key are passed directly: a server created
    // with only a SecureContext (no cert/key) sends handshake_failure to
    // clients that omit SNI — which is every browser connecting to an IP
    // literal (https://192.168.x.x). cert/key keeps the no-SNI default
    // context alive; SNICallback then selects per-host contexts.
    server = createHttpsServer(
      {
        cert: defaultSite.certPem,
        key: defaultSite.keyPem,
        SNICallback: (servername, callback) => callback(null, selectContext(servername)),
      },
      (req, res) => {
        handleRequest(req, res).catch(() => {
          if (!res.headersSent) sendUnauthorized(res)
        })
      },
    )
    server.on('upgrade', handleUpgrade)
    server.on('tlsClientError', (_err, tlsSocket) => tlsSocket && tlsSocket.destroy())
    await new Promise((resolve, reject) => {
      const onListening = () => { server.removeListener('error', onError); resolve() }
      const onError = (err) => { server.removeListener('listening', onListening); reject(err) }
      server.once('listening', onListening)
      server.once('error', onError)
      server.listen({ host: options.listenHost || '0.0.0.0', port: options.port || 19843 })
    })
    boundPort = server.address().port
    server.on('error', (err) => {
      warn(`user-management: listener error — ${err.code || err.message}`)
      if (server !== null && typeof options.onError === 'function') options.onError(err)
    })
    log(
      `user-management: https://${options.listenHost === '0.0.0.0' ? '0.0.0.0' : options.listenHost}:${boundPort} ` +
        `-> ${options.upstream} (hosts: ${allowAll ? '*' : [...allowList].join(',')})`,
    )
    return boundPort
  }

  function stop() {
    try { proxy.close() } catch { /* agent teardown must never take the listener down */ }
    const old = server
    server = null
    boundPort = null
    if (old) {
      try { old.close() } catch { /* already closed */ }
      old.closeAllConnections && old.closeAllConnections()
    }
  }

  return {
    start,
    stop,
    get port() { return boundPort },
    /** SHA-256 fingerprint of the certificate presented when no SNI name matches. */
    defaultCertFingerprint() {
      try { return new X509Certificate(defaultSite.certPem).fingerprint256 } catch { return '' }
    },
  }
}

module.exports = { createGateway }
