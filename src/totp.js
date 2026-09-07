'use strict'

/**
 * TOTP (RFC 6238) — time-based one-time passwords behind the login password.
 *
 * Zero-dependency by house rule: HMAC-SHA1 via node:crypto, base32 (RFC 4648)
 * hand-rolled. The wire format matches every mainstream authenticator app
 * (Google Authenticator, 1Password, Microsoft Authenticator, Aegis, …):
 * 6 digits over a 30-second step, SHA-1, ±1 step of clock-drift tolerance.
 *
 * Verification is constant-time per candidate step and returns the matched
 * step counter so callers can enforce single use (replay guard) by storing it
 * on the user record and rejecting counters ≤ the last used one.
 */

const { createHmac, randomBytes, timingSafeEqual } = require('node:crypto')

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const OTP_STEP_SECONDS = 30
const OTP_DIGITS = 6
/** Accept the previous/next step so a slightly drifting clock still works. */
const OTP_WINDOW = 1
/** 160-bit secrets — the RFC 6238 recommendation and every app's minimum. */
const SECRET_BYTES = 20

function base32Encode(buf) {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

/** Tolerant decode: case-insensitive, ignores `=` padding and whitespace. */
function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/[=\s]/g, '')
  const out = []
  let bits = 0
  let value = 0
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch)
    if (idx === -1) return Buffer.alloc(0)
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** Fresh enrollment secret, base32 (authenticator manual-entry format). */
function generateSecret() {
  return base32Encode(randomBytes(SECRET_BYTES))
}

/** RFC 4226 HOTP — truncated HMAC over an 8-byte big-endian counter. */
function hotp(secretBuf, counter, digits = OTP_DIGITS) {
  const msg = Buffer.alloc(8)
  msg.writeBigUInt64BE(BigInt(counter))
  const digest = createHmac('sha1', secretBuf).update(msg).digest()
  const offset = digest[digest.length - 1] & 0xf
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  return String(binary % 10 ** digits).padStart(digits, '0')
}

/** RFC 6238 TOTP — HOTP with the time step as counter. */
function totpAt(secretBuf, unixSeconds, stepSeconds = OTP_STEP_SECONDS) {
  return hotp(secretBuf, Math.floor(unixSeconds / stepSeconds))
}

/**
 * Verify a user-supplied code. Tolerates surrounding whitespace, requires
 * exactly `OTP_DIGITS` digits. Scans the ±OTP_WINDOW steps around `nowMs`,
 * skipping any step ≤ `lastCounter` (replay / single-use guard). The
 * constant-time comparison runs per candidate step; digit-length mismatch
 * short-circuits before any HMAC work.
 *
 * @returns {{ ok: true, counter: number } | { ok: false }}
 */
function verifyTotp(secretBase32, code, { nowMs = Date.now(), lastCounter = 0 } = {}) {
  const secret = base32Decode(secretBase32)
  if (secret.length === 0) return { ok: false }
  const normalized = String(code || '').replace(/\s+/g, '')
  if (!new RegExp(`^\\d{${OTP_DIGITS}}$`).test(normalized)) return { ok: false }
  const stepNow = Math.floor(nowMs / 1000 / OTP_STEP_SECONDS)
  const given = Buffer.from(normalized, 'utf8')
  for (let counter = stepNow + OTP_WINDOW; counter >= stepNow - OTP_WINDOW; counter -= 1) {
    if (counter <= lastCounter) continue
    const expected = Buffer.from(hotp(secret, counter), 'utf8')
    if (given.length === expected.length && timingSafeEqual(given, expected)) {
      return { ok: true, counter }
    }
  }
  return { ok: false }
}

/** otpauth:// enrollment URI — the payload both QR codes and manual entry carry. */
function otpauthUri({ username, secret, issuer = 'DSH' }) {
  const label = encodeURIComponent(`${issuer}:${username}`)
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(OTP_DIGITS),
    period: String(OTP_STEP_SECONDS),
  })
  return `otpauth://totp/${label}?${params.toString()}`
}

module.exports = {
  OTP_STEP_SECONDS,
  OTP_DIGITS,
  OTP_WINDOW,
  SECRET_BYTES,
  base32Encode,
  base32Decode,
  generateSecret,
  hotp,
  totpAt,
  verifyTotp,
  otpauthUri,
}
