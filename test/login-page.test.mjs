// Login page contract: per-form error targets, native password length gate.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { renderLoginPage } = require('../src/login-page.js')

test('login page renders both tabs with per-form error regions', () => {
  const html = renderLoginPage({ hasUsers: true })
  assert.ok(html.includes('id="login-form"'))
  assert.ok(html.includes('id="register-form"'))
  // two independent error regions, resolved via form.querySelector('.err')
  assert.equal(html.split('<div class="err"></div>').length - 1, 2)
  assert.ok(html.includes("form.querySelector('.err')"), 'errors are written to the submitting form’s region')
  assert.ok(!html.includes("getElementById('err')"), 'no shared error element (would hide register errors)')
})

test('fresh system flips to register with the first-admin hint', () => {
  const fresh = renderLoginPage({ hasUsers: false })
  assert.ok(fresh.includes('var hasUsers = false;'))
  assert.ok(fresh.includes('首个注册的账号将成为管理员'))
  const used = renderLoginPage({ hasUsers: true })
  assert.ok(used.includes('var hasUsers = true;'))
})

test('register password input carries native minlength', () => {
  const html = renderLoginPage({ hasUsers: false })
  assert.ok(html.includes('minlength="6"'), 'browser validates length before the server round-trip')
})

test('otp field is a always-visible optional input (no error-then-reveal handshake)', () => {
  const html = renderLoginPage({ hasUsers: true })
  assert.ok(html.includes('id="login-otp"'), 'otp input exists')
  assert.ok(html.includes('autocomplete="one-time-code"'), 'OTP autofill hint for authenticator browsers')
  assert.ok(html.includes('maxlength="6"'), '6-digit cap')
  // 常驻选填：不再隐藏、不再等 otpRequired 才显示
  assert.ok(html.includes('（未开启请留空）'), 'label tells non-enrolled users to leave it empty')
  assert.ok(!html.includes('id="login-otp" style'), 'never hidden inline')
  assert.ok(html.includes("replace(/\\s+/g, '') || undefined"), 'empty code is sent as absent, not empty string')
  assert.ok(!html.includes('otpRequired'), 'page no longer branches on otpRequired')
  assert.ok(!html.includes('reg-otp'), 'register form stays OTP-free')
})

test('remember-username is an opt-in checkbox, gated on the checked state', () => {
  const html = renderLoginPage({ hasUsers: true })
  assert.ok(html.includes('type="checkbox" id="login-remember" checked'), 'checkbox defaults to checked')
  assert.ok(html.includes('记住用户名'), 'visible label')
  assert.ok(html.includes('if (remember.checked) localStorage.setItem'), 'saved only when checked')
  assert.ok(html.includes('else localStorage.removeItem'), 'unchecked clears the stored name')
  assert.ok(html.includes("document.getElementById('login-username').value = remembered"), 'prefilled on the next visit')
})
